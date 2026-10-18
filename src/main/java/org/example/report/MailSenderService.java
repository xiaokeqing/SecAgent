package org.example.report;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * 每日日报的<b>发信口</b>：配置齐全就真的走 SMTP 发出去，否则只落一份 {@code .eml}。
 *
 * <h3>为什么没有 {@code jakarta.mail}</h3>
 * {@code pom.xml} 里没有 {@code spring-boot-starter-mail}，而任务约束是
 * <b>不新增需要联网的依赖</b>。{@code java.net.http} 只做 HTTP，发不了 SMTP；
 * 但 SMTP 本身是个行文本协议，JDK 的 socket 就够——于是这里手写了一个最小会话
 * （EHLO → [STARTTLS] → AUTH LOGIN → MAIL FROM → RCPT TO → DATA → QUIT），
 * 用 JDK 自带 TLS（{@link SSLSocketFactory}），零新依赖。
 *
 * <h3>两道闸</h3>
 * <ul>
 *   <li><b>配置闸</b>：{@link #missingKeys()} 非空（包括 {@code app.mail.enabled=false}）时
 *       <b>绝不连服务器</b>，只把 {@code .eml} 落到 {@code data/reports/outbox/}，
 *       并在返回值里写明缺哪几项 —— "半个配置"连上去的结果通常是密码被记进日志；</li>
 *   <li><b>失败闸</b>：真发失败（超时、5xx、TLS 握手失败）也落 {@code .eml} 并返回
 *       {@link Mode#EML}，<b>不让日报生成失败</b>：一份发不出去的日报仍然是有价值的产物。</li>
 * </ul>
 *
 * <p>收件人只在配置里（{@code app.mail.to[]}），站点订阅页<b>不收集任何邮箱</b>——
 * 那是隐私边界，见 {@code layouts/subscribe/list.html} 的说明。
 */
@Service
public class MailSenderService {

    private static final Logger logger = LoggerFactory.getLogger(MailSenderService.class);

    /** 投递方式：真的发出去了，还是只落了 eml。 */
    public enum Mode {
        SMTP, EML
    }

    /**
     * 投递结果。
     *
     * @param mode    实际走的路
     * @param note    给人读的一句话（落盘时含"缺哪几项"）
     * @param file    落盘路径（走 SMTP 时为 {@code null}）
     * @param missing 配置缺口（空 = 齐全）
     */
    public record Result(Mode mode, String note, Path file, List<String> missing) {
        public boolean sent() {
            return mode == Mode.SMTP;
        }
    }

    private final MailProperties props;

    public MailSenderService(MailProperties props) {
        this.props = props;
    }

    /**
     * 必填项缺失清单；<b>空列表 = 配置齐全、可以真发</b>。
     * 各项键名与 {@code application.yml} / {@code .env.example} 完全一致，便于运维照着补。
     */
    public List<String> missingKeys() {
        List<String> m = new ArrayList<>();
        if (!props.isEnabled()) {
            m.add("app.mail.enabled=true");
        }
        if (blank(props.getHost())) {
            m.add("app.mail.host");
        }
        if (props.getPort() <= 0) {
            m.add("app.mail.port");
        }
        if (blank(props.getUsername())) {
            m.add("app.mail.username");
        }
        if (blank(props.getPassword())) {
            m.add("app.mail.password");
        }
        if (blank(props.getFrom())) {
            m.add("app.mail.from");
        }
        if (props.getTo() == null || props.getTo().stream().allMatch(MailSenderService::blank)) {
            m.add("app.mail.to[]");
        }
        return m;
    }

    public boolean configured() {
        return missingKeys().isEmpty();
    }

    /** 邮件标题：{@code 前缀 + 日期}（默认 {@code [安全日报] 2026-10-19}）。 */
    public String subject(LocalDate day) {
        String prefix = props.getSubjectPrefix() == null ? "" : props.getSubjectPrefix();
        return prefix + day;
    }

    /**
     * 投递一份日报：齐全则真发，否则（或发送失败）落 {@code .eml}。
     *
     * @param day      日报归属日（用于 eml 文件名）
     * @param subject  标题（已含日期）
     * @param textBody 纯文本正文（Markdown 源）
     * @param htmlBody HTML 正文（内联样式）
     */
    public Result deliver(LocalDate day, String subject, String textBody, String htmlBody) {
        String message = buildMessage(subject, textBody, htmlBody);
        List<String> missing = missingKeys();
        if (!missing.isEmpty()) {
            Path f = writeEml(day, message);
            String note = "未配置 SMTP：已落盘 .eml，可手工发送（缺 " + String.join("、", missing) + "）";
            logger.warn("日报邮件未发送 —— {}；落盘 {}", note, f);
            return new Result(Mode.EML, note, f, missing);
        }
        List<String> to = recipients();
        try {
            new SmtpSession(props).send(props.getFrom().trim(), to, message);
            logger.info("日报邮件已通过 SMTP 发出：{}:{} → {}", props.getHost(), props.getPort(), to);
            return new Result(Mode.SMTP, "已通过 " + props.getHost() + ":" + props.getPort() + " 发送", null, List.of());
        } catch (Exception e) {
            Path f = writeEml(day, message);
            String note = "SMTP 发送失败（" + e.getMessage() + "）：已落盘 .eml，可手工发送";
            logger.warn("日报邮件 SMTP 发送失败，改为落盘 {}：{}", f, e.getMessage());
            return new Result(Mode.EML, note, f, List.of());
        }
    }

    /** 收件人去空白、丢空项（配置里常有尾逗号）。 */
    private List<String> recipients() {
        List<String> out = new ArrayList<>();
        for (String s : props.getTo()) {
            if (!blank(s)) {
                out.add(s.trim());
            }
        }
        return out;
    }

    /** 落盘 {@code data/reports/outbox/daily-YYYY-MM-DD.eml}（同一天重跑即覆盖，不堆积）。 */
    private Path writeEml(LocalDate day, String message) {
        Path dir = Paths.get(props.getOutboxDir());
        try {
            Files.createDirectories(dir);
            Path file = dir.resolve("daily-" + day + ".eml");
            Files.writeString(file, message, StandardCharsets.UTF_8);
            return file;
        } catch (IOException e) {
            logger.error("日报 .eml 落盘失败：{}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * 组装 RFC 5322 报文（CRLF 行尾、UTF-8 base64 正文、RFC 2047 编码标题）。
     * 正文用 base64 而不是 quoted-printable：日语标题与中文正文里都是多字节字符，
     * base64 一行 76 字符的硬约束最容易满足，且不会被各家的 8BITMIME 差异坑。
     */
    String buildMessage(String subject, String textBody, String htmlBody) {
        String boundary = "=secagent-daily-" + UUID.randomUUID().toString().replace("-", "");
        StringBuilder sb = new StringBuilder();
        sb.append("From: ").append(header(props.getFrom())).append("\r\n");
        sb.append("To: ").append(header(String.join(", ", recipients()))).append("\r\n");
        sb.append("Subject: ").append(encodeHeader(subject)).append("\r\n");
        sb.append("Date: ").append(DateTimeFormatter.RFC_1123_DATE_TIME
                .format(ZonedDateTime.now())).append("\r\n");
        sb.append("Message-ID: <").append(UUID.randomUUID()).append("@")
                .append(domainOf(props.getFrom())).append(">\r\n");
        sb.append("MIME-Version: 1.0\r\n");
        sb.append("X-Mailer: sec-agent-daily-digest\r\n");
        sb.append("Content-Type: multipart/alternative; boundary=\"").append(boundary).append("\"\r\n");
        sb.append("\r\n");
        sb.append("--").append(boundary).append("\r\n");
        sb.append("Content-Type: text/plain; charset=UTF-8\r\n");
        sb.append("Content-Transfer-Encoding: base64\r\n\r\n");
        sb.append(base64Lines(textBody)).append("\r\n");
        sb.append("--").append(boundary).append("\r\n");
        sb.append("Content-Type: text/html; charset=UTF-8\r\n");
        sb.append("Content-Transfer-Encoding: base64\r\n\r\n");
        sb.append(base64Lines(htmlBody)).append("\r\n");
        sb.append("--").append(boundary).append("--\r\n");
        return sb.toString();
    }

    /** 头字段防注入：含 CR/LF 的值一律压成空格（配置来自环境变量，不能让换行伪造头）。 */
    private static String header(String v) {
        return v == null ? "" : v.replace('\r', ' ').replace('\n', ' ').trim();
    }

    /** RFC 2047 B 编码：{@code =?UTF-8?B?<base64>?=}（标题里有汉字/假名，直接放原文会被多数服务器拒）。 */
    static String encodeHeader(String v) {
        String s = header(v);
        String b64 = Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
        return "=?UTF-8?B?" + b64 + "?=";
    }

    private static String base64Lines(String body) {
        String b64 = Base64.getEncoder().encodeToString((body == null ? "" : body).getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b64.length(); i += 76) {
            sb.append(b64, i, Math.min(b64.length(), i + 76)).append("\r\n");
        }
        return sb.length() == 0 ? "" : sb.substring(0, sb.length() - 2);
    }

    private static String domainOf(String from) {
        int at = from == null ? -1 : from.indexOf('@');
        String d = at >= 0 ? from.substring(at + 1).trim() : "";
        return d.isEmpty() || d.contains(" ") ? "sec-agent.local" : d;
    }

    private static boolean blank(String s) {
        return s == null || s.trim().isEmpty();
    }

    /**
     * 最小 SMTP 会话（JDK socket，无第三方库）。
     *
     * <p>只实现发日报需要的子集：EHLO / STARTTLS / AUTH LOGIN / MAIL / RCPT / DATA / QUIT。
     * 不支持管道化、不支持多个事务 —— 一次连接只发一封信，发完即断。
     */
    static final class SmtpSession implements AutoCloseable {

        private final MailProperties props;
        private Socket socket;
        private BufferedReader in;
        private BufferedWriter out;

        SmtpSession(MailProperties props) {
            this.props = props;
        }

        void send(String from, List<String> to, String message) throws IOException {
            int timeout = Math.max(1, props.getTimeoutSeconds()) * 1000;
            socket = new Socket();
            socket.connect(new InetSocketAddress(props.getHost(), props.getPort()), timeout);
            socket.setSoTimeout(timeout);
            streams(socket);
            try {
                expect(read(), 220);
                ehlo();
                if (!props.isSsl() && props.isStarttls()) {
                    command("STARTTLS", 220);
                    upgrade();
                    ehlo();
                }
                if (!blank(props.getUsername())) {
                    command("AUTH LOGIN", 334);
                    command(Base64.getEncoder().encodeToString(
                            props.getUsername().getBytes(StandardCharsets.UTF_8)), 334);
                    command(Base64.getEncoder().encodeToString(
                            props.getPassword().getBytes(StandardCharsets.UTF_8)), 235);
                }
                command("MAIL FROM:<" + from + ">", 250);
                for (String rcpt : to) {
                    command("RCPT TO:<" + rcpt + ">", 250);
                }
                command("DATA", 354);
                writeData(message);
                expect(read(), 250);
                command("QUIT", 221);
            } finally {
                closeQuietly();
            }
        }

        /** TLS 升级：在已连接的 socket 上包一层，之后的读写都走加密通道。 */
        private void upgrade() throws IOException {
            SSLSocket ssl = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault())
                    .createSocket(socket, props.getHost(), props.getPort(), true);
            ssl.startHandshake();
            socket = ssl;
            streams(ssl);
        }

        private void streams(Socket s) throws IOException {
            in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
            out = new BufferedWriter(new OutputStreamWriter(s.getOutputStream(), StandardCharsets.UTF_8));
        }

        private void ehlo() throws IOException {
            command("EHLO " + localName(), 250);
        }

        private String localName() {
            try {
                String h = java.net.InetAddress.getLocalHost().getHostName();
                return h == null || h.isBlank() ? "sec-agent.local" : h;
            } catch (IOException e) {
                return "sec-agent.local";
            }
        }

        /** 发一条命令并断言返回码（会话失败就抛，由调用方降级成 .eml）。 */
        private void command(String line, int expectCode) throws IOException {
            out.write(line);
            out.write("\r\n");
            out.flush();
            expect(read(), expectCode);
        }

        /** 写正文：逐行点填充（行首 '.' 前缀再加一个 '.'），最后以单独的 "." 结束。 */
        private void writeData(String message) throws IOException {
            for (String line : message.split("\r\n", -1)) {
                if (line.startsWith(".")) {
                    out.write('.');
                }
                out.write(line);
                out.write("\r\n");
            }
            out.write(".\r\n");
            out.flush();
        }

        /** 读一条（可能多行）应答，返回 "250 ok" / "250-..." 拼接后的首段码。 */
        private String read() throws IOException {
            StringBuilder sb = new StringBuilder();
            String line;
            do {
                line = in.readLine();
                if (line == null) {
                    throw new IOException("SMTP 连接被服务器关闭（未读到应答）");
                }
                if (sb.length() > 0) {
                    sb.append(' ');
                }
                sb.append(line.trim());
            } while (line.length() > 3 && line.charAt(3) == '-');
            return sb.toString();
        }

        private static void expect(String reply, int expectCode) throws IOException {
            if (reply == null || reply.length() < 3) {
                throw new IOException("SMTP 应答异常：" + reply);
            }
            int code;
            try {
                code = Integer.parseInt(reply.substring(0, 3));
            } catch (NumberFormatException e) {
                throw new IOException("SMTP 应答不是三位码：" + reply);
            }
            if (code != expectCode) {
                throw new IOException("SMTP 期望 " + expectCode + " 实得 " + code + "（" + reply + "）");
            }
        }

        private void closeQuietly() {
            try {
                if (socket != null) {
                    socket.close();
                }
            } catch (IOException ignored) {
                // 关闭失败不影响结论：报文已经交给服务器（或本来就没发成）
            }
        }

        @Override
        public void close() {
            closeQuietly();
        }
    }
}
