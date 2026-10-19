package org.example.report;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 隐式 TLS（465 端口）的回归测试。
 *
 * <p>线上真实故障：{@code app.mail.ssl=true, port=465} 时，旧代码连上就发明文
 * {@code EHLO}，而 465 端口上的服务器在等 {@code ClientHello} —— 双方各等各的，
 * 15 秒后一起超时，日志只留下一句"Read timed out"，看起来像网络问题。</p>
 *
 * <p>这里不去拿证书起一个真 TLS 服务器（那需要 keystore，测试里凭空造证书反而脆），
 * 而是让客户端连一个<b>普通</b> TCP 服务器，断言它发出的第一批字节是 TLS 握手记录
 * （{@code 0x16 0x03}），而不是明文 EHLO 的 {@code 'E'}。握手当然失败，所以要求
 * 调用方拿到的是降级后的 {@code .eml} 结果，而不是一个抛到顶层的异常。</p>
 */
class MailSenderServiceTlsTest {

    @Test
    void sslModeSendsTlsHandshakeBeforeWaitingForGreeting(@TempDir Path dir) throws Exception {
        byte[] seen = new byte[8];
        int got;
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Acceptor acc = new Acceptor(server, seen);
            acc.start();

            MailProperties mp = props(server.getLocalPort(), dir);
            MailSenderService svc = new MailSenderService(mp);
            MailSenderService.Result r = svc.deliver(LocalDate.of(2026, 10, 19),
                    "[安全日报] 2026-10-19", "正文", "<p>正文</p>");

            acc.join(10000);
            got = acc.got;

            assertEquals(MailSenderService.Mode.EML, r.mode(),
                    "握手失败必须降级成 .eml（返回结果），不能把异常抛给日报生成器");
            assertEquals(true, got >= 2, "客户端一个字节都没发：说明它连 TLS 都没开始");
            assertArrayEquals(new byte[] { 0x16, 0x03 }, new byte[] { seen[0], seen[1] },
                    "ssl=true 时第一批字节应是 TLS 握手记录 0x16 0x03；见到 0x45('E') 就说明又发成明文 EHLO 了");
        }
    }

    @Test
    void startTlsModeStillSpeaksPlainEhloFirst(@TempDir Path dir) throws Exception {
        byte[] seen = new byte[8];
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Acceptor acc = new Acceptor(server, seen);
            // 587 是明文起步：先给一句 220 欢迎语，客户端才会有 EHLO 可说
            acc.banner = "220 fake.smtp ESMTP\r\n";
            acc.start();

            MailProperties mp = props(server.getLocalPort(), dir);
            mp.setSsl(false);
            mp.setStarttls(true);
            MailSenderService svc = new MailSenderService(mp);
            MailSenderService.Result r = svc.deliver(LocalDate.of(2026, 10, 19),
                    "[安全日报] 2026-10-19", "正文", "<p>正文</p>");

            acc.join(10000);

            assertEquals(MailSenderService.Mode.EML, r.mode(), "服务器不应答 220，同样要降级成 .eml");
            assertEquals(true, acc.got >= 2, "587 路径应发出明文 EHLO");
            assertEquals((byte) 'E', seen[0], "STARTTLS 路径的第一批字节必须是明文 EHLO 的 'E'");
        }
    }

    private static MailProperties props(int port, Path dir) {
        MailProperties mp = new MailProperties();
        mp.setEnabled(true);
        mp.setHost("127.0.0.1");
        mp.setPort(port);
        mp.setUsername("u");
        mp.setPassword("p");
        mp.setFrom("from@example.com");
        mp.setTo(List.of("to@example.com"));
        mp.setSsl(true);
        mp.setStarttls(false);
        mp.setTimeoutSeconds(2);
        mp.setOutboxDir(dir.resolve("outbox").toString());
        return mp;
    }

    /** 收下客户端发来的头几个字节就记下来（不做任何应答，让客户端自己超时）。 */
    private static final class Acceptor extends Thread {
        private final ServerSocket server;
        private final byte[] seen;
        private volatile int got;
        /** 非空时在读到任何东西之前先发这句明文欢迎语（只有 STARTTLS 路径需要）。 */
        private String banner;

        Acceptor(ServerSocket server, byte[] seen) {
            this.server = server;
            this.seen = seen;
            setDaemon(true);
        }

        @Override
        public void run() {
            try (Socket s = server.accept()) {
                if (banner != null) {
                    s.getOutputStream().write(banner.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                    s.getOutputStream().flush();
                }
                InputStream in = s.getInputStream();
                int n = 0;
                while (n < seen.length) {
                    int len = in.read(seen, n, seen.length - n);
                    if (len <= 0) {
                        break;
                    }
                    n += len;
                }
                got = n;
            } catch (IOException ignored) {
                // 客户端握手失败断开，属预期
            }
        }
    }
}
