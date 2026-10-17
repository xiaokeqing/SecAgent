package org.example.selfapi;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 自用登录面的审计追加写（JSONL）。
 *
 * <h3>两条硬约束</h3>
 * <ol>
 *   <li><b>请求线程不做 I/O</b>：写文件在独立守护线程上。
 *       本项目有过一次真实教训 —— 请求路径上做磁盘 I/O 会在慢盘时拖住整个站（当时是 502）。</li>
 *   <li><b>审计里永远没有令牌</b>：本类只接受 {@code tokenLen}（整数），
 *       连"令牌前缀"这种字段都没有 —— 不是靠"调用方记得别传"，而是靠<b>没有这个入参</b>。
 *       {@code UserTokenServiceTest} 用哨兵令牌跑一遍并断言文件里搜不到它。</li>
 * </ol>
 *
 * <h3>队列满 / 未配置时的行为</h3>
 * <ul>
 *   <li><b>未配置</b>（{@code app.user.audit-file} 为空）⇒ 只打日志，不落盘（单测与裁剪部署）；</li>
 *   <li><b>队列满</b>⇒ 丢弃该条并 WARN（有界队列）。宁可丢审计，也不让审计把请求线程拖死 ——
 *       这是与 accesslog 一致的既有取舍。</li>
 * </ul>
 */
public class UserTokenAuditWriter {

    private static final Logger logger = LoggerFactory.getLogger(UserTokenAuditWriter.class);

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssxxx");

    /** 有界队列：满了就丢（见类注释的取舍） */
    private static final int QUEUE_CAPACITY = 4096;

    private final BlockingQueue<String> queue = new ArrayBlockingQueue<>(QUEUE_CAPACITY);
    private final AtomicBoolean started = new AtomicBoolean(false);
    /** 最后一次成功写入的纳秒时刻；空闲超过 IDLE_CLOSE_NANOS 就关句柄（见 loop()）。 */
    private final java.util.concurrent.atomic.AtomicLong lastWriteNanos =
            new java.util.concurrent.atomic.AtomicLong(System.nanoTime());
    private static final long IDLE_CLOSE_NANOS = java.util.concurrent.TimeUnit.SECONDS.toNanos(3);

    /** 为空 = 不落盘。volatile：configure 在启动期写，写线程读 */
    private volatile String file;

    /** 由 {@code UserTokenService.init()} 调用（Spring 启动期，单线程） */
    public void configure(String file) {
        this.file = (file == null || file.isBlank()) ? null : file.trim();
        if (this.file == null) {
            logger.info("自用登录面审计：未配置 app.user.audit-file → 只打日志、不落盘（日志里同样不含令牌）");
            return;
        }
        logger.info("自用登录面审计：落盘 {}（JSONL 追加写；只记 IP 掩码 / 结果 / 长度，永不记令牌）", this.file);
        startWriter();
    }

    /** 是否落盘（供状态端点如实披露，不假装有审计） */
    public boolean enabled() {
        return file != null;
    }

    /**
     * 记一条审计。
     *
     * <p><b>入参里没有令牌</b>（只有长度）—— 这是"永不记录令牌"的结构性保证。
     */
    public void write(String event, String result, String reason, String ipMasked, Integer tokenLen,
                      Integer failCount, Long retryAfter, String conversationIdHash,
                      Integer round, Integer quotaUsed, String state) {
        String line = toJson(event, result, reason, ipMasked, tokenLen, failCount, retryAfter,
                conversationIdHash, round, quotaUsed, state);
        if (file == null) {
            // 未配置落盘：只打日志（INFO 级便于本地调试；生产配了文件就不会刷日志）
            logger.info("SELF-AUDIT {}", line);
            return;
        }
        if (!queue.offer(line)) {
            logger.warn("自用登录面审计队列已满（{}），本条丢弃（不影响请求处理）", QUEUE_CAPACITY);
        }
    }

    /** 纯函数：便于单测直接断言语义，不需要起线程、不需要塞队列 */
    static String toJson(String event, String result, String reason, String ipMasked, Integer tokenLen,
                         Integer failCount, Long retryAfter, String conversationIdHash,
                         Integer round, Integer quotaUsed, String state) {
        StringBuilder sb = new StringBuilder(192);
        sb.append('{');
        sb.append("\"ts\":\"").append(TS.format(OffsetDateTime.now())).append('"');
        append(sb, "event", event);
        append(sb, "result", result);
        append(sb, "reason", reason);
        append(sb, "ipMasked", ipMasked);
        appendNum(sb, "tokenLen", tokenLen);
        appendNum(sb, "failCount", failCount);
        appendNum(sb, "retryAfter", retryAfter);
        append(sb, "conversationIdHash", conversationIdHash);
        appendNum(sb, "round", round);
        appendNum(sb, "quotaUsed", quotaUsed);
        append(sb, "state", state);
        sb.append('}');
        return sb.toString();
    }

    private static void append(StringBuilder sb, String key, String value) {
        if (value == null) {
            return;
        }
        sb.append(",\"").append(key).append("\":\"").append(escape(value)).append('"');
    }

    private static void appendNum(StringBuilder sb, String key, Number value) {
        if (value == null) {
            return;
        }
        sb.append(",\"").append(key).append("\":").append(value.longValue());
    }

    private static String escape(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"' || c == '\\') {
                sb.append('\\').append(c);
            } else if (c < 0x20) {
                sb.append(' ');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private void startWriter() {
        if (!started.compareAndSet(false, true)) {
            return;
        }
        Thread t = new Thread(this::loop, "self-audit-writer");
        t.setDaemon(true);
        t.start();
    }

    private void loop() {
        BufferedWriter writer = null;
        while (true) {
            try {
                String line = queue.poll(1, TimeUnit.SECONDS);
                if (line == null) {
                    if (writer != null) {
                        writer.flush();
                        /* 队列空超过 IDLE_CLOSE_SECONDS 就关掉句柄：
                           ① 生产上审计一天最多几百条，长时间占用文件句柄没有收益；
                           ② Windows 上打开的句柄会让临时目录删不掉（测试 @TempDir 清理偶发
                              "Failed to delete temp directory"，曾把一次发布卡掉）。
                           下一条到达时会重新打开（APPEND，不丢内容）。 */
                        if (System.nanoTime() - lastWriteNanos.get() > IDLE_CLOSE_NANOS) {
                            closeQuietly(writer);
                            writer = null;
                        }
                    }
                    continue;
                }
                if (writer == null) {
                    String target = file;
                    if (target == null) {
                        continue;
                    }
                    Path p = Path.of(target);
                    if (p.getParent() != null) {
                        Files.createDirectories(p.getParent());
                    }
                    writer = Files.newBufferedWriter(p, StandardCharsets.UTF_8,
                            StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                }
                writer.write(line);
                writer.newLine();
                // 每条都 flush：审计的价值在"出事时确实有"，而这里一天最多几百条
                writer.flush();
                lastWriteNanos.set(System.nanoTime());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                logger.warn("自用登录面审计写入失败（继续运行，不阻断请求）：{}", e.getMessage());
                closeQuietly(writer);
                writer = null;
                try {
                    Thread.sleep(1000L);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
    }

    private static void closeQuietly(BufferedWriter writer) {
        if (writer == null) {
            return;
        }
        try {
            writer.close();
        } catch (Exception ignored) {
            // 关闭失败无需处理：下一次写入会重新打开
        }
    }
}
