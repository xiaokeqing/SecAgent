package org.example.accesslog;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

/**
 * {@code GET /api/public/webstats} 的<b>数据面</b>：把"访问日志 + 内存聚合器"包成一个只读服务。
 *
 * <h3>三条线（用户口径③④）</h3>
 * <ol>
 *   <li><b>实时</b>：{@link AccessLogWriter} 的写线程每落盘一行就调一次 {@link #acceptLine(String)}
 *       ——聚合发生在写线程上，<b>请求线程零成本、请求路径零 I/O</b>。</li>
 *   <li><b>回填</b>：启动时（{@link #beginBackfill(Path)}，由 {@code AccessLogFilter} 在写线程启动
 *       <b>之前</b>调用）记下活动文件当时的字节长度，再用后台线程读"<b>最多到那个长度</b>"的
 *       活动文件 + 最近的轮转文件。这样"回填读到的行"与"写线程实时计的行"<b>天然不重叠</b>，
 *       不会把同一行数两遍（这是最容易写错、又不报错的地方）。</li>
 *   <li><b>文件状态</b>：单独的守护线程定期 stat 活动文件（存在/可读），
 *       缺文件要连续两次探测才置 false（轮转的 rename→create 瞬间不能被当成"文件没了"）。
 *       文件重新出现时自动恢复状态并补读"新出现的轮转文件"——
 *       自愈但不重复计数。</li>
 * </ol>
 *
 * <p>读不到就如实说读不到：{@link Status} 原样交给公开端点去区分
 * {@code LOG_FILE_MISSING} / {@code LOG_UNREADABLE} / {@code WINDOW_EMPTY}，
 * <b>绝不用"空分布"冒充"这段时间太平"</b>。
 */
@Component
public class WebStatsService {

    private static final Logger logger = LoggerFactory.getLogger(WebStatsService.class);

    /** 缺文件要连续这么多次探测才算"真的不存在"（躲开轮转的 rename→create 窗口） */
    static final int MISSING_PROBE_THRESHOLD = 2;

    /** 解析失败/读失败时的 WARN 节流间隔 */
    static final long WARN_INTERVAL_MS = 30_000L;

    private final ObjectMapper mapper = new ObjectMapper();

    @Value("${app.webstats.enabled:true}")
    private boolean enabled = true;

    /** UA 截断长度（口径：公网只给 60 字符，且先过控制字符/去 IP） */
    @Value("${app.webstats.ua-max-chars:60}")
    private int uaMaxChars = 60;

    /** 回填总字节预算（MB）：读满就停，剩下的如实算"没覆盖到" */
    @Value("${app.webstats.backfill-max-mb:64}")
    private int backfillMaxMb = 64;

    /** 文件状态探测间隔（秒） */
    @Value("${app.webstats.file-probe-seconds:10}")
    private int fileProbeSeconds = 10;

    /** 与 AccessLogFilter 读同一对键（访问日志没开时本端点只能报 LOG_DISABLED） */
    @Value("${app.accesslog.enabled:true}")
    private boolean accessLogEnabled = true;

    private Clock clock = Clock.systemDefaultZone();

    private volatile WebStatsAggregator aggregator;
    private volatile Path logDir;
    private volatile Path activeFile;
    private volatile long sizeAtStart;
    private volatile boolean running;
    private volatile boolean started;

    // ---- 文件状态（只由探测线程 / 回填线程写，请求线程只读）----
    private volatile boolean fileExists;
    /** 最近一次探测的"文件可读"（不含读失败判定；读失败见 {@link #activeReadFailed}） */
    private volatile boolean probeReadable;
    private volatile boolean activeReadFailed;
    private volatile int consecutiveMissing;
    private volatile boolean backfillRunning;
    private volatile boolean backfillDone;
    private volatile String lastError = "";

    private final AtomicLong parsedRecords = new AtomicLong();
    private final AtomicLong backfilledRecords = new AtomicLong();
    private final AtomicLong skippedLines = new AtomicLong();
    private final AtomicLong rotatedReadFailures = new AtomicLong();
    private final Set<String> readFiles = java.util.Collections.synchronizedSet(new LinkedHashSet<>());

    private final Object backfillSignal = new Object();
    private volatile boolean backfillRequested;

    private volatile Thread probeThread;
    private volatile Thread backfillThread;
    private volatile long lastWarnAt;

    /**
     * 公开端点用的只读状态。
     *
     * <p>把"内存上限"也放在这里：公开端点的 {@code coverage} 里要如实写明
     * "窗口 = 288 个 5 分钟桶、热力图 168 格、UA 每桶 24 槽/全局 128 槽"，
     * 这样"这个数字是怎么来的、会不会被刷爆内存"在响应里就能自证。
     */
    public record Status(boolean enabled,
                         boolean accessLogEnabled,
                         boolean fileExists,
                         boolean fileReadable,
                         boolean backfillRunning,
                         boolean backfillDone,
                         long parsedRecords,
                         long backfilledRecords,
                         long skippedLines,
                         int bucketCount,
                         int bucketSeconds,
                         int hourCells,
                         int uaSlotsPerBucket,
                         int globalUaSlots,
                         String lastError) {
    }

    /**
     * 由 {@code AccessLogFilter} 在<b>写线程启动之前</b>调用（顺序不可换，见类注释）。
     *
     * @param dir 访问日志目录（与 {@code app.accesslog.dir} 同一个值，由 Filter 传进来，
     *            避免在两处各解释一次配置）
     */
    public synchronized void beginBackfill(Path dir) {
        if (started) {
            return;
        }
        started = true;
        this.logDir = dir;
        this.activeFile = dir == null ? null : dir.resolve(AccessLogWriter.DEFAULT_ACTIVE_NAME);
        this.aggregator = new WebStatsAggregator(clock, clock.getZone(), uaMaxChars,
                WebStatsAggregator.UA_SLOTS_PER_BUCKET, WebStatsAggregator.GLOBAL_UA_SLOTS);
        if (!enabled || !accessLogEnabled) {
            logger.info("WEBSTATS 不启动聚合：enabled={} accessLogEnabled={}（端点会如实返回原因，不假装太平）",
                    enabled, accessLogEnabled);
            return;
        }
        captureBackfillPoint();
        probeOnce();
        running = true;
        startProbeThread();
        startBackfillThread();
        requestBackfill();
        logger.info("WEBSTATS 聚合已启动：file={} window=24h(288×{}s) heatmap=7×24 ua={}字符",
                activeFile, WebStatsAggregator.BUCKET_SECONDS, uaMaxChars);
    }

    /** 记录活动文件当前长度：回填只读到这里，剩下的交给写线程实时计（不重复计数） */
    private void captureBackfillPoint() {
        Path f = activeFile;
        long size = 0L;
        if (f != null) {
            try {
                if (Files.exists(f)) {
                    size = Files.size(f);
                }
            } catch (IOException e) {
                recordError("size", e);
            }
        }
        sizeAtStart = size;
    }

    /**
     * 一行访问日志（JSONL 原文）→ 聚合器。由写线程调用。
     *
     * <p><b>绝不抛异常</b>：聚合是"锦上添花"，不能让写线程因为一行脏数据出问题。
     * 解析不了的行计入 {@code skippedLines}（公开响应的 coverage 会如实披露），不静默。
     */
    public boolean acceptLine(String line) {
        if (!enabled) {
            return false;
        }
        WebStatsAggregator agg = aggregator;
        if (line == null || line.isBlank() || agg == null) {
            return false;
        }
        try {
            JsonNode node = mapper.readTree(line);
            OffsetDateTime ts = parseTs(node.path("ts").asText(""));
            if (ts == null) {
                skippedLines.incrementAndGet();
                warnThrottled("访问日志行没有可用时间戳，本行不计入聚合（计数已披露）");
                return false;
            }
            agg.record(ts, node.path("status").asInt(0), node.path("path").asText(""),
                    node.path("ua").asText(""));
            parsedRecords.incrementAndGet();
            return true;
        } catch (Exception e) {
            skippedLines.incrementAndGet();
            recordError("parse", e);
            return false;
        }
    }

    /** 时间戳：日志写的是 ISO-8601 带偏移量；没有偏移量时按本机时区兜底（不丢行） */
    OffsetDateTime parseTs(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return OffsetDateTime.parse(raw);
        } catch (DateTimeParseException ignored) {
            try {
                return LocalDateTime.parse(raw).atZone(clock.getZone()).toOffsetDateTime();
            } catch (DateTimeParseException e) {
                return null;
            }
        }
    }

    // ==================== 文件状态探测（自愈） ====================

    /** 探测一次活动文件状态；缺文件要连续 {@value #MISSING_PROBE_THRESHOLD} 次才置 false */
    void probeOnce() {
        Path f = activeFile;
        if (f == null) {
            fileExists = false;
            probeReadable = false;
            return;
        }
        boolean exists = Files.exists(f);
        if (exists) {
            boolean wasMissing = !fileExists;
            consecutiveMissing = 0;
            fileExists = true;
            probeReadable = Files.isReadable(f);
            if (wasMissing && backfillDone) {
                // 文件重新出现：补读这一段时间里新出现的轮转文件（活动文件本身不重读，避免重复计数）
                captureBackfillPoint();
                requestBackfill();
                logger.info("WEBSTATS 访问日志文件恢复：{}（已请求补读轮转文件）", f);
            }
        } else {
            consecutiveMissing++;
            if (consecutiveMissing >= MISSING_PROBE_THRESHOLD) {
                if (fileExists) {
                    logger.warn("WEBSTATS 访问日志文件不存在（连续 {} 次探测）：{} —— 端点会如实返回 LOG_FILE_MISSING",
                            consecutiveMissing, f);
                }
                fileExists = false;
                probeReadable = false;
            }
            // 未达阈值：保持上一次判断（轮转的 rename→create 瞬间不能报"读不出来"）
        }
    }

    /**
     * 对外口径的"可读"：文件在 + 探测可读 + <b>没有读失败过</b>。
     *
     * <p>刻意把"读失败"（例如活动文件其实是个目录）也算进来：那种情况下
     * {@code Files.isReadable} 仍可能为 true，只有"真的去打开它"才知道读不出来 ——
     * 端点必须据此返回 {@code LOG_UNREADABLE}，而不是"0 请求"。
     */
    private boolean readableNow() {
        return fileExists && probeReadable && !activeReadFailed;
    }

    // ==================== 回填 ====================

    private void startProbeThread() {
        long intervalMs = Math.max(1, fileProbeSeconds) * 1000L;
        Thread t = new Thread(() -> {
            while (running) {
                sleepQuietly(intervalMs);
                if (!running) {
                    return;
                }
                probeOnce();
            }
        }, "secagent-webstats-probe");
        t.setDaemon(true);
        probeThread = t;
        t.start();
    }

    private void startBackfillThread() {
        Thread t = new Thread(this::backfillLoop, "secagent-webstats-backfill");
        t.setDaemon(true);
        backfillThread = t;
        t.start();
    }

    private void requestBackfill() {
        synchronized (backfillSignal) {
            backfillRequested = true;
            backfillSignal.notifyAll();
        }
    }

    private void backfillLoop() {
        while (running) {
            synchronized (backfillSignal) {
                long deadline = System.currentTimeMillis() + 60_000L;
                while (running && !backfillRequested && System.currentTimeMillis() < deadline) {
                    try {
                        backfillSignal.wait(1000L);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
                if (!running) {
                    return;
                }
                if (!backfillRequested) {
                    continue;
                }
                backfillRequested = false;
            }
            backfillBlocking();
        }
    }

    /** 同步跑一遍回填（线程与单测共用的实现） */
    void backfillBlocking() {
        if (!enabled || !accessLogEnabled) {
            backfillDone = true;
            return;
        }
        WebStatsAggregator agg = aggregator;
        Path active = activeFile;
        if (agg == null || active == null) {
            backfillDone = true;
            return;
        }
        backfillRunning = true;
        long budget = Math.max(1, backfillMaxMb) * 1024L * 1024L;
        long used = 0L;
        try {
            String activeName = active.getFileName().toString();
            if (!readFiles.contains(activeName)) {
                // 首次回填：只读 [0, sizeAtStart)（写线程从 sizeAtStart 往后实时计，两边不重叠）
                used += readOne(active, Math.min(budget, sizeAtStart), true);
                readFiles.add(activeName);
            } else {
                // 补读（文件重新出现）：活动文件已被读过，重读会与实时计数重复 —— 只探测能不能打开
                probeReadableOnly(active);
            }
            for (Path f : rotatedFilesNewestFirst()) {
                if (used >= budget) {
                    break;
                }
                String name = f.getFileName().toString();
                if (readFiles.contains(name)) {
                    continue;
                }
                used += readOne(f, budget - used, false);
                readFiles.add(name);
            }
        } finally {
            backfillRunning = false;
            backfillDone = true;
            logger.info("WEBSTATS 回填完成：读入 {} 行（预算用 {}/{} MB），累计跳过 {} 行，轮转文件读失败 {} 次",
                    backfilledRecords.get(), used / (1024 * 1024), Math.max(1, backfillMaxMb),
                    skippedLines.get(), rotatedReadFailures.get());
        }
    }

    /** 只探测"能不能打开"：不读内容，因此不会与实时计数重复（自愈路径用） */
    private void probeReadableOnly(Path f) {
        try (InputStream in = Files.newInputStream(f)) {
            activeReadFailed = false;
        } catch (IOException e) {
            activeReadFailed = true;
            recordError("read", e);
        }
    }

    /** 活动文件 / 轮转文件（新的在前）；活动文件本身不参与"轮转文件"遍历 */
    private List<Path> rotatedFilesNewestFirst() {
        List<Path> out = new ArrayList<>();
        Path dir = logDir;
        if (dir == null) {
            return out;
        }
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, "access-*")) {
            for (Path p : stream) {
                if (Files.isRegularFile(p)) {
                    out.add(p);
                }
            }
        } catch (IOException e) {
            recordError("list", e);
            return out;
        }
        out.sort(Comparator.comparingLong(this::lastModified).reversed());
        return out;
    }

    private long lastModified(Path p) {
        try {
            return Files.getLastModifiedTime(p).toMillis();
        } catch (IOException e) {
            return 0L;
        }
    }

    /**
     * 读一个文件（最多 {@code cap} 字节，避免把 400MB 轮转文件全搬进内存/时间）。
     *
     * <p>达到字节预算边界时最后一行可能是半行：它会解析失败并计入 {@code skippedLines}
     * （公开响应的 coverage 会披露），比"悄悄少算一行"更诚实。
     */
    private long readOne(Path f, long cap, boolean isActiveFile) {
        long used = 0L;
        long fed = 0L;
        try (InputStream in = Files.newInputStream(f);
             BufferedReader reader = new BufferedReader(
                     new InputStreamReader(new BoundedInputStream(in, Math.max(0L, cap)), StandardCharsets.UTF_8))) {
            if (isActiveFile) {
                activeReadFailed = false;
            }
            String line;
            while ((line = reader.readLine()) != null) {
                used += line.getBytes(StandardCharsets.UTF_8).length + 1L;
                if (!line.isBlank() && acceptLine(line)) {
                    fed++;
                }
                if (used >= cap) {
                    break;
                }
            }
        } catch (IOException e) {
            if (isActiveFile) {
                activeReadFailed = true;
            } else {
                rotatedReadFailures.incrementAndGet();
            }
            recordError("read", e);
        }
        backfilledRecords.addAndGet(fed);
        return used;
    }

    // ==================== 只读出口 ====================

    public boolean enabled() {
        return enabled;
    }

    public boolean accessLogEnabled() {
        return accessLogEnabled;
    }

    /** 当前快照（纯内存；请求线程调用，不做任何 I/O） */
    public WebStatsAggregator.Snapshot snapshot(OffsetDateTime now, WebStatsAggregator.Thresholds thresholds) {
        WebStatsAggregator agg = aggregator;
        if (agg == null || !enabled) {
            return WebStatsAggregator.Snapshot.empty();
        }
        return agg.snapshot(now, thresholds);
    }

    public Status status() {
        return new Status(enabled, accessLogEnabled, fileExists, readableNow(), backfillRunning, backfillDone,
                parsedRecords.get(), backfilledRecords.get(), skippedLines.get(),
                WebStatsAggregator.BUCKET_COUNT, WebStatsAggregator.BUCKET_SECONDS, WebStatsAggregator.HOUR_CELLS,
                WebStatsAggregator.UA_SLOTS_PER_BUCKET, WebStatsAggregator.GLOBAL_UA_SLOTS, lastError);
    }

    /** 单测用：等回填结束（真环境不阻塞任何线程） */
    public boolean awaitBackfill(long timeoutMs) {
        long deadline = System.currentTimeMillis() + Math.max(0L, timeoutMs);
        while (System.currentTimeMillis() < deadline) {
            if (backfillDone && !backfillRunning) {
                return true;
            }
            sleepQuietly(10L);
        }
        return backfillDone && !backfillRunning;
    }

    @PreDestroy
    public void stop() {
        running = false;
        requestBackfill();
        joinQuietly(probeThread);
        joinQuietly(backfillThread);
    }

    // ==================== 内部小工具 ====================

    private void joinQuietly(Thread t) {
        if (t == null) {
            return;
        }
        t.interrupt();
        try {
            t.join(2000L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void recordError(String stage, Exception e) {
        lastError = stage + ": " + e.getClass().getSimpleName() + ": " + e.getMessage();
        warnThrottled("WEBSTATS " + stage + " 失败（不影响请求，也不影响落盘）：" + lastError);
    }

    private void warnThrottled(String message) {
        long now = System.currentTimeMillis();
        if (now - lastWarnAt >= WARN_INTERVAL_MS) {
            lastWarnAt = now;
            logger.warn("{}", message);
        }
    }

    private static void sleepQuietly(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** 只允许读 {@code cap} 字节的上游视图（不用第三方库，也不需要读完整个轮转文件） */
    private static final class BoundedInputStream extends InputStream {

        private final InputStream in;
        private long remaining;

        BoundedInputStream(InputStream in, long limit) {
            this.in = in;
            this.remaining = limit;
        }

        @Override
        public int read() throws IOException {
            if (remaining <= 0) {
                return -1;
            }
            int b = in.read();
            if (b >= 0) {
                remaining--;
            }
            return b;
        }

        @Override
        public int read(byte[] buf, int off, int len) throws IOException {
            if (remaining <= 0) {
                return -1;
            }
            int n = in.read(buf, off, (int) Math.min(len, remaining));
            if (n > 0) {
                remaining -= n;
            }
            return n;
        }

        @Override
        public void close() throws IOException {
            in.close();
        }
    }
}
