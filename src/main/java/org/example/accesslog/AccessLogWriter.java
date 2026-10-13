package org.example.accesslog;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 访问日志的<b>异步落盘器</b>：JSONL 追加写 + 按天/按大小轮转 + 按天保留。
 *
 * <h3>为什么必须异步（这是本次设计的核心约束）</h3>
 * 2026-10-13 的生产事故复盘（RUNBOOK §23）里，四条独立缺陷中有两条都是
 * "在请求路径上做 I/O"造成的：请求线程被磁盘/上游拖住 → 整站 502。
 * 访问日志是<b>每个请求都要写一行</b>的东西，如果直接在请求线程里
 * {@code Files.write}，那么慢盘、NFS 抖动、目录 fsync 都会变成"每个请求都慢一点"，
 * 极端情况下写满队列/写阻塞会直接把 Tomcat 线程池拖死。
 * 所以这里刻意做成：请求线程只做一次 {@link BlockingQueue#offer}（无锁、不阻塞），
 * 真正的 I/O 全部在一个守护线程里。
 *
 * <h3>写不出去时的行为（不静默、不拖垮请求）</h3>
 * <ul>
 *   <li>队列满 → 丢弃该条并<b>节流打 WARN</b>（默认每 30 秒最多一条，带累计丢弃数）；
 *       绝不阻塞请求线程去等队列。</li>
 *   <li>写盘抛异常 → 计数 + 节流 WARN，并关闭句柄下次重开；
 *       <b>请求本身永远不受影响</b>。</li>
 * </ul>
 * 这两条合起来就是"如实降级"：日志写不出来是**可见的**（日志里有 WARN、stats 里有计数），
 * 但不会把"用户能用"这件事搭进去。
 *
 * <h3>轮转与保留</h3>
 * <ul>
 *   <li>当前文件固定叫 {@code access.jsonl}（<b>路径稳定</b>）——
 *       fail2ban 与 Wazuh 指的就是这个路径，不能随日期漂移。</li>
 *   <li>跨天或超过 {@code max-file-mb} 时改名成 {@code access-<yyyyMMdd-HHmmss>.jsonl}
 *       （同一秒内多次轮转再加 {@code -1}、{@code -2} 后缀），然后重新创建 {@code access.jsonl}。</li>
 *   <li>保留 {@code retain-days} 天：按 mtime 删除更老的 {@code access-*.jsonl}。
 *       当前文件永远不删。</li>
 * </ul>
 * <b>只有写线程会碰文件</b>，所以下面所有文件相关的字段都不需要同步。
 */
public class AccessLogWriter implements AutoCloseable {

    private static final Logger logger = LoggerFactory.getLogger(AccessLogWriter.class);

    /** 活动文件名固定（fail2ban/Wazuh 依赖这个稳定路径） */
    public static final String DEFAULT_ACTIVE_NAME = "access.jsonl";

    /** 队列容量：按"每秒 2000 行、最多积压 4 秒"的量级取值，异常时先丢再谈 */
    public static final int DEFAULT_QUEUE_CAPACITY = 8192;

    private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

    /** WARN 节流间隔（毫秒）：磁盘坏了的时候不要每条请求打一行日志 */
    static final long WARN_INTERVAL_MS = 30_000L;

    private final Path dir;
    private final String activeName;
    private final int retainDays;
    private final long maxFileBytes;
    private final int queueCapacity;
    private final Clock clock;

    private final BlockingQueue<String> queue;
    private final AtomicLong queued = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong written = new AtomicLong();
    private final AtomicLong failedWrites = new AtomicLong();
    private final AtomicLong rotations = new AtomicLong();
    private final AtomicLong purged = new AtomicLong();

    private volatile String lastError = "";
    /** 最后一次真正落盘所在的线程名 —— 用来钉住"写盘不在请求线程上"这条承诺 */
    private volatile String lastWriteThread = "";
    private volatile long lastWarnAt;
    private volatile boolean running;
    private volatile boolean started;
    private volatile Thread worker;

    // ↓↓↓ 只允许写线程访问（start() 之外不再从别的线程读）
    private BufferedWriter out;
    private Path activePath;
    private long activeBytes;
    private LocalDate activeDay;

    public AccessLogWriter(Path dir, int retainDays, long maxFileBytes) {
        this(dir, DEFAULT_ACTIVE_NAME, retainDays, maxFileBytes, DEFAULT_QUEUE_CAPACITY, Clock.systemDefaultZone());
    }

    public AccessLogWriter(Path dir, String activeName, int retainDays, long maxFileBytes,
                           int queueCapacity, Clock clock) {
        this(dir, activeName, retainDays, maxFileBytes, new ArrayBlockingQueue<>(Math.max(16, queueCapacity)),
                clock, Math.max(16, queueCapacity));
    }

    /**
     * 队列可注入的构造器：<b>只给单测用</b>（用来构造"队列永远满"的形态，
     * 从而确定性地验证"满了就丢、绝不阻塞请求线程"）。
     */
    AccessLogWriter(Path dir, String activeName, int retainDays, long maxFileBytes,
                    BlockingQueue<String> queue, Clock clock, int queueCapacity) {
        this.dir = dir;
        this.activeName = activeName;
        this.retainDays = Math.max(0, retainDays);
        this.maxFileBytes = maxFileBytes;
        this.queueCapacity = Math.max(16, queueCapacity);
        this.clock = clock == null ? Clock.systemDefaultZone() : clock;
        this.queue = queue;
    }

    /**
     * 建目录、定位活动文件、起写线程。
     *
     * <p>刻意把"能不能写"这一步做成<b>可抛异常</b>的：调用方（Filter）要能
     * 在启动时就如实打 WARN 说"访问日志起不来"，而不是等第一条请求才悄悄丢。
     * 注意这里只 {@code createDirectories} + 定位文件，不写任何探针数据。
     */
    public synchronized void start() throws IOException {
        if (started) {
            return;
        }
        Files.createDirectories(dir);
        activePath = dir.resolve(activeName);
        if (!Files.exists(activePath)) {
            Files.createFile(activePath);
        }
        activeBytes = Files.size(activePath);
        activeDay = currentDay();
        running = true;
        started = true;
        Thread t = new Thread(this::runLoop, "secagent-accesslog-writer");
        t.setDaemon(true);
        worker = t;
        t.start();
    }

    /**
     * 投递一行（已序列化好的 JSON）。
     *
     * <p><b>绝不阻塞</b>：返回 false 表示这一行被丢弃（队列满或已停止），
     * 调用方不需要做任何补救 —— 丢弃本身已经计数并打了 WARN。
     */
    public boolean offer(String line) {
        if (line == null) {
            return false;
        }
        if (!running) {
            long total = dropped.incrementAndGet();
            warnThrottled("访问日志写线程未运行（未启动或已关闭），本条被丢弃；累计丢弃 " + total + " 条");
            return false;
        }
        if (queue.offer(line)) {
            queued.incrementAndGet();
            return true;
        }
        long total = dropped.incrementAndGet();
        warnThrottled("访问日志队列已满（容量=" + queueCapacity + "），本条被丢弃；"
                + "累计丢弃 " + total + " 条 —— 说明写盘速度跟不上请求速度，请检查磁盘/目录权限");
        return false;
    }

    private void runLoop() {
        while (running || !queue.isEmpty()) {
            String line;
            try {
                line = queue.poll(500, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            if (line == null) {
                flushQuietly();
                continue;
            }
            writeLine(line);
            // 批量吸干：避免高并发时"一行一次 take"，同时保证不长时间不 flush
            for (int i = 0; i < 1024; i++) {
                String more = queue.poll();
                if (more == null) {
                    break;
                }
                writeLine(more);
            }
            // 每条/每批都 flush：fail2ban 与 Wazuh 读的是这个文件，
            // 攒在用户态缓冲里 = 检测延迟；I/O 在写线程上，不影响请求。
            flushQuietly();
        }
        flushQuietly();
        closeQuietly();
    }

    private void writeLine(String line) {
        try {
            rotateIfNeeded();
            if (out == null) {
                openOut();
            }
            out.write(line);
            out.write('\n');
            activeBytes += line.getBytes(StandardCharsets.UTF_8).length + 1L;
            written.incrementAndGet();
            lastWriteThread = Thread.currentThread().getName();
        } catch (Exception e) {
            failedWrites.incrementAndGet();
            lastError = e.getClass().getSimpleName() + ": " + e.getMessage();
            warnThrottled("访问日志写盘失败（该条丢弃，请求不受影响）: " + lastError);
            closeQuietly();
        }
    }

    private void openOut() throws IOException {
        out = Files.newBufferedWriter(activePath, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    private void rotateIfNeeded() throws IOException {
        LocalDate today = currentDay();
        boolean dayChanged = !today.equals(activeDay);
        boolean sizeExceeded = maxFileBytes > 0 && activeBytes >= maxFileBytes;
        if (dayChanged || sizeExceeded) {
            rotate(dayChanged ? "day" : "size");
        }
    }

    /**
     * 轮转：把活动文件改名成时间戳文件，再建一个新的空活动文件。
     *
     * <p>为什么用"改名"而不是"清空"（copytruncate 的反面）：
     * 改名后新文件是同一目录里的新 inode，fail2ban 会重新打开（它对
     * rename+create 这种标准 logrotate 形态有专门处理）；
     * 而"先清空再写"会让已经打开旧 inode 的读者读到空洞，
     * §21 之所以用 copytruncate 是因为那边读者不接受 inode 变化，
     * 这里我们自己的 fail2ban 过滤器测试过 rename 形态（见 RUNBOOK §24）。
     */
    private void rotate(String reason) throws IOException {
        flushQuietly();
        closeQuietly();
        if (Files.exists(activePath) && Files.size(activePath) > 0) {
            Path target = uniqueRotatedPath();
            try {
                Files.move(activePath, target, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(activePath, target);
            }
            logger.info("访问日志轮转（{}）: {} -> {}（{} 字节）", reason, activePath.getFileName(),
                    target.getFileName(), Files.size(target));
        }
        if (!Files.exists(activePath)) {
            Files.createFile(activePath);
        }
        activeBytes = Files.size(activePath);
        activeDay = currentDay();
        rotations.incrementAndGet();
        purgeOld();
    }

    private Path uniqueRotatedPath() {
        String base = activeName;
        String suffix = "";
        int dot = base.lastIndexOf('.');
        if (dot > 0) {
            suffix = base.substring(dot);
            base = base.substring(0, dot);
        }
        String stamp = STAMP.format(clock.instant().atZone(clock.getZone()));
        Path candidate = dir.resolve(base + "-" + stamp + suffix);
        for (int i = 1; Files.exists(candidate) && i < 1000; i++) {
            candidate = dir.resolve(base + "-" + stamp + "-" + i + suffix);
        }
        return candidate;
    }

    /** 保留策略：删掉超过 {@code retainDays} 天的轮转文件（活动文件永不删） */
    private void purgeOld() {
        if (retainDays <= 0) {
            return;
        }
        long cutoff = clock.millis() - Duration.ofDays(retainDays).toMillis();
        String glob = rotatedGlob();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, glob)) {
            for (Path p : stream) {
                if (p.equals(activePath)) {
                    continue;
                }
                try {
                    if (Files.getLastModifiedTime(p).toMillis() < cutoff) {
                        Files.deleteIfExists(p);
                        purged.incrementAndGet();
                    }
                } catch (IOException e) {
                    warnThrottled("访问日志清理失败（保留 " + retainDays + " 天）: " + p.getFileName() + " " + e.getMessage());
                }
            }
        } catch (IOException e) {
            warnThrottled("访问日志目录扫描失败（保留策略未执行）: " + e.getMessage());
        }
    }

    private String rotatedGlob() {
        String base = activeName;
        int dot = base.lastIndexOf('.');
        if (dot > 0) {
            base = base.substring(0, dot);
        }
        return base + "-*";
    }

    private LocalDate currentDay() {
        return LocalDate.now(clock);
    }

    private void warnThrottled(String message) {
        long now = System.currentTimeMillis();
        if (now - lastWarnAt >= WARN_INTERVAL_MS) {
            lastWarnAt = now;
            logger.warn("{}", message);
        }
    }

    private void flushQuietly() {
        if (out == null) {
            return;
        }
        try {
            out.flush();
        } catch (IOException e) {
            failedWrites.incrementAndGet();
            lastError = "flush: " + e.getMessage();
            warnThrottled("访问日志 flush 失败（请求不受影响）: " + lastError);
            closeQuietly();
        }
    }

    private void closeQuietly() {
        if (out == null) {
            return;
        }
        try {
            out.close();
        } catch (IOException e) {
            lastError = "close: " + e.getMessage();
        } finally {
            out = null;
        }
    }

    /** 停止写线程并把队列里剩下的写掉（只应在应用关闭时调用） */
    @Override
    public void close() {
        running = false;
        Thread t = worker;
        if (t != null) {
            try {
                t.join(3000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        flushQuietly();
        closeQuietly();
        started = false;
    }

    /** 立即把已入队的内容写完并落盘（测试与运维排查用） */
    public void drain() {
        long deadline = System.currentTimeMillis() + 3000;
        while (System.currentTimeMillis() < deadline) {
            boolean queueEmpty = queue.isEmpty();
            boolean allAccounted = written.get() + dropped.get() + failedWrites.get() >= queued.get();
            if (queueEmpty && allAccounted) {
                break;
            }
            sleepQuietly(5);
        }
        // 再给写线程一次 flush 的机会（"已写"不等于"已 flush 到磁盘"）
        sleepQuietly(20);
    }

    private static void sleepQuietly(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public String activeFilePath() {
        return (activePath == null ? dir.resolve(activeName) : activePath).toString();
    }

    public String dirPath() {
        return dir.toString();
    }

    public int retainDays() {
        return retainDays;
    }

    public long maxFileBytes() {
        return maxFileBytes;
    }

    public int queueCapacity() {
        return queueCapacity;
    }

    public long droppedCount() {
        return dropped.get();
    }

    public long writtenCount() {
        return written.get();
    }

    public long failedWriteCount() {
        return failedWrites.get();
    }

    /** 最后一次真正落盘所在线程名（单测用来证明"写盘不在请求线程上"） */
    public String lastWriteThread() {
        return lastWriteThread;
    }

    /** 只读统计（启动自检 / 排障 / 单测用） */
    public Map<String, Object> stats() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("activeFile", activeFilePath());
        m.put("retainDays", retainDays);
        m.put("maxFileBytes", maxFileBytes);
        m.put("queueCapacity", queueCapacity);
        m.put("queued", queued.get());
        m.put("written", written.get());
        m.put("dropped", dropped.get());
        m.put("failedWrites", failedWrites.get());
        m.put("rotations", rotations.get());
        m.put("purged", purged.get());
        m.put("lastError", lastError);
        m.put("lastWriteThread", lastWriteThread);
        return m;
    }
}
