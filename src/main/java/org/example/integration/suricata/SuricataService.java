package org.example.integration.suricata;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.core.model.AlertSeverity;
import org.example.core.model.AlertSource;
import org.example.core.model.AlertType;
import org.example.core.model.SecurityAlert;
import org.example.integration.SuricataGateway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Suricata 对接服务：读取 eve.json 里的 alert / flow / http / dns / tls / netflow 事件。
 *
 * <p>文件不存在 / 不可读 / 解析失败 → 自动降级 MOCK，返回内置网络告警样本
 * （ET SCAN 端口扫描、ET POLICY 可疑外联），保证开箱可演示。
 *
 * <h3>为什么读文件分两条路径</h3>
 * <p>告警接口（{@link #recentNetworkAlerts}）要的是"最新若干条"，且调用方 Expect 一次调用就能看到文件里
 * 已经存在的全部历史；而反查接口要跨事件类型聚合，必须常驻内存。两者混用会把"每次重读文件"的成本
 * 摊到每个反查请求上，所以这里保留原直读路径不动，另起一个 {@code @Scheduled} 增量摄取把事件放进
 * 有界环形缓冲。这样告警通路的行为、以及"没有 eve.json 就返回样本"的现有语义都不受影响。
 */
@Service
public class SuricataService implements SuricataGateway {

    private static final Logger logger = LoggerFactory.getLogger(SuricataService.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    /** 内存中最多保留多少条 alert 事件（防止 eve.json 巨大时占满内存） */
    private static final int MAX_CACHE = 200;
    /** 单轮增量读取上限：追赶积压时也只在一次调度里读 4MB，避免瞬时占满堆 */
    private static final int MAX_BYTES_PER_INGEST = 4 * 1024 * 1024;
    /** 首次摄取从文件尾部回溯的字节数：启动时不需要上一次运行留下的全部历史 */
    private static final long INITIAL_TAIL_BYTES = 8L * 1024 * 1024;
    private static final int DEFAULT_BUFFER_CAPACITY = 50000;
    /** 启动回填时从文件尾部倒读的块大小：只控制单次 IO，不决定内存（内存由行数上限决定） */
    private static final int BACKFILL_CHUNK_BYTES = 64 * 1024;

    @Value("${integration.suricata.enabled:true}")
    private boolean enabled;
    @Value("${integration.suricata.eve-json:/var/log/suricata/eve.json}")
    private String eveJsonPath;
    @Value("${integration.suricata.timeout:5}")
    private int timeout;
    /** 环形缓冲每类的容量上限；eve.json 是持续追加的，必须有界（容器 512MiB，曾因无界缓存 OOM） */
    @Value("${integration.suricata.buffer-capacity:50000}")
    private int bufferCapacity;
    /**
     * 启动回填行数：缓冲是纯内存的，进程/容器一重启就空，端点要等新流量才有数据。
     * 从 eve.json 尾部回溯最近 N 行填进缓冲；0 表示关闭回填（增量摄取行为保持不变）。
     */
    @Value("${integration.suricata.backfill-lines:20000}")
    private int backfillLines;

    private final ObjectMapper mapper = new ObjectMapper();
    private final EveEventParser parser = new EveEventParser(mapper);

    private volatile SuricataEventStore store;
    private volatile boolean available;
    /** 最近一次启动回填的统计；未回填时为全 0 */
    private volatile BackfillResult lastBackfill = BackfillResult.NONE;

    /** 已消费到的字节偏移。跨调度周期保留，靠它做增量而不是每轮重扫全文件 */
    private long ingestOffset;
    /** 是否已经确定过起始偏移（首轮要用"文件尾部"而不是 0） */
    private boolean ingestInitialized;
    /** 上一块结尾是半行：下一块开头要跳到第一个换行之后再解析 */
    private boolean skippingPartialLine;

    @PostConstruct
    public void init() {
        // 无论是否启用都先建好缓冲：查询入口不必到处判空，模式变化也不用重建
        store();
        if (!enabled) {
            logger.info("Suricata 对接未启用，使用内置样本");
            return;
        }
        File f = new File(eveJsonPath);
        if (f.exists() && f.isFile() && f.canRead()) {
            this.available = true;
            logger.info("Suricata eve.json 可读（REAL 模式）：{}", eveJsonPath);
        } else {
            this.available = false;
            // 【2026-10-13 澄清】这条不是故障：Suricata 跑在 srv2，SecAgent 容器里没有它的 eve.json。
            // 真实网络告警是通过 Wazuh agent → indexer（wazuh-alerts-*，rule.groups=suricata）回来的，
            // 也就是 /api/public/alerts 那条通路。原来用 WARN 打印，容易被误读成"检测坏了"，
            // 所以改成 INFO 并把口径写清楚。
            logger.info("未挂载 Suricata eve.json（{}）—— 属预期：网络告警经 Wazuh agent → indexer 通路返回，"
                    + "本进程不使用本地样本（该降级仅影响本进程内的本地文件直读模式）", eveJsonPath);
        }
        if (available) {
            logger.info("Suricata 事件缓冲：每类 {} 条（有界，满后覆盖最旧）", store().capacity());
            // 为什么放在 @PostConstruct 的 init() 里（而不是 ApplicationRunner）：
            // ① 它和 available/store 的初始化在同一处，顺序天然确定，不需要再引入一个 Bean；
            // ② @PostConstruct 在 Web 容器开始接收请求之前执行，端点不会有一段"重启后返回空"的窗口；
            //    ApplicationRunner 跑在 context refresh 之后，此时端口通常已经 listen，早到的请求会看到空缓冲；
            // ③ 增量摄取的首次调度有 15s 延迟，回填先完成时 ingestOffset 已指向文件当前长度，不会重复读；
            // ④ 单测可以直接 new + init() 走这条路径，不必启动 Spring 上下文。
            if (backfillLines > 0) {
                backfillFromTail();
            }
        }
    }

    // ==================== 启动回填 ====================

    /**
     * 从 eve.json 尾部回填最近 {@link #backfillLines} 行到环形缓冲。
     *
     * <h3>为什么不 readAllLines</h3>
     * <p>线上 eve.json 约 300MB，全量读进内存再取尾部既慢又吃堆（容器只有 512MiB）。
     * 这里用 {@link RandomAccessFile} 从文件末尾按 64KB 块倒着找换行，只保留
     * "最后 N 行 + 它们之前那一个换行"的字节窗口；内存由行数上限而不是文件大小决定。
     *
     * <h3>首行半行</h3>
     * <p>跨机同步是先 tail 尾部 8MB 再追加，文件第一行可能从某条 JSON 中间开始。
     * 窗口起点落在换行之后时首行天然完整；只有窗口一直倒读到文件头（文件比窗口小）时
     * 才可能撞上这个半行，交给解析器返回 null 后计入"跳过"，不抛异常。
     *
     * <h3>偏移</h3>
     * <p>回填完成后把增量偏移定位到文件当前长度：回填过的部分不再被 {@link #ingestNewEvents()}
     * 重复解析，之后新追加的行照常增量读取。
     *
     * <p>文件不存在/不可读/读取中断都只返回 0 并保持现有 MOCK/增量语义，绝不影响启动与告警通路。
     */
    public BackfillResult backfillFromTail() {
        long begin = System.nanoTime();
        int maxLines = backfillLines;
        if (maxLines <= 0) {
            return BackfillResult.NONE;
        }
        File f = new File(eveJsonPath);
        if (!f.isFile() || !f.canRead()) {
            return BackfillResult.NONE;
        }
        try (RandomAccessFile raf = new RandomAccessFile(f, "r")) {
            long len = raf.length();
            long startOffset = findBackfillStart(raf, len, maxLines);
            byte[] window = new byte[(int) (len - startOffset)];
            raf.seek(startOffset);
            raf.readFully(window);

            int added = 0;
            int skipped = 0;
            // 窗口里可能多出 1 行（文件末尾没有换行时，倒读切点会多带一行），只取最后 maxLines 行
            int dropFirst = Math.max(0, countLines(window) - maxLines);
            int lineIndex = 0;
            int lineStart = 0;
            for (int i = 0; i < window.length; i++) {
                if (window[i] != '\n') {
                    continue;
                }
                if (lineIndex++ < dropFirst) {
                    lineStart = i + 1;
                    continue;
                }
                int parsed = parseWindowLine(window, lineStart, i);
                if (parsed > 0) {
                    added += parsed;
                } else if (parsed < 0) {
                    skipped++;
                }
                lineStart = i + 1;
            }
            // 文件最后一行没有换行：它仍然是一条完整事件（Suricata 正常会写换行，这里只是兜底）
            if (lineStart < window.length && lineIndex >= dropFirst) {
                int parsed = parseWindowLine(window, lineStart, window.length);
                if (parsed > 0) {
                    added += parsed;
                } else if (parsed < 0) {
                    skipped++;
                }
            }

            // 回填过的字节不再重复读取：偏移直接落到回填结束时的文件长度
            this.ingestOffset = len;
            this.ingestInitialized = true;
            this.skippingPartialLine = false;

            long ms = (System.nanoTime() - begin) / 1_000_000;
            BackfillResult r = new BackfillResult(added, skipped, len, startOffset, ms);
            lastBackfill = r;
            logger.info("Suricata eve.json 启动回填完成：{} 行（跳过 {} 行），耗时 {} ms，文件大小 {} 字节"
                            + "（{} MiB），窗口起点 {}，增量偏移 {}",
                    added, skipped, ms, len, Math.round(len / 104857.6) / 10.0, startOffset, ingestOffset);
            return r;
        } catch (Exception e) {
            long ms = (System.nanoTime() - begin) / 1_000_000;
            logger.warn("Suricata eve.json 启动回填失败（不影响增量摄取与告警通路）：{}", e.toString());
            BackfillResult r = new BackfillResult(0, 0, 0, 0, ms);
            lastBackfill = r;
            return r;
        }
    }

    /**
     * 从文件末尾倒着找第 maxLines+1 个换行，返回它之后的位置。
     *
     * <p>文件以换行结尾时，窗口 [起点, 末尾) 正好是最后 maxLines 行；
     * 文件不以换行结尾时末尾那段也算一行，调用方会按行数再截一次。
     * 找不到足够换行（文件比窗口小）时返回 0，代表一直读到文件头。
     */
    private static long findBackfillStart(RandomAccessFile raf, long len, int maxLines) throws IOException {
        long pos = len;
        int newlines = 0;
        byte[] chunk = new byte[BACKFILL_CHUNK_BYTES];
        while (pos > 0) {
            int toRead = (int) Math.min(chunk.length, pos);
            pos -= toRead;
            raf.seek(pos);
            raf.readFully(chunk, 0, toRead);
            for (int i = toRead - 1; i >= 0; i--) {
                if (chunk[i] == '\n') {
                    newlines++;
                    if (newlines > maxLines) {
                        return pos + i + 1;
                    }
                }
            }
        }
        return 0;
    }

    /** 窗口内的行数：换行数 + 末尾没有换行时的那一行。 */
    private static int countLines(byte[] window) {
        int lines = 0;
        for (byte b : window) {
            if (b == '\n') {
                lines++;
            }
        }
        if (window.length > 0 && window[window.length - 1] != '\n') {
            lines++;
        }
        return lines;
    }

    /**
     * 解析窗口里 [from, to) 的一段。
     *
     * @return 1=解析成功并入缓冲；0=空行（既不算成功也不算跳过）；-1=坏行/半行（计入跳过，不抛）
     */
    private int parseWindowLine(byte[] window, int from, int to) {
        String line = new String(window, from, to - from, StandardCharsets.UTF_8).trim();
        if (line.isEmpty()) {
            return 0;
        }
        EveEvent event = parser.parseLine(line);
        if (event == null) {
            return -1;
        }
        store().add(event);
        return 1;
    }

    /** 一次性回填的统计：成功行数、跳过行数、文件大小、窗口起点、耗时。 */
    public record BackfillResult(int lines, int skipped, long fileSize, long startOffset, long durationMs) {
        /** 未启用/无文件/关闭回填时使用 */
        public static final BackfillResult NONE = new BackfillResult(0, 0, 0, 0, 0);
    }

    /** 供测试与运维观测：最近一次启动回填的统计。 */
    public BackfillResult lastBackfill() {
        return lastBackfill;
    }

    @Override
    public boolean isAvailable() {
        return available;
    }

    @Override
    public String mode() {
        if (!enabled) return "OFF";
        return available ? "REAL" : "MOCK";
    }

    @Override
    public List<SecurityAlert> recentNetworkAlerts(int limit) {
        if (available) {
            try {
                List<SecurityAlert> real = readFromEve(limit);
                if (!real.isEmpty()) {
                    return real;
                }
            } catch (Exception e) {
                logger.warn("读取 eve.json 失败，回退内置样本：{}", e.getMessage());
            }
        }
        return builtinAlerts(limit);
    }

    // ==================== 全事件摄取 ====================

    /**
     * 定时把 eve.json 的新增行解析进环形缓冲。
     *
     * <p>用固定延迟而不是固定频率：一旦积压，下一轮会自然推后，不会把线程池堆满。
     * 首次调度延迟 15s，给启动期的其他初始化让路（磁盘/容器可能还没挂好）。
     *
     * <p>任何异常都只降级为 debug 日志：反查是"锦上添花"的能力，不能因为它让进程或告警通路出问题。
     */
    @Scheduled(initialDelayString = "${integration.suricata.ingest-initial-delay-ms:15000}",
            fixedDelayString = "${integration.suricata.ingest-interval-ms:10000}")
    public void ingestNewEvents() {
        if (!enabled) {
            return;
        }
        File f = new File(eveJsonPath);
        if (!f.isFile() || !f.canRead()) {
            // 文件不在（几乎总是"未挂载"）：保持当前模式，不报错
            return;
        }
        try (RandomAccessFile raf = new RandomAccessFile(f, "r")) {
            long len = raf.length();
            if (len < ingestOffset) {
                // 文件变短只有两种可能：轮转或截断。旧偏移已无意义，重置后重读
                logger.info("eve.json 长度 {} 小于已读偏移 {}，视为轮转/截断，从头重新读取", len, ingestOffset);
                ingestOffset = 0;
                ingestInitialized = false;
                skippingPartialLine = false;
            }
            if (!ingestInitialized) {
                // 首轮只回溯文件尾部一段：启动时把几 GB 历史全量回放既慢又不必要
                ingestOffset = Math.max(0, len - INITIAL_TAIL_BYTES);
                skippingPartialLine = ingestOffset > 0;
                ingestInitialized = true;
                logger.info("eve.json 增量读取起点：{}（文件长度 {}）", ingestOffset, len);
            }
            if (ingestOffset >= len) {
                return;
            }
            long start = ingestOffset;
            int toRead = (int) Math.min(MAX_BYTES_PER_INGEST, len - start);
            byte[] buf = new byte[toRead];
            raf.seek(start);
            raf.readFully(buf);

            int from = 0;
            if (skippingPartialLine) {
                // 起点可能落在某一行中间，那半个 JSON 不能解析，必须跳过一个换行
                int nl = indexOfNewline(buf, 0);
                if (nl < 0) {
                    // 整块都没有换行：还没等到那一行的结尾
                    if (toRead < MAX_BYTES_PER_INGEST) {
                        return; // 到文件尾了，偏移不动，下轮再找
                    }
                    // 单行超过一轮读取上限：只能丢掉，否则每轮都在原地重读、永远追不上
                    ingestOffset = start + toRead;
                    return;
                }
                from = nl + 1;
            }
            int lastNl = lastIndexOfNewline(buf);
            if (lastNl < from) {
                // 块里没有完整的一行：文件还在追加，半行不能丢，偏移保持不动等下一轮
                if (toRead < MAX_BYTES_PER_INGEST) {
                    return;
                }
                ingestOffset = start + toRead;
                return;
            }
            // 到这里才确认"半行已越过、且有完整行可处理"，可以收起跳行标记
            skippingPartialLine = false;

            int added = 0;
            int lineStart = from;
            for (int i = from; i <= lastNl; i++) {
                if (buf[i] != '\n') {
                    continue;
                }
                if (i > lineStart) {
                    String line = new String(buf, lineStart, i - lineStart, StandardCharsets.UTF_8).trim();
                    if (!line.isEmpty()) {
                        EveEvent event = parser.parseLine(line);
                        if (event != null) {
                            store().add(event);
                            added++;
                        }
                    }
                }
                lineStart = i + 1;
            }
            // 只把偏移推进到最后一个完整行之后：结尾的半行下轮再拼
            ingestOffset = start + lastNl + 1;
            if (!available) {
                // 启动时文件还不在、后来才挂上：以最近一次成功读取为准切到 REAL
                available = true;
                logger.info("eve.json 已可读，Suricata 模式切换为 REAL");
            }
            if (added > 0) {
                logger.debug("Suricata 摄取 {} 条事件，偏移推进到 {}", added, ingestOffset);
            }
        } catch (Exception e) {
            // 反查失败不应该影响告警通路，也不该刷屏
            logger.debug("Suricata eve.json 增量读取中断（不影响告警通路）：{}", e.getMessage());
        }
    }

    private static int indexOfNewline(byte[] buf, int from) {
        for (int i = from; i < buf.length; i++) {
            if (buf[i] == '\n') {
                return i;
            }
        }
        return -1;
    }

    private static int lastIndexOfNewline(byte[] buf) {
        for (int i = buf.length - 1; i >= 0; i--) {
            if (buf[i] == '\n') {
                return i;
            }
        }
        return -1;
    }

    // ==================== 反查 ====================

    @Override
    public List<FlowEvent> connectionsByIp(String ip, int limit) {
        try {
            return store().connectionsByIp(ip, limit);
        } catch (Exception e) {
            logger.debug("按 IP 反查连接失败（返回空）：{}", e.getMessage());
            return List.of();
        }
    }

    @Override
    public List<PortCount> topDestPorts(int minutes, int limit) {
        try {
            return store().topDestPorts(minutes, limit);
        } catch (Exception e) {
            logger.debug("目标端口统计失败（返回空）：{}", e.getMessage());
            return List.of();
        }
    }

    @Override
    public List<SniCount> topSni(int minutes, int limit) {
        try {
            return store().topSni(minutes, limit);
        } catch (Exception e) {
            logger.debug("SNI 统计失败（返回空）：{}", e.getMessage());
            return List.of();
        }
    }

    @Override
    public List<Ja3Count> ja3Stats(int minutes, int limit) {
        try {
            return store().ja3Stats(minutes, limit);
        } catch (Exception e) {
            logger.debug("JA3 统计失败（返回空）：{}", e.getMessage());
            return List.of();
        }
    }

    /** 缓冲只建一次：多个调度周期/查询并发到达时用双重检查避免重复分配 */
    private SuricataEventStore store() {
        SuricataEventStore s = store;
        if (s != null) {
            return s;
        }
        synchronized (this) {
            if (store == null) {
                int cap = bufferCapacity > 0 ? bufferCapacity : DEFAULT_BUFFER_CAPACITY;
                store = new SuricataEventStore(cap);
            }
            return store;
        }
    }

    /** 供测试与运维观测使用：当前缓冲里各类事件的条数。 */
    public Map<String, Object> bufferStats() {
        SuricataEventStore s = store();
        Map<String, Object> out = new HashMap<>();
        out.put("capacity", s.capacity());
        out.put("flows", s.flowCount());
        out.put("tls", s.tlsCount());
        out.put("ingested", s.totalIngested());
        out.put("offset", ingestOffset);
        BackfillResult bf = lastBackfill;
        out.put("backfilled", bf.lines());
        out.put("backfillSkipped", bf.skipped());
        return out;
    }

    /**
     * 逐行读 eve.json，只保留 event_type=alert 的最后若干条。
     *
     * <p>和增量摄取不同，这里仍然每次重读全文件：现有 /api/alerts 的语义就是"以文件当前内容为准"，
     * 改成读缓冲会让刚追加的告警延迟一个调度周期才可见。但内存上只留最后 MAX_CACHE 条（同原实现），
     * 不会因为文件大而吃满堆。
     */
    private List<SecurityAlert> readFromEve(int limit) throws Exception {
        Deque<JsonNode> alerts = new ArrayDeque<>();
        try (BufferedReader br = new BufferedReader(new FileReader(eveJsonPath))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }
                try {
                    JsonNode n = mapper.readTree(line);
                    if ("alert".equalsIgnoreCase(n.path("event_type").asText())) {
                        alerts.addLast(n);
                        if (alerts.size() > MAX_CACHE) {
                            alerts.removeFirst();
                        }
                    }
                } catch (Exception parseErr) {
                    // 坏行跳过，不影响整体
                }
            }
        }
        List<SecurityAlert> out = new ArrayList<>();
        // 取最后 limit 条（最新的在文件尾部）
        int skip = Math.max(0, alerts.size() - Math.min(limit, alerts.size()));
        int i = 0;
        for (JsonNode n : alerts) {
            if (i++ < skip) {
                continue;
            }
            out.add(parser.toSecurityAlert(n, "suricata-eve-" + out.size()));
        }
        return out;
    }

    // ==================== 内置网络样本（MOCK） ====================

    /**
     * 内置 eve 风格网络告警样本：ET SCAN 扫描、ET POLICY 可疑外联等。
     * 给出的示例 eve 行（真实文件里长这样）：
     * {"event_type":"alert","timestamp":"...","src_ip":"203.0.113.66","dest_ip":"10.0.10.21",
     *  "dest_port":443,"proto":"TCP","alert":{"signature":"ET SCAN Potential SSL Exploit Scanning",
     *  "category":"Attempted Information Leak","severity":2}}
     */
    private List<SecurityAlert> builtinAlerts(int limit) {
        LocalDateTime now = LocalDateTime.now();
        List<SecurityAlert> all = new ArrayList<>();

        all.add(make("sur-mock-001", "ET SCAN 潜在 SSL 漏洞利用扫描", "Attempted Information Leak",
                2, "203.0.113.66", "扫描器出口", "10.0.10.21", "web-01", 443, "TCP",
                now.minusMinutes(12),
                "{\"event_type\":\"alert\",\"src_ip\":\"203.0.113.66\",\"dest_ip\":\"10.0.10.21\",\"dest_port\":443,\"proto\":\"TCP\",\"alert\":{\"signature\":\"ET SCAN Potential SSL Exploit Scanning\",\"category\":\"Attempted Information Leak\",\"severity\":2}}",
                1));
        all.add(make("sur-mock-002", "ET POLICY 主机向陌生端口可疑外联", "Potential Corporate Privacy Violation",
                3, "10.0.10.22", "web-02 本机", "198.51.100.20", "未知外部主机", 8080, "TCP",
                now.minusMinutes(28),
                "{\"event_type\":\"alert\",\"src_ip\":\"10.0.10.22\",\"dest_ip\":\"198.51.100.20\",\"dest_port\":8080,\"proto\":\"TCP\",\"alert\":{\"signature\":\"ET POLICY UnixSuspicious outbound port 8080\",\"category\":\"Potential Corporate Privacy Violation\",\"severity\":3}}",
                5));
        all.add(make("sur-mock-003", "ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT", "Attempted User Privilege Gain",
                1, "45.83.91.12", "东欧 VPS", "10.0.10.22", "web-02", 80, "TCP",
                now.minusMinutes(24),
                "{\"event_type\":\"alert\",\"src_ip\":\"45.83.91.12\",\"dest_ip\":\"10.0.10.22\",\"dest_port\":80,\"proto\":\"TCP\",\"alert\":{\"signature\":\"ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT\",\"category\":\"Attempted User Privilege Gain\",\"severity\":1}}",
                8));
        all.add(make("sur-mock-004", "ET SCAN 横向端口扫描（内网）", "Attempted Information Leak",
                2, "10.0.10.30", "内网主机", "10.0.10.0/24", "web-01", 22, "TCP",
                now.minusHours(1).minusMinutes(40),
                "{\"event_type\":\"alert\",\"src_ip\":\"10.0.10.30\",\"dest_ip\":\"10.0.10.21\",\"dest_port\":22,\"proto\":\"TCP\",\"alert\":{\"signature\":\"ET SCAN SSH brute force from same src\",\"category\":\"Attempted Information Leak\",\"severity\":2}}",
                60));
        all.add(make("sur-mock-005", "ET DDoS SYN Flood 迹象", "Misc Attack",
                1, "203.0.113.77", "境外", "10.0.10.21", "web-01", 80, "TCP",
                now.minusHours(2).minusMinutes(5),
                "{\"event_type\":\"alert\",\"src_ip\":\"203.0.113.77\",\"dest_ip\":\"10.0.10.21\",\"dest_port\":80,\"proto\":\"TCP\",\"alert\":{\"signature\":\"ET DDoS possible SYN flood high packet rate\",\"category\":\"Misc Attack\",\"severity\":1}}",
                320));

        int n = Math.min(limit, all.size());
        return new ArrayList<>(all.subList(0, Math.max(0, n)));
    }

    private SecurityAlert make(String id, String signature, String category, int severity,
                               String srcIp, String srcGeo, String dstIp, String dstAsset,
                               int dstPort, String proto, LocalDateTime time, String raw, int count) {
        SecurityAlert a = new SecurityAlert(id, "[" + category + "] " + signature,
                AlertSeverity.parse(severity),
                AlertType.guess(signature + " " + category),
                AlertSource.SURICATA);
        a.setRuleName(signature);
        a.setSrcIp(srcIp);
        a.setSrcGeo(srcGeo);
        a.setDstIp(dstIp);
        a.setDstAsset(dstAsset);
        a.setDstPort(dstPort);
        a.setService(proto);
        a.setDescription("[" + category + "] " + signature);
        a.setRawLog(raw);
        a.setOccurredAt(time.format(FMT));
        a.setCount(count);
        Map<String, Object> extra = new HashMap<>();
        extra.put("category", category);
        extra.put("severity", severity);
        extra.put("proto", proto);
        extra.put("mock", true);
        a.setExtra(extra);
        return a;
    }
}
