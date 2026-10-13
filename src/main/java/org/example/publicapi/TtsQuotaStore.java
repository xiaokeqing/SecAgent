package org.example.publicapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.LocalDate;
import java.util.HashMap;
import java.util.Map;

/**
 * TTS 每日额度账本（单 IP 每日 + 全局每日），<b>落盘、重启不丢</b>。
 *
 * <h3>为什么必须有这本账（限流挡不住的正是它）</h3>
 * {@code PublicRateLimiter} 是"每分钟 N 次"的频率闸，进程内、重启清零；
 * 它能挡住"一秒钟刷 100 次"，但挡不住"一整天每隔一分钟刷 20 次"。
 * 语音合成是真花钱的上游调用，所以还需要一本<b>按天</b>的账：
 * <ul>
 *   <li><b>单 IP 每日</b>：防一个来源把额度吃光；</li>
 *   <li><b>全局每日</b>：真正的成本上限 —— 换 IP 也绕不过它。</li>
 * </ul>
 *
 * <h3>为什么落盘</h3>
 * 只放内存时，一次重启就等于"额度重置"，而重启这件事访客是能等的
 * （容器重启 / 部署 / OOM 都会发生）。所以每次计数后写一次
 * {@code data/tts-quota.json}：内容极小（日期 + 全局计数 + 每 IP 计数），
 * 按天清零，写频率 = 成功合成的次数（每天上限 500 次量级，不是请求量级）。
 *
 * <h3>写失败的取舍</h3>
 * 落盘失败时打 ERROR 并<b>继续</b>服务：本进程内的计数仍然生效（当天不会被刷爆），
 * 只有"重启后继续沿用今天已用额度"这一条会失效。让一次磁盘抖动把功能整体打死
 * （匿名访客看到 500）比"重启后额度可能被重置"更糟。这是明确的取舍，不是疏忽。
 */
public class TtsQuotaStore {

    private static final Logger logger = LoggerFactory.getLogger(TtsQuotaStore.class);

    /** 落盘结构（有版本字段：以后改结构时能识别旧文件，而不是当成损坏） */
    static final int SCHEMA_VERSION = 1;

    /** 额度超限的 reason 码（前端/日志用；与 RUNBOOK §30 的 reason 码表一致） */
    public static final String REASON_PER_IP = "PER_IP_DAILY_LIMIT";

    /** 全局额度超限的 reason 码 */
    public static final String REASON_GLOBAL = "GLOBAL_DAILY_LIMIT";

    private final Path file;
    private final ObjectMapper mapper = new ObjectMapper();
    private final Object lock = new Object();

    /** 账本所属的本地日期（yyyy-MM-dd）；跨天即清零 */
    private String date = LocalDate.now().toString();
    private long globalUsed;
    private final Map<String, Long> perIpUsed = new HashMap<>();

    public TtsQuotaStore(Path file) {
        this.file = file == null ? Path.of("data/tts-quota.json") : file;
        load();
    }

    /**
     * 记一次"真的要去调上游"的合成，并判断是否放行。
     *
     * <p>只被 {@link TtsService} 在<b>缓存未命中</b>时调用：缓存命中不花钱，
     * 不该吃每日额度（否则前端重播一次就少一次额度，访客完全看不出为什么）。
     *
     * @param clientIp   调用方 IP（取不到时归入 unknown 桶）
     * @param perIpLimit 单 IP 每日上限
     * @param globalLimit 全局每日上限
     */
    public Decision tryConsume(String clientIp, int perIpLimit, int globalLimit) {
        String key = normalizeIp(clientIp);
        synchronized (lock) {
            rolloverIfNeeded();
            long ipUsed = perIpUsed.getOrDefault(key, 0L);
            if (ipUsed >= perIpLimit) {
                return new Decision(false, REASON_PER_IP, globalUsed, ipUsed, perIpLimit, globalLimit);
            }
            if (globalUsed >= globalLimit) {
                return new Decision(false, REASON_GLOBAL, globalUsed, ipUsed, perIpLimit, globalLimit);
            }
            perIpUsed.put(key, ipUsed + 1);
            globalUsed++;
            persist();
            return new Decision(true, null, globalUsed, ipUsed + 1, perIpLimit, globalLimit);
        }
    }

    /** 当前账本快照（只读，不计数）：供响应头/自检展示，避免"额度多少只存在于配置里" */
    public Snapshot snapshot() {
        synchronized (lock) {
            rolloverIfNeeded();
            return new Snapshot(date, globalUsed, Map.copyOf(perIpUsed));
        }
    }

    private static String normalizeIp(String clientIp) {
        return (clientIp == null || clientIp.isBlank()) ? "unknown" : clientIp.trim();
    }

    /** 跨天清零：额度是"每日"的，跨天后昨天的数字不能继续压着今天 */
    private void rolloverIfNeeded() {
        String today = LocalDate.now().toString();
        if (!today.equals(date)) {
            date = today;
            globalUsed = 0;
            perIpUsed.clear();
        }
    }

    private void load() {
        if (!Files.isReadable(file)) {
            return;
        }
        try {
            JsonNode root = mapper.readTree(Files.readString(file, StandardCharsets.UTF_8));
            String storedDate = root.path("date").asText("");
            if (!LocalDate.now().toString().equals(storedDate)) {
                // 昨天（或更早）的账本：直接当"今天还没用过"（下次计数时会写回今天）
                return;
            }
            globalUsed = Math.max(0, root.path("globalUsed").asLong(0));
            JsonNode perIp = root.path("perIp");
            if (perIp.isObject()) {
                perIp.fields().forEachRemaining(e -> {
                    long v = e.getValue().asLong(0);
                    if (v > 0) {
                        perIpUsed.put(e.getKey(), v);
                    }
                });
            }
            logger.info("TTS 每日额度已从 {} 装载：日期={} 全局已用={} 来源数={}",
                    file, date, globalUsed, perIpUsed.size());
        } catch (IOException | RuntimeException e) {
            // 文件损坏（半截写入/手工改坏）：按"今天还没用过"起步，并如实打日志，
            // 绝不静默 —— 否则"额度好像被重置了"会变成没人说得清的事。
            logger.warn("TTS 额度文件读取失败（{}）：{} —— 本次按空账本起步", file, e.getMessage());
            globalUsed = 0;
            perIpUsed.clear();
        }
    }

    private void persist() {
        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            ObjectNode root = mapper.createObjectNode();
            root.put("schemaVersion", SCHEMA_VERSION);
            root.put("date", date);
            root.put("globalUsed", globalUsed);
            ObjectNode perIp = root.putObject("perIp");
            perIpUsed.forEach(perIp::put);
            byte[] bytes = mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(root);

            // 先写临时文件再原子替换：避免"写到一半进程被杀"留下半个 JSON
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            Files.write(tmp, bytes);
            try {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (IOException atomicUnsupported) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            logger.error("TTS 额度落盘失败（{}）：{} —— 本进程内计数仍然生效，但重启后今天的额度会重置",
                    file, e.getMessage());
        }
    }

    /**
     * 一次额度判定的结果。
     *
     * @param allowed     是否放行
     * @param reason      不放行时的 reason 码（{@link #REASON_PER_IP} / {@link #REASON_GLOBAL}），放行时为 null
     */
    public record Decision(boolean allowed, String reason, long globalUsed, long ipUsed,
                           int perIpLimit, int globalLimit) {
    }

    /** 只读快照 */
    public record Snapshot(String date, long globalUsed, Map<String, Long> perIpUsed) {
    }
}
