package org.example.metrics;

import org.example.core.model.SecurityAlert;
import org.example.integration.SuricataGateway;
import org.example.integration.WazuhGateway;
import org.example.response.AuditService;
import org.example.response.BlockRecord;
import org.example.response.BlockRecordStore;
import org.example.response.ResponseAudit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 检测与响应时效（MTTD / MTTR）统计。
 *
 * <h3>指标口径（前端与复盘都按这一段算）</h3>
 * <ul>
 *   <li><b>MTTD</b>（检测时延）：同一来源 IP 在本窗口内的<b>首次告警时间</b> →
 *       该 IP <b>首次进入处置记录</b>的时间。处置时间取两处<b>较早者</b>：
 *       {@link BlockRecord#getCreatedAt()}（真正封禁生效的那一刻）与
 *       {@link AuditService} 里 {@code block-ip} 留痕的 {@code time} ——
 *       封禁记录文件被轮转/清理后，审计留痕仍能支撑该口径。IP 在窗口内没有处置记录就不构成样本。
 *       与 MTTR 一样，处置早于检测（负时延）的样本丢弃而不是钳成 0。</li>
 *   <li><b>MTTR</b>（处置时延）：每条<b>已解除</b>的 {@link BlockRecord} 的创建时间 →
 *       恢复时间。恢复时间取 {@code unblockedAt} 与 {@code expiresAt} 中<b>较早者</b>：
 *       到期自动解封用 {@code expiresAt}（调度器每轮扫描有延迟，把轮询延迟算进 MTTR 会虚高），
 *       人工提前解封则 {@code unblockedAt} 更早 —— 两者都缺失的记录跳过并计入 {@code dropped}。
 *       未解除（仍在封禁中）的记录<b>不进分母</b>：它们还没有"恢复时间"，算进去只会得到一个假的 0。</li>
 *   <li>中位数按分钟、保留 1 位小数；<b>偶数个样本取中间两个的平均值</b>。</li>
 *   <li>样本少于 {@value #MIN_SAMPLES} 条时该指标返回
 *       {@code {available:false, reason:"样本不足", samples:n}}，不返回 0 ——
 *       "没有样本"和"时延为 0"在页面上必须能区分。</li>
 * </ul>
 *
 * <h3>为什么按数据源模式 fail-closed</h3>
 * <p>{@link WazuhGateway} / {@link SuricataGateway} 在连不上真实数据源时会返回内置演示样本，
 * 样本 IP 是 203.0.113.x 这类文档地址。把它们算进时效指标会得到一条很漂亮的假曲线，
 * 所以这里与 {@code AlertBoardController} 同一口径：只采信 {@code mode=REAL} 的那一侧，
 * 另一侧的样本整体剔除，并把两侧真实模式如实体现在 {@code wazuhMode}/{@code suricataMode} 里。
 *
 * <h3>时钟偏移</h3>
 * <p>告警时间来自远端（Wazuh/Suricata 主机的时钟），封禁时间来自本机，两者不同步时会出现
 * "处置早于检测"。这类负时延样本一律<b>丢弃</b>（不钳成 0，否则偏移会把中位数拉低），
 * 丢弃条数写进 {@code dropped.negativeMttd/negativeMttr} 供排查。
 *
 * <p>本类只读现有组件（两个网关 + {@link BlockRecordStore} + {@link AuditService}），不新增数据源、不改既有配置文件。
 */
@Service
public class MetricsSummaryService {

    private static final Logger logger = LoggerFactory.getLogger(MetricsSummaryService.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /** 默认统计窗口：24 小时 */
    public static final int DEFAULT_HOURS = 24;
    /** 窗口下限：1 小时（更短的窗口里几乎不可能凑够 3 个样本） */
    public static final int MIN_HOURS = 1;
    /** 窗口上限：168 小时（7 天）—— 与公开故事线的窗口上限保持一致 */
    public static final int MAX_HOURS = 168;

    /** 少于 3 个样本不给中位数：2 个点算"中位数"没有统计意义 */
    static final int MIN_SAMPLES = 3;

    /**
     * 单次最多拉多少条告警用于算 MTTD。
     *
     * <p>两个网关的告警接口都是"最近 N 条"，不是按时间窗聚合的（Wazuh 侧按 @timestamp 倒序，
     * 24h 实测可达十万条）。这里取 1000 条上限：样本量大到足以覆盖常见窗口，
     * 又不会把 MB 级原始日志（含 payload）搬进应用进程。窗口内告警超过上限时，
     * MTTD 只用最新的一批 —— 这是<b>已知的保守偏差</b>，写在 {@code samples.alerts} 里可被前端识别。
     */
    static final int ALERT_FETCH_LIMIT = 1000;

    /** worst 最多给几条：前端"下钻"面板固定 3 行 */
    static final int WORST_LIMIT = 3;

    private final WazuhGateway wazuhGateway;
    private final SuricataGateway suricataGateway;
    private final BlockRecordStore blockRecordStore;
    private final AuditService auditService;

    /** 可注入时钟：窗口边界与"现在"都从它取，单测才能钉死时间 */
    private Clock clock = Clock.systemDefaultZone();

    public MetricsSummaryService(WazuhGateway wazuhGateway,
                                 SuricataGateway suricataGateway,
                                 BlockRecordStore blockRecordStore,
                                 AuditService auditService) {
        this.wazuhGateway = wazuhGateway;
        this.suricataGateway = suricataGateway;
        this.blockRecordStore = blockRecordStore;
        this.auditService = auditService;
    }

    /** 仅测试用：固定时钟，避免依赖真实时间导致用例跨零点抖动 */
    void setClock(Clock clock) {
        this.clock = clock == null ? Clock.systemDefaultZone() : clock;
    }

    /**
     * 生成时效指标摘要。
     *
     * @param hours 统计窗口（小时）；越界值收敛到 {@value #MIN_HOURS}..{@value #MAX_HOURS}，
     *              不抛 400 —— 与 {@code /api/sec/conn} 的参数收敛口径一致
     * @return 直接放进统一信封 {@code data} 的字段表，字段含义见类注释
     */
    public Map<String, Object> summary(int hours) {
        int h = clamp(hours);
        LocalDateTime now = LocalDateTime.now(clock).truncatedTo(ChronoUnit.SECONDS);
        LocalDateTime windowStart = now.minusHours(h);

        String wazuhMode = safeMode(true);
        String suricataMode = safeMode(false);
        boolean wazuhReal = isReal(wazuhMode);
        boolean suricataReal = isReal(suricataMode);

        // ===== 告警侧：窗口内每个 IP 的首次告警 =====
        Map<String, LocalDateTime> firstAlertAt = new LinkedHashMap<>();
        Map<String, String> firstAlertSource = new LinkedHashMap<>();
        int alertsInWindow = 0;
        int unparseableAlertTimes = 0;
        for (SecurityAlert a : dedupe(fetchRealAlerts(wazuhReal, suricataReal))) {
            String ip = trimToNull(a.getSrcIp());
            if (ip == null) {
                continue;
            }
            LocalDateTime t = parseTime(a.getOccurredAt());
            if (t == null) {
                unparseableAlertTimes++;
                continue;
            }
            if (t.isBefore(windowStart) || t.isAfter(now)) {
                continue;
            }
            alertsInWindow++;
            LocalDateTime prev = firstAlertAt.get(ip);
            if (prev == null || t.isBefore(prev)) {
                firstAlertAt.put(ip, t);
                firstAlertSource.put(ip, a.getSource() == null ? "UNKNOWN" : a.getSource().name());
            }
        }

        // ===== 处置侧：每条封禁记录（首条按 IP 记忆，窗口内记录进样本池） =====
        Map<String, LocalDateTime> firstBlockAt = new LinkedHashMap<>();
        List<BlockRecord> windowBlocks = new ArrayList<>();
        int unparseableBlockTimes = 0;
        for (BlockRecord r : safeBlocks()) {
            LocalDateTime created = parseTime(r.getCreatedAt());
            if (created == null) {
                unparseableBlockTimes++;
                continue;
            }
            String ip = trimToNull(r.getIp());
            if (ip != null) {
                LocalDateTime prev = firstBlockAt.get(ip);
                if (prev == null || created.isBefore(prev)) {
                    firstBlockAt.put(ip, created);
                }
            }
            if (!created.isBefore(windowStart) && !created.isAfter(now)) {
                windowBlocks.add(r);
            }
        }

        // ===== 审计留痕：block-ip 动作同样代表"进入处置记录" =====
        // 封禁记录文件可能被轮转/清理，审计留痕是更持久的处置痕迹；与 createdAt 取较早者。
        Map<String, LocalDateTime> firstAuditBlockAt = new LinkedHashMap<>();
        int unparseableAuditTimes = 0;
        for (ResponseAudit a : safeBlockAudits()) {
            String ip = trimToNull(a.getTarget());
            if (ip == null) {
                continue;   // 非 IP 目标的 block-ip 留痕不算时效样本
            }
            LocalDateTime t = parseTime(a.getTime());
            if (t == null) {
                unparseableAuditTimes++;
                continue;
            }
            LocalDateTime prev = firstAuditBlockAt.get(ip);
            if (prev == null || t.isBefore(prev)) {
                firstAuditBlockAt.put(ip, t);
            }
        }

        // ===== MTTD：窗口内首次告警 → 该 IP 首次处置（封禁记录 / 审计留痕取较早者） =====
        List<Sample> mttdSamples = new ArrayList<>();
        int negativeMttd = 0;
        for (Map.Entry<String, LocalDateTime> e : firstAlertAt.entrySet()) {
            LocalDateTime respondedAt = earliest(firstBlockAt.get(e.getKey()), firstAuditBlockAt.get(e.getKey()));
            if (respondedAt == null) {
                continue;   // 告警了但从未进入处置记录：不是"慢"，是没样本
            }
            double minutes = minutesBetween(e.getValue(), respondedAt);
            if (minutes < 0) {
                // 处置早于检测：远端告警时钟偏慢或该 IP 在本窗口前就已被封。丢弃，不钳 0。
                negativeMttd++;
                continue;
            }
            mttdSamples.add(new Sample("MTTD", e.getKey(), minutes,
                    firstAlertSource.get(e.getKey()), e.getValue()));
        }

        // ===== MTTR：封禁创建 → 恢复（只统计已解除） =====
        List<Sample> mttrSamples = new ArrayList<>();
        int negativeMttr = 0;
        int missingRecoveryTime = 0;
        for (BlockRecord r : windowBlocks) {
            if (!r.isUnblocked()) {
                continue;
            }
            LocalDateTime created = parseTime(r.getCreatedAt());
            LocalDateTime recoveredAt = resolveRecoveredAt(r);
            if (created == null || recoveredAt == null) {
                missingRecoveryTime++;
                continue;
            }
            double minutes = minutesBetween(created, recoveredAt);
            if (minutes < 0) {
                negativeMttr++;
                continue;
            }
            mttrSamples.add(new Sample("MTTR", trimToNull(r.getIp()) == null ? "" : r.getIp(),
                    minutes, r.getSource() == null ? "UNKNOWN" : r.getSource(), created));
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("mode", overallMode(wazuhReal, suricataReal));
        data.put("wazuhMode", wazuhMode);
        data.put("suricataMode", suricataMode);

        Map<String, Object> window = new LinkedHashMap<>();
        window.put("hours", h);
        window.put("start", FMT.format(windowStart));
        window.put("end", FMT.format(now));
        data.put("window", window);

        data.put("mttd", metric(mttdSamples));
        data.put("mttr", metric(mttrSamples));

        Map<String, Object> samples = new LinkedHashMap<>();
        samples.put("alerts", alertsInWindow);
        samples.put("blocks", windowBlocks.size());
        samples.put("mttdPairs", mttdSamples.size());
        samples.put("mttrPairs", mttrSamples.size());
        data.put("samples", samples);

        data.put("worst", worst(mttdSamples, mttrSamples));

        Map<String, Object> dropped = new LinkedHashMap<>();
        dropped.put("negativeMttd", negativeMttd);
        dropped.put("negativeMttr", negativeMttr);
        dropped.put("unparseableAlertTimes", unparseableAlertTimes);
        dropped.put("unparseableBlockTimes", unparseableBlockTimes);
        dropped.put("unparseableAuditTimes", unparseableAuditTimes);
        dropped.put("missingRecoveryTime", missingRecoveryTime);
        data.put("dropped", dropped);

        data.put("generatedAt", FMT.format(now));
        return data;
    }

    // ==================== 采样 ====================

    /** 只采信 REAL 的一侧；MOCK/OFF 的样本整体剔除（与告警大屏同一 fail-closed 口径） */
    private List<SecurityAlert> fetchRealAlerts(boolean wazuhReal, boolean suricataReal) {
        List<SecurityAlert> out = new ArrayList<>();
        if (wazuhReal) {
            try {
                List<SecurityAlert> l = wazuhGateway.recentAlerts(ALERT_FETCH_LIMIT);
                if (l != null) {
                    out.addAll(l);
                }
            } catch (Exception e) {
                logger.warn("时效指标拉取 Wazuh 告警失败，本轮按 0 条计：{}", e.getMessage());
            }
        }
        if (suricataReal) {
            try {
                List<SecurityAlert> l = suricataGateway.recentNetworkAlerts(ALERT_FETCH_LIMIT);
                if (l != null) {
                    out.addAll(l);
                }
            } catch (Exception e) {
                logger.warn("时效指标拉取 Suricata 告警失败，本轮按 0 条计：{}", e.getMessage());
            }
        }
        return out;
    }

    /** 同一事件可能同时出现在两个来源（Wazuh agent 也采集 Suricata），按 id 去重 */
    private static List<SecurityAlert> dedupe(List<SecurityAlert> alerts) {
        Map<String, SecurityAlert> byId = new LinkedHashMap<>();
        int noId = 0;
        for (SecurityAlert a : alerts) {
            if (a == null) {
                continue;
            }
            String id = trimToNull(a.getId());
            byId.putIfAbsent(id == null ? "#" + (noId++) : id, a);
        }
        return new ArrayList<>(byId.values());
    }

    private List<BlockRecord> safeBlocks() {
        try {
            List<BlockRecord> l = blockRecordStore.listAll();
            return l == null ? List.of() : l;
        } catch (Exception e) {
            logger.warn("时效指标读取封禁记录失败，本轮按 0 条计：{}", e.getMessage());
            return List.of();
        }
    }

    /** 只取"真正执行成功"的 block-ip 留痕：被护栏拦截/待审批的动作不算进入处置 */
    private List<ResponseAudit> safeBlockAudits() {
        try {
            List<ResponseAudit> l = auditService.list("block-ip", true);
            return l == null ? List.of() : l;
        } catch (Exception e) {
            logger.warn("时效指标读取处置审计失败，本轮按 0 条计：{}", e.getMessage());
            return List.of();
        }
    }

    private static LocalDateTime earliest(LocalDateTime a, LocalDateTime b) {
        if (a == null) {
            return b;
        }
        if (b == null) {
            return a;
        }
        return a.isBefore(b) ? a : b;
    }

    // ==================== 口径工具 ====================

    /**
     * 恢复时间：{@code unblockedAt} 与 {@code expiresAt} 取较早者。
     *
     * <p>到期自动解封由 {@code UnblockScheduler} 轮询写入 {@code unblockedAt}，
     * 天然晚于 {@code expiresAt}；把这段轮询延迟算进 MTTR 会随调度周期虚高。
     * 人工提前解封时 {@code unblockedAt} 早于 {@code expiresAt}，取它才是真实恢复时刻。
     */
    private static LocalDateTime resolveRecoveredAt(BlockRecord r) {
        LocalDateTime unblockedAt = parseTime(r.getUnblockedAt());
        LocalDateTime expiresAt = parseTime(r.getExpiresAt());
        if (unblockedAt == null) {
            return expiresAt;
        }
        if (expiresAt == null) {
            return unblockedAt;
        }
        return unblockedAt.isBefore(expiresAt) ? unblockedAt : expiresAt;
    }

    /** 单个指标块：样本不足时只给 available/reason/samples，不编造 0 时延 */
    private static Map<String, Object> metric(List<Sample> samples) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (samples.size() < MIN_SAMPLES) {
            out.put("available", false);
            out.put("reason", "样本不足");
            out.put("samples", samples.size());
            return out;
        }
        double[] values = samples.stream().mapToDouble(Sample::minutes).sorted().toArray();
        out.put("available", true);
        out.put("medianMinutes", round1(median(values)));
        out.put("samples", values.length);
        out.put("unit", "minutes");
        return out;
    }

    /** 偶数个取中间两个的平均；调用方保证数组已升序且非空 */
    static double median(double[] sorted) {
        int n = sorted.length;
        if (n == 0) {
            throw new IllegalArgumentException("median of empty samples");
        }
        if (n % 2 == 1) {
            return sorted[n / 2];
        }
        return (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0;
    }

    /** 窗口内最慢的 3 条（两个指标合并排序，带 metric 字段区分来源指标） */
    private static List<Map<String, Object>> worst(List<Sample> mttd, List<Sample> mttr) {
        List<Sample> all = new ArrayList<>(mttd.size() + mttr.size());
        all.addAll(mttd);
        all.addAll(mttr);
        // 稳定排序：分钟数相同时保留采样顺序，响应体在多次请求间可复现
        all.sort(Comparator.comparingDouble(Sample::minutes).reversed());

        List<Map<String, Object>> out = new ArrayList<>();
        for (int i = 0; i < Math.min(WORST_LIMIT, all.size()); i++) {
            Sample s = all.get(i);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("metric", s.metric());
            m.put("ip", s.ip());
            m.put("minutes", round1(s.minutes()));
            m.put("source", s.source());
            m.put("at", FMT.format(s.at()));
            out.add(m);
        }
        return out;
    }

    private static double minutesBetween(LocalDateTime from, LocalDateTime to) {
        return Duration.between(from, to).toMillis() / 60000.0;
    }

    private static double round1(double v) {
        return Math.round(v * 10.0) / 10.0;
    }

    private static LocalDateTime parseTime(String s) {
        if (s == null || s.isBlank()) {
            return null;
        }
        try {
            return LocalDateTime.parse(s.trim(), FMT);
        } catch (Exception e) {
            return null;
        }
    }

    private static String trimToNull(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static boolean isReal(String mode) {
        return mode != null && "REAL".equalsIgnoreCase(mode.trim());
    }

    /** 两源都真 = REAL；只有一侧真 = PARTIAL；否则 MOCK（该侧样本已被剔除） */
    private static String overallMode(boolean wazuhReal, boolean suricataReal) {
        if (wazuhReal && suricataReal) {
            return "REAL";
        }
        if (wazuhReal || suricataReal) {
            return "PARTIAL";
        }
        return "MOCK";
    }

    /** 网关 mode 可能抛异常（外部依赖初始化失败），降级为 null 而不是让整个端点 500 */
    private String safeMode(boolean wazuh) {
        try {
            return wazuh ? wazuhGateway.mode() : suricataGateway.mode();
        } catch (Exception e) {
            logger.warn("读取{}数据源模式失败：{}", wazuh ? " Wazuh" : " Suricata", e.getMessage());
            return null;
        }
    }

    static int clamp(int hours) {
        if (hours < MIN_HOURS) {
            return MIN_HOURS;
        }
        return Math.min(hours, MAX_HOURS);
    }

    /** 一条时延样本；metric 用于 worst 列表区分 MTTD/MTTR */
    private record Sample(String metric, String ip, double minutes, String source, LocalDateTime at) {
    }
}
