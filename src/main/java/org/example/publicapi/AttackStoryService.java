package org.example.publicapi;

import org.example.core.model.AlertSeverity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * <b>攻击故事线</b>：把同一个来源的「告警 → 诱饵端口 → 蜜罐会话 → 处置审计」串成一条时间线。
 *
 * <h3>两个端点（都在 {@code /api/public/**} 上，复用同一套外壳）</h3>
 * <p>设计说明（给博客对接方）：{@code docs/design-attack-story-endpoint.md}；
 * 运维口径、字段表与真实实测：{@code RUNBOOK §32}。
 * <ul>
 *   <li>{@code GET /api/public/stories} —— "值得看的来源"列表：每个来源在四个阶段各有几条、
 *       首末时间、最高等级，以及 <b>{@code gaps[]}</b>（哪些阶段<b>没有数据</b>）；</li>
 *   <li>{@code GET /api/public/story?src=&lt;IP&gt;} —— 该来源的按时间排序的事件流 + 每阶段
 *       {@code coverage}（查到多少条、哪些阶段读不到/未接入 + 原因）。</li>
 * </ul>
 *
 * <h3>这个类最不能违反的一条：宁可少一段，也不许编一段</h3>
 * 四个阶段的数据可得性<b>天生不一样</b>：
 * <ol>
 *   <li>{@code alerts} / {@code decoyPorts} / {@code honeypotLogins} 来自 Wazuh indexer
 *       （{@code rule.groups} 分别是"非蜜罐"、{@code dionaea}、{@code cowrie} 登录规则）；</li>
 *   <li>{@code auditActions} 来自应用侧的处置留痕文件（{@code response-audit.json}）——
 *       <b>根本不在 indexer 里</b>，所以它必须单独拼装、单独给状态。</li>
 * </ol>
 * 只要某一段取不到，就写"没有数据 / 未接入 + 原因"，绝不用别的数据顶替、
 * 也不用 0 冒充"这个来源没干过这件事"。
 * 蜜罐的<b>命令时间线</b>同理：数据源里没有命令执行规则，所以一律
 * {@code commandsAvailable=false}，页面必须如实标注。
 *
 * <h3>为什么"原始 IP"只在内部流转</h3>
 * 掩码态下 {@code 45.205.***.***} 匹配不到任何记录，所以四段关联必须用索引/留痕里的
 * <b>原始地址</b>做 key。这些原始值只存在于本类的内部结构（{@link StoriesSnapshot}）里，
 * 公开载荷一律经过 {@link PublicIpPolicy#display(String)}；
 * 内部 key 与公开载荷是<b>两个对象</b>，从结构上就不可能"顺手把原始 IP 带出去"。
 *
 * <h3>复用既有外壳，一个新机制都不加</h3>
 * 限流（同一个 {@link PublicRateLimiter}，20 次/分钟）、CORS（{@link PublicCorsInterceptor}）、
 * ETag/304（{@link PublicEtagFilter}）、15 秒快照（本类的 {@link #cached}）、
 * 出参信封与资产名过滤（{@code PublicApiController.ok(...)}）全部沿用既有实现。
 */
@Component
public class AttackStoryService {

    private static final Logger logger = LoggerFactory.getLogger(AttackStoryService.class);

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /** 阶段名（公开契约的固定键名，只许新增不许改名） */
    public static final String STAGE_ALERTS = "alerts";
    public static final String STAGE_DECOY = "decoyPorts";
    public static final String STAGE_HONEYPOT = "honeypotLogins";
    public static final String STAGE_AUDIT = "auditActions";

    /** 固定阶段顺序（gaps[]、事件排序、coverage 的键序都按它，保证确定性） */
    public static final List<String> STAGE_ORDER =
            List.of(STAGE_ALERTS, STAGE_DECOY, STAGE_HONEYPOT, STAGE_AUDIT);

    /** 阶段中文标签（页面直接用，不必自己维护映射表） */
    public static Map<String, String> stageLabels() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put(STAGE_ALERTS, "告警");
        m.put(STAGE_DECOY, "诱饵端口");
        m.put(STAGE_HONEYPOT, "蜜罐登录");
        m.put(STAGE_AUDIT, "处置审计");
        return m;
    }

    /** 允许的窗口（小时）。只列"确实有数据源"的窗口，不假装支持任意值 */
    public static final List<Integer> SUPPORTED_WINDOWS = List.of(1, 6, 24, 72);

    /** 默认窗口：24 小时（与其余公开端点同一口径） */
    public static final int DEFAULT_WINDOW_HOURS = 24;

    /** 默认 limit（`/stories` 返回多少条） */
    public static final int DEFAULT_LIMIT = 10;

    /** 单条 summary 的截断长度（规则描述原文可能很长；只给摘要与结论） */
    static final int SUMMARY_MAX_CHARS = 200;

    @Autowired
    private PublicAlertSource source;

    @Autowired
    private PublicAuditReader auditReader;

    /** IP 显示口径（唯一来源；缺注入时按掩码兜底，与其余公开端点一致） */
    @Autowired(required = false)
    private PublicIpPolicy ipPolicy;

    @Value("${app.public-api.cache-seconds:15}")
    private int cacheSeconds = 15;

    /** 候选来源上限（indexer terms size）：它同时是 `/story` 的"可查询来源池"大小 */
    @Value("${app.public-api.story.top-sources:50}")
    private int topSources = 50;

    /** 单个来源、单个阶段最多取回多少条事件（每段独立限量，避免一段刷屏挤掉另外两段） */
    @Value("${app.public-api.story.max-events-per-stage:40}")
    private int maxEventsPerStage = 40;

    /** `/stories` 的 limit 上限（防止有人用 limit=100000 把响应撑大） */
    @Value("${app.public-api.story.max-limit:20}")
    private int maxLimit = 20;

    /**
     * 我方出口 IP（与 {@code /api/public/geo} 同一个配置键）。
     *
     * <p>为什么故事线也必须排除它们：实测 24 小时里 {@code data.src_ip} 的前几名就有
     * srv1/srv2 自己的公网地址（自检与隧道探测流量）。不排掉，"值得看的攻击来源"榜单
     * 上会出现我们自己的服务器。
     */
    @Value("${app.geoip.self-ips:}")
    private String selfIps = "";

    private static final PublicIpPolicy FAIL_CLOSED_POLICY = PublicIpPolicy.masking();

    private PublicIpPolicy policy() {
        PublicIpPolicy p = ipPolicy;
        return p != null ? p : FAIL_CLOSED_POLICY;
    }

    // ==================== 参数口径（纯函数，控制器与测试共用） ====================

    /**
     * 解析 {@code window} 参数。
     *
     * @return 小时数；{@code null} 表示"不认识这个窗口"（控制器据此回 400，而不是悄悄按 24h 处理）
     */
    public static Integer parseWindowHours(String window) {
        if (window == null || window.isBlank()) {
            return DEFAULT_WINDOW_HOURS;
        }
        String v = window.trim().toLowerCase();
        if (v.endsWith("h")) {
            v = v.substring(0, v.length() - 1);
        }
        try {
            int hours = Integer.parseInt(v);
            return SUPPORTED_WINDOWS.contains(hours) ? hours : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** 规范化的窗口写法（回显用，例如 {@code 24h}） */
    public static String windowLabel(int hours) {
        return hours + "h";
    }

    /** limit 归一：非法/越界一律夹到 [1, maxLimit]，绝不因为参数离谱就返回整表 */
    public static int parseLimit(String limit, int maxLimit) {
        int max = Math.max(1, maxLimit);
        if (limit == null || limit.isBlank()) {
            return Math.min(DEFAULT_LIMIT, max);
        }
        try {
            int v = Integer.parseInt(limit.trim());
            if (v <= 0) {
                return 1;
            }
            return Math.min(v, max);
        } catch (NumberFormatException e) {
            return Math.min(DEFAULT_LIMIT, max);
        }
    }

    /** limit 归一（用本实例读到的上限）：控制器与测试都走这一个入口 */
    public int parseLimit(String limit) {
        return parseLimit(limit, Math.max(1, maxLimit));
    }

    // ==================== 对外入口 ====================

    /** {@code GET /api/public/stories} 的载荷（已按 limit 截断）。 */
    public Map<String, Object> stories(int windowHours, int limit) {
        int w = clampWindow(windowHours);
        int lim = Math.max(1, Math.min(limit, Math.max(1, maxLimit)));
        StoriesSnapshot snap = snapshot(w);
        return applyLimit(snap.payload, lim);
    }

    /**
     * {@code GET /api/public/story?src=} 的载荷。
     *
     * @return 该来源的载荷；{@code null} 表示它<b>不在当前窗口的候选池</b>里
     *         （控制器据此回 404）。刻意只服务候选池内的来源：
     *         否则这个端点会变成"随便给个 IP 就能问'他有没有打过我们'"的查询器 ——
     *         那本身就是情报泄露，而且它与"给榜上的攻击源画时间线"是两件事。
     */
    public Map<String, Object> story(String srcIp, int windowHours) {
        int w = clampWindow(windowHours);
        String raw = srcIp == null ? "" : srcIp.trim();
        StoriesSnapshot snap = snapshot(w);
        if (!Boolean.TRUE.equals(snap.payload.get("available"))) {
            String reason = str(snap.payload.get("reason"), "DATA_SOURCE_UNAVAILABLE");
            String note = str(snap.payload.get("note"), "数据源不可用");
            return cached("story-down:" + w, () -> buildStoryUnavailable(w, reason, note, raw));
        }
        PoolEntry entry = snap.pool.get(raw);
        if (entry == null) {
            return null;
        }
        String key = "story:" + w + ":" + raw;
        return cached(key, () -> buildStory(entry, snap, w));
    }

    private int clampWindow(int hours) {
        return SUPPORTED_WINDOWS.contains(hours) ? hours : DEFAULT_WINDOW_HOURS;
    }

    private int topSourcesCapped() {
        return Math.max(1, Math.min(topSources, 500));
    }

    private int maxEventsCapped() {
        return Math.max(1, Math.min(maxEventsPerStage, 200));
    }

    /** 按 limit 截断 sources（其余字段原样；载荷本身来自 15 秒快照，所以同一快照内逐字节稳定） */
    static Map<String, Object> applyLimit(Map<String, Object> payload, int limit) {
        Map<String, Object> out = new LinkedHashMap<>(payload);
        List<Map<String, Object>> all = asMapList(payload.get("sources"));
        List<Map<String, Object>> cut = new ArrayList<>();
        for (int i = 0; i < all.size() && i < limit; i++) {
            cut.add(all.get(i));
        }
        out.put("limit", limit);
        out.put("sourceCount", cut.size());
        out.put("sources", cut);
        out.put("note", payload.get("note") + " limit=" + limit + "：只展示前 " + cut.size()
                + " 条（候选 " + all.size() + " 条，截断由 sourceCount 与 candidates 如实披露）。");
        return out;
    }

    // ==================== /stories 载荷组装 ====================

    private StoriesSnapshot snapshot(int windowHours) {
        return cached("stories:" + windowHours, () -> buildSnapshot(windowHours));
    }

    private StoriesSnapshot buildSnapshot(int windowHours) {
        String now = LocalDateTime.now().format(FMT);
        LocalDateTime since = LocalDateTime.now().minusHours(windowHours);

        Map<String, Object> raw = source == null
                ? unavailableRaw("DATA_SOURCE_UNAVAILABLE", "公网只能读数据源未装配")
                : source.storySources(windowHours, topSourcesCapped());

        Map<String, Object> auditStatus = auditReader == null ? null : auditReader.status();
        Map<String, List<Map<String, Object>>> auditEvents =
                auditReader == null ? Map.of() : auditReader.eventsByTargetSince(since);

        Map<String, String> stageStatus = new LinkedHashMap<>();
        Map<String, String> stageNotes = new LinkedHashMap<>();
        stageStatus.put(STAGE_ALERTS, "UNKNOWN");
        stageStatus.put(STAGE_DECOY, "UNKNOWN");
        stageStatus.put(STAGE_HONEYPOT, "UNKNOWN");
        stageStatus.put(STAGE_AUDIT, auditReader == null
                ? "NOT_WIRED" : (Boolean.TRUE.equals(auditStatus.get("actionsReadable")) ? "OK" : "NOT_WIRED"));
        stageNotes.put(STAGE_ALERTS, "Wazuh indexer：rule.groups 不含 cowrie/dionaea 的告警");
        stageNotes.put(STAGE_DECOY, "Wazuh indexer：rule.groups=dionaea（蜜罐诱饵端口）");
        stageNotes.put(STAGE_HONEYPOT, "Wazuh indexer：Cowrie 登录规则 100101/100102");
        stageNotes.put(STAGE_AUDIT, auditReader == null
                ? "处置留痕读取器未装配：本阶段未接入"
                : (Boolean.TRUE.equals(auditStatus.get("actionsReadable"))
                        ? "应用侧处置留痕文件 response-audit.json（不在 indexer 里）"
                        : "处置留痕文件读不到：" + auditStatus.get("actionsReadable")));

        if (!Boolean.TRUE.equals(raw.get("available"))) {
            Map<String, Object> payload = buildStoriesUnavailable(
                    str(raw.get("reason"), "DATA_SOURCE_UNAVAILABLE"),
                    str(raw.get("note"), "告警数据源不可用（或未拿到真实数据）"),
                    windowHours, now, topSourcesCapped(), maxEventsCapped(),
                    stageStatus, stageNotes, auditStatus);
            return new StoriesSnapshot(payload, Map.of(), stageStatus, stageNotes, auditStatus);
        }

        stageStatus.put(STAGE_ALERTS, wiring(raw, STAGE_ALERTS, "OK"));
        stageStatus.put(STAGE_DECOY, wiring(raw, STAGE_DECOY, "NOT_WIRED"));
        stageStatus.put(STAGE_HONEYPOT, wiring(raw, STAGE_HONEYPOT, "NOT_WIRED"));

        Set<String> self = PublicApiController.parseSelfIps(selfIps);
        // 按【来源个数】计数，不按记录条数：同一个内网地址在四段里各出现一次也只算一个来源，
        // 否则 coverage.excludedInternal 会随着"它在几段里有数据"而变，没人能解释这个数字
        Set<String> excludedSelfIps = new LinkedHashSet<>();
        Set<String> excludedInternalIps = new LinkedHashSet<>();
        Map<String, PoolEntry> pool = new LinkedHashMap<>();

        for (Map<String, Object> s : asMapList(raw.get("sources"))) {
            String ip = str(s.get("srcIp"), "");
            if (ip.isEmpty()) {
                continue;
            }
            if (isSelf(ip, self)) {
                excludedSelfIps.add(ip);
                continue;
            }
            if (!isPublicIp(ip)) {
                excludedInternalIps.add(ip);
                continue;
            }
            PoolEntry e = new PoolEntry(ip);
            e.stages.put(STAGE_ALERTS, num(s.get("alerts")));
            e.stages.put(STAGE_DECOY, num(s.get("decoyPorts")));
            e.stages.put(STAGE_HONEYPOT, num(s.get("honeypotLogins")));
            e.honeypotEvents = num(s.get("honeypotEvents"));
            e.firstSeen = strOrNull(s.get("firstSeen"));
            e.lastSeen = strOrNull(s.get("lastSeen"));
            e.observeSeverity(AlertSeverity.fromWazuhLevel(num(s.get("maxLevel"))));
            pool.put(ip, e);
        }

        for (Map.Entry<String, List<Map<String, Object>>> en : auditEvents.entrySet()) {
            String ip = en.getKey();
            if (isSelf(ip, self)) {
                excludedSelfIps.add(ip);
                continue;
            }
            if (!isPublicIp(ip)) {
                excludedInternalIps.add(ip);
                continue;
            }
            PoolEntry e = pool.computeIfAbsent(ip, PoolEntry::new);
            e.stages.put(STAGE_AUDIT, (long) en.getValue().size());
            e.auditEvents = en.getValue();
            for (Map<String, Object> a : en.getValue()) {
                e.observeTime(strOrNull(a.get("ts")));
                e.observeSeverity(severityOfRisk(strOrNull(a.get("riskLevel"))));
            }
        }

        List<PoolEntry> sorted = new ArrayList<>(pool.values());
        sorted.sort(AttackStoryService::compareEntries);

        List<Map<String, Object>> sources = new ArrayList<>();
        for (PoolEntry e : sorted) {
            sources.add(publicSource(e));
        }

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("generatedAt", now);
        payload.put("cacheSeconds", Math.max(0, cacheSeconds));
        payload.put("window", windowLabel(windowHours));
        payload.put("windowHours", windowHours);
        payload.put("available", true);
        payload.put("reason", sources.isEmpty() ? "NO_DATA_IN_WINDOW" : "OK");
        payload.put("limit", DEFAULT_LIMIT);
        payload.put("candidates", sources.size());
        payload.put("sourceCount", sources.size());
        payload.put("stageLabels", stageLabels());
        payload.put("sources", sources);
        payload.put("coverage", storiesCoverage(windowHours, raw, stageStatus, stageNotes,
                auditStatus, excludedSelfIps.size(), excludedInternalIps.size(), topSourcesCapped()));
        payload.put("limits", limits());
        payload.put("note", sources.isEmpty()
                ? "数据源可用，但该窗口内没有任何可公开的候选来源（内网/保留地址与我方 IP 已排除，"
                        + "详见 coverage）。这不是故障，也不以内置样本顶替。"
                : "按剧本完整度排序（阶段数多者在前，再看最高等级与事件条数）；"
                        + "gaps[] 是【这个来源确实没有数据】的阶段，coverage.stageStatus 说明该阶段"
                        + "本身是'已接入'还是'未接入'—— 两者必须分开读，否则会把'没接入'误读成'没发生'。"
                        + "内网/保留地址与我方 IP 已排除。");
        return new StoriesSnapshot(payload, pool, stageStatus, stageNotes, auditStatus);
    }

    /** 同一份输入必须得到同一份排序（ETag/304 的前提） */
    private static int compareEntries(PoolEntry a, PoolEntry b) {
        int c = Integer.compare(b.stagesWithData(), a.stagesWithData());
        if (c != 0) {
            return c;
        }
        c = Integer.compare(b.severityRank(), a.severityRank());
        if (c != 0) {
            return c;
        }
        c = Long.compare(b.total(), a.total());
        if (c != 0) {
            return c;
        }
        c = compareDesc(a.lastSeen, b.lastSeen);
        if (c != 0) {
            return c;
        }
        return String.valueOf(a.rawIp).compareTo(String.valueOf(b.rawIp));
    }

    private static int compareDesc(String a, String b) {
        if (a == null && b == null) {
            return 0;
        }
        if (a == null) {
            return 1;
        }
        if (b == null) {
            return -1;
        }
        return b.compareTo(a);
    }

    private Map<String, Object> publicSource(PoolEntry e) {
        Map<String, Object> stages = new LinkedHashMap<>();
        for (String s : STAGE_ORDER) {
            stages.put(s, e.stages.getOrDefault(s, 0L));
        }
        List<String> gaps = new ArrayList<>();
        for (String s : STAGE_ORDER) {
            if (e.stages.getOrDefault(s, 0L) <= 0) {
                gaps.add(s);
            }
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("srcIp", policy().display(e.rawIp));
        m.put("stages", stages);
        m.put("stagesWithData", e.stagesWithData());
        m.put("stageCount", STAGE_ORDER.size());
        m.put("firstSeen", e.firstSeen);
        m.put("lastSeen", e.lastSeen);
        m.put("severityMax", e.severityMax == null ? null : e.severityMax.name());
        m.put("severityMaxLabel", e.severityMax == null ? null : e.severityMax.getLabel());
        m.put("gaps", gaps);
        m.put("gapLabels", gaps.stream().map(AttackStoryService::stageLabel).toList());
        // "连上过蜜罐但没登录"的旁证：全量 Cowrie 事件数（不进 stages 计数）
        m.put("honeypotEvents", e.honeypotEvents);
        return m;
    }

    static String stageLabel(String stage) {
        switch (stage) {
            case STAGE_ALERTS:
                return "告警";
            case STAGE_DECOY:
                return "诱饵端口";
            case STAGE_HONEYPOT:
                return "蜜罐登录";
            default:
                return "处置审计";
        }
    }

    private Map<String, Object> limits() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("defaultLimit", DEFAULT_LIMIT);
        m.put("maxLimit", Math.max(1, maxLimit));
        m.put("topSources", topSourcesCapped());
        m.put("maxEventsPerStage", maxEventsCapped());
        m.put("supportedWindows", SUPPORTED_WINDOWS.stream().map(AttackStoryService::windowLabel).toList());
        return m;
    }

    private Map<String, Object> storiesCoverage(int windowHours, Map<String, Object> raw,
                                                Map<String, String> stageStatus,
                                                Map<String, String> stageNotes,
                                                Map<String, Object> auditStatus,
                                                int excludedSelf, int excludedInternal, int topSourcesCapped) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("windowHours", windowHours);
        c.put("indexerTotalAlerts", num(raw.get("indexerTotal")));
        c.put("withSourceIp", num(raw.get("withSourceIp")));
        c.put("topSources", topSourcesCapped);
        c.put("stageStatus", new LinkedHashMap<>(stageStatus));
        c.put("stageNotes", new LinkedHashMap<>(stageNotes));
        c.put("excludedSelf", excludedSelf);
        c.put("excludedInternal", excludedInternal);
        c.put("audit", auditStatus == null ? Map.of() : new LinkedHashMap<>(auditStatus));
        return c;
    }

    private Map<String, Object> buildStoriesUnavailable(String reason, String note, int windowHours,
                                                        String now, int topSources, int maxEvents,
                                                        Map<String, String> stageStatus,
                                                        Map<String, String> stageNotes,
                                                        Map<String, Object> auditStatus) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("generatedAt", now);
        payload.put("cacheSeconds", Math.max(0, cacheSeconds));
        payload.put("window", windowLabel(windowHours));
        payload.put("windowHours", windowHours);
        payload.put("available", false);
        payload.put("reason", reason);
        payload.put("limit", DEFAULT_LIMIT);
        payload.put("candidates", 0);
        payload.put("sourceCount", 0);
        payload.put("stageLabels", stageLabels());
        payload.put("sources", List.of());
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("windowHours", windowHours);
        c.put("indexerTotalAlerts", 0L);
        c.put("withSourceIp", 0L);
        c.put("topSources", topSources);
        c.put("stageStatus", new LinkedHashMap<>(stageStatus));
        c.put("stageNotes", new LinkedHashMap<>(stageNotes));
        c.put("excludedSelf", 0);
        c.put("excludedInternal", 0);
        c.put("audit", auditStatus == null ? Map.of() : new LinkedHashMap<>(auditStatus));
        payload.put("coverage", c);
        Map<String, Object> limits = new LinkedHashMap<>();
        limits.put("defaultLimit", DEFAULT_LIMIT);
        limits.put("maxLimit", DEFAULT_LIMIT);
        limits.put("topSources", topSources);
        limits.put("maxEventsPerStage", maxEvents);
        limits.put("supportedWindows", SUPPORTED_WINDOWS.stream().map(AttackStoryService::windowLabel).toList());
        payload.put("limits", limits);
        payload.put("note", note);
        return payload;
    }

    // ==================== /story 载荷组装 ====================

    /**
     * 故事线明细不可用时的载荷（字段名与可用载荷对齐：前端只判 {@code available} 一个开关）。
     *
     * <p>刻意<b>不用</b> "/stories 的载荷"来顶替：两个端点的形状不同，
     * 混着返回会让页面把"候选列表"当成"事件流"渲染。
     */
    private Map<String, Object> buildStoryUnavailable(int windowHours, String reason, String note, String rawSrcIp) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("generatedAt", LocalDateTime.now().format(FMT));
        payload.put("cacheSeconds", Math.max(0, cacheSeconds));
        payload.put("window", windowLabel(windowHours));
        payload.put("windowHours", windowHours);
        payload.put("available", false);
        payload.put("reason", reason);
        payload.put("srcIp", policy().display(rawSrcIp));
        payload.put("firstSeen", null);
        payload.put("lastSeen", null);
        payload.put("severityMax", null);
        payload.put("severityMaxLabel", null);
        payload.put("gaps", List.of());
        Map<String, Object> stages = new LinkedHashMap<>();
        for (String s : STAGE_ORDER) {
            stages.put(s, 0L);
        }
        payload.put("stages", stages);
        payload.put("events", List.of());
        payload.put("eventCount", 0);
        payload.put("truncated", false);
        Map<String, Object> cov = new LinkedHashMap<>();
        for (String stage : STAGE_ORDER) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("status", "UNKNOWN");
            m.put("reason", "STORY_UNAVAILABLE");
            m.put("note", "故事线明细不可用，这一段没有取到任何数据（不代表没有发生）");
            m.put("queried", 0L);
            m.put("returned", 0L);
            m.put("truncated", false);
            m.put("source", STAGE_AUDIT.equals(stage)
                    ? "应用侧处置留痕 data/response-audit.json"
                    : "Wazuh indexer（wazuh-alerts-*）");
            cov.put(stage, m);
        }
        cov.put("windowHours", windowHours);
        cov.put("maxEventsPerStage", maxEventsCapped());
        payload.put("coverage", cov);
        payload.put("commandsAvailable", false);
        payload.put("commandsNote", COMMANDS_NOTE);
        payload.put("limits", limits());
        payload.put("note", note + "（不返回任何事件，也不用别的阶段或内部样本顶替）");
        return payload;
    }

    private Map<String, Object> buildStory(PoolEntry entry, StoriesSnapshot snap, int windowHours) {
        String now = LocalDateTime.now().format(FMT);
        Map<String, Object> raw = source == null
                ? unavailableRaw("DATA_SOURCE_UNAVAILABLE", "公网只读数据源未装配")
                : source.storyEvents(entry.rawIp, windowHours, maxEventsCapped());

        if (!Boolean.TRUE.equals(raw.get("available"))) {
            return buildStoryUnavailable(windowHours, str(raw.get("reason"), "DATA_SOURCE_UNAVAILABLE"),
                    str(raw.get("note"), "故事线明细不可用"), entry.rawIp);
        }
        Map<String, Object> rawStages = asMap(raw.get("stages"));
        List<Map<String, Object>> events = new ArrayList<>();
        for (String stage : List.of(STAGE_ALERTS, STAGE_DECOY, STAGE_HONEYPOT)) {
            Map<String, Object> st = asMap(rawStages.get(stage));
            for (Map<String, Object> ev : asMapList(st.get("events"))) {
                events.add(publicIndexerEvent(stage, ev));
            }
        }
        for (Map<String, Object> ev : entry.auditEvents) {
            events.add(publicAuditEvent(ev));
        }
        events.sort(AttackStoryService::compareEvents);

        boolean truncated = false;
        for (String stage : List.of(STAGE_ALERTS, STAGE_DECOY, STAGE_HONEYPOT)) {
            if (Boolean.TRUE.equals(asMap(rawStages.get(stage)).get("truncated"))) {
                truncated = true;
            }
        }

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("generatedAt", now);
        payload.put("cacheSeconds", Math.max(0, cacheSeconds));
        payload.put("window", windowLabel(windowHours));
        payload.put("windowHours", windowHours);
        payload.put("available", true);
        payload.put("reason", "OK");
        payload.put("srcIp", policy().display(entry.rawIp));
        payload.put("firstSeen", entry.firstSeen);
        payload.put("lastSeen", entry.lastSeen);
        payload.put("severityMax", entry.severityMax == null ? null : entry.severityMax.name());
        payload.put("severityMaxLabel", entry.severityMax == null ? null : entry.severityMax.getLabel());
        payload.put("gaps", gapsOf(entry));
        payload.put("stages", publicStages(entry));
        payload.put("events", events);
        payload.put("eventCount", events.size());
        payload.put("truncated", truncated);
        payload.put("coverage", storyCoverage(windowHours, snap, entry, rawStages));
        payload.put("commandsAvailable", false);
        payload.put("commandsNote", COMMANDS_NOTE);
        payload.put("limits", limits());
        payload.put("note", "事件按时间升序合并；每段各自限量（超过则 truncated=true，"
                + "coverage 里给的是【查到了多少条】而不是取回了多少条）。"
                + "只给摘要与结论：规则描述里的口令一律隐去，内部资产名与内网地址不出现在响应里。");
        return payload;
    }

    /** 蜜罐命令时间线的口径（与 /honeypot 同一句话术：数据源里没有，所以不编） */
    static final String COMMANDS_NOTE =
            "蜜罐命令时间线的数据源尚未接入（Wazuh 侧没有命令执行规则），"
                    + "所以 commandsAvailable=false —— 不编造命令序列。";

    private Map<String, Object> publicStages(PoolEntry e) {
        Map<String, Object> stages = new LinkedHashMap<>();
        for (String s : STAGE_ORDER) {
            stages.put(s, e.stages.getOrDefault(s, 0L));
        }
        return stages;
    }

    private List<String> gapsOf(PoolEntry e) {
        List<String> gaps = new ArrayList<>();
        for (String s : STAGE_ORDER) {
            if (e.stages.getOrDefault(s, 0L) <= 0) {
                gaps.add(s);
            }
        }
        return gaps;
    }

    /**
     * 每个阶段的覆盖度：<b>查到多少条</b>、取回多少条、是否被截断，以及
     * "读不到 / 未接入 + 原因"。
     */
    private Map<String, Object> storyCoverage(int windowHours, StoriesSnapshot snap, PoolEntry entry,
                                              Map<String, Object> rawStages) {
        Map<String, Object> cov = new LinkedHashMap<>();
        for (String stage : List.of(STAGE_ALERTS, STAGE_DECOY, STAGE_HONEYPOT)) {
            Map<String, Object> st = rawStages == null ? null : asMap(rawStages.get(stage));
            String status = snap.stageStatus.getOrDefault(stage, "UNKNOWN");
            Map<String, Object> m = new LinkedHashMap<>();
            long queried = st == null ? entry.stages.getOrDefault(stage, 0L) : num(st.get("total"));
            long returned = st == null ? 0L : num(st.get("returned"));
            m.put("status", status);
            m.put("reason", coverageReason(status));
            m.put("note", coverageNote(stage, status, queried));
            m.put("queried", queried);
            m.put("returned", returned);
            m.put("truncated", st != null && Boolean.TRUE.equals(st.get("truncated")));
            m.put("source", "Wazuh indexer（wazuh-alerts-*）");
            cov.put(stage, m);
        }

        Map<String, Object> audit = new LinkedHashMap<>();
        boolean readable = snap.auditStatus != null
                && Boolean.TRUE.equals(snap.auditStatus.get("actionsReadable"));
        long auditQueried = entry.stages.getOrDefault(STAGE_AUDIT, 0L);
        audit.put("status", readable ? "OK" : "NOT_WIRED");
        audit.put("reason", readable ? "OK" : "AUDIT_FILE_UNREADABLE");
        audit.put("note", !readable
                ? "处置留痕文件读不到（data/response-audit.json）：本阶段未接入，不代表没有处置"
                : (auditQueried > 0
                        ? "窗口内该来源有 " + auditQueried + " 条处置记录（来自留痕文件，不在 indexer 里）"
                        : "留痕文件可读，但窗口内该来源没有任何处置记录（不是故障，也不是被隐藏）"));
        audit.put("queried", auditQueried);
        audit.put("returned", auditQueried);
        audit.put("truncated", false);
        audit.put("source", "应用侧处置留痕 data/response-audit.json");
        if (snap.auditStatus != null) {
            audit.put("actionRecords", snap.auditStatus.get("actionRecords"));
            audit.put("blockRecords", snap.auditStatus.get("blockRecords"));
            audit.put("actionsWithoutTime", snap.auditStatus.get("actionsWithoutTime"));
        }
        cov.put(STAGE_AUDIT, audit);
        cov.put("windowHours", windowHours);
        cov.put("maxEventsPerStage", maxEventsCapped());
        return cov;
    }

    private static String coverageReason(String status) {
        return switch (status) {
            case "OK" -> "OK";
            case "NOT_WIRED" -> "STAGE_NOT_WIRED";
            default -> "STAGE_STATUS_UNKNOWN";
        };
    }

    private static String coverageNote(String stage, String status, long queried) {
        if ("NOT_WIRED".equals(status)) {
            return stageLabel(stage) + "这一段没有接入数据源（索引里根本查不到这类规则/日志）："
                    + "页面必须显示'未接入'，不能画成'这个来源没做这一步'";
        }
        if (!"OK".equals(status)) {
            return stageLabel(stage) + "这一段能不能查到数据尚未确认（判定查询失败）：按'未知'显示，不猜";
        }
        return queried > 0
                ? stageLabel(stage) + "这一段窗口内查到 " + queried + " 条"
                : stageLabel(stage) + "这一段窗口内该来源没有记录（数据源可用）";
    }

    /**
     * 一条索引事件 → 公开事件。
     *
     * <p>{@code summary} 是规则描述原文，可能内嵌来源 IP 与完整口令，
     * 所以固定顺序处理：<b>先隐口令</b>（与开关无关），<b>再按 IP 口径</b>处理文本，
     * 最后截断。少任何一步，前面结构化字段处理得再干净也照样漏。
     */
    private Map<String, Object> publicIndexerEvent(String stage, Map<String, Object> ev) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ts", strOrNull(ev.get("ts")));
        m.put("stage", stage);
        m.put("stageLabel", stageLabel(stage));
        m.put("kind", scrub(str(ev.get("kind"), "")));
        m.put("summary", scrub(str(ev.get("summary"), "")));
        AlertSeverity sev = AlertSeverity.fromWazuhLevel(num(ev.get("level")));
        m.put("severity", sev.name());
        m.put("severityLabel", sev.getLabel());
        m.put("outcome", strOrNull(ev.get("outcome")));
        return m;
    }

    /** 一条处置留痕 → 公开事件（不含 reason 正文与 detail：故事线只给结论） */
    private Map<String, Object> publicAuditEvent(Map<String, Object> ev) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ts", strOrNull(ev.get("ts")));
        m.put("stage", STAGE_AUDIT);
        m.put("stageLabel", stageLabel(STAGE_AUDIT));
        m.put("kind", scrub(actionLabel(strOrNull(ev.get("action")))));
        m.put("summary", scrub("操作者=" + str(ev.get("actor"), "未知")
                + "；模式=" + str(ev.get("mode"), "未知")
                + "；结果=" + ("SUCCESS".equals(ev.get("outcome")) ? "成功"
                        : "BLOCKED_BY_GUARD".equals(ev.get("outcome")) ? "被护栏拦截" : "失败")));
        AlertSeverity sev = severityOfRisk(strOrNull(ev.get("riskLevel")));
        m.put("severity", sev == null ? null : sev.name());
        m.put("severityLabel", sev == null ? null : sev.getLabel());
        m.put("outcome", strOrNull(ev.get("outcome")));
        return m;
    }

    private static String actionLabel(String action) {
        if (action == null) {
            return "处置动作";
        }
        return switch (action) {
            case "block-ip" -> "封禁 IP";
            case "unblock-ip" -> "解封 IP";
            default -> action;
        };
    }

    /** 事件排序：时间升序；时间相同按阶段固定顺序；再按 kind —— 全确定，无随机 */
    private static int compareEvents(Map<String, Object> a, Map<String, Object> b) {
        String ta = strOrNull(a.get("ts"));
        String tb = strOrNull(b.get("ts"));
        if (ta == null && tb != null) {
            return 1;
        }
        if (tb == null && ta != null) {
            return -1;
        }
        if (ta != null) {
            int c = ta.compareTo(tb);
            if (c != 0) {
                return c;
            }
        }
        int c = Integer.compare(STAGE_ORDER.indexOf(a.get("stage")), STAGE_ORDER.indexOf(b.get("stage")));
        if (c != 0) {
            return c;
        }
        c = String.valueOf(a.get("kind")).compareTo(String.valueOf(b.get("kind")));
        if (c != 0) {
            return c;
        }
        return String.valueOf(a.get("summary")).compareTo(String.valueOf(b.get("summary")));
    }

    /** 文本出海前的统一处理：隐口令（与开关无关）→ IP 口径 → 去控制字符 → 截断 */
    String scrub(String text) {
        if (text == null) {
            return "";
        }
        String out = policy().displayText(CredentialStructure.hidePasswords(text));
        StringBuilder sb = new StringBuilder(out.length());
        for (int i = 0; i < out.length(); i++) {
            char ch = out.charAt(i);
            sb.append(ch < 0x20 || ch == 0x7f ? ' ' : ch);
        }
        String cleaned = sb.toString().trim();
        return cleaned.length() > SUMMARY_MAX_CHARS ? cleaned.substring(0, SUMMARY_MAX_CHARS) + "…" : cleaned;
    }

    private static AlertSeverity severityOfRisk(String riskLevel) {
        if (riskLevel == null || riskLevel.isBlank()) {
            return null;   // 没有等级就不猜（不把 null 说成"中危"）
        }
        return AlertSeverity.parse(riskLevel);
    }

    // ==================== IP 判定 ====================

    private static boolean isSelf(String ip, Set<String> self) {
        return self.contains(ip);
    }

    /**
     * 是否是<b>可以公开的来源地址</b>：认得出来的公网 IPv4/IPv6 字面量。
     *
     * <p>内网/保留/链路地址（{@code 10.0.0.10}、{@code 172.19.0.1}、{@code ::1} …）一律不进候选池：
     * 它们在公开口径里都写成「内网/未知」，好几个不同的内网地址会合并成同一个显示值，
     * 画出来就是"内网/未知 打了我们 4 万次" —— 那比不给更误导。
     * 判定用原始值，与掩码开关无关（否则掩码态下会退化成空榜）。
     */
    static boolean isPublicIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return false;
        }
        String host = PublicIpMask.host(ip);
        return host != null && PublicIpMask.isIpLiteral(host) && !PublicIpMask.isInternalAddress(host);
    }

    // ==================== 缓存与工具 ====================

    /** 15 秒快照（与其余公开端点同一个 TTL 语义；按 key 分开存，避免不同窗口互相顶掉） */
    private final Map<String, CacheEntry> cache = Collections.synchronizedMap(
            new LinkedHashMap<>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, CacheEntry> eldest) {
                    return size() > 32;
                }
            });

    @SuppressWarnings("unchecked")
    private <T> T cached(String key, java.util.function.Supplier<T> loader) {
        long now = System.currentTimeMillis();
        CacheEntry e = cache.get(key);
        if (e != null && now < e.expiresAt) {
            return (T) e.value;
        }
        CacheEntry fresh;
        try {
            fresh = new CacheEntry(loader.get(),
                    System.currentTimeMillis() + Math.max(0, cacheSeconds) * 1000L);
        } catch (Exception ex) {
            // 刷新失败：不把异常抛给匿名访客变成 500；如实降级（有旧值就继续用旧的）
            logger.warn("故事线快照刷新失败（按降级载荷返回）：{}", ex.getMessage());
            if (e != null) {
                fresh = new CacheEntry(e.value, System.currentTimeMillis() + 5000L);
            } else {
                Object value;
                if (key.startsWith("stories:")) {
                    Map<String, String> unknown = new LinkedHashMap<>();
                    for (String s : STAGE_ORDER) {
                        unknown.put(s, "UNKNOWN");
                    }
                    Map<String, Object> down = buildStoriesUnavailable("INTERNAL_ERROR",
                            "故事线组装失败（" + ex.getMessage() + "）：不返回任何数据，也不用内部样本顶替",
                            DEFAULT_WINDOW_HOURS, LocalDateTime.now().format(FMT),
                            topSourcesCapped(), maxEventsCapped(), unknown, Map.of(), null);
                    value = new StoriesSnapshot(down, Map.of(), unknown, Map.of(), null);
                } else {
                    int hours = DEFAULT_WINDOW_HOURS;
                    value = buildStoryUnavailable(hours, "INTERNAL_ERROR",
                            "故事线明细组装失败（" + ex.getMessage() + "）", null);
                }
                fresh = new CacheEntry(value, System.currentTimeMillis() + 5000L);
            }
        }
        cache.put(key, fresh);
        return (T) fresh.value;
    }

    private static final class CacheEntry {
        private final Object value;
        private final long expiresAt;

        private CacheEntry(Object value, long expiresAt) {
            this.value = value;
            this.expiresAt = expiresAt;
        }
    }

    /** 候选来源的内部表示：<b>带原始 IP</b>，只在服务端流转，绝不进公开载荷 */
    private static final class PoolEntry {
        private final String rawIp;
        private final Map<String, Long> stages = new LinkedHashMap<>();
        private String firstSeen;
        private String lastSeen;
        private AlertSeverity severityMax;
        private long honeypotEvents;
        private List<Map<String, Object>> auditEvents = List.of();

        private PoolEntry(String rawIp) {
            this.rawIp = rawIp;
            for (String s : STAGE_ORDER) {
                stages.put(s, 0L);
            }
        }

        private long total() {
            return stages.getOrDefault(STAGE_ALERTS, 0L)
                    + stages.getOrDefault(STAGE_DECOY, 0L)
                    + stages.getOrDefault(STAGE_HONEYPOT, 0L);
        }

        private int stagesWithData() {
            int n = 0;
            for (String s : STAGE_ORDER) {
                if (stages.getOrDefault(s, 0L) > 0) {
                    n++;
                }
            }
            return n;
        }

        private int severityRank() {
            return severityMax == null ? -1 : severityMax.getRank();
        }

        private void observeSeverity(AlertSeverity sev) {
            if (sev == null) {
                return;
            }
            if (severityMax == null || sev.getRank() > severityMax.getRank()) {
                severityMax = sev;
            }
        }

        private void observeTime(String ts) {
            if (ts == null || ts.isBlank()) {
                return;
            }
            if (firstSeen == null || ts.compareTo(firstSeen) < 0) {
                firstSeen = ts;
            }
            if (lastSeen == null || ts.compareTo(lastSeen) > 0) {
                lastSeen = ts;
            }
        }
    }

    /** 一次快照：公开载荷 + 只在内网侧使用的候选池（原始 IP ↔ 阶段计数） */
    private static final class StoriesSnapshot {
        private final Map<String, Object> payload;
        private final Map<String, PoolEntry> pool;
        private final Map<String, String> stageStatus;
        private final Map<String, String> stageNotes;
        private final Map<String, Object> auditStatus;

        private StoriesSnapshot(Map<String, Object> payload, Map<String, PoolEntry> pool,
                                Map<String, String> stageStatus, Map<String, String> stageNotes,
                                Map<String, Object> auditStatus) {
            this.payload = payload;
            this.pool = pool;
            this.stageStatus = stageStatus;
            this.stageNotes = stageNotes;
            this.auditStatus = auditStatus;
        }
    }

    private static String wiring(Map<String, Object> raw, String stage, String fallback) {
        Object w = raw.get("stageWiring");
        if (w instanceof Map<?, ?> m) {
            Object v = m.get(stage);
            if (v != null) {
                return String.valueOf(v);
            }
        }
        return fallback;
    }

    private static Map<String, Object> unavailableRaw(String reason, String note) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("available", false);
        m.put("reason", reason);
        m.put("note", note);
        return m;
    }

    // ---- 出参解析的防御性工具（网关返回 Map，字段可能缺失/类型不对；这里绝不抛异常） ----

    static String str(Object v, String dflt) {
        if (v == null) {
            return dflt;
        }
        String s = String.valueOf(v);
        return s.isBlank() ? dflt : s;
    }

    static String strOrNull(Object v) {
        if (v == null) {
            return null;
        }
        String s = String.valueOf(v);
        return s.isBlank() || "null".equals(s) ? null : s;
    }

    static long num(Object v) {
        if (v instanceof Number n) {
            return n.longValue();
        }
        try {
            return v == null ? 0L : Long.parseLong(String.valueOf(v).trim());
        } catch (NumberFormatException e) {
            return 0L;
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> asMap(Object v) {
        return v instanceof Map<?, ?> m ? (Map<String, Object>) m : new LinkedHashMap<>();
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> asMapList(Object v) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (v instanceof List<?> l) {
            for (Object o : l) {
                if (o instanceof Map<?, ?> m) {
                    out.add((Map<String, Object>) m);
                }
            }
        }
        return out;
    }
}
