package org.example.publicapi;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.core.model.AlertSeverity;
import org.example.core.model.AlertSource;
import org.example.core.model.AlertType;
import org.example.core.model.SecurityAlert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * 公网只读端点：{@code /api/public/**}。
 *
 * <h3>它和自用界面接口的区别（这是本类的全部意义）</h3>
 * <ol>
 *   <li><b>匿名可访问</b>：不要求 Token。因此它只能返回"公开出去也不心疼"的数据 ——
 *       源 IP 掩码到网段、不含内网目的地址与资产名、不含原始日志与完整 payload。</li>
 *   <li><b>字段白名单，不是黑名单</b>：出参按固定字段逐个挑出来放行。
 *       黑名单的问题是"新增字段默认就泄露"，而白名单是"新增字段默认不出现"。</li>
 *   <li><b>独立限流</b>（见 {@link PublicRateLimiter}）+ <b>应用内缓存</b>
 *       （默认 15 秒，并下发 {@code Cache-Control} 让边缘也缓存）。</li>
 *   <li><b>fail-closed</b>：数据源不是 REAL 时返回空数据 + 明确的 degraded 标记，
 *       绝不返回内置样本。宁可页面上写"数据源不可用"。</li>
 * </ol>
 *
 * <h3>为什么只有三个端点，而不是最初设想的五个</h3>
 * 蜜罐战报 / 红队评测 / 处置审计各自还需要独立的数据通路与脱敏口径，
 * 按"每期只做已验证的部分"推进 —— 那些端点跟着 P2 的页面一起加，
 * 避免先造出一批没人调用的公开端点（公开端点是攻击面，不是越多越好）。
 */
@RestController
@RequestMapping("/api/public")
public class PublicApiController {

    private static final Logger logger = LoggerFactory.getLogger(PublicApiController.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final DateTimeFormatter HOUR_FMT = DateTimeFormatter.ofPattern("HH:mm");

    @Autowired
    private PublicAlertSource source;

    @Autowired
    private PublicRateLimiter rateLimiter;

    /** 应用内快照有效期；同时作为 Cache-Control 的 max-age 下发给浏览器/边缘 */
    @Value("${app.public-api.cache-seconds:15}")
    private int cacheSeconds;

    /** 是否在公网端点暴露构建版本号。health 早已公开它，且它是开源仓库的提交号，不敏感 */
    @Value("${app.public-api.expose-build-sha:true}")
    private boolean exposeBuildSha;

    @Value("${app.build.sha:unknown}")
    private String buildSha;

    private final Snapshot overviewCache = new Snapshot();
    private final Snapshot alertsCache = new Snapshot();
    private final Snapshot honeypotCache = new Snapshot();
    private final Snapshot auditCache = new Snapshot();

    /** 处置审计只读读取器（读留痕文件，不注入任何处置 Bean —— 隔离测试会强校验） */
    @Autowired
    private PublicAuditReader auditReader;

    // ==================== P4：公开 AI 问答 + 知识库公开只读检索 ====================

    /** 公开问答业务实现（四道护栏 + state 归一化 + 输出脱敏） */
    @Autowired
    private PublicAskService publicAskService;

    /** 公开知识库检索（复用向量检索，但只出白名单字段） */
    @Autowired
    private PublicKbService publicKbService;

    /** 公开问答的独立限流器（默认 6 次/分钟，与只读端点的 20 次/分钟分开） */
    @Autowired
    @Qualifier("publicAskRateLimiter")
    private PublicAskRateLimiter publicAskRateLimiter;

    /**
     * 公开知识库检索的限流器。
     *
     * <p>与问答共用 {@link PublicAskRateLimiter} 这个实现，但注入的是<b>另一个实例</b> ——
     * 于是两者各自一份计数与各自一份上限（检索 20 次/分钟、问答 6 次/分钟）。
     * 为什么不用同一个实例：共用一个桶意味着"多刷几次检索"会顺手把问答的额度也占掉，
     * 而访客完全看不出这两件事为什么互相影响。
     */
    @Autowired
    @Qualifier("publicKbRateLimiter")
    private PublicAskRateLimiter publicKbRateLimiter;

    /** 每 IP 并发 1 守卫（匿名重操作不能靠限流兜住） */
    @Autowired
    private PublicConcurrencyGuard publicConcurrencyGuard;

    /** 单次公开问答的请求体长度上限（比服务内的字符上限略宽，挡住超大 body） */
    @Value("${app.public-api.ask.max-body-chars:4000}")
    private int maxBodyChars;

    /**
     * 公开 AI 问答：<b>匿名可访问</b>，但必须过四道护栏。
     *
     * <h3>为什么匿名还要做这么多事</h3>
     * 公开的意义是"访客不用注册就能试一句"，代价是它会<b>调模型</b>（真金白银）。
     * 所以这里同时上四把锁：输入注入防护、输出护栏、脱敏、配额与限流；
     * 并且公开路径上的 RESPONDER <b>只解释、不调工具</b> —— 匿名访客永远无法触发处置。
     *
     * <h3>为什么用一次性返回而不是 SSE（第一步）</h3>
     * 项目既有纪律是"不做匿名常驻连接"（{@link PublicCorsInterceptor} 同源的取舍）。
     * 短连接 SSE 要另建一条只为公开页面服务的流式通道（含断连清理、背压、错误帧），
     * 属于"能上但不是这次必须"的部分：先把四道护栏与配额隔离做扎实，
     * 流式作为第二步单独上，避免把两件事的验收标准混在一起。
     * 页面侧因此按"一次性请求 + 明确的等待态"实现，不假装在流式输出。
     */
    @PostMapping("/ask")
    public ResponseEntity<Map<String, Object>> ask(@RequestBody(required = false) Map<String, Object> body,
                                                   HttpServletRequest req,
                                                   HttpServletResponse res) {
        String ip = clientIp(req);

        // ① 限流（每 IP 每分钟 N 次）—— 先于一切上游动作，包括并发登记
        if (!publicAskRateLimiter.allow(ip)) {
            return tooMany(res, publicAskRateLimiter, "公开问答请求过于频繁（每 IP 每分钟 "
                    + publicAskRateLimiter.limitPerMinute() + " 次），请稍后再试");
        }

        // ② 并发 1（每 IP 同时只允许一个在飞）
        if (!publicConcurrencyGuard.tryAcquire(ip)) {
            res.setHeader(HttpHeaders.RETRY_AFTER, "5");
            res.setHeader("X-Public-Concurrency", "1");
            Map<String, Object> b = new LinkedHashMap<>();
            b.put("code", 429);
            b.put("message", "同一来源同时只允许 1 个公开问答请求在飞，请等上一条返回后再试");
            b.put("reason", "per-ip-concurrency-limit");
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(b);
        }

        try {
            String question = extractQuestion(body);
            Map<String, Object> data = publicAskService.ask(question, ip);

            // 一次性返回：公开问答的响应永不被边缘缓存（它是"这一次提问"的结果）
            res.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
            res.setHeader("X-Data-Source", "PUBLIC_ASK");
            res.setHeader("X-RateLimit-Limit", String.valueOf(publicAskRateLimiter.limitPerMinute()));
            res.setHeader("X-RateLimit-Remaining",
                    String.valueOf(Math.max(0, publicAskRateLimiter.remaining(ip))));

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("code", 200);
            out.put("message", "success");
            out.put("data", data);
            return ResponseEntity.ok(out);
        } catch (Exception e) {
            logger.warn("公开问答失败（已按 fail-closed 处理）：{}", e.getMessage());
            Map<String, Object> b = new LinkedHashMap<>();
            b.put("code", 500);
            b.put("message", "公开问答暂时不可用，请稍后再试");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(b);
        } finally {
            publicConcurrencyGuard.release(ip);
        }
    }

    /**
     * 公开知识库检索：<b>只读、匿名、掩码、限流</b>。
     *
     * <p>只返回经过白名单与脱敏的片段（标题 + 片段摘要 + 来源类型 + 可信度），
     * 不返回原始内部路径与文件名；内部文档即使被语义命中也不会出现在这里
     * （口径见 {@link org.example.knowledge.PublicKbVisibility}）。
     */
    @GetMapping("/kb")
    public ResponseEntity<Map<String, Object>> kb(@RequestParam(value = "q", required = false) String q,
                                                  HttpServletRequest req,
                                                  HttpServletResponse res) {
        String ip = clientIp(req);
        if (!publicKbRateLimiter.allow(ip)) {
            return tooMany(res, publicKbRateLimiter, "知识库检索请求过于频繁（每 IP 每分钟 "
                    + publicKbRateLimiter.limitPerMinute() + " 次），请稍后再试");
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", LocalDateTime.now().format(FMT));
        data.put("query", q == null ? "" : q.trim());
        data.put("rule", publicKbService.ruleSummary());

        String query = q == null ? "" : q.trim();
        if (query.isEmpty()) {
            data.put("results", List.of());
            data.put("hitCount", 0);
            data.put("available", true);
            data.put("note", "未提供查询词（q）。");
            return ok(data, res);
        }
        if (query.length() > 200) {
            data.put("results", List.of());
            data.put("hitCount", 0);
            data.put("available", true);
            data.put("note", "查询词过长（上限 200 字符）。");
            return ok(data, res);
        }

        try {
            List<Map<String, Object>> results = publicKbService.search(query);
            data.put("results", results);
            data.put("hitCount", results.size());
            data.put("available", true);
            data.put("note", results.isEmpty()
                    ? "公开知识库未检索到相关片段（未命中就是未命中，不用别的数据顶替）。"
                    : "片段已截断并脱敏；IP 已掩码，内部路径与凭据不出现在响应里。");
        } catch (PublicKbService.PublicKbUnavailableException e) {
            // fail-closed：检索不可用就如实说不可用，不回空列表冒充"没有相关内容"
            data.put("results", List.of());
            data.put("hitCount", 0);
            data.put("available", false);
            data.put("note", "知识库检索不可用（向量检索异常）：未返回任何内容，也不以内置样本顶替。");
        }
        return ok(data, res);
    }

    /** 请求体取问题：只认 {@code question} / {@code q} 两个键，其余一律忽略 */
    private static String extractQuestion(Map<String, Object> body) {
        if (body == null) {
            return "";
        }
        Object v = body.get("question");
        if (v == null) {
            v = body.get("q");
        }
        return v == null ? "" : String.valueOf(v);
    }

    // ==================== 端点 ====================

    /** 首页状态条用：两台服务器在线状态 + 告警概览。载荷刻意做小。 */
    @GetMapping("/overview")
    public ResponseEntity<Map<String, Object>> overview(HttpServletRequest req, HttpServletResponse res) {
        if (!rateLimiter.allow(clientIp(req))) {
            return tooMany(res);
        }
        Map<String, Object> data = overviewCache.get(cacheSeconds, this::buildOverview);
        return ok(data, res);
    }

    /** 告警看板用：聚合后的实时告警流 + 分布 + 24 小时趋势，一次请求拿全。 */
    @GetMapping("/alerts")
    public ResponseEntity<Map<String, Object>> alerts(HttpServletRequest req, HttpServletResponse res) {
        if (!rateLimiter.allow(clientIp(req))) {
            return tooMany(res);
        }
        Map<String, Object> data = alertsCache.get(cacheSeconds, this::buildAlerts);
        return ok(data, res);
    }

    /**
     * 聚合告警下钻：返回该簇内的原始明细（同样经过掩码与字段白名单）。
     *
     * <p>聚合口径与自用界面一致，所以 aggId 可以直接复用。
     */
    @GetMapping("/alerts/{aggId}")
    public ResponseEntity<Map<String, Object>> drillDown(@PathVariable("aggId") String aggId,
                                                         HttpServletRequest req,
                                                         HttpServletResponse res) {
        if (!rateLimiter.allow(clientIp(req))) {
            return tooMany(res);
        }

        List<Map<String, Object>> aggs = source.aggregated();
        Map<String, Object> hit = null;
        for (Map<String, Object> g : aggs) {
            if (aggId.equals(String.valueOf(g.get("aggId")))) {
                hit = g;
                break;
            }
        }
        if (hit == null) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("code", 404);
            body.put("message", "未找到聚合告警（可能已超出当前取数窗口）");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(body);
        }

        List<String> memberIds = asStringList(hit.get("memberIds"));
        Map<String, SecurityAlert> byId = new LinkedHashMap<>();
        for (SecurityAlert a : source.readAlerts()) {
            byId.put(a.getId(), a);
        }
        List<Map<String, Object>> members = new ArrayList<>();
        for (String mid : memberIds) {
            SecurityAlert a = byId.get(mid);
            if (a != null) {
                members.add(publicAlert(a));
            }
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", LocalDateTime.now().format(FMT));
        data.put("summary", publicAggregate(hit));
        data.put("members", members);
        data.put("memberCount", members.size());
        return ok(data, res);
    }

    /** 蜜罐战报：连接/登录计数、账号口令 Top、来源分布（掩码）、事件时间线。 */
    @GetMapping("/honeypot")
    public ResponseEntity<Map<String, Object>> honeypot(HttpServletRequest req, HttpServletResponse res) {
        if (!rateLimiter.allow(clientIp(req))) {
            return tooMany(res);
        }
        return ok(honeypotCache.get(cacheSeconds, this::buildHoneypot), res);
    }

    /** 处置审计（只读）：封禁记录 + 审计流水，IP 全部掩码，不含原始 detail。 */
    @GetMapping("/audit")
    public ResponseEntity<Map<String, Object>> audit(HttpServletRequest req, HttpServletResponse res) {
        if (!rateLimiter.allow(clientIp(req))) {
            return tooMany(res);
        }
        return ok(auditCache.get(cacheSeconds, this::buildAudit), res);
    }

    // ==================== 载荷组装 ====================

    private Map<String, Object> buildHoneypot() {
        Map<String, Object> raw = source.honeypotSummary(800);
        boolean available = Boolean.TRUE.equals(raw.get("available"));

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", LocalDateTime.now().format(FMT));
        data.put("cacheSeconds", cacheSeconds);
        data.put("available", available);
        data.put("commandsAvailable", Boolean.TRUE.equals(raw.get("commandsAvailable")));
        data.put("note", available
                ? "IP 已掩码到网段；命令时间线的数据源尚未接入（Wazuh 侧没有命令执行规则，不编造）"
                : "蜜罐数据源不可达，本页不展示任何蜜罐数据");

        if (available) {
            data.put("total", raw.get("total"));
            data.put("connections", raw.get("connections"));
            data.put("logins", raw.get("logins"));
            data.put("loginFails", raw.get("loginFails"));
            data.put("sampled", raw.get("sampled"));
            // 账号口令 Top 原样保留（那是攻击者试的弱口令，是战报的核心信息）
            data.put("topCredentials", raw.get("topCredentials"));
            data.put("topSources", maskKeys(raw.get("topSources")));
            data.put("topClients", raw.get("topClients"));
            data.put("timeline", maskTimeline(raw.get("timeline")));
        }
        return data;
    }

    private Map<String, Object> buildAudit() {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", LocalDateTime.now().format(FMT));
        data.put("cacheSeconds", cacheSeconds);
        data.put("readOnly", true);
        data.put("summary", auditReader.summary());
        data.put("blocks", auditReader.blocks(20));
        data.put("actions", maskActionText(auditReader.actions(30)));
        return data;
    }

    /** 审计流水的文本字段（reason）也过一遍 IP 掩码 —— 文本里可能内嵌 IP */
    private static List<Map<String, Object>> maskActionText(List<Map<String, Object>> in) {
        for (Map<String, Object> m : in) {
            Object reason = m.get("reason");
            if (reason != null) {
                m.put("reason", PublicIpMask.maskAll(String.valueOf(reason)));
            }
        }
        return in;
    }

    /** 把 [{key,count}] 里的 key 当 IP 掩码 */
    private static List<Map<String, Object>> maskKeys(Object v) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (v instanceof List<?> l) {
            for (Object o : l) {
                if (o instanceof Map<?, ?> m) {
                    Map<String, Object> x = new LinkedHashMap<>();
                    x.put("key", PublicIpMask.mask(m.get("key") == null ? null : String.valueOf(m.get("key"))));
                    x.put("count", m.get("count"));
                    out.add(x);
                }
            }
        }
        return out;
    }

    /** 时间线里的源 IP 掩码 */
    private static List<Map<String, Object>> maskTimeline(Object v) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (v instanceof List<?> l) {
            for (Object o : l) {
                if (o instanceof Map<?, ?> m) {
                    Map<String, Object> x = new LinkedHashMap<>();
                    x.put("time", m.get("time"));
                    x.put("kind", m.get("kind"));
                    x.put("srcIp", PublicIpMask.mask(m.get("srcIp") == null ? null : String.valueOf(m.get("srcIp"))));
                    // detail 是规则描述原文，里面内嵌了完整 IP —— 必须过一遍文本掩码，
                    // 否则前面结构化字段掩得再干净，这里照样漏（实测漏过一次）
                    x.put("detail", PublicIpMask.maskAll(m.get("detail") == null ? null : String.valueOf(m.get("detail"))));
                    out.add(x);
                }
            }
        }
        return out;
    }

    private Map<String, Object> buildOverview() {
        boolean real = source.available();
        List<SecurityAlert> raw = source.readAlerts();

        Map<String, Object> alerts = new LinkedHashMap<>();
        alerts.put("windowSize", source.windowSize());
        alerts.put("windowCount", raw.size());
        alerts.put("windowFull", raw.size() >= source.windowSize());
        alerts.put("windowDescription", "最近 " + source.windowSize() + " 条告警窗口"
                + (raw.size() >= source.windowSize() ? "（已取满，实际数量更多）" : ""));
        alerts.put("todayInWindow", countToday(raw));
        alerts.put("critical", countSeverity(raw, AlertSeverity.CRITICAL));
        alerts.put("high", countSeverity(raw, AlertSeverity.HIGH));
        alerts.put("bySeverity", severityStats(raw));
        alerts.put("bySource", sourceStats(raw));

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", LocalDateTime.now().format(FMT));
        data.put("cacheSeconds", cacheSeconds);
        data.put("nodes", nodes(real));
        data.put("alerts", alerts);
        data.put("dataSource", dataSource(real));
        return data;
    }

    private Map<String, Object> buildAlerts() {
        boolean real = source.available();
        List<SecurityAlert> raw = source.readAlerts();
        List<Map<String, Object>> aggs = source.aggregated();

        List<Map<String, Object>> publicList = new ArrayList<>();
        for (Map<String, Object> g : aggs) {
            publicList.add(publicAggregate(g));
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", LocalDateTime.now().format(FMT));
        data.put("cacheSeconds", cacheSeconds);
        data.put("dataSource", dataSource(real));
        data.put("windowSize", source.windowSize());
        data.put("rawTotal", raw.size());
        data.put("total", publicList.size());
        data.put("aggregated", source.aggregationEnabled());
        data.put("windowMinutes", source.aggregationWindowMinutes());
        data.put("list", publicList);
        data.put("stats", Map.of(
                "bySeverity", severityStats(raw),
                "bySource", sourceStats(raw),
                "byType", typeStats(raw),
                "trend", trend(raw)
        ));
        // 近 24 小时口径：KPI 的"严重/高危"与趋势图都取这一份 ——
        // 取数窗口会被低危网络告警刷屏，按时间范围聚合才是"这段时间到底怎么样"
        data.put("stats24h", source.summary24h());
        return data;
    }

    /** 两台服务器的在线状态。判据写清楚：不写"我觉得在线"。 */
    private List<Map<String, Object>> nodes(boolean dataLinkUp) {
        List<Map<String, Object>> nodes = new ArrayList<>();

        Map<String, Object> srv1 = new LinkedHashMap<>();
        srv1.put("id", "srv1");
        srv1.put("label", "服务机 · SecAgent");
        srv1.put("online", true);
        srv1.put("probe", "本进程正在响应");
        srv1.put("detail", exposeBuildSha ? ("build " + buildSha) : "");
        nodes.add(srv1);

        Map<String, Object> srv2 = new LinkedHashMap<>();
        srv2.put("id", "srv2");
        srv2.put("label", "数据机 · Wazuh / Suricata / Cowrie");
        srv2.put("online", dataLinkUp);
        srv2.put("probe", "indexer(9200) 经 SSH 隧道可达");
        srv2.put("detail", dataLinkUp ? "数据链路正常" : "数据链路不可达，告警不展示");
        nodes.add(srv2);

        return nodes;
    }

    private Map<String, Object> dataSource(boolean real) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("wazuhMode", source.mode());
        m.put("degraded", !real);
        m.put("note", real
                ? "网络告警（Suricata）经 Wazuh agent 采集后随 indexer 一起返回，来源已按规则分组判定"
                : "告警数据源不可达，本页不展示任何告警（不以内置样本代替）");
        return m;
    }

    /**
     * 聚合告警 → 公网字段白名单。
     *
     * <p>被<b>刻意丢掉</b>的字段：{@code dstIp} / {@code dstAsset} / {@code assets}
     * （内网拓扑）、{@code memberIds}（内部 id 集合）、{@code rawLog} / 完整 payload。
     */
    private Map<String, Object> publicAggregate(Map<String, Object> src) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("aggId", src.get("aggId"));
        m.put("count", src.get("count"));
        m.put("startTime", src.get("startTime"));
        m.put("endTime", src.get("endTime"));
        m.put("title", src.get("title"));
        m.put("ruleName", src.get("ruleName"));
        m.put("srcIp", PublicIpMask.mask(asString(src.get("srcIp"))));
        m.put("srcGeo", src.get("srcGeo"));
        m.put("occurredAt", src.get("occurredAt"));
        m.put("status", src.get("status"));
        m.put("hitCount", src.get("hitCount"));
        putEnum(m, "severity", src.get("severity"));
        putEnum(m, "type", src.get("type"));
        putEnum(m, "source", src.get("source"));
        return m;
    }

    /** 原始告警 → 公网字段白名单（下钻明细用） */
    private Map<String, Object> publicAlert(SecurityAlert a) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", a.getId());
        m.put("title", a.getTitle());
        m.put("ruleName", a.getRuleName());
        m.put("srcIp", PublicIpMask.mask(a.getSrcIp()));
        m.put("srcGeo", a.getSrcGeo());
        m.put("occurredAt", a.getOccurredAt());
        m.put("status", a.getStatus());
        m.put("hitCount", a.getCount());
        putEnum(m, "severity", a.getSeverity());
        putEnum(m, "type", a.getType());
        putEnum(m, "source", a.getSource());
        return m;
    }

    /** 枚举字段统一输出 {枚举名, 中文标签}，前端不必自己维护映射表 */
    private void putEnum(Map<String, Object> target, String field, Object value) {
        if (value == null) {
            target.put(field, null);
            target.put(field + "Label", null);
            return;
        }
        if (value instanceof AlertSeverity s) {
            target.put(field, s.name());
            target.put(field + "Label", s.getLabel());
        } else if (value instanceof AlertSource s) {
            target.put(field, s.name());
            target.put(field + "Label", s.getLabel());
        } else if (value instanceof AlertType t) {
            target.put(field, t.name());
            target.put(field + "Label", t.getLabel());
        } else {
            target.put(field, String.valueOf(value));
            target.put(field + "Label", String.valueOf(value));
        }
    }

    // ==================== 统计 ====================

    private List<Map<String, Object>> severityStats(List<SecurityAlert> raw) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (AlertSeverity s : AlertSeverity.values()) {
            out.add(bucket(s.name(), s.getLabel(), countSeverity(raw, s)));
        }
        return out;
    }

    private List<Map<String, Object>> sourceStats(List<SecurityAlert> raw) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (AlertSource s : AlertSource.values()) {
            long c = raw.stream().filter(a -> a.getSource() == s).count();
            out.add(bucket(s.name(), s.getLabel(), c));
        }
        return out;
    }

    private List<Map<String, Object>> typeStats(List<SecurityAlert> raw) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (AlertType t : AlertType.values()) {
            long c = raw.stream().filter(a -> a.getType() == t).count();
            if (c > 0) {
                out.add(bucket(t.name(), t.getLabel(), c));
            }
        }
        return out;
    }

    private Map<String, Object> bucket(String key, String label, long count) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("key", key);
        m.put("label", label);
        m.put("count", count);
        return m;
    }

    /** 最近 24 小时按小时分桶 */
    private List<Map<String, Object>> trend(List<SecurityAlert> raw) {
        LocalDateTime now = LocalDateTime.now().withMinute(0).withSecond(0).withNano(0);
        Map<String, Long> buckets = new LinkedHashMap<>();
        for (int i = 23; i >= 0; i--) {
            buckets.put(now.minusHours(i).format(HOUR_FMT), 0L);
        }
        for (SecurityAlert a : raw) {
            LocalDateTime t = parseTime(a.getOccurredAt());
            if (t == null || t.isBefore(now.minusHours(24)) || t.isAfter(now.plusHours(1))) {
                continue;
            }
            buckets.merge(t.withMinute(0).format(HOUR_FMT), 1L, Long::sum);
        }
        List<Map<String, Object>> out = new ArrayList<>();
        buckets.forEach((k, v) -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("time", k);
            m.put("count", v);
            out.add(m);
        });
        return out;
    }

    private long countToday(List<SecurityAlert> raw) {
        String today = LocalDate.now().toString();
        return raw.stream()
                .filter(a -> a.getOccurredAt() != null && a.getOccurredAt().startsWith(today))
                .count();
    }

    private long countSeverity(List<SecurityAlert> raw, AlertSeverity s) {
        return raw.stream().filter(a -> a.getSeverity() == s).count();
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

    // ==================== 限流 / 缓存 / 响应 ====================

    /**
     * 取调用方 IP。
     *
     * <p>线上流量经 Cloudflare 隧道进来，{@code remoteAddr} 是隧道侧地址、
     * 所有访客会落进同一个桶 —— 所以优先取 {@code CF-Connecting-IP}。
     * 边界说明：这两个头在<b>直连</b>场景下可伪造，因此它只用于限流，
     * 不作为任何安全判定依据（真正的边界在隧道与拦截器上）。
     */
    private String clientIp(HttpServletRequest req) {
        String cf = req.getHeader("CF-Connecting-IP");
        if (cf != null && !cf.isBlank()) {
            return cf.trim();
        }
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            int comma = xff.indexOf(',');
            return (comma > 0 ? xff.substring(0, comma) : xff).trim();
        }
        return req.getRemoteAddr();
    }

    private ResponseEntity<Map<String, Object>> ok(Map<String, Object> data, HttpServletResponse res) {
        res.setHeader(HttpHeaders.CACHE_CONTROL, "public, max-age=" + Math.max(0, cacheSeconds));
        res.setHeader("X-Data-Source", source.available() ? "WAZUH_REAL" : "UNAVAILABLE");
        res.setHeader("X-RateLimit-Limit", String.valueOf(rateLimiter.limitPerMinute()));

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", 200);
        body.put("message", "success");
        body.put("data", data);
        return ResponseEntity.ok(body);
    }

    private ResponseEntity<Map<String, Object>> tooMany(HttpServletResponse res) {
        res.setHeader(HttpHeaders.RETRY_AFTER, "60");
        res.setHeader("X-RateLimit-Limit", String.valueOf(rateLimiter.limitPerMinute()));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", 429);
        body.put("message", "请求过于频繁，请稍后再试");
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(body);
    }

    /**
     * 429：带上"哪个限流器挡的、上限多少、还剩多少、多久能再试"。
     *
     * <p>为什么要多这几个字段：公开页面必须能显示人话（"请稍后再试"），
     * 而排障时最需要知道的恰恰是"被哪一条规则挡的" —— 只回一个裸 429，
     * 前端只能笼统提示，站主也只能靠猜。
     */
    private ResponseEntity<Map<String, Object>> tooMany(HttpServletResponse res,
                                                        PublicAskRateLimiter limiter,
                                                        String message) {
        res.setHeader(HttpHeaders.RETRY_AFTER, "60");
        res.setHeader("X-RateLimit-Limit", String.valueOf(limiter.limitPerMinute()));
        res.setHeader("X-RateLimit-Remaining", "0");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", 429);
        body.put("message", message);
        body.put("limitPerMinute", limiter.limitPerMinute());
        body.put("retryAfterSeconds", 60);
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(body);
    }

    @SuppressWarnings("unchecked")
    private static List<String> asStringList(Object v) {
        if (v instanceof List<?> l) {
            List<String> out = new ArrayList<>();
            for (Object o : l) {
                out.add(String.valueOf(o));
            }
            return out;
        }
        return Collections.emptyList();
    }

    private static String asString(Object v) {
        return v == null ? null : String.valueOf(v);
    }

    /**
     * 极简快照缓存：TTL 内直接返回上一次的结果。
     *
     * <p>为什么值得要：公网页面每次刷新都会触发一次"读 indexer + 聚合"，
     * 而数据本身只按分钟级变化。缓存把上游查询量与访客数解耦，
     * 同时让"数据同步时间"变成一个可以如实展示的值（generatedAt）。
     */
    private static final class Snapshot {

        private volatile Map<String, Object> value;
        private volatile long expiresAt;

        Map<String, Object> get(int ttlSeconds, Supplier<Map<String, Object>> loader) {
            Map<String, Object> cur = value;
            if (cur != null && System.currentTimeMillis() < expiresAt) {
                return cur;
            }
            synchronized (this) {
                if (value != null && System.currentTimeMillis() < expiresAt) {
                    return value;
                }
                try {
                    Map<String, Object> fresh = loader.get();
                    value = fresh;
                    expiresAt = System.currentTimeMillis() + Math.max(0, ttlSeconds) * 1000L;
                    return fresh;
                } catch (Exception e) {
                    // 刷新失败：有旧快照就继续用旧的（页面标注同步时间），
                    // 没有旧快照就抛出，让调用方看到错误而不是"空白但 200"
                    logger.warn("公网快照刷新失败：{}", e.getMessage());
                    if (value != null) {
                        expiresAt = System.currentTimeMillis() + 5000L;
                        return value;
                    }
                    throw new IllegalStateException("公网快照刷新失败且无可用旧快照", e);
                }
            }
        }
    }
}
