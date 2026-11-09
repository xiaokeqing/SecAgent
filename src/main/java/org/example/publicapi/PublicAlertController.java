package org.example.publicapi;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
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
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

/**
 * 告警、蜜罐、审计与"最新态势"域：/overview、/alerts、/alerts/{aggId}、/honeypot、/audit、/latest。
 *
 * <p>本类是原 {@code PublicApiController}（已删除的委托门面）拆分出的按域 controller 之一：只做搬移，路径、参数、
 * 响应字段、状态码、缓存头与限流口径与原 god controller 逐字一致。
 * 共享状态与通用工具（快照缓存、出关脱敏、信封/缓存头）在 {@link PublicApiSupport} 里，
 * 由构造器注入；历史门面 {@code PublicApiController} 已删除，测试改为直接装配这些 controller。
 */
@RestController
@RequestMapping("/api/public")
public class PublicAlertController {

    private static final Logger logger = LoggerFactory.getLogger(PublicAlertController.class);

    private final PublicApiSupport support;

    public PublicAlertController(PublicApiSupport support) {
        this.support = support;
    }

    // ==================== 端点 ====================

    /** 首页状态条用：两台服务器在线状态 + 告警概览。载荷刻意做小。 */
    @GetMapping({"/overview", "/overview.js"})
    public ResponseEntity<Map<String, Object>> overview(HttpServletRequest req, HttpServletResponse res) {
        if (!support.rateLimiter.allow(support.clientIp(req))) {
            return support.tooMany(res);
        }
        Map<String, Object> data = support.overviewCache.get(support.cacheSeconds, this::buildOverview);
        return support.ok(data, res);
    }

    /** 告警看板用：聚合后的实时告警流 + 分布 + 24 小时趋势，一次请求拿全。 */
    @GetMapping({"/alerts", "/alerts.js"})
    public ResponseEntity<Map<String, Object>> alerts(HttpServletRequest req, HttpServletResponse res) {
        if (!support.rateLimiter.allow(support.clientIp(req))) {
            return support.tooMany(res);
        }
        Map<String, Object> data = support.alertsCache.get(support.cacheSeconds, this::buildAlerts);
        return support.ok(data, res);
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
        if (!support.rateLimiter.allow(support.clientIp(req))) {
            return support.tooMany(res);
        }

        List<Map<String, Object>> aggs = support.source.aggregated();
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

        List<String> memberIds = PublicApiSupport.asStringList(hit.get("memberIds"));
        Map<String, SecurityAlert> byId = new LinkedHashMap<>();
        for (SecurityAlert a : support.source.readAlerts()) {
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
        data.put("generatedAt", LocalDateTime.now().format(PublicApiSupport.FMT));
        data.put("summary", publicAggregate(hit));
        data.put("members", members);
        data.put("memberCount", members.size());
        return support.ok(data, res);
    }

    /**
     * 蜜罐战报：连接/登录计数、账号口令 Top（<b>只给结构</b>）、来源分布、事件时间线。
     *
     * <p>来源 IP 按 {@code app.public.mask-ips} 口径显示（默认真实地址，内网/保留写「内网/未知」）；
     * 口令在任何口径下都只给长度/字符类/弱口令标记，永不给出原文。
     */
    @GetMapping({"/honeypot", "/honeypot.js"})
    public ResponseEntity<Map<String, Object>> honeypot(HttpServletRequest req, HttpServletResponse res) {
        if (!support.rateLimiter.allow(support.clientIp(req))) {
            return support.tooMany(res);
        }
        return support.ok(support.honeypotCache.get(support.cacheSeconds, this::buildHoneypot), res);
    }

    /** 处置审计（只读）：封禁记录 + 审计流水，IP 按开关口径显示，不含原始 detail。 */
    @GetMapping({"/audit", "/audit.js"})
    public ResponseEntity<Map<String, Object>> audit(HttpServletRequest req, HttpServletResponse res) {
        if (!support.rateLimiter.allow(support.clientIp(req))) {
            return support.tooMany(res);
        }
        return support.ok(support.auditCache.get(support.cacheSeconds, this::buildAudit), res);
    }

    /**
     * 最近一次同步 / 最近一条事件的聚合摘要。
     *
     * <h3>这个端点为什么存在（2026-10-13 收口）</h3>
     * 前端曾经调用 {@code /api/public/latest}，而它从未实现 —— 探测拿到 404 之后，
     * 页面上出现了一段技术免责文字（"latest 未就绪 HTTP 500 / 用 audit 替代"）。
     * 那段文字后来从前端移走了，但<b>端点本身仍然悬空</b>：谁都可以再调一次，
     * 然后再造一次同样的含糊提示。缺口只能二选一收口：实现它，或彻底删掉并写明"不得调用"。
     *
     * <p>这里选<b>实现</b>，理由：
     * <ol>
     *   <li>数据全部来自既有公开白名单口径（{@link PublicAlertSource#readAlerts()} 的
     *       掩码字段 + {@link PublicAuditReader} 的掩码记录），<b>没有新增任何数据面</b>：</li>
     *   <li>不放宽公开面 —— 它不返回标题、不返回内网目的地址、不返回聚合 id 与成员 id，
     *       只返回"窗口内多少条 / 什么等级分布 / 最近一次是什么时间、哪一类、来自哪个网段"；</li>
     *   <li>限流 / CORS / 掩码 / ETag 与其余公开端点走同一条通路（同一个 {@code Snapshot} 缓存、
     *       同一个 {@code ok(...)}，因此 ETag Filter 与 CORS 拦截器照样生效）。</li>
     * </ol>
     * 若将来需要"最近一条的标题"，那属于扩大公开面，必须在 RUNBOOK §10 里显式评审后再做 ——
     * 不要顺手加。
     *
     * <p>无数据时如实返回 {@code available=false} + 可读原因（machine-readable 的 {@code reason}
     * 与人读的 {@code note} 成对给出），绝不用 0 冒充"这段时间太平"。
     */
    @GetMapping({"/latest", "/latest.js"})
    public ResponseEntity<Map<String, Object>> latest(HttpServletRequest req, HttpServletResponse res) {
        if (!support.rateLimiter.allow(support.clientIp(req))) {
            return support.tooMany(res);
        }
        return support.ok(support.latestCache.get(support.cacheSeconds, this::buildLatest), res);
    }

    // ==================== 载荷组装 ====================

    Map<String, Object> buildHoneypot() {
        Map<String, Object> raw = support.source.honeypotSummary(800);
        boolean available = Boolean.TRUE.equals(raw.get("available"));

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", LocalDateTime.now().format(PublicApiSupport.FMT));
        data.put("cacheSeconds", support.cacheSeconds);
        data.put("available", available);
        data.put("commandsAvailable", Boolean.TRUE.equals(raw.get("commandsAvailable")));
        data.put("note", available
                ? (support.policy().masked()
                        ? "IP 已掩码到网段；命令时间线的数据源尚未接入（Wazuh 侧没有命令执行规则，不编造）"
                        : "IP 显示观测到的真实来源地址（内网/保留地址一律写作「内网/未知」）；"
                                + "口令只给结构，命令时间线的数据源尚未接入（Wazuh 侧没有命令执行规则，不编造）")
                : "蜜罐数据源不可达，本页不展示任何蜜罐数据");

        if (available) {
            data.put("total", raw.get("total"));
            data.put("connections", raw.get("connections"));
            data.put("logins", raw.get("logins"));
            data.put("loginFails", raw.get("loginFails"));
            data.put("sampled", raw.get("sampled"));
            // 【2026-10-14 修】账号口令 Top 不再原样透出。
            // 改造前的注释写着"那是攻击者试的弱口令，是战报的核心信息"——来源里确实是这么想的，
            // 但原样输出的是【完整口令】（键的形状是 "root / 123456"），而站主的硬约束是
            // 蜜罐抓到的完整口令/凭据永不上公网（与投诉无关，是硬伤害）。
            // 现在只出结构：用户名 + 长度 + 字符类 + 弱口令标记；key 仍是同一个键，
            // 值改成结构摘要（"root / 6 位·小写字母+数字·弱口令"），页面无需为"口令列"改结构。
            data.put("topCredentials", credentialShapes(raw.get("topCredentials")));
            data.put("topSources", topSourcesForPublic(raw.get("topSources"), support.policy()));
            data.put("topClients", raw.get("topClients"));
            data.put("timeline", timelineForPublic(raw.get("timeline"), support.policy()));
        }
        return data;
    }

    Map<String, Object> buildAudit() {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", LocalDateTime.now().format(PublicApiSupport.FMT));
        data.put("cacheSeconds", support.cacheSeconds);
        data.put("readOnly", true);
        data.put("summary", support.auditReader.summary());
        data.put("blocks", support.auditReader.blocks(20));
        data.put("actions", actionTextForPublic(support.auditReader.actions(30), support.policy()));
        return data;
    }

    /** {@code /latest} 的取数入口（控制器方法，便于测试时只换数据源） */
    Map<String, Object> buildLatest() {
        List<SecurityAlert> alerts = support.source.readAlerts();
        String mode = support.source.mode();
        boolean available = support.source.realData() && !alerts.isEmpty();

        List<Map<String, Object>> blocks = support.auditReader == null ? List.of() : support.auditReader.blocks(1);
        return buildLatest(alerts, available, mode, support.source.windowSize(), support.cacheSeconds, support.generatedAt(),
                blocks, support.policy());
    }

    /**
     * {@code /latest} 的载荷组装 —— <b>纯函数</b>（除入参外不读任何状态）。
     *
     * <p>抽成 static 是为了能被单测直接喂数据：这条端点的关键承诺是
     * "无数据时如实 available=false + reason"，而那个分支在真环境里很难复现
     * （要刚好把隧道掐在某一步）。给它一个纯函数入口，就能把每种失败形态都钉住。
     *
     * <h3>字段白名单（不加字段是纪律，不是偷懒）</h3>
     * 出参只有：生成时间、缓存秒数、可用性与原因、窗口大小与条数、等级分布、
     * 来源分布（已按口径处理）、最近一条事件的<b>时间/等级/类型/来源地址</b>、最近一次封禁的
     * <b>时间/地址/动作</b>，以及统一口径字段 {@code ipDisclosure}。
     * 刻意<b>不含</b>：标题、规则名、内网目的地址与资产名、聚合 id 与成员 id、原始日志、
     * reason 正文（可能含内网信息）。
     *
     * @param alerts       已经过 fail-closed 过滤的真实告警（内置样本已在数据源侧剔除）
     * @param available    数据源是否真的拿到了真实数据
     * @param mode         数据源模式（REAL / MOCK / OFF），如实回显
     * @param windowSize   取数窗口大小（口径说明用）
     * @param cacheSeconds 应用内快照 TTL，同时作为 Cache-Control 的 max-age
     * @param generatedAt  本次载荷生成时间
     * @param latestBlocks 最近一次封禁记录（已按口径处理；可为空）
     */
    static Map<String, Object> buildLatest(List<SecurityAlert> alerts, boolean available, String mode,
                                           int windowSize, int cacheSeconds, String generatedAt,
                                           List<Map<String, Object>> latestBlocks) {
        // 【保留这个 7 参重载】它等价于"掩码态"，也就是改造前的口径：
        // 既有的载荷口径测试（PublicApiLatestTest）用的就是它，因此它们
        // 一字不改仍然是"掩码回归"的证据。生产链路走下面带 policy 的重载。
        return buildLatest(alerts, available, mode, windowSize, cacheSeconds, generatedAt,
                latestBlocks, PublicIpPolicy.masking());
    }

    /**
     * {@link #buildLatest(List, boolean, String, int, int, String, List)} 的口径显式版本。
     *
     * @param policy IP 显示口径（唯一来源：{@code app.public.mask-ips}）
     */
    static Map<String, Object> buildLatest(List<SecurityAlert> alerts, boolean available, String mode,
                                           int windowSize, int cacheSeconds, String generatedAt,
                                           List<Map<String, Object>> latestBlocks, PublicIpPolicy policy) {
        PublicIpPolicy p = policy == null ? PublicIpPolicy.masking() : policy;
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", generatedAt);
        data.put("cacheSeconds", cacheSeconds);
        data.put("available", available);
        data.put("wazuhMode", mode);
        data.put("windowSize", windowSize);
        data.put("windowAlertCount", alerts == null ? 0 : alerts.size());

        if (!available) {
            // 如实说原因。两种"没有数据"必须区分开：数据源不可用 vs 确实这段时间没有告警 ——
            // 前者是故障，后者是常态，混在一起会让前端把"链路断了"渲染成"一切太平"。
            String reason = "REAL".equalsIgnoreCase(mode == null ? "" : mode.trim())
                    ? "NO_DATA_IN_WINDOW" : "DATA_SOURCE_UNAVAILABLE";
            data.put("reason", reason);
            data.put("note", "DATA_SOURCE_UNAVAILABLE".equals(reason)
                    ? "告警数据源不可达（或未拿到真实数据），本次不展示任何告警数字，也不以内置样本顶替"
                    : "数据源可用，但当前取数窗口内没有任何真实告警（不是故障）");
            data.put("latestEvent", null);
            data.put("latestBlock", latestBlocks == null || latestBlocks.isEmpty() ? null : latestBlocks.get(0));
            return data;
        }

        data.put("reason", "OK");
        data.put("note", p.masked()
                ? "字段全部来自公开白名单：来源 IP 已掩码到网段，不含标题/内网目的地址/聚合 id"
                : "字段全部来自公开白名单：来源 IP 显示观测到的真实地址（内网/保留地址写作「内网/未知」），"
                        + "不含标题/内网目的地址/聚合 id");

        data.put("severityCounts", severityCounts(alerts));
        data.put("sourceCounts", sourceCounts(alerts));

        SecurityAlert newest = newest(alerts);
        Map<String, Object> ev = new LinkedHashMap<>();
        ev.put("occurredAt", newest == null ? null : newest.getOccurredAt());
        putEnum(ev, "severity", newest == null ? null : newest.getSeverity());
        putEnum(ev, "type", newest == null ? null : newest.getType());
        putEnum(ev, "source", newest == null ? null : newest.getSource());
        ev.put("srcIp", p.display(newest == null ? null : newest.getSrcIp()));
        data.put("latestEvent", ev);
        data.put("latestBlock", latestBlocks == null || latestBlocks.isEmpty() ? null : latestBlocks.get(0));
        return data;
    }

    /** 等级分布（固定枚举顺序，前端不必自己兜底缺失档位） */
    static List<Map<String, Object>> severityCounts(List<SecurityAlert> alerts) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (AlertSeverity s : AlertSeverity.values()) {
            out.add(bucketOf(s.name(), s.getLabel(),
                    alerts.stream().filter(a -> a.getSeverity() == s).count()));
        }
        return out;
    }

    /** 来源分布（固定枚举顺序） */
    static List<Map<String, Object>> sourceCounts(List<SecurityAlert> alerts) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (AlertSource s : AlertSource.values()) {
            out.add(bucketOf(s.name(), s.getLabel(),
                    alerts.stream().filter(a -> a.getSource() == s).count()));
        }
        return out;
    }

    /** 窗口内最近一条（按 occurredAt 倒序；时间解析不了的一律排到最后，不拿它冒充"最近"） */
    static SecurityAlert newest(List<SecurityAlert> alerts) {
        SecurityAlert best = null;
        LocalDateTime bestTime = null;
        for (SecurityAlert a : alerts) {
            LocalDateTime t = parseTime(a == null ? null : a.getOccurredAt());
            if (t == null) {
                continue;
            }
            if (bestTime == null || t.isAfter(bestTime)) {
                bestTime = t;
                best = a;
            }
        }
        return best;
    }

    /** {@link #bucket} 的 static 版本（{@link #buildLatest} 是静态方法，不能调实例方法） */
    static Map<String, Object> bucketOf(String key, String label, long count) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("key", key);
        m.put("label", label);
        m.put("count", count);
        return m;
    }

    /** 审计流水的文本字段（reason）也过一遍 IP 口径与口令隐藏 —— 文本里可能内嵌 IP / 口令 */
    static List<Map<String, Object>> actionTextForPublic(List<Map<String, Object>> in,
                                                                 PublicIpPolicy policy) {
        for (Map<String, Object> m : in) {
            Object reason = m.get("reason");
            if (reason != null) {
                // 先隐口令（与 IP 口径无关的硬约束），再按开关处理 IP
                m.put("reason", policy.displayText(CredentialStructure.hidePasswords(String.valueOf(reason))));
            }
        }
        return in;
    }

    /**
     * 账号口令 Top → <b>只给结构</b>（"永不公开完整口令"的执行点）。
     *
     * <p>输入形状：{@code [{key:"root / 123456", count:3113}]}（{@code key} 里含完整口令）。
     * 输出形状：{@code [{key:"root / 6 位·小写字母+数字·弱口令", count:3113,
     * username:"root", passwordLength:6, passwordCharClasses:"小写字母+数字", weakPassword:true}]}。
     * {@code key} / {@code count} 两个既有字段都保留（契约"只许新增字段"），
     * 新增的四个字段让页面能自己组装结构说明。口令原文字符<b>一个都不出现</b>。
     */
    static List<Map<String, Object>> credentialShapes(Object v) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (v instanceof List<?> l) {
            for (Object o : l) {
                if (o instanceof Map<?, ?> m) {
                    Map<String, Object> x = CredentialStructure.describe(
                            m.get("key") == null ? null : String.valueOf(m.get("key")));
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("key", x.get("key"));
                    entry.put("count", m.get("count"));
                    entry.put("username", x.get("username"));
                    entry.put("passwordLength", x.get("passwordLength"));
                    entry.put("passwordCharClasses", x.get("passwordCharClasses"));
                    entry.put("weakPassword", x.get("weakPassword"));
                    out.add(entry);
                }
            }
        }
        return out;
    }

    /** 把 [{key,count}] 里的 key 当来源 IP 处理（口径由 {@link PublicIpPolicy} 决定） */
    static List<Map<String, Object>> topSourcesForPublic(Object v, PublicIpPolicy policy) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (v instanceof List<?> l) {
            for (Object o : l) {
                if (o instanceof Map<?, ?> m) {
                    Map<String, Object> x = new LinkedHashMap<>();
                    x.put("key", policy.display(m.get("key") == null ? null : String.valueOf(m.get("key"))));
                    x.put("count", m.get("count"));
                    out.add(x);
                }
            }
        }
        return out;
    }

    /**
     * 时间线 → 来源 IP + detail 文本（口径由 {@link PublicIpPolicy} 决定）。
     *
     * <p><b>2026-10-14 修</b>：{@code detail} 是蜜罐规则的<b>描述原文</b>，形状是
     * {@code 蜜罐: 攻击者"登录成功" 用户=root 口令=123456 来源=106.37.205.248}。
     * 改造前这里只对 IP 做掩码，<b>完整口令就这样随 timeline 出过公网</b>。
     * 现在先整段隐口令（与开关无关），再按口径处理 IP。
     */
    static List<Map<String, Object>> timelineForPublic(Object v, PublicIpPolicy policy) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (v instanceof List<?> l) {
            for (Object o : l) {
                if (o instanceof Map<?, ?> m) {
                    Map<String, Object> x = new LinkedHashMap<>();
                    x.put("time", m.get("time"));
                    x.put("kind", m.get("kind"));
                    x.put("srcIp", policy.display(m.get("srcIp") == null ? null : String.valueOf(m.get("srcIp"))));
                    // detail 是规则描述原文，里面内嵌了完整 IP 与完整口令 —— 两者都必须处理，
                    // 否则前面结构化字段处理得再干净，这里照样漏（实测漏过一次）
                    x.put("detail", policy.displayText(CredentialStructure.hidePasswords(
                            m.get("detail") == null ? null : String.valueOf(m.get("detail")))));
                    out.add(x);
                }
            }
        }
        return out;
    }

    Map<String, Object> buildOverview() {
        // 先取数、再判定可用性：若上游"连得上但查询失败"退回内置样本，
        // readAlerts() 会把样本剔除并把 mockFallback 置位，realData() 随后如实返回 false，
        // 于是响应里的 degraded=true（而不是拿样本当真实告警、还写 degraded=false）。
        List<SecurityAlert> raw = support.source.readAlerts();
        boolean real = support.source.realData();

        Map<String, Object> alerts = new LinkedHashMap<>();
        alerts.put("windowSize", support.source.windowSize());
        alerts.put("windowCount", raw.size());
        alerts.put("windowFull", raw.size() >= support.source.windowSize());
        alerts.put("windowDescription", "最近 " + support.source.windowSize() + " 条告警窗口"
                + (raw.size() >= support.source.windowSize() ? "（已取满，实际数量更多）" : ""));
        alerts.put("todayInWindow", countToday(raw));
        alerts.put("critical", countSeverity(raw, AlertSeverity.CRITICAL));
        alerts.put("high", countSeverity(raw, AlertSeverity.HIGH));
        alerts.put("bySeverity", severityStats(raw));
        alerts.put("bySource", sourceStats(raw));

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", LocalDateTime.now().format(PublicApiSupport.FMT));
        data.put("cacheSeconds", support.cacheSeconds);
        data.put("nodes", nodes(real));
        data.put("alerts", alerts);
        data.put("dataSource", dataSource(real));
        return data;
    }

    Map<String, Object> buildAlerts() {
        // 先取数、再判定可用性：若上游"连得上但查询失败"退回内置样本，
        // readAlerts() 会把样本剔除并把 mockFallback 置位，realData() 随后如实返回 false，
        // 于是响应里的 degraded=true（而不是拿样本当真实告警、还写 degraded=false）。
        List<SecurityAlert> raw = support.source.readAlerts();
        boolean real = support.source.realData();
        List<Map<String, Object>> aggs = support.source.aggregated();
        List<Map<String, Object>> publicList = new ArrayList<>();
        for (Map<String, Object> g : aggs) {
            publicList.add(publicAggregate(g));
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", LocalDateTime.now().format(PublicApiSupport.FMT));
        data.put("cacheSeconds", support.cacheSeconds);
        data.put("dataSource", dataSource(real));
        data.put("windowSize", support.source.windowSize());
        data.put("rawTotal", raw.size());
        data.put("total", publicList.size());
        data.put("aggregated", support.source.aggregationEnabled());
        data.put("windowMinutes", support.source.aggregationWindowMinutes());
        data.put("list", publicList);
        data.put("stats", Map.of(
                "bySeverity", severityStats(raw),
                "bySource", sourceStats(raw),
                "byType", typeStats(raw),
                "trend", trend(raw)
        ));
        // 近 24 小时口径：KPI 的"严重/高危"与趋势图都取这一份 ——
        // 取数窗口会被低危网络告警刷屏，按时间范围聚合才是"这段时间到底怎么样"
        Map<String, Object> stats24h = support.source.summary24h();
        data.put("stats24h", stats24h);
        // 把 24h 聚合的机读状态也放进 dataSource：前端 Hero 的第一个数字取的是 stats24h，
        // 而"链路没起来(warming)"与"后端真的坏了(degraded)"要显示成不同的话。
        // 这里是【新增字段】，既有 available/degraded 口径不变。
        if (stats24h.get("state") != null) {
            data.put("stats24hState", stats24h.get("state"));
            data.put("stats24hReason", stats24h.get("reason"));
        }
        return data;
    }

    /** 两台服务器的在线状态。判据写清楚：不写"我觉得在线"。 */
    List<Map<String, Object>> nodes(boolean dataLinkUp) {
        List<Map<String, Object>> nodes = new ArrayList<>();

        Map<String, Object> srv1 = new LinkedHashMap<>();
        srv1.put("id", "srv1");
        srv1.put("label", "服务机 · SecAgent");
        srv1.put("online", true);
        srv1.put("probe", "本进程正在响应");
        srv1.put("detail", support.exposeBuildSha ? ("build " + support.buildSha) : "");
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

    Map<String, Object> dataSource(boolean real) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("wazuhMode", support.source.mode());
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
    Map<String, Object> publicAggregate(Map<String, Object> src) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("aggId", src.get("aggId"));
        m.put("count", src.get("count"));
        m.put("startTime", src.get("startTime"));
        m.put("endTime", src.get("endTime"));
        m.put("title", src.get("title"));
        m.put("ruleName", src.get("ruleName"));
        // ATT&CK 技术编号（只新增字段，既有键一个不动）：由规则名查 AttackTechniqueMapper 的
        // 有序映射表。映射不到时明确给 null —— 前端据此显示"未归类"，而不是拿 type/source
        // 再猜一次（AlertType 本身就是关键词粗分类，二次猜测只会把没把握包装成有把握）。
        m.put("attck", AttackTechniqueMapper.toMap(PublicApiSupport.asString(src.get("ruleName"))));
        m.put("srcIp", support.policy().display(PublicApiSupport.asString(src.get("srcIp"))));
        // 公开面【刻意】恒为 null：srcGeo 的内部形状是「国家|省|城市|ASN|机构」（GeoIpInfo.describe()），
        // 逐条输出它等于把"某个攻击者属于哪个机构"搬上公网页面；公开面的地理口径只有聚合
        // （GET /api/public/geo，见 docs/design-geo-endpoint.md）。
        // 键名保留、值保持空 —— 这正是本轮改造前它对真实告警的取值（内置样本不进公开面），
        // 所以不是语义变更，而是"不让新富化的数据从这条缝里漏出去"。测试：PublicApiGeoLeakTest。
        m.put("srcGeo", null);
        // 来源国家二字码（新增字段，既有键一个不动）：只给 ISO-3166-1 alpha-2 大写二字码，
        // 取不到就 null（前端据此不在地图上打点），绝不写 ""/"XX"/"未知"。
        // 与 SSE 的 alert 帧共用 PublicAlertSource#countryCode —— 同一个聚合项两处取值必然一致。
        m.put("cc", support.source == null ? null : support.source.countryCode(src));
        m.put("occurredAt", src.get("occurredAt"));
        m.put("status", src.get("status"));
        m.put("hitCount", src.get("hitCount"));
        putEnum(m, "severity", src.get("severity"));
        putEnum(m, "type", src.get("type"));
        putEnum(m, "source", src.get("source"));
        return m;
    }

    /** 原始告警 → 公网字段白名单（下钻明细用） */
    Map<String, Object> publicAlert(SecurityAlert a) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", a.getId());
        m.put("title", a.getTitle());
        m.put("ruleName", a.getRuleName());
        m.put("srcIp", support.policy().display(a.getSrcIp()));
        // 同 publicAggregate：srcGeo 只在内网面可见，公开面恒为 null（口径见上）
        m.put("srcGeo", null);
        m.put("occurredAt", a.getOccurredAt());
        m.put("status", a.getStatus());
        m.put("hitCount", a.getCount());
        putEnum(m, "severity", a.getSeverity());
        putEnum(m, "type", a.getType());
        putEnum(m, "source", a.getSource());
        return m;
    }

    /** 枚举字段统一输出 {枚举名, 中文标签}，前端不必自己维护映射表 */
    static void putEnum(Map<String, Object> target, String field, Object value) {
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

    List<Map<String, Object>> severityStats(List<SecurityAlert> raw) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (AlertSeverity s : AlertSeverity.values()) {
            out.add(bucket(s.name(), s.getLabel(), countSeverity(raw, s)));
        }
        return out;
    }

    List<Map<String, Object>> sourceStats(List<SecurityAlert> raw) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (AlertSource s : AlertSource.values()) {
            long c = raw.stream().filter(a -> a.getSource() == s).count();
            out.add(bucket(s.name(), s.getLabel(), c));
        }
        return out;
    }

    List<Map<String, Object>> typeStats(List<SecurityAlert> raw) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (AlertType t : AlertType.values()) {
            long c = raw.stream().filter(a -> a.getType() == t).count();
            if (c > 0) {
                out.add(bucket(t.name(), t.getLabel(), c));
            }
        }
        return out;
    }

    Map<String, Object> bucket(String key, String label, long count) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("key", key);
        m.put("label", label);
        m.put("count", count);
        return m;
    }

    /** 最近 24 小时按小时分桶 */
    List<Map<String, Object>> trend(List<SecurityAlert> raw) {
        LocalDateTime now = LocalDateTime.now().withMinute(0).withSecond(0).withNano(0);
        Map<String, Long> buckets = new LinkedHashMap<>();
        for (int i = 23; i >= 0; i--) {
            buckets.put(now.minusHours(i).format(PublicApiSupport.HOUR_FMT), 0L);
        }
        for (SecurityAlert a : raw) {
            LocalDateTime t = parseTime(a.getOccurredAt());
            if (t == null || t.isBefore(now.minusHours(24)) || t.isAfter(now.plusHours(1))) {
                continue;
            }
            buckets.merge(t.withMinute(0).format(PublicApiSupport.HOUR_FMT), 1L, Long::sum);
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

    long countToday(List<SecurityAlert> raw) {
        String today = LocalDate.now().toString();
        return raw.stream()
                .filter(a -> a.getOccurredAt() != null && a.getOccurredAt().startsWith(today))
                .count();
    }

    long countSeverity(List<SecurityAlert> raw, AlertSeverity s) {
        return raw.stream().filter(a -> a.getSeverity() == s).count();
    }

    static LocalDateTime parseTime(String s) {
        if (s == null || s.isBlank()) {
            return null;
        }
        try {
            return LocalDateTime.parse(s.trim(), PublicApiSupport.FMT);
        } catch (Exception e) {
            return null;
        }
    }
}
