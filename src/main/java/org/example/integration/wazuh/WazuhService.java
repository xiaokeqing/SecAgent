package org.example.integration.wazuh;

import com.fasterxml.jackson.databind.JsonNode;
import org.example.core.model.ActiveResponseResult;
import org.example.core.model.AlertSeverity;
import org.example.core.model.AlertSource;
import org.example.core.model.AlertType;
import org.example.core.model.RawLogLine;
import org.example.core.model.SecurityAlert;
import org.example.integration.WazuhGateway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Wazuh 对接服务（网关实现）。
 *
 * <p>启动时按 integration.wazuh.enabled 尝试连真实 Wazuh：
 * <ul>
 *   <li>连上 → mode=REAL，告警/日志走 Wazuh API，active-response 可真实下发；</li>
 *   <li>连不上或未启用 → mode=MOCK，返回内置可演示样本（SSH 爆破、SQL 注入、Webshell、目录扫描），
 *       保证无真实环境时大屏照样完整演示。</li>
 * </ul>
 */
@Service
public class WazuhService implements WazuhGateway {

    private static final Logger logger = LoggerFactory.getLogger(WazuhService.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /** 故事线查询体用 Jackson 构造（不拼字符串：字段名/取值里一个引号就能把查询变成语法错误） */
    private static final com.fasterxml.jackson.databind.ObjectMapper MAPPER =
            new com.fasterxml.jackson.databind.ObjectMapper();

    @Value("${integration.wazuh.enabled:true}")
    private boolean enabled;
    @Value("${integration.wazuh.base-url:https://localhost:55000}")
    private String baseUrl;
    @Value("${integration.wazuh.username:wazuh}")
    private String username;
    @Value("${integration.wazuh.password:wazuh}")
    private String password;
    @Value("${integration.wazuh.verify-ssl:false}")
    private boolean verifySsl;
    /**
     * 统一出站超时（connect 3s / read 12s / call 15s）。
     *
     * <p>原来这里有一个 {@code integration.wazuh.timeout:10}，管理 API 与 indexer 共用，
     * 与 LLM 通道的 15s/8s 各说各话 —— 外部依赖挂起时无法解释"到底会等多久"。
     * 现在三类出站链路统一走 {@code app.outbound.*}，并由启动自检把生效值打进日志。
     */
    @org.springframework.beans.factory.annotation.Autowired
    private org.example.config.OutboundTimeouts outboundTimeouts;

    /**
     * 出站守卫：有界等待 + 每依赖 60s 冷却 + 半开。
     *
     * <p>与 embedding 通道复用同一个 Bean（不是另造一套）：一次超时后该依赖进入冷却，
     * 期间立即失败，避免"一次请求里每个调用点各等一遍超时"的叠加。
     */
    @org.springframework.beans.factory.annotation.Autowired
    private org.example.llm.OutboundGuard outboundGuard;
    /**
     * Wazuh indexer（OpenSearch）地址 —— 告警真正存放的地方。
     *
     * 为什么单独一个配置项而不是复用 base-url：
     *   管理 API（55000）和 indexer（9200）是两个不同的服务、端口、凭据。
     *   而【管理 API 里根本没有查询告警的端点】，只配 base-url 拿不到真实告警
     *   —— 这正是那个"界面上永远是内置样本"的 bug 的根因。
     */
    @Value("${integration.wazuh.indexer-url:}")
    private String indexerUrl;
    @Value("${integration.wazuh.indexer-username:admin}")
    private String indexerUsername;
    @Value("${integration.wazuh.indexer-password:}")
    private String indexerPassword;
    @Value("${integration.wazuh.active-response-enabled:true}")
    private boolean activeResponseEnabled;

    /** SSH 直连封禁执行器（处置的首选路径，已端到端验证）。 */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private SshBlockExecutor sshExecutor;

    /**
     * 通知门面（③ 系统降级事件）。
     *
     * <p>可空注入：{@code OutboundSelfCheckTest} 之类的单测直接 new 本类，
     * 不该被迫连通知一起造。缺失时本类行为与改造前完全一致。
     */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private org.example.notify.SecurityEventNotifier securityEventNotifier;

    private WazuhClient client;
    private volatile boolean available;

    @PostConstruct
    public void init() {
        if (!enabled) {
            logger.info("Wazuh 对接未启用（integration.wazuh.enabled=false），直接使用内置样本");
            return;
        }
        try {
            this.client = new WazuhClient(baseUrl, username, password, verifySsl,
                    outboundTimeouts, outboundGuard,
                    indexerUrl, indexerUsername, indexerPassword);
            logger.info("Wazuh 出站超时生效值（manager/indexer 共用）：{}（守卫={}）",
                    outboundTimeouts.describe(), outboundGuard != null);
            this.available = probe();
            if (available) {
                logger.info("Wazuh 已连接（REAL 模式）：manager={}  indexer={}", baseUrl, indexerUrl);
            } else {
                logger.warn("Wazuh 数据链路不可用（manager={} indexer={}），本次降级为内置样本（MOCK）；"
                        + "后台会周期性重探，恢复后自动切回 REAL", baseUrl, indexerUrl);
            }
            observeModeForNotify();
        } catch (Exception e) {
            this.available = false;
            logger.warn("Wazuh 初始化异常，降级为内置样本（MOCK）：{}", e.getMessage());
            observeModeForNotify();
        }
    }

    /**
     * ③ 系统降级通知的触发点。
     *
     * <p>只在"模式真的变了"时通知（由 {@code SecurityEventNotifier.observeMode} 判定），
     * 首次调用只记录不通知 —— 否则每次启动都会推一条"系统降级"，
     * 而它可能只是隧道还没起来的时序问题（实测 30 秒后就会自己恢复）。
     */
    private void observeModeForNotify() {
        if (securityEventNotifier == null) {
            return;
        }
        try {
            securityEventNotifier.observeMode(mode());
        } catch (Exception e) {
            logger.warn("系统降级通知失败（已吞掉，不影响探测）：{}", e.getMessage());
        }
    }

    /**
     * 探测「能不能取到真实告警」。
     *
     * <p>两个条件都要满足，缺一不算 REAL：
     * <ol>
     *   <li>管理 API 能登录 —— 取证日志走这条路；</li>
     *   <li><b>indexer 可达且鉴权通过</b> —— 告警真正存放的地方。</li>
     * </ol>
     * 只测第 1 条会给出一个安慰性的绿灯：管理 API 通、取告警的链路断了，
     * 页面就变成「有模式、没数据」，而且看不出是哪一端的问题。
     */
    private boolean probe() {
        if (client == null) {
            return false;
        }
        boolean manager = client.testConnection();
        boolean indexer = client.indexerReachable();
        if (!manager) {
            logger.warn("Wazuh 管理 API 不可达：{}", baseUrl);
        }
        if (!indexer) {
            logger.warn("Wazuh indexer 不可达：{}（取不到真实告警，不能报 REAL）", indexerUrl);
        }
        return manager && indexer;
    }

    /**
     * 周期性重新探测数据链路 —— <b>让「不可达」能自愈</b>。
     *
     * <h3>为什么必须有它（一次真实事故）</h3>
     * 原来只在启动时探测一次，失败就把 {@code available=false} 一直缓存着。
     * 而线上部署时 {@code docker compose up -d} 会<b>同时</b>重启隧道和应用：
     * 隧道要 30 多秒才连上，应用那次探测必然失败 ——
     * 实测日志：应用 13:55:16 启动、隧道 13:55:50 才起来，应用 13:55:23 探测失败，
     * 于是「数据源 MOCK」一直挂到下一次重启，从外部完全看不出来。
     * <p>
     * 启动时序靠运气的问题不该靠「记得先起隧道」解决，系统应该自己恢复。
     * 这里每 60 秒重探一次，REAL/MOCK 的每次切换都留日志。
     */
    @Scheduled(initialDelayString = "${integration.wazuh.reprobe-initial-delay-ms:20000}",
               fixedDelayString = "${integration.wazuh.reprobe-interval-ms:60000}")
    public void reprobe() {
        if (!enabled || client == null) {
            return;
        }
        boolean was = available;
        try {
            available = probe();
        } catch (Exception e) {
            available = false;
            logger.warn("Wazuh 重新探测异常：{}", e.getMessage());
        }
        if (available && !was) {
            logger.info("Wazuh 数据链路已恢复：模式 MOCK -> REAL（manager={} indexer={}）", baseUrl, indexerUrl);
        } else if (!available && was) {
            logger.warn("Wazuh 数据链路断开：模式 REAL -> MOCK。"
                    + "对外页面会如实显示「数据源不可用」，不会拿内置样本填充", baseUrl);
        }
        if (available != was) {
            // 每次真实的状态切换都推一次（降级与恢复都推）：只报坏消息的通道会被当成噪声
            observeModeForNotify();
        }
    }

    /**
     * 近 24 小时告警概览 —— 用<b>时间范围聚合</b>回答"这段时间有多少、其中多少严重的"。
     *
     * <h3>为什么不能靠告警列表凑</h3>
     * 告警流取的是"最新 N 条"。网络侧低危告警一刷屏，高危就被挤出窗口，
     * 面板上于是显示「严重 0 / 高危 0」——让人以为没出事，其实只是被噪声挤掉了。
     * 口径问题只能靠口径解决。
     *
     * <h3>2026-10-13 修复：冷启动首个请求为什么判 false（"查询失败"与"确实无数据"必须分开）</h3>
     * <b>现象</b>：同一 URL 连续请求，{@code stats24h.available} 在 true/false 之间交替，
     * 博客 Hero 的第一个数字因此会抖。
     *
     * <p><b>根因（两个独立缺陷叠在一起）</b>：
     * <ol>
     *   <li><b>可用性判据是异步缓存的，查询却拿它当"现在能不能查"</b>：
     *       {@code available} 由 {@link #reprobe()} 每 60 秒刷新一次，启动时也探测一次。
     *       而 {@code docker compose up -d} 会同时重启隧道与应用，隧道要 30 多秒才连上 ——
     *       启动那次探测必然失败。于是<b>从进程起来到下一次重探（最多 60 秒）之间</b>，
     *       每个缓存过期的请求都会在 {@code if (!available)} 处直接返回
     *       {@code available=false}，<b>根本没有去查一次</b>。
     *       indexer 明明已经就绪，页面却在说"数据源不可用"。</li>
     *   <li><b>失败形态被吞成同一个值</b>：原来 catch 分支只 {@code put("available", false)}
     *       就返回，与"查询成功但 24 小时内 0 条告警"这个<b>完全不同的含义</b>
     *       在响应里长得一模一样。前端无法区分"我们坏了"与"这段时间太平"，
     *       而这两件事对看板主人的含义正好相反。</li>
     * </ol>
     *
     * <p><b>修法</b>：
     * <ol>
     *   <li>本方法<b>不再把缓存的 {@code available} 当查询前提</b>，而是直接查；
     *       indexer 真的可达时会正常返回 —— 冷启动后的首个请求因此就能拿到真值；</li>
     *   <li>查询失败时<b>现场探一次</b>（{@link #probe()}，有界）来区分两种失败：
     *       探测通过 = 对端在、只是这次查询失败 → {@code state=degraded}；
     *       探测不过 = 链路还没起来 → {@code state=warming}（这是"正在预热"，
     *       不是"后端故障"，前端应当重试而不是显示故障）；</li>
     *   <li>新增机读字段 {@code state}（{@code ok} / {@code no_data} / {@code warming} / {@code degraded}）
     *       与 {@code reason}（人读原因）。{@code available} 的口径保持不变
     *       （只有"真拿到了 24h 聚合"才为 true）—— 公开 API 契约只增不改，
     *       已有前端按 {@code available} 降级的逻辑不受影响。</li>
     * </ol>
     *
     * <p>为什么不做"重试一次"：初次失败最常见的两种原因（隧道未就绪、熔断冷却）
     * 都不会因为立刻重试而消失 —— 重试只会让首个请求多等一次超时（实测最坏 15s+15s）。
     * 真正有效的动作是<b>尝试一次查询</b>（本来就这么做了）＋<b>如实标注状态</b>。
     */
    @Override
    public Map<String, Object> summary24h() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("available", false);

        if (client == null) {
            return degraded(out, "CLIENT_NOT_READY",
                    "Wazuh 客户端未初始化（未启用或初始化失败），无法查询 24h 概览");
        }
        try {
            JsonNode root = client.fetchSummary24h();
            long total = root.path("hits").path("total").path("value").asLong(0);

            Map<String, Long> bySeverity = new LinkedHashMap<>();
            for (AlertSeverity s : AlertSeverity.values()) {
                bySeverity.put(s.name(), 0L);
            }
            for (JsonNode bucket : root.path("aggregations").path("by_level").path("buckets")) {
                // rule.level 是 Wazuh 的 0–15 档，必须按 Wazuh 口径换算（不能用 parse()）
                AlertSeverity sev = AlertSeverity.fromWazuhLevel(bucket.path("key").asText(""));
                bySeverity.merge(sev.name(), bucket.path("doc_count").asLong(0), Long::sum);
            }

            List<Map<String, Object>> trend = new ArrayList<>();
            for (JsonNode bucket : root.path("aggregations").path("by_hour").path("buckets")) {
                String local = WazuhTime.toLocal(bucket.path("key_as_string").asText(""));
                Map<String, Object> point = new LinkedHashMap<>();
                point.put("time", local.length() >= 16 ? local.substring(11, 16) : local);
                point.put("count", bucket.path("doc_count").asLong(0));
                trend.add(point);
            }

            out.put("available", true);
            out.put("total", total);
            out.put("bySeverity", bySeverity);
            out.put("trend", trend);
            out.put("windowHours", 24);
            out.put("state", total > 0 ? "ok" : "no_data");
            out.put("reason", total > 0 ? "OK" : "NO_ALERTS_IN_24H");
            out.put("note", total > 0
                    ? "24 小时聚合已取到（按 @timestamp 时间范围聚合，不受取数窗口影响）"
                    : "查询成功：最近 24 小时确实没有任何告警（这是真实结果，不是数据源故障）");
            // 查询成功说明链路是通的：顺手把可用性标记扶正，省掉"最多 60 秒"的空窗
            if (!available) {
                available = true;
                logger.info("24h 聚合查询成功 —— 可用性标记由 false 扶正为 true（无需等下一次重探）");
            }
            return out;
        } catch (Exception e) {
            // 区分"查询失败"与"确实无数据"：现场探一次，探测结果为真说明对端在、只是这一查失败。
            boolean reachable = false;
            try {
                reachable = probe();
            } catch (Exception probeErr) {
                logger.debug("查询失败后的现场探测也失败：{}", probeErr.getMessage());
            }
            if (reachable) {
                available = true;       // 链路通：把可用性标记扶正，避免后续请求继续按"不可用"短路
                logger.warn("24h 聚合查询失败，但现场探测通过（对端可达）—— 按 degraded 上报，不是无数据：{}",
                        e.getMessage());
                return degraded(out, "QUERY_FAILED",
                        "数据源可达，但这次 24h 聚合查询失败（" + e.getMessage() + "）；"
                                + "这不是'这段时间没有告警'，前端应显示为降级并重试");
            }
            logger.warn("24h 聚合查询失败且现场探测不通过 —— 按 warming 上报（链路尚未就绪/正在自愈）：{}",
                    e.getMessage());
            out.put("state", "warming");
            out.put("reason", "DATA_SOURCE_WARMING");
            out.put("note", "数据链路尚未就绪（隧道/鉴权正在建立或处于熔断冷却），本次没有拿到 24h 聚合；"
                    + "这是预热状态，不是'没有告警'，也不是后端故障判定 —— 稍后重试即可");
            return out;
        }
    }

    /** 统一的降级载荷：{@code state=degraded} 表示"能连上但这次没查成"，与 {@code no_data} 明确区分 */
    private static Map<String, Object> degraded(Map<String, Object> out, String reason, String note) {
        out.put("state", "degraded");
        out.put("reason", reason);
        out.put("note", note);
        return out;
    }

    /** 蜜罐规则描述里的取值（实测形状见下）；用全限定名避免再加 import */
    private static final java.util.regex.Pattern RE_CRED =
            java.util.regex.Pattern.compile("用户=(\\S+)\\s+口令=(\\S+)");
    private static final java.util.regex.Pattern RE_SRC =
            java.util.regex.Pattern.compile("来源=([0-9a-fA-F:.]+)");
    private static final java.util.regex.Pattern RE_CLIENT =
            java.util.regex.Pattern.compile("SSH 客户端版本 (\\S+)");

    /**
     * 蜜罐战报：从 indexer 取 Cowrie 告警后聚合（<b>返回未脱敏值</b>，掩码在公网边界做）。
     *
     * <p>实测规则形状（2026-10-12，共 9352 条）：
     * <pre>
     *   100100 蜜罐: 新的 SSH 连接来自 &lt;ip&gt;                          3127
     *   100104 蜜罐: SSH 客户端版本 &lt;ver&gt; 来源=&lt;ip&gt;                  3122
     *   100102 蜜罐: 攻击者"登录成功" 用户=&lt;u&gt; 口令=&lt;p&gt; 来源=&lt;ip&gt;  3113
     *   100101 登录失败                                                    5
     * </pre>
     * 值直接写在 {@code rule.description} 里，所以在 Java 侧用正则抽取再聚合 ——
     * 这些字段在 OpenSearch 里没法直接做 terms 聚合。
     *
     * <p><b>命令时间线没有数据源</b>：蜜罐规则里没有"命令执行"这一条，
     * 因此 {@code commandsAvailable=false}。页面必须如实写"数据源未接"，
     * 不能用别的字段拼一条看起来像命令时间线的东西。
     */
    @Override
    public Map<String, Object> honeypotSummary(int size) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("available", false);
        out.put("commandsAvailable", false);

        if (!available || client == null) {
            return out;
        }
        try {
            int want = Math.min(Math.max(size, 1), 2000);
            String body = "{\"size\":" + want + ",\"sort\":[{\"@timestamp\":\"desc\"}],"
                    + "\"query\":{\"term\":{\"rule.groups\":\"cowrie\"}}}";
            JsonNode root = client.search("wazuh-alerts-*", body);

            long connections = 0;
            long logins = 0;
            long loginFails = 0;
            Map<String, Long> creds = new LinkedHashMap<>();
            Map<String, Long> sources = new LinkedHashMap<>();
            Map<String, Long> clients = new LinkedHashMap<>();
            List<Map<String, Object>> timeline = new ArrayList<>();

            for (JsonNode h : root.path("hits").path("hits")) {
                JsonNode s = h.path("_source");
                String ruleId = s.path("rule").path("id").asText("");
                String desc = s.path("rule").path("description").asText("");
                String ts = normalizeTime(s.path("@timestamp").asText(""));

                if ("100100".equals(ruleId)) {
                    connections++;
                } else if ("100102".equals(ruleId)) {
                    logins++;
                } else if ("100101".equals(ruleId)) {
                    loginFails++;
                }

                java.util.regex.Matcher mCred = RE_CRED.matcher(desc);
                if (mCred.find()) {
                    creds.merge(mCred.group(1) + " / " + mCred.group(2), 1L, Long::sum);
                }
                java.util.regex.Matcher mSrc = RE_SRC.matcher(desc);
                String src = mSrc.find() ? mSrc.group(1) : "";
                if (!src.isEmpty()) {
                    sources.merge(src, 1L, Long::sum);
                }
                java.util.regex.Matcher mCli = RE_CLIENT.matcher(desc);
                if (mCli.find()) {
                    clients.merge(mCli.group(1), 1L, Long::sum);
                }

                if (timeline.size() < 40) {
                    String kind = "100102".equals(ruleId) ? "登录成功"
                            : "100101".equals(ruleId) ? "登录失败"
                            : "100104".equals(ruleId) ? "客户端指纹" : "新连接";
                    Map<String, Object> e = new LinkedHashMap<>();
                    e.put("time", ts);
                    e.put("kind", kind);
                    e.put("srcIp", src);
                    e.put("detail", desc);
                    timeline.add(e);
                }
            }

            out.put("available", true);
            out.put("total", root.path("hits").path("total").path("value").asLong(0));
            out.put("connections", connections);
            out.put("logins", logins);
            out.put("loginFails", loginFails);
            out.put("topCredentials", topN(creds, 10));
            out.put("topSources", topN(sources, 10));
            out.put("topClients", topN(clients, 8));
            out.put("timeline", timeline);
            out.put("sampled", root.path("hits").path("hits").size());
            return out;
        } catch (Exception e) {
            logger.warn("蜜罐战报查询失败（页面会显示数据源不可用）：{}", e.getMessage());
            return out;
        }
    }

    /** 取 Top N（按计数倒序） */
    private static List<Map<String, Object>> topN(Map<String, Long> src, int n) {
        List<Map<String, Object>> list = new ArrayList<>();
        src.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(n)
                .forEach(e -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("key", e.getKey());
                    m.put("count", e.getValue());
                    list.add(m);
                });
        return list;
    }

    /**
     * <b>攻击故事线</b>（候选来源聚合）—— 见 {@link WazuhGateway#storySources(int, int)}。
     *
     * <h3>为什么不看缓存的 {@code available} 就直接查</h3>
     * 与 {@link #summary24h()} 同一条教训：{@code available} 由每 60 秒一次的重探刷新，
     * 而 {@code docker compose up -d} 会同时重启隧道与应用 —— 启动那次探测必然失败。
     * 若把缓存的 {@code available} 当查询前提，冷启动后最多 60 秒内的每个请求都会
     * 直接返回"数据源不可用"，而 indexer 其实已经就绪。所以这里直接查，异常才降级。
     */
    @Override
    public Map<String, Object> storySources(int windowHours, int topSources) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("available", false);
        if (client == null) {
            out.put("reason", "CLIENT_NOT_READY");
            out.put("note", "Wazuh 客户端未初始化（未启用或初始化失败），故事线候选聚合无法查询");
            return out;
        }
        List<String> fields = srcIpFields();
        try {
            JsonNode root = client.fetchStorySources(windowHours, topSources, fields);
            Map<String, Object> parsed = parseStorySources(root, fields.size(),
                    Math.max(1, Math.min(windowHours, 168)));
            if (Boolean.TRUE.equals(parsed.get("available"))) {
                // "接没接上"的判定：窗口内某阶段一条都没有时，再确认一次索引里到底有没有这类数据。
                // 没有这一步，"诱饵端口还没接入"与"这个窗口没人打诱饵端口"在响应里长得一模一样。
                Map<String, Object> wiring = new LinkedHashMap<>();
                wiring.put("alerts", indexerTotal(parsed) > 0 ? "OK" : "NOT_WIRED");
                wiring.put("decoyPorts", decoyWiring(parsed));
                wiring.put("honeypotLogins", honeypotWiring(parsed));
                parsed.put("stageWiring", wiring);
            }
            return parsed;
        } catch (Exception e) {
            logger.warn("故事线候选聚合查询失败（公开端点会如实降级）：{}", e.getMessage());
            out.put("reason", "QUERY_FAILED");
            out.put("note", "故事线候选聚合查询失败（" + e.getMessage() + "）；"
                    + "这不是'这段时间没有攻击'，页面应显示为降级并重试");
            return out;
        }
    }

    private static long indexerTotal(Map<String, Object> parsed) {
        Object v = parsed.get("indexerTotal");
        return v instanceof Number n ? n.longValue() : 0L;
    }

    /** 窗口内诱饵端口为 0 时，确认索引里究竟有没有 Dionaea 数据（区分"未接入"与"窗口内没有"） */
    private String decoyWiring(Map<String, Object> parsed) {
        Object v = parsed.get("decoyTotal");
        if (v instanceof Number n && n.longValue() > 0) {
            return "OK";
        }
        return indexerHasAny("{\"size\":0,\"track_total_hits\":true,"
                + "\"query\":{\"term\":{\"rule.groups\":\"dionaea\"}}}");
    }

    /** 窗口内蜜罐登录为 0 时，确认索引里有没有 100101/100102 这两条登录规则 */
    private String honeypotWiring(Map<String, Object> parsed) {
        Object v = parsed.get("honeypotLoginTotal");
        if (v instanceof Number n && n.longValue() > 0) {
            return "OK";
        }
        return indexerHasAny("{\"size\":0,\"track_total_hits\":true,"
                + "\"query\":{\"terms\":{\"rule.id\":[\"100101\",\"100102\"]}}}");
    }

    /** 索引（不限时间窗口）里有没有这类文档。查询失败返回 {@code UNKNOWN}（不猜"未接入"） */
    private String indexerHasAny(String bodyJson) {
        try {
            JsonNode r = client.search("wazuh-alerts-*", bodyJson);
            long total = r.path("hits").path("total").path("value").asLong(0);
            return total > 0 ? "OK" : "NOT_WIRED";
        } catch (Exception e) {
            logger.warn("阶段接入判定查询失败（按 UNKNOWN 上报，不猜'未接入'）：{}", e.getMessage());
            return "UNKNOWN";
        }
    }

    /**
     * 解析 {@link WazuhClient#fetchStorySources} 的响应（<b>纯函数，便于单测直接喂 JSON</b>）。
     *
     * <p>把多个 filter 聚合按来源 IP 合并成"每个来源各阶段多少条、首末时间、最高等级"。
     * 两个来源字段（{@code data.srcip} / {@code data.src_ip}）分别聚合后<b>相加</b>：
     * 同一条文档若两个字段都有且相同会被计两次 —— 实测未见，但响应里同时给出
     * {@code withSourceIp}（带任一来源字段的文档数）供读者核对，不假装它一定等于各来源之和。
     *
     * @param root        OpenSearch 响应
     * @param fieldCount  查询里用了几个来源字段（聚合名是 {@code *_0..*_{n-1}}）
     * @param windowHours 窗口小时数（如实回显，便于前端画时间轴刻度）
     */
    static Map<String, Object> parseStorySources(JsonNode root, int fieldCount, int windowHours) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("windowHours", windowHours);
        if (root == null || root.isMissingNode() || root.isNull()
                || !root.path("aggregations").isObject()) {
            out.put("available", false);
            out.put("reason", "EMPTY_RESPONSE");
            out.put("note", "聚合响应里没有 aggregations 节点（查询未按预期执行）");
            return out;
        }

        Map<String, StorySource> byIp = new LinkedHashMap<>();
        for (int i = 0; i < fieldCount; i++) {
            collectStage(byIp, root, "alerts_" + i, "alerts");
            collectStage(byIp, root, "decoy_" + i, "decoy");
            collectStage(byIp, root, "honeypot_" + i, "honeypot");
            collectStage(byIp, root, "logins_" + i, "logins");
        }

        long withIp = root.path("aggregations").path("src_present").path("doc_count").asLong(0);
        long total = root.path("hits").path("total").path("value").asLong(0);
        long decoyTotal = 0;
        long loginTotal = 0;

        List<Map<String, Object>> sources = new ArrayList<>();
        for (StorySource s : byIp.values()) {
            decoyTotal += s.decoy;
            loginTotal += s.honeypotLogins;
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("srcIp", s.ip);
            m.put("alerts", s.alerts);
            m.put("decoyPorts", s.decoy);
            m.put("honeypotLogins", s.honeypotLogins);
            // 全量 Cowrie 事件（含新连接/客户端指纹）：只用来解释"为什么登录数是 0"，
            // 不进 stages（否则"连上过"会被当成"登录过"）
            m.put("honeypotEvents", s.honeypotEvents);
            m.put("total", s.alerts + s.decoy + s.honeypotLogins);
            m.put("firstSeen", s.firstSeen);
            m.put("lastSeen", s.lastSeen);
            m.put("maxLevel", s.maxLevel);
            sources.add(m);
        }
        // 排序确定（同输入 → 同输出，ETag/304 的前提）：条数多的在前，再按 IP 升序
        sources.sort((a, b) -> {
            int c = Long.compare(num(b.get("total")), num(a.get("total")));
            return c != 0 ? c : String.valueOf(a.get("srcIp")).compareTo(String.valueOf(b.get("srcIp")));
        });

        out.put("available", true);
        out.put("reason", sources.isEmpty() ? "NO_DATA_IN_WINDOW" : "OK");
        out.put("indexerTotal", total);
        out.put("withSourceIp", withIp);
        out.put("decoyTotal", decoyTotal);
        out.put("honeypotLoginTotal", loginTotal);
        out.put("sourceCount", sources.size());
        out.put("sources", sources);
        out.put("note", sources.isEmpty()
                ? "查询成功：该窗口内没有任何带来源 IP 的告警（这是真实结果，不是数据源故障）"
                : "按来源聚合完成：两个来源字段（data.srcip / data.src_ip）分别聚合后按 IP 合并");
        return out;
    }

    private static long num(Object v) {
        return v instanceof Number n ? n.longValue() : 0L;
    }

    /** 把一个阶段（某个来源字段）的分桶合并进 {@code byIp} */
    private static void collectStage(Map<String, StorySource> byIp, JsonNode root,
                                     String aggName, String stage) {
        JsonNode buckets = root.path("aggregations").path(aggName).path("ips").path("buckets");
        if (!buckets.isArray()) {
            return;
        }
        for (JsonNode b : buckets) {
            String ip = b.path("key").asText("");
            if (ip.isEmpty()) {
                continue;
            }
            long count = b.path("doc_count").asLong(0);
            if (count <= 0) {
                continue;
            }
            StorySource s = byIp.computeIfAbsent(ip, StorySource::new);
            switch (stage) {
                case "alerts" -> s.alerts += count;
                case "decoy" -> s.decoy += count;
                // 全量 Cowrie 事件只作"连上过蜜罐但没登录"的旁证，不进 stages 计数（只有登录算登录阶段）
                case "honeypot" -> s.honeypotEvents += count;
                default -> s.honeypotLogins += count;
            }
            s.observe(b.path("min_ts").path("value_as_string").asText(""),
                    b.path("max_ts").path("value_as_string").asText(""),
                    b.path("max_level").path("value").asInt(0));
        }
    }

    /** 故事线的单来源累加器（只在本类内使用；IP 是索引里的原值，脱敏在公开侧做） */
    private static final class StorySource {
        private final String ip;
        private long alerts;
        private long decoy;
        private long honeypotLogins;
        private long honeypotEvents;
        private String firstSeen;
        private String lastSeen;
        private int maxLevel;

        private StorySource(String ip) {
            this.ip = ip;
        }

        private void observe(String minIso, String maxIso, int level) {
            if (minIso != null && !minIso.isBlank()) {
                String t = normalizeTime(minIso);
                if (firstSeen == null || t.compareTo(firstSeen) < 0) {
                    firstSeen = t;
                }
            }
            if (maxIso != null && !maxIso.isBlank()) {
                String t = normalizeTime(maxIso);
                if (lastSeen == null || t.compareTo(lastSeen) > 0) {
                    lastSeen = t;
                }
            }
            if (level > maxLevel) {
                maxLevel = level;
            }
        }
    }

    /**
     * <b>攻击故事线</b>（单来源明细）—— 见 {@link WazuhGateway#storyEvents(String, int, int)}。
     *
     * <p>三个阶段各自一条查询、各自一个上限（不共用 size）：某个阶段刷屏时，
     * 另外两段不会从时间轴上消失。
     *
     * <p>{@code _source} 是<b>字段白名单</b>（{@link #STORY_EVENT_FIELDS}）：
     * 蜜罐文档里有 {@code data.password} / {@code data.message}（明文口令）、
     * {@code full_log} / {@code previous_output}（原始日志）。用 _source 过滤后，
     * 这些字段<b>根本不进入本进程</b> —— 比"取回来再记得别输出"可靠得多。
     */
    @Override
    public Map<String, Object> storyEvents(String srcIp, int windowHours, int maxPerStage) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("available", false);
        if (client == null) {
            out.put("reason", "CLIENT_NOT_READY");
            out.put("note", "Wazuh 客户端未初始化（未启用或初始化失败）");
            return out;
        }
        String ip = srcIp == null ? "" : srcIp.trim();
        if (ip.isEmpty()) {
            out.put("reason", "INVALID_SRC");
            out.put("note", "来源地址为空，未执行任何查询（不拿空条件去查全库）");
            return out;
        }
        int cap = Math.max(1, Math.min(maxPerStage, 200));
        int hours = Math.max(1, Math.min(windowHours, 168));
        try {
            Map<String, Object> stages = new LinkedHashMap<>();
            stages.put("alerts", oneStage(ip, hours, cap,
                    Map.of("bool", Map.of("must_not", List.of(
                            Map.of("terms", Map.of("rule.groups", List.of("cowrie", "dionaea")))))),
                    "alerts"));
            stages.put("decoyPorts", oneStage(ip, hours, cap,
                    Map.of("term", Map.of("rule.groups", "dionaea")), "decoy"));
            stages.put("honeypotLogins", oneStage(ip, hours, cap,
                    Map.of("terms", Map.of("rule.id", List.of("100101", "100102"))), "honeypot"));
            out.put("available", true);
            out.put("reason", "OK");
            out.put("stages", stages);
            out.put("note", "每段各一条查询、各自限量；truncated=true 表示这一段还有更早的事件没取回");
            return out;
        } catch (Exception e) {
            logger.warn("故事线明细查询失败（公开端点会如实降级）：{}", e.getMessage());
            out.put("reason", "QUERY_FAILED");
            out.put("note", "故事线明细查询失败（" + e.getMessage() + "）；这不是'这个来源没有行为'");
            return out;
        }
    }

    /** 单个来源、单个阶段的事件列表（总量 + 已取回条数 + 是否被截断） */
    private Map<String, Object> oneStage(String srcIp, int windowHours, int cap,
                                         Map<String, Object> stageFilter, String stage) throws java.io.IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("size", cap);
        body.put("track_total_hits", true);
        body.put("sort", List.of(Map.of("@timestamp", "desc")));
        body.put("_source", STORY_EVENT_FIELDS);
        body.put("query", Map.of("bool", Map.of("filter", List.of(
                Map.of("range", Map.of("@timestamp", Map.of("gte", "now-" + windowHours + "h"))),
                Map.of("bool", Map.of("should", List.of(
                                Map.of("term", Map.of("data.srcip", srcIp)),
                                Map.of("term", Map.of("data.src_ip", srcIp))),
                        "minimum_should_match", 1)),
                stageFilter))));

        JsonNode root = client.search("wazuh-alerts-*", MAPPER.writeValueAsString(body));
        long total = root.path("hits").path("total").path("value").asLong(0);
        List<Map<String, Object>> events = new ArrayList<>();
        for (JsonNode h : root.path("hits").path("hits")) {
            Map<String, Object> e = toEvent(h.path("_source"), stage);
            if (e != null) {
                events.add(e);
            }
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("total", total);
        m.put("returned", events.size());
        m.put("truncated", total > events.size());
        m.put("events", events);
        return m;
    }

    /**
     * 故事线事件要用的字段（<b>白名单</b>）。
     *
     * <p>刻意不含：{@code data.password} / {@code data.message}（明文口令）、
     * {@code full_log} / {@code previous_output}（原始日志，含内网目的地址与完整 payload）、
     * {@code agent.*} / {@code manager.*}（内部资产名）。少取一个字段就少一条泄露路径。
     */
    static final List<String> STORY_EVENT_FIELDS = List.of(
            "@timestamp", "rule.id", "rule.level", "rule.description", "rule.groups",
            "data.srcip", "data.src_ip", "data.src_port", "data.dst_port", "data.eventid",
            "data.connection.protocol", "data.username");

    /**
     * 一条索引文档 → 一条故事线事件（<b>未脱敏</b>：IP 与口令的处理在 publicapi 侧）。
     *
     * <p>{@code summary} 用 {@code rule.description}：它与公开端点 {@code /alerts} 已经在
     * 输出的 {@code title}/{@code ruleName} 是同一类信息（不是内部规则正则原文）。
     * {@code data.message}（含明文口令，形如 {@code login attempt [root/Abcd@123] succeeded}）
     * 一律不用。
     */
    static Map<String, Object> toEvent(JsonNode s, String stage) {
        if (s == null || s.isMissingNode()) {
            return null;
        }
        String ts = normalizeTime(s.path("@timestamp").asText(""));
        String desc = s.path("rule").path("description").asText("");
        int level = s.path("rule").path("level").asInt(0);
        String ruleId = s.path("rule").path("id").asText("");
        String eventId = s.path("data").path("eventid").asText("");

        Map<String, Object> e = new LinkedHashMap<>();
        e.put("ts", ts);
        e.put("summary", desc);
        e.put("level", level);
        e.put("outcome", null);
        switch (stage) {
            case "decoy" -> {
                String proto = s.path("data").path("connection").path("protocol").asText("");
                String port = s.path("data").path("dst_port").asText("");
                e.put("kind", "诱饵端口 " + decoyProtocolLabel(proto) + (port.isEmpty() ? "" : "（" + port + "/tcp）"));
                e.put("outcome", "ACCEPT");
            }
            case "honeypot" -> {
                boolean success = "100102".equals(ruleId) || eventId.endsWith("login.success");
                e.put("kind", success ? "蜜罐 SSH 登录成功" : "蜜罐 SSH 登录失败");
                e.put("outcome", success ? "SUCCESS" : "FAILED");
            }
            default -> e.put("kind", AlertType.guess(desc).getLabel());
        }
        return e;
    }

    /** 诱饵端口协议 → 人读标签（认不出就给原值，不猜） */
    private static String decoyProtocolLabel(String protocol) {
        if (protocol == null || protocol.isBlank()) {
            return "连接";
        }
        return switch (protocol.toLowerCase()) {
            case "smbd" -> "SMB";
            case "mysqld" -> "MySQL";
            case "mssqld" -> "MSSQL";
            case "httpd" -> "HTTP";
            case "ftpd" -> "FTP";
            case "ftpdatalisten" -> "FTP-DATA";
            default -> protocol;
        };
    }

    // ==================== IP 画像（/api/public/ip；个人版 AbuseIPDB） ====================

    /** IP 画像的样本上限：聚合口径在样本上做，样本大小如实写进 {@code sampled}/{@code truncated} */
    static final int IP_ACTIVITY_SAMPLE = 300;

    /**
     * <b>IP 画像</b>（跨数据源汇总）—— 见 {@link org.example.integration.WazuhGateway#ipActivity(String, int)}。
     *
     * <h3>一条查询 + 一组聚合，而不是三段各查一次</h3>
     * 与 {@link #storyEvents} 的取舍相反：那边要"每段各自限量"，是因为某段刷屏会让别段从时间轴上消失；
     * 这里要的是<b>同一个来源的总量与分布</b>，三段共用一次查询反而不会割裂。
     * 精确值（总条数、首末时间、各阶段条数）全部由聚合给出，<b>不受样本上限影响</b>；
     * 只有"按行为分类 / 端口 / 口令"这三项在样本上统计，并在 {@code note} 里写清是样本口径 ——
     * 不把样本数当总量（那正是最容易编数的地方）。
     *
     * <h3>三个刻意的边界</h3>
     * <ol>
     *   <li>{@code _source} 仍是 {@link #STORY_EVENT_FIELDS} 白名单：{@code data.password} /
     *       {@code data.message} / {@code full_log} <b>不进本进程</b>。口令只从
     *       {@code rule.description} 里按既有正则抽（与 {@link #honeypotSummary} 同一条路），
     *       且只在 {@code topCredentials} 里给 publicapi 侧转成<b>结构</b>；</li>
     *   <li>IP 条件与故事线<b>完全同一组</b>（{@code data.srcip} / {@code data.src_ip} 二者其一），
     *       否则同一个 IP 在两个端点上会得到不同条数；</li>
     *   <li>失败一律 {@code available=false} + 原因，<b>不返回 0</b>：「查不到」与「没有行为」
     *       在公开页面上必须是两件事。</li>
     * </ol>
     */
    @Override
    public Map<String, Object> ipActivity(String srcIp, int windowHours) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("available", false);
        if (client == null) {
            out.put("reason", "CLIENT_NOT_READY");
            out.put("note", "Wazuh 客户端未初始化（未启用或初始化失败）");
            return out;
        }
        String ip = srcIp == null ? "" : srcIp.trim();
        if (ip.isEmpty()) {
            out.put("reason", "INVALID_SRC");
            out.put("note", "来源地址为空，未执行任何查询（不拿空条件去查全库）");
            return out;
        }
        int hours = Math.max(1, Math.min(windowHours, 168));
        int cap = IP_ACTIVITY_SAMPLE;
        try {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("size", cap);
            body.put("track_total_hits", true);
            body.put("sort", List.of(Map.of("@timestamp", "desc")));
            body.put("_source", STORY_EVENT_FIELDS);
            body.put("query", Map.of("bool", Map.of("filter", List.of(
                    Map.of("range", Map.of("@timestamp", Map.of("gte", "now-" + hours + "h"))),
                    Map.of("bool", Map.of("should", List.of(
                                    Map.of("term", Map.of("data.srcip", ip)),
                                    Map.of("term", Map.of("data.src_ip", ip))),
                            "minimum_should_match", 1))))));
            Map<String, Object> aggs = new LinkedHashMap<>();
            aggs.put("first_ts", Map.of("min", Map.of("field", "@timestamp")));
            aggs.put("last_ts", Map.of("max", Map.of("field", "@timestamp")));
            // 三段精确计数：与 storyEvents 用同一组过滤条件（否则两个端点会自相矛盾）
            Map<String, Object> notHoneypot = Map.of("bool", Map.of("must_not",
                    List.of(Map.of("terms", Map.of("rule.groups", List.of("cowrie", "dionaea"))))));
            aggs.put("st_alerts", Map.of("filter", notHoneypot));
            aggs.put("st_decoy", Map.of("filter", Map.of("term", Map.of("rule.groups", "dionaea"))));
            aggs.put("st_logins", Map.of("filter", Map.of("terms", Map.of("rule.id", List.of("100101", "100102")))));
            aggs.put("st_login_ok", Map.of("filter", Map.of("term", Map.of("rule.id", "100102"))));
            body.put("aggs", aggs);

            JsonNode root = client.search("wazuh-alerts-*", MAPPER.writeValueAsString(body));
            JsonNode ag = root.path("aggregations");
            long total = root.path("hits").path("total").path("value").asLong(0);

            Map<String, Long> kinds = new LinkedHashMap<>();
            Map<String, Long> ports = new LinkedHashMap<>();
            Map<String, Long> creds = new LinkedHashMap<>();
            int sampled = 0;
            for (JsonNode h : root.path("hits").path("hits")) {
                JsonNode s = h.path("_source");
                sampled++;
                String desc = s.path("rule").path("description").asText("");
                String ruleId = s.path("rule").path("id").asText("");
                String port = s.path("data").path("dst_port").asText("");

                String kind;
                if ("100102".equals(ruleId)) {
                    kind = "蜜罐登录成功";
                } else if ("100101".equals(ruleId)) {
                    kind = "蜜罐登录失败";
                } else if ("100100".equals(ruleId)) {
                    kind = "蜜罐新连接";
                } else if ("100104".equals(ruleId)) {
                    kind = "蜜罐客户端指纹";
                } else {
                    // 与 /alerts、故事线同一套归类（不另起一套"看起来更细"的分类）
                    kind = AlertType.guess(desc).getLabel();
                }
                kinds.merge(kind, 1L, Long::sum);
                if (isPortNumber(port)) {
                    ports.merge(port, 1L, Long::sum);
                }
                java.util.regex.Matcher mCred = RE_CRED.matcher(desc);
                if (mCred.find()) {
                    // 密钥串（"用户 / 口令"）只在服务端流转：publicapi 侧必须先转成结构再出海
                    creds.merge(mCred.group(1) + " / " + mCred.group(2), 1L, Long::sum);
                }
            }

            out.put("available", true);
            out.put("reason", "OK");
            out.put("windowHours", hours);
            out.put("total", total);
            out.put("firstSeen", tsOf(ag.path("first_ts")));
            out.put("lastSeen", tsOf(ag.path("last_ts")));
            Map<String, Object> stages = new LinkedHashMap<>();
            long logins = docCount(ag.path("st_logins"));
            long loginOk = docCount(ag.path("st_login_ok"));
            stages.put("alerts", docCount(ag.path("st_alerts")));
            stages.put("decoyPorts", docCount(ag.path("st_decoy")));
            stages.put("honeypotLogins", logins);
            stages.put("honeypotSuccess", loginOk);
            stages.put("honeypotFailed", Math.max(0, logins - loginOk));
            out.put("stages", stages);
            out.put("byKind", topN(kinds, 12));
            out.put("ports", topN(ports, 20));
            out.put("topCredentials", topN(creds, 10));
            out.put("sampled", sampled);
            out.put("truncated", total > sampled);
            out.put("note", total > sampled
                    ? "总条数、首末时间、各阶段计数是精确值；按行为分类/端口/口令只基于最近 " + sampled
                            + " 条（该来源在窗口内共 " + total + " 条），属于样本口径"
                    : "窗口内该来源的全部记录都已取回（" + total + " 条），各项计数均为精确值");
            return out;
        } catch (Exception e) {
            logger.warn("IP 画像查询失败（公开端点会如实降级）：{}", e.getMessage());
            out.put("reason", "QUERY_FAILED");
            out.put("note", "IP 画像查询失败（" + e.getMessage() + "）；这不是'这个来源没有行为'");
            return out;
        }
    }

    /** min/max 聚合的时间戳（value_as_string → 本地 {@code yyyy-MM-dd HH:mm:ss}；取不到给 null，不猜） */
    private static String tsOf(JsonNode agg) {
        String v = agg.path("value_as_string").asText("");
        if (v.isBlank()) {
            return null;
        }
        String t = normalizeTime(v);
        return (t == null || t.isBlank()) ? null : t;
    }

    private static long docCount(JsonNode agg) {
        return agg.path("doc_count").asLong(0);
    }

    /** 只接受纯数字端口（{@code data.dst_port} 可能是协议名，那不是端口） */
    private static boolean isPortNumber(String s) {
        if (s == null || s.isEmpty() || s.length() > 5) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            if (!Character.isDigit(s.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * 处置通道是否可用 —— 与 {@link #isAvailable()} 语义不同，不要混用。
     *
     * <p>{@code isAvailable()} 回答的是"Wazuh 管理 API 连上了吗"，
     * 它决定的是【告警数据】能不能取到真实值。
     * <p>这个方法回答的是"处置动作能不能真的执行"。
     * 处置的首选路径是 SSH 直连（不依赖 Wazuh API），
     * 所以两者必须分开判断 —— 混用会导致
     * "链路是通的，但业务代码认为不可用，直接走了 MOCK"。
     */
    public boolean isResponseCapable() {
        return activeResponseEnabled
                && sshExecutor != null
                && sshExecutor.isEnabled();
    }

    @Override
    public boolean isAvailable() {
        return available;
    }

    /**
     * 出站超时的<b>实际生效值</b>（启动自检用）。
     *
     * <p>取自真正构造 WazuhClient 的那个对象，而不是"再读一遍配置"——
     * 后者会在"配置改了但客户端没拿到"时打印出骗人的值。
     */
    public org.example.config.OutboundTimeouts effectiveOutboundTimeouts() {
        return (client != null) ? client.effectiveTimeouts() : outboundTimeouts;
    }

    /** 出站守卫是否已接入该客户端（自检用：false 表示只有传输层超时） */
    public boolean outboundGuardEnabled() {
        return client != null && client.guardEnabled();
    }

    @Override
    public String mode() {
        if (!enabled) return "OFF";
        return available ? "REAL" : "MOCK";
    }

    // ==================== 告警 ====================

    /**
     * 离线地理富化（可空：单测里直接 {@code new WazuhService()} 时没有它）。
     *
     * <p>刻意用 {@code required=false} 而不是构造器注入：这个服务在很多单测里是
     * 手写 new 出来的，加一个必填依赖会让它们全部编译/启动失败；
     * 而"没有富化"是完全可以接受的状态（{@code srcGeo} 保持 null，页面显示"未知"）。
     */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private org.example.geoip.GeoIpService geoIpService;

    @Override
    public List<SecurityAlert> recentAlerts(int limit) {
        if (available && client != null) {
            try {
                return mapRealAlerts(client.fetchAlerts(limit), limit);
            } catch (Exception e) {
                logger.warn("拉取 Wazuh 真实告警失败，回退到内置样本：{}", e.getMessage());
            }
        }
        return builtinAlerts(limit);
    }

    /** 来源 IP 的字段名：主机侧/蜜罐与 Suricata 用的不是同一个（实测），所以做成配置 */
    @Value("${app.geoip.src-ip-fields:data.srcip,data.src_ip}")
    private String srcIpFieldsConfig;

    private List<String> srcIpFields() {
        List<String> out = new ArrayList<>();
        if (srcIpFieldsConfig != null) {
            for (String f : srcIpFieldsConfig.split(",")) {
                String v = f.trim();
                if (!v.isEmpty()) {
                    out.add(v);
                }
            }
        }
        return out.isEmpty() ? List.of("data.srcip") : out;
    }

    /**
     * 24 小时来源 IP 分布（公开地理端点的取数口径）。
     *
     * <p>不返回内置样本：数据源不可用时返回 {@code available=false}，
     * 让公开端点如实显示"地理分布不可用"，<b>而不是拿样本里的文档网段画一张假地图</b>。
     */
    @Override
    public org.example.geoip.GeoWindow geoWindow24h(int topN) {
        if (client == null) {
            return org.example.geoip.GeoWindow.unavailable("CLIENT_NOT_READY",
                    "Wazuh 客户端未初始化（未启用或初始化失败）");
        }
        List<String> fields = srcIpFields();
        try {
            JsonNode root = client.fetchGeoAggregates24h(topN, fields);
            return parseGeoWindow(root, fields.size());
        } catch (Exception e) {
            logger.warn("来源 IP 分布查询失败（公开地理端点将如实降级）：{}", e.getMessage());
            return org.example.geoip.GeoWindow.unavailable("QUERY_FAILED",
                    "来源分布聚合查询失败（" + e.getMessage() + "）；这不是'没有攻击'，前端应显示降级");
        }
    }

    /**
     * 解析 {@link WazuhClient#fetchGeoAggregates24h} 的响应（<b>纯函数，便于单测直接喂 JSON</b>）。
     *
     * @param root       OpenSearch 响应
     * @param fieldCount 查询里用了几个来源字段（聚合名是 {@code by_ip_0..by_ip_{n-1}}）
     */
    static org.example.geoip.GeoWindow parseGeoWindow(JsonNode root, int fieldCount) {
        if (root == null || root.isMissingNode() || root.isNull()) {
            return org.example.geoip.GeoWindow.unavailable("EMPTY_RESPONSE");
        }
        // 没有 aggregations 节点 = 这不是一次正常的聚合响应（被中间件改成错误页、索引名写错等）。
        // 不能当成"窗口里没有带来源 IP 的告警"——那会把一次查询故障渲染成"天下太平"。
        if (!root.path("aggregations").isObject()) {
            return org.example.geoip.GeoWindow.unavailable("EMPTY_RESPONSE",
                    "聚合响应里没有 aggregations 节点（查询未按预期执行）");
        }
        long total = root.path("hits").path("total").path("value").asLong(0);
        JsonNode aggs = root.path("aggregations");
        JsonNode present = aggs.path("src_present");
        long withIp = present.path("doc_count").asLong(0);

        Map<String, Long> byIp = new LinkedHashMap<>();
        // 每个 IP 的"按小时分布"（稀疏桶：只有有数据的整点）。取不到就整套为空 ——
        // GeoAggregator 据此把 byCountryHour 如实标成 available:false，而不是摊分合计。
        Map<String, Map<String, Long>> hourByIp = new LinkedHashMap<>();
        boolean truncated = false;
        for (int i = 0; i < fieldCount; i++) {
            JsonNode buckets = aggs.path("by_ip_" + i).path("buckets");
            if (!buckets.isArray()) {
                continue;
            }
            if (aggs.path("by_ip_" + i).path("sum_other_doc_count").asLong(0) > 0) {
                truncated = true;
            }
            for (JsonNode b : buckets) {
                String ip = b.path("key").asText("");
                if (ip.isEmpty()) {
                    continue;
                }
                byIp.merge(ip, b.path("doc_count").asLong(0), Long::sum);
                JsonNode hourBuckets = b.path("by_hour").path("buckets");
                if (hourBuckets.isArray()) {
                    Map<String, Long> hm = hourByIp.computeIfAbsent(ip, k -> new LinkedHashMap<>());
                    for (JsonNode hb : hourBuckets) {
                        String hl = hourLabel(hb);
                        long c = hb.path("doc_count").asLong(0);
                        if (!hl.isEmpty() && c > 0) {
                            hm.merge(hl, c, Long::sum);
                        }
                    }
                }
            }
        }
        List<org.example.geoip.GeoAggregator.IpCount> counts = new ArrayList<>();
        byIp.entrySet().stream()
                .sorted(java.util.Comparator
                        .comparingLong((Map.Entry<String, Long> e) -> e.getValue()).reversed()
                        .thenComparing(Map.Entry::getKey))
                .forEach(e -> counts.add(new org.example.geoip.GeoAggregator.IpCount(
                        e.getKey(), e.getValue(), hourByIp.getOrDefault(e.getKey(), Map.of()))));

        List<org.example.geoip.GeoAggregator.TrendPoint> trend = new ArrayList<>();
        for (JsonNode b : present.path("by_hour").path("buckets")) {
            trend.add(new org.example.geoip.GeoAggregator.TrendPoint(hourLabel(b), b.path("doc_count").asLong(0)));
        }
        if (counts.isEmpty()) {
            return org.example.geoip.GeoWindow.empty(total);
        }
        return new org.example.geoip.GeoWindow(true, "OK", null, total, withIp, truncated, counts, trend);
    }

    /** date_histogram 桶 → 本地整点标签（{@code yyyy-MM-dd'T'HH:mm}，与 trend 同一个格式，可对齐） */
    private static String hourLabel(JsonNode bucket) {
        String local = WazuhTime.toLocal(bucket.path("key_as_string").asText(""));
        // date_histogram 的 key 就是整点，取到分钟即可（"2026-10-13 20:00:00" → "2026-10-13T20:00"）
        return local.length() >= 16 ? local.substring(0, 16).replace(' ', 'T') : local;
    }

    /**
     * 把取回的 JSON 规整为 SecurityAlert。
     *
     * <h3>两种返回结构都要认</h3>
     * <ul>
     *   <li><b>OpenSearch（现在走的就是这条）</b>：
     *       {@code {hits:{hits:[{_id:..., _source:{@timestamp, rule:{...}, agent:{...}}}]}}}
     *       —— 真实告警在 {@code _source} 里，时间字段叫 {@code @timestamp}</li>
     *   <li>Wazuh 管理 API 风格：{@code {data:{affected_items:[...]}}}
     *       —— 保留兼容</li>
     * </ul>
     * 原实现只认第二种。<b>换了数据源但不换解析逻辑，等于没换</b> ——
     * 所以这次两件事必须一起改。
     */
    private List<SecurityAlert> mapRealAlerts(JsonNode root, int limit) {
        List<SecurityAlert> out = new ArrayList<>();

        // 先认 OpenSearch 的 hits.hits[]._source
        List<JsonNode> nodes = new ArrayList<>();
        JsonNode hits = root.path("hits").path("hits");
        if (hits.isArray()) {
            for (JsonNode h : hits) {
                JsonNode src = h.path("_source");
                nodes.add((src.isMissingNode() || src.isNull()) ? h : src);
            }
        } else {
            JsonNode items = root.path("data").path("affected_items");
            if (!items.isArray()) {
                items = root.path("data");
            }
            if (items.isArray()) {
                for (JsonNode n : items) {
                    nodes.add(n);
                }
            }
        }

        for (JsonNode n : nodes) {
            if (out.size() >= limit) break;
            JsonNode rule = n.path("rule");
            String ruleName = text(rule.path("description"),
                    text(rule.path("name"), text(rule.path("id"), "wazuh-alert")));
            String levelRaw = text(rule.path("level"), "2");
            // indexer 里时间字段是 @timestamp；管理 API 风格是 timestamp
            String ts = text(n.path("@timestamp"), text(n.path("timestamp"), ""));
            String srcIp = text(n.path("data").path("srcip"), text(n.path("data").path("src_ip"), ""));
            String dstIp = text(n.path("agent").path("ip"), "");
            String dstAsset = text(n.path("agent").path("name"), dstIp);
            String desc = ruleName;
            String raw = text(n.path("full_log"), n.toString());

            SecurityAlert a = new SecurityAlert(
                    text(n.path("id"), text(n.path("_id"), "wz-" + out.size())),
                    desc,
                    AlertSeverity.fromWazuhLevel(levelRaw),
                    AlertType.guess(ruleName + " " + desc),
                    classifySource(n));
            a.setRuleName(ruleName);
            a.setSrcIp(srcIp);
            // ===== 离线地理富化（任务 2）：只填 srcGeo 这一个既有字段，不改任何现有字段语义 =====
            // 形状：国家ISO2|一级行政区|城市|ASN|AS组织（未知段写 "-"）；定位不到时为 null。
            // 刻意【不】在公开面输出它（PublicApiController 里显式置 null）：
            // 逐条的地理+ASN 等于把"某个攻击者属于哪个机构"搬到公网页面，
            // 公开面只允许国家/省份级聚合（见 GeoAggregator）。
            // 库不可用/未启用时 geoIpService 为 null 或 ready()=false → srcGeo 保持 null，如实"未知"。
            if (geoIpService != null && geoIpService.ready()) {
                a.setSrcGeo(geoIpService.describe(srcIp));
            }
            a.setDstIp(dstIp);
            a.setDstAsset(dstAsset);
            a.setDescription(desc);
            a.setRawLog(raw);
            a.setOccurredAt(normalizeTime(ts));
            a.getExtra().put("wazuhLevel", levelRaw);
            out.add(a);
        }
        return out;
    }

    /**
     * 判定这条 indexer 告警的<b>真实来源</b>。
     *
     * <h3>修的是什么</h3>
     * 原实现把从 indexer 取回的每一条都硬编码成 {@link AlertSource#WAZUH}。
     * 但 indexer 的 {@code wazuh-alerts-*} 是<b>所有检测器的汇总</b> ——
     * Wazuh agent 会把服务器 2 上 Suricata 的 {@code eve.json} 也读进去，
     * 所以索引里绝大部分文档其实是<b>网络告警</b>。
     * <p>
     * 实测（2026-10-11 线上）：全库 7415 条里 {@code rule.groups} 含 suricata 的
     * 有 6633 条；取最新 200 条分类后是
     * <b>Suricata 154 条 / 蜜罐 8 条 / 主机侧 38 条</b>。
     * 也就是说告警大屏上那个"Wazuh 主机告警 200 条"里，
     * 有四分之三根本不是主机告警 —— 来源分布图等于在骗人。
     * <p>
     * 顺带说明为什么这也解释了"网络告警为什么只有 5 条"：
     * 那 5 条来自 {@code SuricataService} 读 {@code /var/log/suricata/eve.json}
     * 的内置样本路径（那个文件在服务器 2，容器里根本没有），
     * 真数据 6633 条反而被算进了 Wazuh 那一栏。
     *
     * @param n indexer 命中的文档（_source）
     * @return SURICATA（网络层）/ WAZUH（主机侧、蜜罐等一切非 Suricata 来源）
     */
    private static AlertSource classifySource(JsonNode n) {
        JsonNode groups = n.path("rule").path("groups");
        if (groups.isArray()) {
            for (JsonNode g : groups) {
                if (g.asText("").toLowerCase().contains("suricata")) {
                    return AlertSource.SURICATA;
                }
            }
        }
        return AlertSource.WAZUH;
    }

    // ==================== 取证日志 ====================

    @Override
    public List<RawLogLine> forensicLogs(String query, int limit) {
        if (available && client != null) {
            try {
                List<RawLogLine> real = mapRealLogs(client.fetchManagerLogs(query, limit), limit);
                if (!real.isEmpty()) {
                    return real;
                }
            } catch (Exception e) {
                logger.warn("拉取 Wazuh 真实取证日志失败，回退到内置样本：{}", e.getMessage());
            }
        }
        return builtinForensicLogs(query, limit);
    }

    private List<RawLogLine> mapRealLogs(JsonNode root, int limit) {
        List<RawLogLine> out = new ArrayList<>();
        JsonNode items = root.path("data").path("affected_items");
        if (!items.isArray()) items = root.path("data");
        if (!items.isArray()) return out;
        for (JsonNode n : items) {
            if (out.size() >= limit) break;
            String log = text(n.path("description"), n.toString());
            RawLogLine line = new RawLogLine(
                    normalizeTime(text(n.path("timestamp"), "")),
                    "manager-logs",
                    text(n.path("rule").path("name"), "wazuh-log"),
                    text(n.path("data").path("srcip"), ""),
                    text(n.path("agent").path("name"), "wazuh-manager"),
                    log);
            line.setLevel(text(n.path("level"), "5"));
            out.add(line);
        }
        return out;
    }

    // ==================== 主动响应 ====================

    @Override
    public ActiveResponseResult runActiveResponse(String command, Map<String, Object> arguments) {
        String target = String.valueOf(arguments.getOrDefault("target", arguments.getOrDefault("ip", "-")));
        String auditId = "AR-" + System.currentTimeMillis();

        // ==================== 处置路径 1：SSH 直连（默认，已验证可用）====================
        //
        // 为什么它排在 Wazuh API 前面：
        //   Wazuh 的 active-response 投递链路在这套环境里走不通 ——
        //   配置全对（命令注册、ar.conf 一致、agent 002 确认产生告警、
        //   <expect>srcip</expect> 也加了），API 也报
        //   "AR command was sent to all agents"，但 agent 就是不执行。
        //   而封禁脚本手工执行 100% 有效。
        //   所以换成一条我能端到端验证的链路：SSH forced command。
        //   权限也更小：那把密钥只能封/解封 IP，开不了 shell。
        if (sshExecutor != null && sshExecutor.isEnabled() && activeResponseEnabled) {
            String action = ("unblock".equalsIgnoreCase(command) || "delete".equalsIgnoreCase(command))
                    ? "delete" : "add";
            try {
                String out = sshExecutor.run(action, target);
                logger.info("SSH 直连处置成功: {} {}（auditId={}）", action, target, auditId);
                return ActiveResponseResult.real(command, target,
                        "已通过 SSH 直连在防护主机上执行 " + action + " " + target + "：" + out,
                        auditId);
            } catch (Exception e) {
                // 失败要如实上报，不能悄悄降级成"模拟成功"——
                // 那正是这个项目反复踩过的"看着成功、实际没做"的坑。
                logger.error("SSH 直连处置失败: {} {} -> {}", action, target, e.getMessage());
                return ActiveResponseResult.failed(command, target,
                        "SSH 直连处置失败（未生效）：" + e.getMessage());
            }
        }

        // ==================== 处置路径 2：Wazuh API（保留但默认不用）====================
        boolean canReal = enabled && activeResponseEnabled && available && client != null;
        if (canReal) {
            try {
                JsonNode resp = client.sendActiveResponse(command, arguments);
                int fail = resp.path("data").path("failed_items").asInt(0);
                if (fail > 0) {
                    return ActiveResponseResult.failed(command, target,
                            "Wazuh active-response 返回失败项数=" + fail + "：" + snippet(resp.toString()));
                }
                logger.info("Wazuh 真实下发 active-response: {} -> {}（auditId={}）", command, target, auditId);
                return ActiveResponseResult.real(command, target,
                        "已通过 Wazuh 真实下发 " + command + "，目标 " + target, auditId);
            } catch (Exception e) {
                logger.warn("Wazuh 真实下发失败，转模拟：{}", e.getMessage());
                return ActiveResponseResult.failed(command, target,
                        "Wazuh 下发异常：" + e.getMessage());
            }
        }

        // 降级：清楚标注是模拟
        String reason = !enabled ? "Wazuh 总开关未启用"
                : !activeResponseEnabled ? "active-response-enabled=false（仅模拟）"
                : "未配置 SSH 直连且 Wazuh 未连接（MOCK）";
        return ActiveResponseResult.mock(command, target,
                "【模拟处置】未真实下发：" + reason + "。演示命令=" + command + " 目标=" + target, auditId);
    }

    // ==================== 内置样本（MOCK） ====================

    /**
     * 内置主机安全样本：覆盖 SSH 暴力破解、SQL 注入、Webshell、目录扫描，
     * 攻击 IP / 资产与既有 Mock 口径保持一致：
     * 103.146.184.77 / 45.83.91.12 → web-01(10.0.10.21) / web-02(10.0.10.22)。
     * 时间相对当前时间铺开，让大屏"时间趋势"图看起来是活的。
     */
    private List<SecurityAlert> builtinAlerts(int limit) {
        LocalDateTime now = LocalDateTime.now();
        List<SecurityAlert> all = new ArrayList<>();

        all.add(make("wz-mock-001", "SSH 暴力破解尝试（多次认证失败）", AlertSeverity.HIGH,
                AlertType.BRUTE_FORCE, "103.146.184.77", "境外扫描节点",
                "web-01", "10.0.10.21", 22, "sshd",
                now.minusMinutes(6),
                "Accepted password for root from 103.146.184.77 port 45122 sshd2 [反复尝试 root/密码爆破，失败 47 次后成功一次登录]",
                47));
        all.add(make("wz-mock-002", "SQL 注入尝试（UNION SELECT 探测）", AlertSeverity.CRITICAL,
                AlertType.SQL_INJECTION, "45.83.91.12", "东欧 VPS",
                "web-02", "10.0.10.22", 80, "nginx",
                now.minusMinutes(22),
                "GET /news.php?id=1%20UNION%20SELECT%201,version(),user()-- HTTP/1.1 (nginx access log)",
                12));
        all.add(make("wz-mock-003", "Webshell 上传与落地检测", AlertSeverity.CRITICAL,
                AlertType.WEBSHELL, "45.83.91.12", "东欧 VPS",
                "web-02", "10.0.10.22", 80, "nginx",
                now.minusMinutes(38),
                "File uploaded: /var/www/html/upload/shell.php (<?php @eval($_POST['x']); ?>) 命中 webshell 规则",
                3));
        all.add(make("wz-mock-004", "Web 目录扫描（敏感路径探测）", AlertSeverity.MEDIUM,
                AlertType.SCAN, "103.146.184.77", "境外扫描节点",
                "web-01", "10.0.10.21", 80, "nginx",
                now.minusHours(1).minusMinutes(5),
                "大量 404：/.env / /admin/.git/config / /phpmyadmin/ / /wp-login.php (目录爆破)",
                156));
        all.add(make("wz-mock-005", "sudo 提权异常（普通用户执行 root 命令）", AlertSeverity.HIGH,
                AlertType.PRIVILEGE_ESCALATION, "10.0.10.21", "本机进程",
                "web-01", "10.0.10.21", null, "sudo",
                now.minusHours(2).minusMinutes(10),
                "user www-data : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -p",
                2));
        all.add(make("wz-mock-006", "非法外联（可疑 C2 回连）", AlertSeverity.HIGH,
                AlertType.C2, "10.0.10.22", "本机进程",
                "web-02", "10.0.10.22", 4444, "firewall",
                now.minusHours(3).minusMinutes(20),
                "OUTBOUND 10.0.10.22:48223 -> 185.220.101.4:4444/tcp 命中可疑外联规则",
                9));

        int n = Math.min(limit, all.size());
        return new ArrayList<>(all.subList(0, n));
    }

    private SecurityAlert make(String id, String title, AlertSeverity sev, AlertType type,
                               String srcIp, String srcGeo, String dstAsset, String dstIp, Integer dstPort,
                               String service, LocalDateTime time, String rawLog, int count) {
        SecurityAlert a = new SecurityAlert(id, title, sev, type, AlertSource.WAZUH);
        a.setRuleName(title);
        a.setSrcIp(srcIp);
        a.setSrcGeo(srcGeo);
        a.setDstAsset(dstAsset);
        a.setDstIp(dstIp);
        a.setDstPort(dstPort);
        a.setService(service);
        a.setDescription(title);
        a.setRawLog(rawLog);
        a.setOccurredAt(time.format(FMT));
        a.setCount(count);
        a.setStatus("ACTIVE");
        Map<String, Object> extra = new HashMap<>();
        extra.put("mock", true);
        a.setExtra(extra);
        return a;
    }

    /** 内置取证日志样本，与内置告警口径一致；query 非空时做简单关键字过滤。 */
    private List<RawLogLine> builtinForensicLogs(String query, int limit) {
        LocalDateTime now = LocalDateTime.now();
        List<RawLogLine> all = new ArrayList<>();

        all.add(log("auth-logs", "sshd brute force", "103.146.184.77", "web-01",
                now.minusMinutes(6), "WARNING",
                "sshd[8123]: Failed password for root from 103.146.184.77 port 45122 ssh2"));
        all.add(log("auth-logs", "sshd login success", "103.146.184.77", "web-01",
                now.minusMinutes(5), "CRITICAL",
                "sshd[8123]: Accepted password for root from 103.146.184.77 port 45122 ssh2"));
        all.add(log("web-access-logs", "sqli attempt", "45.83.91.12", "web-02",
                now.minusMinutes(22), "CRITICAL",
                "nginx: GET /news.php?id=1 UNION SELECT 1,version(),user()-- 200 182.4"));
        all.add(log("web-access-logs", "webshell upload", "45.83.91.12", "web-02",
                now.minusMinutes(38), "CRITICAL",
                "nginx: POST /upload.php multipart shell.php -> /var/www/html/upload/shell.php 200"));
        all.add(log("web-access-logs", "dir scan", "103.146.184.77", "web-01",
                now.minusHours(1).plusMinutes(55), "MEDIUM",
                "nginx: GET /.env 404, GET /.git/config 404, GET /phpmyadmin/ 404 (连续 156 个敏感路径)"));
        all.add(log("sys-logs", "sudo priv esc", "10.0.10.21", "web-01",
                now.minusHours(2).minusMinutes(10), "HIGH",
                "sudo: www-data : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -p"));
        all.add(log("firewall-logs", "c2 outbound", "10.0.10.22", "web-02",
                now.minusHours(3).minusMinutes(20), "HIGH",
                "iptables: OUT 10.0.10.22:48223 -> 185.220.101.4:4444/tcp NEW conntrack"));

        List<RawLogLine> filtered = new ArrayList<>();
        String q = query == null ? "" : query.trim().toLowerCase();
        for (RawLogLine l : all) {
            boolean hit = q.isEmpty()
                    || l.getMessage().toLowerCase().contains(q)
                    || (l.getSrcIp() != null && l.getSrcIp().contains(q))
                    || (l.getRule() != null && l.getRule().toLowerCase().contains(q));
            if (hit) filtered.add(l);
            if (filtered.size() >= limit) break;
        }
        return filtered;
    }

    private RawLogLine log(String topic, String rule, String srcIp, String asset,
                           LocalDateTime time, String level, String message) {
        RawLogLine line = new RawLogLine(time.format(FMT), topic, rule, srcIp, asset, message);
        line.setLevel(level);
        return line;
    }

    // ==================== 工具 ====================

    private static String text(JsonNode n, String dflt) {
        if (n == null || n.isMissingNode() || n.isNull()) return dflt;
        String s = n.asText();
        return (s == null || s.isEmpty()) ? dflt : s;
    }

    /**
     * Wazuh 时间 → <b>本地时区</b>的 yyyy-MM-dd HH:mm:ss。
     *
     * <p>实现与事故说明见 {@link WazuhTime}（抽出去是为了能用固定时区写断言 ——
     * 依赖 JVM 默认时区的测试会在别的机器上飘，而会飘的测试最终一定会被忽略）。
     */
    private static String normalizeTime(String iso) {
        return WazuhTime.toLocal(iso, ZoneId.systemDefault());
    }

    private static String snippet(String s) {
        if (s == null) return "";
        s = s.trim();
        return s.length() > 200 ? s.substring(0, 200) + "..." : s;
    }
}
