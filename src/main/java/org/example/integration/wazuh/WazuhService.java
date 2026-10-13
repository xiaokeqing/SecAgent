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
