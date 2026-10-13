package org.example.agent.tool;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * 安全告警查询工具
 * 用于查询告警系统（如 Prometheus/Alertmanager、WAF/IDS 汇聚的告警）中的活动安全告警。
 * 支持 Mock 模式，提供与安全日志、知识库相互印证的模拟安全告警数据。
 */
@Component
public class QueryMetricsTools {

    private static final Logger logger = LoggerFactory.getLogger(QueryMetricsTools.class);

    /** 工具名常量，用于动态构建提示词 */
    public static final String TOOL_QUERY_PROMETHEUS_ALERTS = "queryPrometheusAlerts";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${prometheus.base-url}")
    private String prometheusBaseUrl;

    @Value("${prometheus.timeout:10}")
    private int timeout;

    @Value("${prometheus.mock-enabled:false}")
    private boolean mockEnabled;

    private OkHttpClient httpClient;

    @jakarta.annotation.PostConstruct
    public void init() {
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(Duration.ofSeconds(timeout))
                .readTimeout(Duration.ofSeconds(timeout))
                .build();
        logger.info("✅ QueryMetricsTools 初始化成功, 告警系统 URL: {}, Mock模式: {}", prometheusBaseUrl, mockEnabled);
    }

    /**
     * 查询当前活动安全告警（支持可选时间窗口过滤，如近 1 小时 / 24 小时）
     */
    @Tool(description = "Query currently active security alerts (e.g. SSH brute-force, SQL injection, webshell upload, directory scanning) " +
            "from the alerting system. Returns active/firing alerts with name, description, severity, state and active time. " +
            "Optionally filter by time window, e.g. '1h' for the last hour or '24h' for the last 24 hours. " +
            "Use this at the beginning of a security incident investigation to know what attacks are happening now.")
    public String queryPrometheusAlerts(
            @ToolParam(required = false, description = "Time window filter, e.g. '1h' / '30m' / '24h'; empty or absent means no filter")
            String timeRange) {
        logger.info("开始查询活动安全告警, Mock模式: {}, timeRange: {}", mockEnabled, timeRange);

        // 【公开身份：工具层直接拒绝（F2 收紧，2026-10-13）】
        // 活动告警是内部真实事件数据（告警名/描述/活跃时间），公开面一律不读；
        // 编排层已把公开身份挡在取证分支外，这里再挡一层并留痕。
        if (org.example.security.EvalIdentity.isPublicRequest()) {
            logger.warn("公开身份请求被拒绝：queryPrometheusAlerts（公开面不读取内部告警数据）");
            return buildErrorResponse("公开身份不得读取内部告警数据：公开面只基于公开知识库回答，不读取内部事件数据。",
                    "public-identity-no-internal-data");
        }

        try {
            List<SimplifiedAlert> simplifiedAlerts;

            if (mockEnabled) {
                simplifiedAlerts = buildMockAlerts();
                simplifiedAlerts = filterByTimeRange(simplifiedAlerts, timeRange);
                logger.info("使用 Mock 数据，按时间窗口过滤后返回 {} 个模拟安全告警", simplifiedAlerts.size());
            } else {
                PrometheusAlertsResult result = fetchPrometheusAlerts();

                if (!"success".equals(result.getStatus())) {
                    return buildErrorResponse("告警系统 API 返回非成功状态: " + result.getStatus(), result.getError());
                }

                Set<String> seenAlertNames = new HashSet<>();
                simplifiedAlerts = new ArrayList<>();

                for (PrometheusAlert alert : result.getData().getAlerts()) {
                    String alertName = alert.getLabels().get("alertname");
                    if (seenAlertNames.contains(alertName)) {
                        continue;
                    }
                    seenAlertNames.add(alertName);

                    SimplifiedAlert simplified = new SimplifiedAlert();
                    simplified.setAlertName(alertName);
                    simplified.setDescription(alert.getAnnotations().getOrDefault("description", ""));
                    simplified.setState(alert.getState());
                    simplified.setActiveAt(alert.getActiveAt());
                    simplified.setDuration(calculateDuration(alert.getActiveAt()));

                    simplifiedAlerts.add(simplified);
                }
            }

            PrometheusAlertsOutput output = new PrometheusAlertsOutput();
            output.setSuccess(true);
            output.setAlerts(simplifiedAlerts);
            // 数据源打标：Mock/降级模式下明确标识为演示样本，避免把模拟数据误当真实告警
            String dataSourceNote = mockEnabled ? "（演示样本数据，非真实告警）" : "";
            output.setMessage(String.format("成功检索到 %d 个活动安全告警%s", simplifiedAlerts.size(), dataSourceNote));

            String jsonResult = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(output);
            logger.info("安全告警查询完成: 找到 {} 个告警", simplifiedAlerts.size());

            // 告警描述含攻击者可控文本，包裹为"不可信数据"并做提示注入检测
            return new org.example.security.PromptInjectionGuard().wrapUntrusted("安全告警", jsonResult);

        } catch (Exception e) {
            logger.error("查询安全告警失败", e);
            return buildErrorResponse("查询失败", e.getMessage());
        }
    }

    /**
     * 按时间窗口过滤告警（Mock/本地演示生效；真实告警源由上游按窗口查询）。
     * 支持格式：数字+单位（s=秒 / m=分钟 / h=小时 / d=天），如 1h、30m、24h；裸数字按分钟计。
     */
    private List<SimplifiedAlert> filterByTimeRange(List<SimplifiedAlert> alerts, String timeRange) {
        if (timeRange == null || timeRange.trim().isEmpty()) {
            return alerts;
        }
        long windowMs = parseWindowMs(timeRange.trim());
        if (windowMs <= 0) {
            return alerts;
        }
        Instant cutoff = Instant.now().minus(windowMs, ChronoUnit.MILLIS);
        List<SimplifiedAlert> filtered = new ArrayList<>();
        for (SimplifiedAlert a : alerts) {
            try {
                Instant at = Instant.parse(a.getActiveAt());
                if (at.isAfter(cutoff)) {
                    filtered.add(a);
                }
            } catch (Exception e) {
                filtered.add(a); // 时间解析失败不误删
            }
        }
        return filtered;
    }

    /** 解析时间窗口表达式为毫秒；无法解析返回 -1（表示不启用过滤） */
    private long parseWindowMs(String timeRange) {
        try {
            String s = timeRange.trim();
            if (s.endsWith("h")) {
                return Long.parseLong(s.substring(0, s.length() - 1)) * 3_600_000L;
            }
            if (s.endsWith("m")) {
                return Long.parseLong(s.substring(0, s.length() - 1)) * 60_000L;
            }
            if (s.endsWith("d")) {
                return Long.parseLong(s.substring(0, s.length() - 1)) * 86_400_000L;
            }
            if (s.endsWith("s")) {
                return Long.parseLong(s.substring(0, s.length() - 1)) * 1_000L;
            }
            return Long.parseLong(s) * 60_000L; // 裸数字默认分钟
        } catch (Exception e) {
            return -1;
        }
    }

    /**
     * 构建 Mock 安全告警数据（与安全日志、安全知识库相互印证）
     */
    private List<SimplifiedAlert> buildMockAlerts() {
        List<SimplifiedAlert> alerts = new ArrayList<>();
        Instant now = Instant.now();

        // 告警1：SSH 暴力破解 - 严重
        SimplifiedAlert sshAlert = new SimplifiedAlert();
        sshAlert.setAlertName("SSHBruteForce");
        sshAlert.setDescription("【严重】检测到针对堡垒机/主机 web-01（10.0.10.21）SSH(22端口) 的暴力破解："
                + "来源 IP 103.146.184.77 在 10 分钟内触发 217 次登录失败，随后出现 1 次登录成功，疑似爆破得手，需要立即核查。");
        sshAlert.setState("firing");
        Instant sshAt = now.minus(22, ChronoUnit.MINUTES);
        sshAlert.setActiveAt(sshAt.toString());
        sshAlert.setDuration(calculateDuration(sshAt.toString()));
        alerts.add(sshAlert);

        // 告警2：SQL 注入攻击 - 高危
        SimplifiedAlert sqlAlert = new SimplifiedAlert();
        sqlAlert.setAlertName("WebSqlInjection");
        sqlAlert.setDescription("【高危】WAF 检测到对站点 api.example.com 接口 /api/order/detail?id= 的 SQL 注入尝试，"
                + "载荷包含 union select 与 information_schema，来源 IP 45.83.91.12，5 分钟内 36 次，部分请求绕过前置规则到达应用。");
        sqlAlert.setState("firing");
        Instant sqlAt = now.minus(12, ChronoUnit.MINUTES);
        sqlAlert.setActiveAt(sqlAt.toString());
        sqlAlert.setDuration(calculateDuration(sqlAt.toString()));
        alerts.add(sqlAlert);

        // 告警3：Webshell 上传与访问 - 严重
        SimplifiedAlert webshellAlert = new SimplifiedAlert();
        webshellAlert.setAlertName("WebshellDetected");
        webshellAlert.setDescription("【严重】Web 主机 web-02 的上传目录 /upload/files/ 下检测到脚本文件 x.asp;.jpg 被访问，"
                + "URL 特征符合一句话木马，来源 IP 103.146.184.77，疑似已落地 WebShell。");
        webshellAlert.setState("firing");
        Instant webAt = now.minus(8, ChronoUnit.MINUTES);
        webshellAlert.setActiveAt(webAt.toString());
        webshellAlert.setDuration(calculateDuration(webAt.toString()));
        alerts.add(webshellAlert);

        // 告警4：目录扫描/探测 - 中危
        SimplifiedAlert scanAlert = new SimplifiedAlert();
        scanAlert.setAlertName("DirectoryScanning");
        scanAlert.setDescription("【中危】检测到对 api.example.com 的高频目录扫描，1 分钟内 400+ 次 404，"
                + "探测路径包含 /admin、/.env、/phpmyadmin、/actuator，来源 IP 45.83.91.12，疑似自动化漏扫器。");
        scanAlert.setState("firing");
        Instant scanAt = now.minus(5, ChronoUnit.MINUTES);
        scanAlert.setActiveAt(scanAt.toString());
        scanAlert.setDuration(calculateDuration(scanAt.toString()));
        alerts.add(scanAlert);

        return alerts;
    }

    /**
     * 从告警系统 API 获取告警数据
     */
    private PrometheusAlertsResult fetchPrometheusAlerts() throws Exception {
        String apiUrl = prometheusBaseUrl + "/api/v1/alerts";
        logger.debug("请求告警系统 API: {}", apiUrl);

        Request request = new Request.Builder()
                .url(apiUrl)
                .get()
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new RuntimeException("HTTP 请求失败: " + response.code());
            }

            String responseBody = response.body().string();
            return objectMapper.readValue(responseBody, PrometheusAlertsResult.class);
        }
    }

    private String calculateDuration(String activeAtStr) {
        try {
            Instant activeAt = Instant.parse(activeAtStr);
            Duration duration = Duration.between(activeAt, Instant.now());

            long hours = duration.toHours();
            long minutes = duration.toMinutes() % 60;
            long seconds = duration.getSeconds() % 60;

            if (hours > 0) {
                return String.format("%dh%dm%ds", hours, minutes, seconds);
            } else if (minutes > 0) {
                return String.format("%dm%ds", minutes, seconds);
            } else {
                return String.format("%ds", seconds);
            }
        } catch (Exception e) {
            logger.warn("解析时间失败: {}", activeAtStr, e);
            return "unknown";
        }
    }

    private String buildErrorResponse(String message, String error) {
        try {
            PrometheusAlertsOutput output = new PrometheusAlertsOutput();
            output.setSuccess(false);
            output.setMessage(message);
            output.setError(error);
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(output);
        } catch (Exception e) {
            return String.format("{\"success\":false,\"message\":\"%s\",\"error\":\"%s\"}", message, error);
        }
    }

    // ==================== 数据模型 ====================

    @Data
    public static class PrometheusAlert {
        private Map<String, String> labels;
        private Map<String, String> annotations;
        private String state;
        private String activeAt;
        private String value;
    }

    @Data
    public static class PrometheusAlertsResult {
        private String status;
        private AlertsData data;
        private String error;
        private String errorType;
    }

    @Data
    public static class AlertsData {
        private List<PrometheusAlert> alerts = new ArrayList<>();
    }

    @Data
    public static class SimplifiedAlert {
        @JsonProperty("alert_name")
        private String alertName;

        @JsonProperty("description")
        private String description;

        @JsonProperty("state")
        private String state;

        @JsonProperty("active_at")
        private String activeAt;

        @JsonProperty("duration")
        private String duration;
    }

    @Data
    public static class PrometheusAlertsOutput {
        @JsonProperty("success")
        private boolean success;

        @JsonProperty("alerts")
        private List<SimplifiedAlert> alerts;

        @JsonProperty("message")
        private String message;

        @JsonProperty("error")
        private String error;
    }
}
