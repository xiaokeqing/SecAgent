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
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
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
    @Value("${integration.wazuh.timeout:10}")
    private int timeout;
    @Value("${integration.wazuh.active-response-enabled:true}")
    private boolean activeResponseEnabled;

    private WazuhClient client;
    private volatile boolean available;

    @PostConstruct
    public void init() {
        if (!enabled) {
            logger.info("Wazuh 对接未启用（integration.wazuh.enabled=false），直接使用内置样本");
            return;
        }
        try {
            this.client = new WazuhClient(baseUrl, username, password, verifySsl, timeout);
            this.available = client.testConnection();
            if (available) {
                logger.info("Wazuh 已连接（REAL 模式）：{}", baseUrl);
            } else {
                logger.warn("Wazuh 无法连接（{}），降级为内置样本（MOCK）", baseUrl);
            }
        } catch (Exception e) {
            this.available = false;
            logger.warn("Wazuh 初始化异常，降级为内置样本（MOCK）：{}", e.getMessage());
        }
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

    /** 把 Wazuh /security/alerts 返回的 JSON 规整为 SecurityAlert。 */
    private List<SecurityAlert> mapRealAlerts(JsonNode root, int limit) {
        List<SecurityAlert> out = new ArrayList<>();
        JsonNode items = root.path("data").path("affected_items");
        if (items.isMissingNode() || !items.isArray()) {
            items = root.path("data");
        }
        if (!items.isArray()) {
            items = root.path("data").path("hits");
        }
        if (!items.isArray()) {
            return out;
        }
        for (JsonNode n : items) {
            if (out.size() >= limit) break;
            String ruleName = text(n.path("rule").path("name"), text(n.path("rule").path("id"), "wazuh-alert"));
            String levelRaw = text(n.path("rule").path("level"), "2");
            String ts = text(n.path("timestamp"), "");
            String srcIp = text(n.path("data").path("srcip"), text(n.path("data").path("src_ip"), ""));
            String dstIp = text(n.path("agent").path("ip"), "");
            String dstAsset = text(n.path("agent").path("name"), dstIp);
            String desc = text(n.path("data").path("description"), text(n.path("description"), ruleName));
            String raw = text(n.path("full_log"), n.toString());

            SecurityAlert a = new SecurityAlert(
                    text(n.path("id"), "wz-" + out.size()),
                    desc,
                    AlertSeverity.parse(levelRaw),
                    AlertType.guess(ruleName + " " + desc),
                    AlertSource.WAZUH);
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
                : "Wazuh 未连接真实服务（MOCK）";
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

    /** Wazuh 时间多为 ISO8601（如 2026-09-29T10:20:30.000Z），统一转成 yyyy-MM-dd HH:mm:ss。 */
    private static String normalizeTime(String iso) {
        if (iso == null || iso.isBlank()) {
            return LocalDateTime.now().format(FMT);
        }
        try {
            String s = iso.trim();
            // 兼容带时区的 ISO
            if (s.contains("T")) {
                s = s.replace('T', ' ');
            }
            // 去掉毫秒和时区后缀
            int dot = s.indexOf('.');
            if (dot > 0) s = s.substring(0, dot);
            s = s.replaceAll("[Zz]\\s*$", "").trim();
            return LocalDateTime.parse(s, DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")).format(FMT);
        } catch (Exception e) {
            return iso;
        }
    }

    private static String snippet(String s) {
        if (s == null) return "";
        s = s.trim();
        return s.length() > 200 ? s.substring(0, 200) + "..." : s;
    }
}
