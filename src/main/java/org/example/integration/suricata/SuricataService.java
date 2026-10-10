package org.example.integration.suricata;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.core.model.AlertSeverity;
import org.example.core.model.AlertSource;
import org.example.core.model.AlertType;
import org.example.core.model.SecurityAlert;
import org.example.integration.SuricataGateway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Suricata 对接服务：逐行读取 eve.json，抽取 event_type=alert 的网络告警。
 *
 * <p>文件不存在 / 不可读 / 解析失败 → 自动降级 MOCK，返回内置网络告警样本
 * （ET SCAN 端口扫描、ET POLICY 可疑外联），保证开箱可演示。
 */
@Service
public class SuricataService implements SuricataGateway {

    private static final Logger logger = LoggerFactory.getLogger(SuricataService.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    /** 内存中最多保留多少条 alert 事件（防止 eve.json 巨大时占满内存） */
    private static final int MAX_CACHE = 200;

    @Value("${integration.suricata.enabled:true}")
    private boolean enabled;
    @Value("${integration.suricata.eve-json:/var/log/suricata/eve.json}")
    private String eveJsonPath;
    @Value("${integration.suricata.timeout:5}")
    private int timeout;

    private final ObjectMapper mapper = new ObjectMapper();
    private volatile boolean available;

    @PostConstruct
    public void init() {
        if (!enabled) {
            logger.info("Suricata 对接未启用，使用内置样本");
            return;
        }
        File f = new File(eveJsonPath);
        if (f.exists() && f.isFile() && f.canRead()) {
            this.available = true;
            logger.info("Suricata eve.json 可读（REAL 模式）：{}", eveJsonPath);
        } else {
            this.available = false;
            logger.warn("Suricata eve.json 不存在或不可读（{}），降级为内置网络告警样本（MOCK）", eveJsonPath);
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

    @Override
    public List<SecurityAlert> recentNetworkAlerts(int limit) {
        if (available) {
            try {
                List<SecurityAlert> real = readFromEve(limit);
                if (!real.isEmpty()) {
                    return real;
                }
            } catch (Exception e) {
                logger.warn("读取 eve.json 失败，回退内置样本：{}", e.getMessage());
            }
        }
        return builtinAlerts(limit);
    }

    /** 逐行读 eve.json，只保留 event_type=alert 的最后若干条。 */
    private List<SecurityAlert> readFromEve(int limit) throws Exception {
        Deque<JsonNode> alerts = new ArrayDeque<>();
        try (BufferedReader br = new BufferedReader(new FileReader(eveJsonPath))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                try {
                    JsonNode n = mapper.readTree(line);
                    if ("alert".equalsIgnoreCase(n.path("event_type").asText())) {
                        alerts.addLast(n);
                        if (alerts.size() > MAX_CACHE) alerts.removeFirst();
                    }
                } catch (Exception parseErr) {
                    // 坏行跳过，不影响整体
                }
            }
        }
        List<SecurityAlert> out = new ArrayList<>();
        // 取最后 limit 条（最新的在文件尾部）
        int skip = Math.max(0, alerts.size() - Math.min(limit, alerts.size()));
        int i = 0;
        for (JsonNode n : alerts) {
            if (i++ < skip) continue;
            out.add(toAlert(n, "suricata-eve-" + out.size()));
        }
        return out;
    }

    private SecurityAlert toAlert(JsonNode n, String fallbackId) {
        String signature = n.path("alert").path("signature").asText("suricata-alert");
        String category = n.path("alert").path("category").asText("");
        int severity = n.path("alert").path("severity").asInt(2);
        String srcIp = n.path("src_ip").asText("");
        String dstIp = n.path("dest_ip").asText("");
        int dstPort = n.path("dest_port").asInt(0);
        String proto = n.path("proto").asText("");
        String timestamp = n.path("timestamp").asText("");

        SecurityAlert a = new SecurityAlert(fallbackId, signature,
                AlertSeverity.parse(severity),
                AlertType.guess(signature + " " + category),
                AlertSource.SURICATA);
        a.setRuleName(signature);
        a.setSrcIp(srcIp);
        a.setDstIp(dstIp);
        a.setDstAsset(dstIp);
        a.setDstPort(dstPort > 0 ? dstPort : null);
        a.setService(proto);
        a.setDescription("[" + category + "] " + signature);
        a.setRawLog(n.toString());
        a.setOccurredAt(normalizeTime(timestamp));
        Map<String, Object> extra = new HashMap<>();
        extra.put("category", category);
        extra.put("severity", severity);
        extra.put("proto", proto);
        a.setExtra(extra);
        return a;
    }

    // ==================== 内置网络样本（MOCK） ====================

    /**
     * 内置 eve 风格网络告警样本：ET SCAN 扫描、ET POLICY 可疑外联等。
     * 给出的示例 eve 行（真实文件里长这样）：
     * {"event_type":"alert","timestamp":"...","src_ip":"203.0.113.66","dest_ip":"10.0.10.21",
     *  "dest_port":443,"proto":"TCP","alert":{"signature":"ET SCAN Potential SSL Exploit Scanning",
     *  "category":"Attempted Information Leak","severity":2}}
     */
    private List<SecurityAlert> builtinAlerts(int limit) {
        LocalDateTime now = LocalDateTime.now();
        List<SecurityAlert> all = new ArrayList<>();

        all.add(make("sur-mock-001", "ET SCAN 潜在 SSL 漏洞利用扫描", "Attempted Information Leak",
                2, "203.0.113.66", "扫描器出口", "10.0.10.21", "web-01", 443, "TCP",
                now.minusMinutes(12),
                "{\"event_type\":\"alert\",\"src_ip\":\"203.0.113.66\",\"dest_ip\":\"10.0.10.21\",\"dest_port\":443,\"proto\":\"TCP\",\"alert\":{\"signature\":\"ET SCAN Potential SSL Exploit Scanning\",\"category\":\"Attempted Information Leak\",\"severity\":2}}",
                1));
        all.add(make("sur-mock-002", "ET POLICY 主机向陌生端口可疑外联", "Potential Corporate Privacy Violation",
                3, "10.0.10.22", "web-02 本机", "198.51.100.20", "未知外部主机", 8080, "TCP",
                now.minusMinutes(28),
                "{\"event_type\":\"alert\",\"src_ip\":\"10.0.10.22\",\"dest_ip\":\"198.51.100.20\",\"dest_port\":8080,\"proto\":\"TCP\",\"alert\":{\"signature\":\"ET POLICY UnixSuspicious outbound port 8080\",\"category\":\"Potential Corporate Privacy Violation\",\"severity\":3}}",
                5));
        all.add(make("sur-mock-003", "ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT", "Attempted User Privilege Gain",
                1, "45.83.91.12", "东欧 VPS", "10.0.10.22", "web-02", 80, "TCP",
                now.minusMinutes(24),
                "{\"event_type\":\"alert\",\"src_ip\":\"45.83.91.12\",\"dest_ip\":\"10.0.10.22\",\"dest_port\":80,\"proto\":\"TCP\",\"alert\":{\"signature\":\"ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT\",\"category\":\"Attempted User Privilege Gain\",\"severity\":1}}",
                8));
        all.add(make("sur-mock-004", "ET SCAN 横向端口扫描（内网）", "Attempted Information Leak",
                2, "10.0.10.30", "内网主机", "10.0.10.0/24", "web-01", 22, "TCP",
                now.minusHours(1).minusMinutes(40),
                "{\"event_type\":\"alert\",\"src_ip\":\"10.0.10.30\",\"dest_ip\":\"10.0.10.21\",\"dest_port\":22,\"proto\":\"TCP\",\"alert\":{\"signature\":\"ET SCAN SSH brute force from same src\",\"category\":\"Attempted Information Leak\",\"severity\":2}}",
                60));
        all.add(make("sur-mock-005", "ET DDoS SYN Flood 迹象", "Misc Attack",
                1, "203.0.113.77", "境外", "10.0.10.21", "web-01", 80, "TCP",
                now.minusHours(2).minusMinutes(5),
                "{\"event_type\":\"alert\",\"src_ip\":\"203.0.113.77\",\"dest_ip\":\"10.0.10.21\",\"dest_port\":80,\"proto\":\"TCP\",\"alert\":{\"signature\":\"ET DDoS possible SYN flood high packet rate\",\"category\":\"Misc Attack\",\"severity\":1}}",
                320));

        int n = Math.min(limit, all.size());
        return new ArrayList<>(all.subList(0, n));
    }

    private SecurityAlert make(String id, String signature, String category, int severity,
                               String srcIp, String srcGeo, String dstIp, String dstAsset,
                               int dstPort, String proto, LocalDateTime time, String raw, int count) {
        SecurityAlert a = new SecurityAlert(id, "[" + category + "] " + signature,
                AlertSeverity.parse(severity),
                AlertType.guess(signature + " " + category),
                AlertSource.SURICATA);
        a.setRuleName(signature);
        a.setSrcIp(srcIp);
        a.setSrcGeo(srcGeo);
        a.setDstIp(dstIp);
        a.setDstAsset(dstAsset);
        a.setDstPort(dstPort);
        a.setService(proto);
        a.setDescription("[" + category + "] " + signature);
        a.setRawLog(raw);
        a.setOccurredAt(time.format(FMT));
        a.setCount(count);
        Map<String, Object> extra = new HashMap<>();
        extra.put("category", category);
        extra.put("severity", severity);
        extra.put("proto", proto);
        extra.put("mock", true);
        a.setExtra(extra);
        return a;
    }

    private static String normalizeTime(String iso) {
        if (iso == null || iso.isBlank()) {
            return LocalDateTime.now().format(FMT);
        }
        try {
            String s = iso.trim().replace('T', ' ');
            int dot = s.indexOf('.');
            if (dot > 0) s = s.substring(0, dot);
            s = s.replaceAll("[Zz]\\s*$", "").trim();
            return LocalDateTime.parse(s, DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")).format(FMT);
        } catch (Exception e) {
            return iso;
        }
    }
}
