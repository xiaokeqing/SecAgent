package org.example.integration.suricata;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.core.model.AlertSeverity;
import org.example.core.model.AlertSource;
import org.example.core.model.AlertType;
import org.example.core.model.SecurityAlert;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * eve.json 单行 → 事件记录的解析器。
 *
 * <p>为什么把解析从 {@link SuricataService} 里拆出来：服务类负责"文件怎么读、降到什么模式"，
 * 解析器负责"一行 JSON 怎么变成一个记录"。拆开后解析逻辑可以不启动 Spring、不碰文件系统直接单测，
 * 而 eve.json 的字段位置（http.http_user_agent、tls.ja3.hash、dns.answers[]）正是最容易写错的地方。
 *
 * <p>失败即降级：坏行、未知 event_type 一律返回 null，由调用方跳过。日志里一行坏 JSON 不该
 * 让整批事件都丢掉，这是读日志文件必须遵守的口径。
 */
public final class EveEventParser {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final ObjectMapper mapper;
    /** 仅用于给缓冲里的告警生成不重复的 id（现有 /api/alerts 的 id 仍由调用方按序号生成） */
    private final AtomicLong seq = new AtomicLong();

    public EveEventParser(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    /** 解析一行；空行/坏行/不认识的类型返回 null。 */
    public EveEvent parseLine(String line) {
        if (line == null || line.isBlank()) {
            return null;
        }
        try {
            return parse(mapper.readTree(line));
        } catch (Exception e) {
            // 单行坏 JSON：跳过，不影响同批次其他行
            return null;
        }
    }

    /** 解析一条已解析的 JSON 节点。 */
    public EveEvent parse(JsonNode n) {
        if (n == null || n.isNull()) {
            return null;
        }
        String type = n.path("event_type").asText("");
        if (type.isEmpty()) {
            return null;
        }
        switch (type.toLowerCase(Locale.ROOT)) {
            case "alert":
                return new AlertEvent(parseTime(n.path("timestamp").asText("")),
                        toSecurityAlert(n, "suricata-eve-" + seq.incrementAndGet()));
            case "flow":
                return toFlow(n, "flow");
            case "netflow":
                return toFlow(n, "netflow");
            case "http":
                return toHttp(n);
            case "dns":
                return toDns(n);
            case "tls":
                return toTls(n);
            default:
                // stats / fileinfo / dhcp 等不在反查范围内：不占缓冲，也不报错
                return null;
        }
    }

    // ==================== 各类型 ====================

    private FlowEvent toFlow(JsonNode n, String eventType) {
        JsonNode flow = n.path("flow");
        return new FlowEvent(
                eventType,
                parseTime(n.path("timestamp").asText("")),
                text(n, "src_ip"),
                n.path("src_port").asInt(0),
                text(n, "dest_ip"),
                n.path("dest_port").asInt(0),
                text(n, "proto"),
                text(n, "app_proto"),
                flow.path("bytes_toserver").asLong(0),
                flow.path("bytes_toclient").asLong(0),
                flow.path("pkts_toserver").asLong(0),
                flow.path("pkts_toclient").asLong(0),
                parseTime(flow.path("start").asText("")),
                parseTime(flow.path("end").asText("")));
    }

    private HttpEvent toHttp(JsonNode n) {
        JsonNode http = n.path("http");
        int status = http.path("status").asInt(0);
        if (status == 0) {
            // 少数版本把响应码放在顶层 http.status 之外
            status = n.path("status").asInt(0);
        }
        String ua = text(http, "http_user_agent");
        if (ua.isEmpty()) {
            ua = text(n, "http_user_agent");
        }
        return new HttpEvent(
                parseTime(n.path("timestamp").asText("")),
                text(n, "src_ip"),
                text(n, "dest_ip"),
                text(http, "hostname"),
                text(http, "url"),
                text(http, "http_method"),
                status,
                ua);
    }

    private DnsEvent toDns(JsonNode n) {
        JsonNode dns = n.path("dns");
        List<String> answers = new ArrayList<>();
        JsonNode arr = dns.path("answers");
        if (arr.isArray()) {
            for (JsonNode a : arr) {
                String row = (text(a, "rrname") + " " + text(a, "rrtype") + " " + text(a, "rdata")).trim();
                if (!row.isEmpty()) {
                    answers.add(row);
                }
            }
        }
        return new DnsEvent(
                parseTime(n.path("timestamp").asText("")),
                text(n, "src_ip"),
                text(n, "dest_ip"),
                text(dns, "rrname"),
                text(dns, "rrtype"),
                text(dns, "rcode"),
                List.copyOf(answers));
    }

    private TlsEvent toTls(JsonNode n) {
        JsonNode tls = n.path("tls");
        return new TlsEvent(
                parseTime(n.path("timestamp").asText("")),
                text(n, "src_ip"),
                text(n, "dest_ip"),
                n.path("dest_port").asInt(0),
                text(tls, "sni"),
                text(tls, "version"),
                text(tls.path("ja3"), "hash"),
                text(tls.path("ja3s"), "hash"),
                text(tls, "fingerprint"));
    }

    /**
     * 把 aleart 事件转成现有告警模型（原 {@code SuricataService#toAlert} 的搬迁，行为不变）。
     *
     * <p>放在解析器里是为了让"文件直读"与"环形缓冲"两条路径共用同一份字段映射 ——
     * 两处各写一遍，改一处漏一处时不会报错，只会让同一个告警在两个接口里长得不一样。
     */
    public SecurityAlert toSecurityAlert(JsonNode n, String id) {
        String signature = n.path("alert").path("signature").asText("suricata-alert");
        String category = n.path("alert").path("category").asText("");
        int severity = n.path("alert").path("severity").asInt(2);
        String srcIp = n.path("src_ip").asText("");
        String dstIp = n.path("dest_ip").asText("");
        int dstPort = n.path("dest_port").asInt(0);
        String proto = n.path("proto").asText("");
        String timestamp = n.path("timestamp").asText("");

        SecurityAlert a = new SecurityAlert(id, signature,
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

    // ==================== 工具 ====================

    /**
     * 取字段文本，兼容"单值 / 单元素数组"两种形态。
     *
     * <p>为什么需要：{@code tls.fingerprint}、{@code tls.sni} 在不同 Suricata 版本里
     * 有字符串和数组两种写法。只处理字符串时，数组会解析成空串 —— 不报错，只是整列 SNI 全空。
     */
    private static String text(JsonNode node, String field) {
        JsonNode v = node.path(field);
        if (v.isArray()) {
            v = v.path(0);
        }
        return v.asText("");
    }

    /**
     * 解析 eve.json 时间戳，失败返回 null（不拿当前时间顶替，否则"时间未知"会被伪装成"刚刚发生"）。
     *
     * <p>兼容三种真实形态：
     * {@code 2026-11-06T22:24:47.123456+0800}（偏移无冒号）、
     * {@code ...Z} / {@code ...+08:00}、以及不带时区的裸本地时间。
     *
     * <p>口径：**带偏移的时间戳一律按偏移换算成瞬时**（+0000 与 Z 等价），绝不走无时区的
     * {@code LocalDateTime}。原因：Suricata 在 UTC 主机上写的是 {@code 16:11:02.911209+0000}，
     * 若把这个偏移丢掉、按 JVM 时区（+08）解释成 16:11 本地，事件会凭空早 8 小时，
     * 于是"最近 60 分钟"这类窗口一条都命中不到 —— 端点返回空列表却不报任何错。
     */
    public static Instant parseTime(String iso) {
        if (iso == null) {
            return null;
        }
        String s = iso.trim();
        if (s.isEmpty()) {
            return null;
        }
        // eve.json 常见 "+0800"：ISO 解析器要求 "+08:00"，先补冒号。
        // 这一步必须保留，否则带偏移的字符串会落进下面的裸本地时间分支
        if (s.matches(".*[+-]\\d{4}$")) {
            s = s.substring(0, s.length() - 2) + ":" + s.substring(s.length() - 2);
        }
        // 先按"带偏移"解析：OffsetDateTime 同时接受 +08:00 与 Z，
        // 且转换结果就是绝对瞬时，不受 JVM 默认时区影响
        try {
            return OffsetDateTime.parse(s).toInstant();
        } catch (Exception ignored) {
            // 继续尝试 Instant 的严格形态
        }
        try {
            return Instant.parse(s);
        } catch (Exception ignored) {
            // 继续尝试裸本地时间
        }
        // 只有完全不带偏移时才按 JVM 时区解释：eve.json 不产这种形态，留作兜底
        try {
            return LocalDateTime.parse(s.replace(' ', 'T'))
                    .atZone(ZoneId.systemDefault()).toInstant();
        } catch (Exception ignored) {
            return null;
        }
    }

    /** 转成项目里通用的 "yyyy-MM-dd HH:mm:ss"（沿用原 normalizeTime 的口径与降级行为）。 */
    public static String normalizeTime(String iso) {
        Instant instant = parseTime(iso);
        if (instant == null) {
            if (iso == null || iso.isBlank()) {
                return LocalDateTime.now().format(FMT);
            }
            return iso;
        }
        return LocalDateTime.ofInstant(instant, ZoneId.systemDefault()).format(FMT);
    }
}
