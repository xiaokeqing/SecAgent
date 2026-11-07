package org.example.publicapi;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.geoip.GeoIpInfo;
import org.example.geoip.GeoIpService;
import org.example.integration.SuricataGateway;
import org.example.integration.suricata.FlowEvent;
import org.example.integration.suricata.Ja3Count;
import org.example.integration.suricata.PortCount;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * 公开只读端点：连接统计的<b>脱敏投影</b>（top-ports / by-ip / tls-stats）。
 *
 * <p>与 {@code /api/sec/conn/*} 的关系：同一份 Suricata 连接缓冲，
 * 但公开面只回答三件事 —— 端口号+次数、国家+次数、JA3 指纹+次数。
 * 完整 IP、内网地址、目的地址、字节数、时间线一律不出现在响应里。
 *
 * <h3>IP 口径</h3>
 * 不像其它公开端点那样跟随 {@code app.public.mask-ips} 开关：
 * 本端点即使在全站"显示真实来源 IP"的口径下，也<b>固定</b>把 IP 遮蔽成
 * {@code 1.2.3.x}（只留前三段），内网/保留地址直接拒绝查询（400 INTERNAL_IP）。
 * 原因：端口/国家/JA3 已经能回答"这个站在被扫什么"，再给完整来源地址，
 * 就等于免费提供一份攻击源情报聚合；这与"公开面板"的目的不成比例。
 */
@RestController
@RequestMapping("/api/public")
public class PublicConnController {

    /** 公开面比登录面更严：一次最多 100 条，窗口最长 24 小时 */
    static final int MAX_LIMIT = 100;
    static final int MAX_MINUTES = 1440;

    private static final Set<String> VIEWS = Set.of("all", "top-ports", "by-ip", "tls-stats");
    private static final String DISCLOSURE_NOTICE =
            "连接统计只提供脱敏聚合（端口号+次数 / 国家+次数 / JA3+次数）；IP 一律遮蔽为 1.2.3.x，"
                    + "内网与保留地址不展示";

    private final PublicApiSupport support;
    private final SuricataGateway suricata;

    @Autowired(required = false)
    private GeoIpService geoIpService;

    public PublicConnController(PublicApiSupport support, SuricataGateway suricata) {
        this.support = support;
        this.suricata = suricata;
    }

    @GetMapping({"/conn", "/conn.js"})
    public Object conn(@RequestParam(value = "view", required = false) String view,
                       @RequestParam(value = "ip", required = false) String ip,
                       @RequestParam(value = "minutes", defaultValue = "15") int minutes,
                       @RequestParam(value = "limit", defaultValue = "10") int limit,
                       HttpServletRequest req, HttpServletResponse res) {
        if (!support.rateLimiter.allow(support.clientIp(req))) {
            return support.tooMany(res);
        }
        String v = (view == null || view.isBlank())
                ? "all" : view.trim().toLowerCase(Locale.ROOT);
        if (!VIEWS.contains(v)) {
            return support.badRequest(res, "VIEW_NOT_SUPPORTED",
                    "view 只支持 all / top-ports / by-ip / tls-stats");
        }
        int window = clamp(minutes, 1, MAX_MINUTES);
        int top = clamp(limit, 1, MAX_LIMIT);

        String mode = safeMode();
        boolean real = "REAL".equalsIgnoreCase(mode);

        List<Map<String, Object>> ports = List.of();
        List<Map<String, Object>> ja3 = List.of();
        List<Map<String, Object>> countries = List.of();
        String maskedIp = null;
        List<String> notes = new ArrayList<>();

        if (!real) {
            notes.add("连接数据源不是 REAL（当前 " + mode
                    + "）：不返回任何连接统计，也不以内置样本顶替");
        } else {
            if ("all".equals(v) || "top-ports".equals(v)) {
                ports = projectPorts(suricata.topDestPorts(window, top));
            }
            if ("all".equals(v) || "tls-stats".equals(v)) {
                ja3 = projectJa3(suricata.ja3Stats(window, top));
            }
            if (ip != null && !ip.isBlank()) {
                String host = PublicIpMask.host(ip);
                if (!PublicIpMask.isIpLiteral(host)) {
                    return support.badRequest(res, "INVALID_IP", "ip 不是合法的 IP 地址");
                }
                if (PublicIpMask.isInternalAddress(host)) {
                    // 不回显输入值：400 的 message 里也不带这个内网地址
                    return support.badRequest(res, "INTERNAL_IP",
                            "内网/保留地址不提供公开查询");
                }
                maskedIp = maskForPublic(host);
                List<FlowEvent> flows = suricata.connectionsByIp(host, top);
                long count = flows == null ? 0 : flows.size();
                if (count > 0) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("country", countryOf(host));
                    row.put("count", count);
                    countries = List.of(row);
                } else {
                    notes.add("该地址在当前连接缓冲中没有记录（0 条，真实结果）");
                }
                if (count >= top) {
                    notes.add("该来源的连接记录达到 limit 上限，次数按前 " + top + " 条统计");
                }
            }
            if (("all".equals(v) || "by-ip".equals(v)) && maskedIp == null) {
                notes.add("国家分布需要 ?ip= 参数：只返回该来源的国家 + 次数，IP 输出为 1.2.3.x");
            }
            if (notes.isEmpty()) {
                notes.add("只提供脱敏聚合：端口号+次数、国家+次数、JA3 指纹+次数");
            }
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("mode", real ? "REAL" : mode);
        data.put("generatedAt", support.generatedAt());
        data.put("view", v);
        data.put("minutes", window);
        data.put("limit", top);
        data.put("ports", ports);
        data.put("countries", countries);
        data.put("ja3", ja3);
        if (maskedIp != null) {
            data.put("ip", maskedIp);
        }
        data.put("note", String.join("；", notes));
        data.put("ipDisclosure", disclosure());
        return support.ok(data, res);
    }

    private String safeMode() {
        try {
            String m = suricata.mode();
            return (m == null || m.isBlank()) ? "UNAVAILABLE" : m.trim();
        } catch (RuntimeException e) {
            return "UNAVAILABLE";
        }
    }

    /** 端口号 + 次数：{@link PortCount} 本来就只有这两个字段，这里显式重建以固定契约。 */
    private static List<Map<String, Object>> projectPorts(List<PortCount> rows) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (rows == null) return out;
        for (PortCount p : rows) {
            if (p == null) continue;
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("port", p.port());
            row.put("count", p.count());
            out.add(row);
        }
        return out;
    }

    /** JA3 指纹 + 次数（指纹本身不是 IP，原样给出才有比对价值）。 */
    private static List<Map<String, Object>> projectJa3(List<Ja3Count> rows) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (rows == null) return out;
        for (Ja3Count j : rows) {
            if (j == null) continue;
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("ja3", j.ja3());
            row.put("count", j.count());
            out.add(row);
        }
        return out;
    }

    private String countryOf(String host) {
        if (geoIpService == null) {
            return PublicIpPolicy.UNKNOWN_LABEL;
        }
        try {
            GeoIpInfo info = geoIpService.lookup(host);
            if (info != null && info.hasCountry()
                    && info.getCountry() != null && !info.getCountry().isBlank()) {
                return info.getCountry();
            }
        } catch (RuntimeException ignored) {
            // 地理库不可用就写"未知"：不能因为查不到国家就把整条统计丢掉
        }
        return PublicIpPolicy.UNKNOWN_LABEL;
    }

    /**
     * 固定遮蔽口径：IPv4 → 前三段 + {@code .x}（如 {@code 45.205.1.x}）；
     * IPv6 → 前三组 + {@code :x}；内网/不可识别 → {@link PublicIpMask#INTERNAL_UNKNOWN_LABEL}/{@code ***}。
     *
     * <p>不走 {@link PublicIpMask#mask(String)}：那是"保留两段"的历史口径（{@code 45.205.***.***}），
     * 而本端点要求给出能在端口/国家维度对照的网段（{@code 1.2.3.x}）。
     */
    static String maskForPublic(String raw) {
        String host = PublicIpMask.host(raw);
        if (host == null || !PublicIpMask.isIpLiteral(host)) {
            return "***";
        }
        if (PublicIpMask.isInternalAddress(host)) {
            return PublicIpMask.INTERNAL_UNKNOWN_LABEL;
        }
        if (PublicIpMask.isIpv4Literal(host)) {
            String[] parts = host.split("\\.");
            return parts[0] + "." + parts[1] + "." + parts[2] + ".x";
        }
        String[] groups = host.split(":");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(3, groups.length); i++) {
            if (i > 0) sb.append(':');
            sb.append(groups[i]);
        }
        return sb.append(":x").toString();
    }

    private static Map<String, Object> disclosure() {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("masked", true);
        d.put("notice", DISCLOSURE_NOTICE);
        d.put("removalContact", PublicIpPolicy.DEFAULT_REMOVAL_CONTACT);
        return d;
    }

    private static int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }
}
