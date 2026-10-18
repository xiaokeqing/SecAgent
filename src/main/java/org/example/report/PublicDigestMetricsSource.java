package org.example.report;

import org.example.geoip.CountryNames;
import org.example.geoip.GeoAggregator;
import org.example.geoip.GeoIpService;
import org.example.geoip.GeoWindow;
import org.example.publicapi.PublicAlertSource;
import org.example.publicapi.PublicAuditReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 日报取数的<b>真实现</b>：直接调用站点已有只读端点背后的服务方法，<b>不发 HTTP 给自己</b>。
 *
 * <h3>为什么是这几个方法</h3>
 * 日报和 {@code /api/public/*} 必须说同一套数字，否则同一天两处数字对不上，
 * 读者只会相信先看到的那个。所以这里刻意复用：
 * <ul>
 *   <li>{@link PublicAlertSource#summary24h()} —— 24h 告警总量与严重度（与 /alerts 的 {@code stats24h} 同源）；</li>
 *   <li>{@link PublicAlertSource#geoWindow24h(int)} + {@link GeoAggregator#aggregate} —— 来源国家，
 *       与 /geo 完全同一套门槛（minCount / minShare / 排除本机·内网·保留地址）；</li>
 *   <li>{@link PublicAlertSource#honeypotSummary(int)} —— 蜜罐连接与登录尝试（Cowrie）；</li>
 *   <li>{@link PublicAuditReader#summary()} —— 封禁 / 解封（处置留痕）。</li>
 * </ul>
 *
 * <h3>取不到怎么办</h3>
 * 一律交给 {@link DigestMetrics.Builder} 记进「缺数据」，<b>不用 0 顶替</b>：
 * "今天没有告警"和"读不到告警"是两条完全不同的结论，日报里混淆它们等于撒谎。
 * 本类只做"读 + 记缺口"，任何一边抛异常都不让它冒到调用方（日报要能带着缺口生成）。
 */
@Component
public class PublicDigestMetricsSource implements DigestMetricsSource {

    private static final Logger logger = LoggerFactory.getLogger(PublicDigestMetricsSource.class);

    /** 日报只要 Top3 来源国家：Top5 是任务下限，页面已经另有完整榜单，日报里再长就是噪音 */
    private static final int DIGEST_TOP_COUNTRIES = 5;
    /** 蜜罐样本条数：与 /api/public/honeypot 的取样一致（800 条） */
    private static final int HONEYPOT_SAMPLE = 800;
    /** 来源 IP 窗口：与 /api/public/geo 的 geoTopIps 默认一致 */
    private static final int GEO_TOP_IPS = 1000;
    /** 「值得注意」的单一来源尝试阈值 */
    private static final long NOTABLE_ATTEMPTS = 1000;

    private final PublicAlertSource alerts;
    private final PublicAuditReader auditReader;
    private final ObjectProvider<GeoIpService> geoIp;
    private final GeoAggregator.Thresholds geoThresholds;
    private final String selfIpsCsv;

    public PublicDigestMetricsSource(PublicAlertSource alerts,
                                     PublicAuditReader auditReader,
                                     ObjectProvider<GeoIpService> geoIp,
                                     @Value("${app.geoip.min-count:3}") int geoMinCount,
                                     @Value("${app.geoip.min-share-percent:1.0}") double geoMinSharePercent,
                                     @Value("${app.geoip.top-countries:20}") int geoTopCountries,
                                     @Value("${app.geoip.top-provinces:10}") int geoTopProvinces,
                                     @Value("${app.geoip.top-asns:10}") int geoTopAsns,
                                     @Value("${app.geoip.self-ips:}") String selfIpsCsv) {
        this.alerts = alerts;
        this.auditReader = auditReader;
        this.geoIp = geoIp;
        this.geoThresholds = new GeoAggregator.Thresholds(
                Math.max(1, geoMinCount), Math.max(0d, geoMinSharePercent),
                Math.max(1, geoTopCountries), Math.max(1, geoTopProvinces), Math.max(1, geoTopAsns));
        this.selfIpsCsv = selfIpsCsv;
    }

    @Override
    public DigestMetrics collect(LocalDate day) {
        DigestMetrics.Builder b = DigestMetrics.builder(day).generatedAt(LocalDateTime.now());

        readAlerts(b);
        readCountries(b);
        List<DigestMetrics.IpSource> sources = readHoneypot(b);
        readBlocks(b);

        // 值得注意：有据可依才点出来（阈值 1000 次），没触发就明写"未触发"，不留空
        b.notable(notableOf(sources),
                "来源：Cowrie topSources（最近 " + HONEYPOT_SAMPLE + " 条蜜罐告警内的 srcIp 计数）");

        // 端口探测器判定：蜜罐汇总只有「来源 IP 计数」，没有端口维度 —— 明写不猜
        b.missing("端口探测器判定：蜜罐汇总不含端口维度（topSources 只有 IP 计数），本次未做该判定");

        return b.build();
    }

    /** 告警：24h 总数 + 严重度分布。 */
    private void readAlerts(DigestMetrics.Builder b) {
        Map<String, Object> s = alerts.summary24h();
        String src = "来源：/api/public/alerts 的 stats24h（Wazuh，窗口 24h）";
        if (s == null || s.isEmpty()) {
            b.alerts(null, null, src);
            b.missing("告警总数：stats24h 读取为空（Wazuh 网关未返回或抛异常）");
            return;
        }
        Object avail = s.get("available");
        Long total = asLong(s.get("total"));
        if (Boolean.FALSE.equals(avail) || total == null) {
            b.alerts(null, null, src);
            String state = String.valueOf(s.getOrDefault("state", "unknown"));
            String reason = String.valueOf(s.getOrDefault("reason", s.getOrDefault("note", "")));
            b.missing("告警总数：stats24h 判为不可用（state=" + state + "，reason=" + reason
                    + "）；同一窗口的严重度分布随之缺失");
            return;
        }
        b.alerts(total, severity(s.get("bySeverity")), src);
    }

    /** 严重度分布：只保留 Map 里的数字项，键沿用 Wazuh 的枚举名（CRITICAL/HIGH/...）。 */
    private static Map<String, Long> severity(Object raw) {
        if (!(raw instanceof Map<?, ?> m) || m.isEmpty()) {
            return null;
        }
        java.util.LinkedHashMap<String, Long> out = new java.util.LinkedHashMap<>();
        for (Map.Entry<?, ?> e : m.entrySet()) {
            Long v = asLong(e.getValue());
            if (v != null) {
                out.put(String.valueOf(e.getKey()), v);
            }
        }
        return out;
    }

    /** 来源国家：与 /api/public/geo 同一套聚合与门槛。 */
    private void readCountries(DigestMetrics.Builder b) {
        String src = "来源：/api/public/geo 同一套 GeoAggregator 聚合（Wazuh 24h 来源 IP 窗口，"
                + "门槛 count≥" + geoThresholds.minCount() + " 且占比≥" + geoThresholds.minSharePercent()
                + "%，已排除本机/内网/保留地址；地理库 DB-IP Lite，CC BY 4.0）";
        GeoIpService svc = geoIp.getIfAvailable();
        if (svc == null) {
            b.countries(null, null, src);
            b.missing("来源国家：地理富化未装配（没有 GeoIpService）");
            return;
        }
        if (!svc.ready()) {
            b.countries(null, null, src);
            b.missing("来源国家：离线地理库不可用（reason=" + svc.reason() + "）");
            return;
        }
        GeoWindow window = alerts.geoWindow24h(GEO_TOP_IPS);
        if (window == null || !window.available()) {
            b.countries(null, null, src);
            b.missing("来源国家：24h 来源窗口不可用（reason="
                    + (window == null ? "无法读取" : window.reason()) + "）");
            return;
        }
        Map<String, Object> agg = GeoAggregator.aggregate(
                new GeoAggregator.Inputs(window.ipCounts(), window.alertsTotal24h(),
                        window.alertsWithSourceIp24h(), window.bucketsTruncated(), window.trend(),
                        parseSelfIps(selfIpsCsv)),
                svc, geoThresholds, LocalDateTime.now().format(java.time.format.DateTimeFormatter
                        .ofPattern("yyyy-MM-dd HH:mm:ss")));
        List<DigestMetrics.Country> countries = countriesOf(agg.get("byCountry"), DIGEST_TOP_COUNTRIES);
        b.countries(window.alertsWithSourceIp24h(), countries, src);
        if (Boolean.TRUE.equals(agg.get("available")) && countries.isEmpty()) {
            b.missing("来源国家：地理库可用但 24h 窗口内没有国家入榜（可能是窗口内无带来源 IP 的告警）");
        }
    }

    @SuppressWarnings("unchecked")
    private static List<DigestMetrics.Country> countriesOf(Object raw, int limit) {
        if (!(raw instanceof List<?> list) || list.isEmpty()) {
            return List.of();
        }
        List<DigestMetrics.Country> out = new ArrayList<>();
        for (Object o : list) {
            if (out.size() >= limit) {
                break;
            }
            if (!(o instanceof Map<?, ?> m)) {
                continue;
            }
            String code = String.valueOf(m.get("country"));
            String name = m.get("countryName") == null ? CountryNames.of(code) : String.valueOf(m.get("countryName"));
            Long count = asLong(m.get("count"));
            if (code == null || code.isBlank() || count == null) {
                continue;
            }
            out.add(new DigestMetrics.Country(code, name,
                    count, asLongOr(m.get("uniqueIps"), 0L),
                    m.get("sharePercent") instanceof Number n ? n.doubleValue() : 0d));
        }
        return out;
    }

    /** 蜜罐：连接数 / 登录数 / 登录失败数 + 来源 IP 计数（返回来源计数供「值得注意」判定）。 */
    private List<DigestMetrics.IpSource> readHoneypot(DigestMetrics.Builder b) {
        String src = "来源：/api/public/honeypot 同一份 Cowrie 汇总（最近 " + HONEYPOT_SAMPLE
                + " 条蜜罐告警，不是 24h 时间窗）";
        Map<String, Object> h = alerts.honeypotSummary(HONEYPOT_SAMPLE);
        if (h == null || h.isEmpty() || Boolean.FALSE.equals(h.get("available"))) {
            b.honeypot(null, null, null, null, src);
            b.missing("蜜罐连接/登录：honeypotSummary 不可用（Cowrie 数据源未就绪）");
            b.topSources(null, src);
            return List.of();
        }
        Integer connections = asInt(h.get("connections"));
        if (connections == null) {
            b.honeypot(null, null, null, null, src);
            b.missing("蜜罐连接数：汇总里没有 connections 字段");
        } else {
            b.honeypot(connections, asInt(h.get("logins")), asInt(h.get("loginFails")),
                    asInt(h.get("sampled")), src);
        }
        List<DigestMetrics.IpSource> sources = topSourcesOf(h.get("topSources"));
        b.topSources(sources, src);
        return sources;
    }

    /** 处置留痕：封禁总数 / 仍生效 / 被护栏拦截 / 成功动作。 */
    private void readBlocks(DigestMetrics.Builder b) {
        String src = "来源：/api/public/audit 同一份处置审计留痕（data/response-audit.json，"
                + "全量，不限 24h）；解封数 = 总封禁 − 仍生效";
        Map<String, Object> s;
        try {
            s = auditReader.summary();
        } catch (Exception e) {
            logger.warn("日报读取处置留痕失败：{}", e.getMessage());
            s = null;
        }
        if (s == null || s.isEmpty()) {
            b.blocks(null, null, null, null, src);
            b.missing("封禁/解封数：处置审计留痕读取失败");
            return;
        }
        Integer total = asInt(s.get("blockTotal"));
        if (total == null) {
            b.blocks(null, null, null, null, src);
            b.missing("封禁/解封数：留痕汇总里没有 blockTotal 字段");
            return;
        }
        b.blocks(total, asInt(s.get("blockActive")), asInt(s.get("blockedByGuard")),
                asInt(s.get("executedActions")), src);
    }

    @SuppressWarnings("unchecked")
    private static List<DigestMetrics.IpSource> topSourcesOf(Object raw) {
        if (!(raw instanceof List<?> list) || list.isEmpty()) {
            return List.of();
        }
        List<DigestMetrics.IpSource> out = new ArrayList<>();
        for (Object o : list) {
            if (out.size() >= 5) {
                break;
            }
            if (!(o instanceof Map<?, ?> m)) {
                continue;
            }
            Long count = asLong(m.get("count"));
            String ip = m.get("key") == null ? null : String.valueOf(m.get("key"));
            if (ip == null || ip.isBlank() || count == null) {
                continue;
            }
            out.add(new DigestMetrics.IpSource(ip, count));
        }
        // 排序确定（尝试次数降序、IP 升序），保证同一批输入得到同一份日报
        out.sort(java.util.Comparator.comparingLong(DigestMetrics.IpSource::attempts).reversed()
                .thenComparing(DigestMetrics.IpSource::ip));
        return out;
    }

    /** 值得注意：单一来源尝试 ≥1000 次时点出来；否则 {@code null}（渲染层写"未触发"）。 */
    public static String notableOf(List<DigestMetrics.IpSource> topSources) {
        if (topSources == null || topSources.isEmpty()) {
            return null;
        }
        DigestMetrics.IpSource worst = topSources.get(0);
        if (worst.attempts() >= NOTABLE_ATTEMPTS) {
            return "来源 IP " + worst.ip() + " 在蜜罐窗口内尝试 " + worst.attempts()
                    + " 次（≥ " + NOTABLE_ATTEMPTS + " 次阈值）";
        }
        return null;
    }

    static Set<String> parseSelfIps(String csv) {
        Set<String> out = new LinkedHashSet<>();
        if (csv == null) {
            return out;
        }
        for (String s : csv.split(",")) {
            String v = s.trim();
            if (!v.isEmpty()) {
                out.add(v);
            }
        }
        return out;
    }

    private static Long asLong(Object v) {
        if (v instanceof Number n) {
            return n.longValue();
        }
        if (v instanceof String s) {
            try {
                return Long.parseLong(s.trim());
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private static long asLongOr(Object v, long fallback) {
        Long l = asLong(v);
        return l == null ? fallback : l;
    }

    private static Integer asInt(Object v) {
        Long l = asLong(v);
        return l == null ? null : (int) Math.min(Integer.MAX_VALUE, Math.max(Integer.MIN_VALUE, l));
    }
}
