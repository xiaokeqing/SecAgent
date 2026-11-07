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
 * 地理分布与 IP 画像域：/geo、/ip。
 *
 * <p>本类是 {@code PublicApiController} 拆分出的按域 controller 之一：只做搬移，路径、参数、
 * 响应字段、状态码、缓存头与限流口径与原 god controller 逐字一致。
 * 共享状态与通用工具（快照缓存、出关脱敏、信封/缓存头）在 {@link PublicApiSupport} 里，
 * 由构造器注入；旧类 {@code PublicApiController} 保留为委托门面（历史单测直接 new 它）。
 */
@RestController
@RequestMapping("/api/public")
public class PublicGeoController {

    private static final Logger logger = LoggerFactory.getLogger(PublicGeoController.class);

    private final PublicApiSupport support;

    public PublicGeoController(PublicApiSupport support) {
        this.support = support;
    }

    /**
     * 攻击来源地理分布（<b>只聚合</b>）：国家 + 省份 + ASN + 时间桶，供博客大屏画"攻击来源分布"。
     *
     * <h3>三条红线（都写进了测试）</h3>
     * <ol>
     *   <li><b>不含任何 IP</b>：连掩码 IP 都不给。入参里必须有 IP（聚合要用），出参里一个都不许有 ——
     *       "某个 IP 被打了几次"本身就是情报；能公开的只有"哪个国家/省份被打了几次"。</li>
     *   <li><b>不含单条告警</b>：没有标题、没有规则名、没有逐条时间线、没有内网资产与目的地址。</li>
     *   <li><b>库不可用就说不可用</b>：{@code available=false} + 机读 {@code reason}
     *       （{@code GEO_DB_MISSING} / {@code GEO_DB_UNUSABLE} / {@code GEO_DB_LOADING} /
     *       {@code GEO_DISABLED}）+ 人读 {@code note}；<b>不返回空分布</b> ——
     *       "地理库没装好"和"这段时间没有攻击"必须能被区分开。</li>
     * </ol>
     *
     * <p>分母诚实披露（站主 2026-10-13 明确要求）：实测 24 小时有 11 万条告警，
     * 但只有约 700 条带来源 IP 字段（{@code data.srcip} / {@code data.src_ip} 两种形状都查）。
     * 所以响应里同时给 {@code totalAlerts / withSourceIp / geocoded / excludedInternal}，
     * 页面必须写"有来源 IP 的 N 条 / 总 M 条"，<b>不许把 700 条画成全量分布</b>。
     *
     * <p>复用既有公开端点外壳（同一个限流器 20 次/分钟、同一个 CORS 白名单、同一个 ETag 过滤器、
     * 同一个 15 秒 {@link Snapshot}、同一个 {@code ok(...)} 信封，因此也自动获得
     * {@code ship(...)} 的资产名过滤与 {@code ipDisclosure} 口径），不新增任何公开面机制。
     *
     * <p>署名：DB-IP Lite 是 CC BY 4.0，<b>必须在输出上署名</b> ——
     * 所以 {@code note} 与 {@code geoAttribution} 两处都带
     * {@link org.example.geoip.GeoIpService#ATTRIBUTION}。
     */
    @GetMapping({"/geo", "/geo.js"})
    public ResponseEntity<Map<String, Object>> geo(HttpServletRequest req, HttpServletResponse res) {
        if (!support.rateLimiter.allow(support.clientIp(req))) {
            return support.tooMany(res);
        }
        return support.ok(support.geoCache.get(support.cacheSeconds, this::buildGeo), res);
    }

    Map<String, Object> buildGeo() {
        org.example.geoip.GeoIpService svc = support.geoIpService;
        if (svc == null) {
            // 没有地理库 Bean（例如裁剪过的部署）：与"库缺失"同一口径，不假装有数据
            return buildGeoUnavailable("GEO_DB_MISSING",
                    "地理富化未装配（没有 GeoIpService）：本端点不返回任何分布，也不以 0 冒充'没有攻击'。",
                    support.cacheSeconds, support.generatedAt());
        }
        if (!svc.ready()) {
            return buildGeoUnavailable(svc.reason(), geoUnavailableNote(svc), support.cacheSeconds, support.generatedAt());
        }
        return buildGeo(svc, support.source.geoWindow24h(support.geoTopIps), geoThresholds(), support.cacheSeconds,
                support.generatedAt(), support.geoSelfIps);
    }

    static String geoUnavailableNote(org.example.geoip.GeoIpService svc) {
        return switch (svc.state()) {
            case DISABLED -> "地理富化已在配置中关闭（app.geoip.enabled=false）：不返回分布，也不以内置样本顶替。";
            case MISSING -> "离线地理库不存在（app.geoip.city-db 指向的文件/目录里没有 dbip-city-lite-*.csv.gz）："
                    + "请先跑 scripts/srv1-geoip-update.sh 落地 DB-IP Lite 库；本端点不返回任何数字。";
            case LOADING -> "离线地理库正在后台装载：稍后重试即可（这不是'没有攻击'）。";
            default -> "离线地理库读取失败（不是 gzip / 被截断 / 坏行超阈值 / 区间乱序）："
                    + "请按 RUNBOOK §26 回滚到上一份库文件；本次不返回任何分布。";
        };
    }

    org.example.geoip.GeoAggregator.Thresholds geoThresholds() {
        return new org.example.geoip.GeoAggregator.Thresholds(
                Math.max(1, support.geoMinCount), Math.max(0d, support.geoMinSharePercent),
                Math.max(1, support.geoTopCountries), Math.max(1, support.geoTopProvinces), Math.max(1, support.geoTopAsns));
    }

    /** 不可用载荷（纯函数：字段名与可用载荷对齐，前端只判 {@code available} 一个开关） */
    static Map<String, Object> buildGeoUnavailable(String reason, String note, int cacheSeconds, String now) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", now);
        data.put("cacheSeconds", cacheSeconds);
        data.put("available", false);
        data.put("reason", reason);
        data.put("geoSource", null);
        data.put("geoAttribution", org.example.geoip.GeoIpService.ATTRIBUTION);
        data.put("window", "24h");
        data.put("coverage", org.example.geoip.GeoAggregator.emptyCoverage());
        data.put("byCountry", List.of());
        data.put("byProvinceCN", List.of());
        data.put("byAsnTop", List.of());
        data.put("trend", List.of());
        // 小时 × 国家 这一块即便端点整体不可用也保持同形（前端只判 available 一个开关）
        Map<String, Object> byCountryHour = new LinkedHashMap<>();
        byCountryHour.put("available", false);
        byCountryHour.put("reason", "HOUR_CROSS_MISSING");
        byCountryHour.put("hours", List.of());
        byCountryHour.put("series", List.of());
        data.put("byCountryHour", byCountryHour);
        data.put("note", note + " " + org.example.geoip.GeoIpService.ATTRIBUTION);
        return data;
    }

    /**
     * 可用性判定 + 聚合（<b>纯函数</b>：除入参外不读任何状态）。
     *
     * <p>抽成 static 是为了能被单测直接喂各种组合（库不可用 / 数据源不可用 / 窗口为空 / 正常聚合），
     * 而不用起 Spring 上下文 —— 这些分支在真环境里几乎不可能同时复现。
     */
    static Map<String, Object> buildGeo(org.example.geoip.GeoIpService geo,
                                        org.example.geoip.GeoWindow window,
                                        org.example.geoip.GeoAggregator.Thresholds thresholds,
                                        int cacheSeconds, String now, String selfIps) {
        if (window == null || !window.available()) {
            String reason = window == null ? "DATA_SOURCE_UNAVAILABLE" : window.reason();
            String note = "DATA_SOURCE_UNAVAILABLE".equals(reason)
                    ? "告警数据源不可达（或未拿到真实数据）：本次不展示任何地理分布，也不以内置样本顶替。"
                    : reason + "；" + (window == null || window.note() == null ? "" : window.note());
            return buildGeoUnavailable(reason, note, cacheSeconds, now);
        }
        Map<String, Object> data = org.example.geoip.GeoAggregator.aggregate(
                new org.example.geoip.GeoAggregator.Inputs(
                        window.ipCounts(), window.alertsTotal24h(), window.alertsWithSourceIp24h(),
                        window.bucketsTruncated(), window.trend(), parseSelfIps(selfIps)),
                geo, thresholds, now);
        data.put("cacheSeconds", cacheSeconds);
        if (window.ipCounts().isEmpty()) {
            // 数据源可用但窗口内没有任何带来源 IP 的告警：仍然 available=true（不是故障），
            // 但必须把这句话写进 note —— 否则读者会把"地图上什么都没有"读成"全量分布为空"
            data.put("reason", "NO_DATA_IN_WINDOW");
            data.put("note", "数据源可用，但最近 24 小时没有任何带来源 IP 的告警（不是故障）。"
                    + org.example.geoip.GeoIpService.ATTRIBUTION);
        }
        return data;
    }

    /** 我方公网 IP 配置 → 集合（去空白、丢空项） */
    static java.util.Set<String> parseSelfIps(String csv) {
        java.util.Set<String> out = new java.util.LinkedHashSet<>();
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

    /**
     * <b>「这个 IP 干过什么」</b>：一个来源 IP 的画像（个人版 AbuseIPDB）。
     *
     * <p>跨三个源聚合：索引里的告警 + 蜜罐会话（{@link PublicAlertSource#ipActivity}）、
     * 应用侧处置留痕（{@link PublicAuditReader#bansFor}）、GeoIP 库。字段：
     * {@code firstSeen/lastSeen/events/byKind/ports/credStructure/geo/banned}
     * （外加 {@code sources} 说明每个源接没接上、{@code notes[]} 逐项说明为什么是 null）。
     *
     * <h3>口径（与 /stories 同一套壳）</h3>
     * <ol>
     *   <li><b>不许编</b>：任何一项取不到就写 {@code null} 并在 {@code notes[]} 里写原因 ——
     *       "读不到"与"没有数据"必须能分开读；</li>
     *   <li><b>不混数据</b>：只按 {@code q} 这一个字面量查，不按网段、不按 ASN、不按"相近的地址"
     *       扩张，也不把别人的记录并进来；</li>
     *   <li><b>IP 严格校验</b>：只要 IPv4 字面量（非法 → 400）；内网/保留地址也 400
     *       （理由见 {@link PublicIpProfileService#isQueryable}）；</li>
     *   <li><b>口令只给结构</b>：{@link PublicApiController#credentialShapes} 把
     *       {@code root / 123456} 换成 {@code root / 6 位·纯数字·弱口令}，原文字符不出现。</li>
     * </ol>
     *
     * <p>复用既有外壳：同一个限流器（20 次/分钟）、同一个 CORS 白名单、同一个 ETag 过滤器、
     * 同一个 {@code cache-seconds} TTL（按 IP 分开存）、同一个 {@code ok(...)}
     * （因此自动带 {@code ipDisclosure} 与内部资产名过滤）。
     */
    @GetMapping({"/ip", "/ip.js"})
    public ResponseEntity<Map<String, Object>> ipProfile(
            @RequestParam(value = "q", required = false) String q,
            HttpServletRequest req, HttpServletResponse res) {
        if (!support.rateLimiter.allow(support.clientIp(req))) {
            return support.tooMany(res);
        }
        String ip = q == null ? "" : q.trim();
        if (ip.isEmpty()) {
            return support.badRequest(res, "MISSING_Q",
                    "缺少 q 参数：要查的 IPv4 地址，例如 /api/public/ip?q=45.155.205.233");
        }
        if (!PublicIpProfileService.isIpv4Literal(ip)) {
            return support.badRequest(res, "INVALID_IP",
                    "q 必须是 IPv4 字面量（四段十进制、每段 0-255）；IPv6 / 域名 / 带端口 / 网段写法"
                            + "一律不接受，也不做任何猜测性解析");
        }
        if (!PublicIpProfileService.isQueryable(ip)) {
            return support.badRequest(res, "NOT_PUBLIC_IP",
                    "内网/保留/链路地址不在公开查询口径内：它们在公开面上统一写作「内网/未知」，"
                            + "而多个不同的内网地址会共用同一个输入，按 IP 查只会给出误导性的答案");
        }
        if (support.ipProfileService == null) {
            return support.ok(PublicIpProfileService.disabled(support.policy().display(ip), support.cacheSeconds), res);
        }
        return support.ok(support.ipProfileService.profile(ip), res);
    }
}
