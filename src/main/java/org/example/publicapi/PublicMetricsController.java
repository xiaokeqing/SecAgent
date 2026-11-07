package org.example.publicapi;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.metrics.MetricsSummaryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 公开只读的"处置时效"指标（MTTD / MTTR）。
 *
 * <p>为什么不直接开 {@code /api/sec/metrics/summary}：那条端点要 API token（未登录 401），
 * 是"运维面"；站点上要给所有访客看的是**脱敏后的聚合值** —— 只有中位数、样本数、口径时间窗，
 * 不含任何 IP / 主机名 / 逐条事件。所以这里复算一遍后端同一份 {@link MetricsSummaryService#summary(int)}
 * 的结果，把 {@code worst}（里面带 IP）与 {@code dropped}（内部诊断细节）裁掉再发。</p>
 *
 * <p>另外两条硬约束：
 * <ul>
 *   <li><b>样本不足不返回 0</b>：沿用 service 的 {@code {available:false, reason:"样本不足", samples:n}}
 *       —— 页面上写 0 会被读成"处理得飞快"。</li>
 *   <li>允许值只有 1/6/24/72 小时（与本页其它统计口径一致），其它值一律 400，避免被拿来当任意查询口。</li>
 * </ul></p>
 *
 * <p>纯读、无写、无状态；限流沿用 {@code PublicApiSupport.rateLimiter}（每 IP 每分钟 20 次）。</p>
 */
@RestController
@RequestMapping("/api/public")
public class PublicMetricsController {

    private static final List<Integer> ALLOWED_HOURS = List.of(1, 6, 24, 72);

    /** 单次 summary() 要现查 Wazuh 24h 窗口（实测 ~10 s），但结果 60 秒内几乎不变 ⇒ 进程内缓存。 */
    private static final long CACHE_TTL_MS = 60_000L;

    private final PublicApiSupport support;
    private final MetricsSummaryService metricsSummaryService;

    @Autowired
    public PublicMetricsController(PublicApiSupport support,
                                   MetricsSummaryService metricsSummaryService) {
        this.support = support;
        this.metricsSummaryService = metricsSummaryService;
    }

    @GetMapping({"/metrics", "/metrics.js"})
    public Object metrics(@RequestParam(value = "hours", required = false) String hoursRaw,
                          @RequestParam(value = "window", required = false) String windowRaw,
                          HttpServletRequest req, HttpServletResponse res) {
        if (!support.rateLimiter.allow(support.clientIp(req))) {
            return support.tooMany(res);
        }
        int hours = 24;
        String raw = windowRaw != null && !windowRaw.isBlank() ? windowRaw : hoursRaw;
        if (raw != null && !raw.isBlank()) {
            try {
                hours = Integer.parseInt(raw.trim());
            } catch (NumberFormatException e) {
                return support.badRequest(res, "WINDOW_NOT_SUPPORTED", "hours/window 只能是 1/6/24/72");
            }
            if (!ALLOWED_HOURS.contains(hours)) {
                return support.badRequest(res, "WINDOW_NOT_SUPPORTED", "hours/window 只能是 1/6/24/72");
            }
        }

        Map<String, Object> full;
        try {
            full = summaryCached(hours);
        } catch (RuntimeException e) {
            return support.ok(publicData(hours, unavailable("数据源不可用"), unavailable("数据源不可用"),
                    new LinkedHashMap<>()), res);
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("mode", full.get("mode"));
        data.put("window", full.get("window"));
        data.put("mttd", sanitizeMetric(full.get("mttd")));
        data.put("mttr", sanitizeMetric(full.get("mttr")));
        Object samples = full.get("samples");
        if (samples instanceof Map<?, ?> m) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("alerts", m.get("alerts"));
            out.put("blocks", m.get("blocks"));
            out.put("mttdPairs", m.get("mttdPairs"));
            out.put("mttrPairs", m.get("mttrPairs"));
            data.put("samples", out);
        }
        data.put("generatedAt", full.get("generatedAt"));
        return support.ok(data, res);
    }

    /**
     * 60 秒进程内缓存（只缓存"最近一次成功"的结果，异常不缓存，避免把故障写死一分钟）。
     * 单实例、只读、可重复计算 ⇒ 用最简单的 volatile + 时间戳，不引缓存框架。
     */
    private Map<String, Object> summaryCached(int hours) {
        long now = System.currentTimeMillis();
        Map<String, Object> hit = cache;
        if (hit != null && cacheHours == hours && now - cacheAtMs < CACHE_TTL_MS) {
            return hit;
        }
        synchronized (this) {
            now = System.currentTimeMillis();
            if (cache != null && cacheHours == hours && now - cacheAtMs < CACHE_TTL_MS) {
                return cache;
            }
            Map<String, Object> fresh = metricsSummaryService.summary(hours);
            cache = fresh;
            cacheHours = hours;
            cacheAtMs = System.currentTimeMillis();
            return fresh;
        }
    }

    private volatile Map<String, Object> cache;
    private volatile int cacheHours = -1;
    private volatile long cacheAtMs;

    /** 只留中位数 / 样本数 / 单位；worst、dropped 一律不出门。 */    @SuppressWarnings("unchecked")
    private static Map<String, Object> sanitizeMetric(Object raw) {
        if (!(raw instanceof Map<?, ?> m)) {
            return unavailable("数据源不可用");
        }
        Map<String, Object> out = new LinkedHashMap<>();
        Object available = m.get("available");
        out.put("available", Boolean.TRUE.equals(available));
        if (Boolean.TRUE.equals(available)) {
            out.put("medianMinutes", m.get("medianMinutes"));
            out.put("samples", m.get("samples"));
            out.put("unit", "minutes");
        } else {
            out.put("reason", m.get("reason"));
            out.put("samples", m.get("samples"));
        }
        return out;
    }

    private static Map<String, Object> unavailable(String reason) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("available", false);
        out.put("reason", reason);
        out.put("samples", 0);
        return out;
    }

    private static Map<String, Object> publicData(int hours, Map<String, Object> mttd,
                                                  Map<String, Object> mttr, Map<String, Object> extra) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("mode", "OFF");
        data.put("hours", hours);
        data.put("mttd", mttd);
        data.put("mttr", mttr);
        data.putAll(extra);
        return data;
    }
}
