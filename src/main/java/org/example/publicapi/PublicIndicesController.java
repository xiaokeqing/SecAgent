package org.example.publicapi;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.integration.WazuhGateway;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 公开只读端点：Wazuh 最近 7 天日索引的条目数与占用估算。
 *
 * <p>为什么公开这个：索引占用是"这个站还在不在收数据、保留策略有没有生效"的
 * 最直接证据，但它不含任何告警内容 —— 只透出索引名里的日期、条数、字节数。
 * 索引名本身（{@code wazuh-alerts-4.x-2026.11.07}）不会泄露内网拓扑。
 *
 * <h3>绝不编数</h3>
 * 取不到就 {@code mode:"MOCK"} + 空数组 + {@code note} 说明原因；
 * 不拿"平均每条告警 N 字节"去乘出一个占用，也不返回 0 假装查到了空结果。
 *
 * <h3>缓存</h3>
 * 与 {@link PublicMetricsController} 同一套写法：60 秒进程内缓存，
 * <b>只缓存成功结果</b>（MOCK 不缓存，避免数据源恢复后还要等一分钟才反映）。
 */
@RestController
@RequestMapping("/api/public")
public class PublicIndicesController {

    private static final long CACHE_TTL_MS = 60_000L;
    private static final int RETENTION_DAYS = 7;

    private final PublicApiSupport support;
    private final WazuhGateway wazuh;

    private volatile Map<String, Object> cache;
    private volatile long cacheAtMs;

    public PublicIndicesController(PublicApiSupport support, WazuhGateway wazuh) {
        this.support = support;
        this.wazuh = wazuh;
    }

    @GetMapping({"/indices", "/indices.js"})
    public Object indices(HttpServletRequest req, HttpServletResponse res) {
        if (!support.rateLimiter.allow(support.clientIp(req))) {
            return support.tooMany(res);
        }
        return support.ok(payload(), res);
    }

    private Map<String, Object> payload() {
        Map<String, Object> cached = cache;
        if (cached != null && System.currentTimeMillis() - cacheAtMs < CACHE_TTL_MS) {
            return cached;
        }
        synchronized (this) {
            cached = cache;
            if (cached != null && System.currentTimeMillis() - cacheAtMs < CACHE_TTL_MS) {
                return cached;
            }
            Map<String, Object> fresh = build();
            if ("REAL".equals(fresh.get("mode"))) {
                cache = fresh;
                cacheAtMs = System.currentTimeMillis();
            }
            return fresh;
        }
    }

    private Map<String, Object> build() {
        Map<String, Object> raw = null;
        RuntimeException failure = null;
        try {
            raw = wazuh.alertIndices(RETENTION_DAYS);
        } catch (RuntimeException e) {
            failure = e;
        }
        boolean available = failure == null && raw != null
                && Boolean.TRUE.equals(raw.get("available"));

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("mode", available ? "REAL" : "MOCK");
        data.put("generatedAt", support.generatedAt());
        data.put("retentionDays", RETENTION_DAYS);
        if (available) {
            data.put("total", raw.getOrDefault("total", 0L));
            data.put("indices", raw.getOrDefault("indices", List.of()));
            data.put("note", String.valueOf(raw.getOrDefault("note", "")));
        } else {
            data.put("total", 0L);
            data.put("indices", List.of());
            data.put("note", mockNote(raw, failure));
        }
        return data;
    }

    /** MOCK 说明：必须点名原因，并明确"没有数字"不是"数字是 0"。 */
    private static String mockNote(Map<String, Object> raw, RuntimeException failure) {
        String reason = failure != null ? "QUERY_FAILED"
                : raw == null ? "NO_RESULT"
                : String.valueOf(raw.getOrDefault("reason", "DATA_SOURCE_UNAVAILABLE"));
        String detail = raw != null && raw.get("note") != null
                ? String.valueOf(raw.get("note"))
                : failure != null ? String.valueOf(failure.getMessage()) : "网关没有返回可用结果";
        return "Wazuh 索引统计不可用（" + reason + "）：" + detail
                + "；因此不展示任何条目数/占用数字，也不做估算。";
    }
}
