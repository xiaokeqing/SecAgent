package org.example.metrics;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 检测与响应时效指标端点：{@code GET /api/sec/metrics/summary}。
 *
 * <h3>为什么放在 /api/sec 而不是 /api/public</h3>
 * <p>时效指标会暴露"我们平均多久才发现/处置一次攻击"，属于内部运营数据，
 * 与 {@code /api/sec/conn} 同一口径：{@code ApiTokenInterceptor} 覆盖 {@code /api/**}，
 * 白名单里没有 {@code /api/sec} 前缀 ⇒ 必须登录（或带 X-API-Token）才能访问，未登录 401。
 * 这里不额外发明鉴权注解。
 *
 * <h3>为什么 {@code mode} 放在 data 里</h3>
 * <p>与 {@code SecConnController} 一致：REAL 之外的数据源模式返回的是被剔除后的空样本，
 * 前端必须能区分"确实没有样本"和"根本没连上数据源"，否则会把"数据源没配好"误读成"我们的响应很快"。
 */
@RestController
@RequestMapping("/api/sec/metrics")
public class SecMetricsController {

    private final MetricsSummaryService metricsSummaryService;

    public SecMetricsController(MetricsSummaryService metricsSummaryService) {
        this.metricsSummaryService = metricsSummaryService;
    }

    /**
     * 窗口内 MTTD / MTTR 中位数与最慢样本。
     *
     * <p>示例：{@code GET /api/sec/metrics/summary?hours=24}
     *
     * @param hours 统计窗口（小时），默认 24，越界收敛到 1..168（不报 400）
     */
    @GetMapping("/summary")
    public Map<String, Object> summary(
            @RequestParam(value = "hours", defaultValue = "24") int hours) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", 200);
        body.put("message", "success");
        body.put("data", metricsSummaryService.summary(hours));
        return body;
    }
}
