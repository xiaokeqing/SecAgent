package org.example.response;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 自动处置观测端点：{@code GET /api/sec/auto-response/state}。
 *
 * <h3>鉴权</h3>
 * 与 {@code /api/sec/**} 其它接口同一口径：{@code ApiTokenInterceptor} 覆盖 {@code /api/**}，
 * 白名单里没有 {@code /api/sec} 前缀，因此必须登录（或带 X-API-Token），未登录 401。
 * 这里不额外发明鉴权注解。
 *
 * <h3>为什么 AutoResponder 关闭时这个端点仍然存在</h3>
 * 自动处置默认关闭。如果本控制器也跟着条件化，部署前就<strong>没有任何办法</strong>确认
 * "打开后阈值是多少、dry-run 是不是开着" —— 只能先打开再猜。所以控制器常驻，
 * 从 {@link ObjectProvider} 里取可选 Bean：
 * <ul>
 *   <li>Bean 存在（enabled=true）→ 返回 Bean 里的实时状态与最近 10 次决策；</li>
 *   <li>Bean 不存在（enabled=false）→ 返回 {@code enabled=false} 与配置里的阈值、空决策列表。</li>
 * </ul>
 * 这样"没开"和"开了但一轮都没跑"在接口上是可区分的两种状态，而不是都显示 0。
 */
@RestController
@RequestMapping("/api/sec/auto-response")
public class AutoResponseController {

    private final ObjectProvider<AutoResponder> responderProvider;

    @Value("${app.response.auto.enabled:false}")
    private boolean enabled = false;

    @Value("${app.response.auto.dry-run:true}")
    private boolean dryRun = true;

    @Value("${app.response.auto.min-high:30}")
    private int minHigh = 30;

    @Value("${app.response.auto.min-critical:3}")
    private int minCritical = 3;

    @Value("${app.response.auto.duration-minutes:60}")
    private int durationMinutes = 60;

    public AutoResponseController(ObjectProvider<AutoResponder> responderProvider) {
        this.responderProvider = responderProvider;
    }

    /**
     * 自动处置当前状态。
     *
     * <p>示例：{@code GET /api/sec/auto-response/state}
     */
    @GetMapping("/state")
    public Map<String, Object> state() {
        Map<String, Object> data;
        AutoResponder responder;
        try {
            responder = responderProvider == null ? null : responderProvider.getIfAvailable();
        } catch (Exception e) {
            // 取 Bean 失败按"未启用"展示，不能让观测端点自己 500 —— 它本来就是排障用的
            responder = null;
        }
        if (responder != null) {
            data = responder.state();
        } else {
            data = new LinkedHashMap<>();
            data.put("enabled", enabled);
            data.put("dryRun", dryRun);
            data.put("minHigh", minHigh);
            data.put("minCritical", minCritical);
            data.put("durationMinutes", durationMinutes);
            data.put("windows", List.of());
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", 200);
        body.put("message", "success");
        body.put("data", data);
        return body;
    }
}
