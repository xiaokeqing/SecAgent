package org.example.controller;

import org.example.integration.SuricataGateway;
import org.example.integration.suricata.Ja3Count;
import org.example.integration.suricata.PortCount;
import org.example.integration.suricata.SniCount;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 网络连接反查接口：按 IP / 端口 / SNI / JA3 回看 Suricata 已观测到的连接。
 *
 * <h3>为什么放在 /api/sec/conn 而不是 /api/public</h3>
 * <p>连接反查会暴露内网拓扑（谁在连哪些内部地址、开了哪些端口），
 * 比告警列表更敏感，所以走 {@code /api/**} 的默认鉴权（{@code ApiTokenInterceptor}
 * 白名单里没有这个前缀 ⇒ 必须携带登录态或 X-API-Token），
 * 不额外发明鉴权注解 —— 现有拦截器链已经把这层管住了。
 *
 * <h3>为什么每个响应都带 mode</h3>
 * <p>REAL 之外的模式返回的是空结果（不是样本）。前端必须能区分
 * "确实没这个 IP 的连接"和"根本没读到 eve.json"，否则会把"没挂文件"误报成"该主机很干净"。
 * 这和 /api/alerts 里 MOCK 数据被剔除后仍返回 suricataMode 是同一个口径。
 */
@RestController
@RequestMapping("/api/sec/conn")
public class SecConnController {

    /** 单次最多返回多少条：反查是给排障用的，几百条足够，再多前端也画不下 */
    private static final int MAX_LIMIT = 500;
    /** 时间窗上限一天：缓冲本来只覆盖最近一段时间，更大的窗口没有数据可统计 */
    private static final int MAX_MINUTES = 1440;

    private final SuricataGateway suricata;

    public SecConnController(SuricataGateway suricata) {
        this.suricata = suricata;
    }

    /**
     * 该 IP 作为源或目标的最近连接。
     *
     * <p>示例：{@code GET /api/sec/conn/by-ip?ip=10.0.10.21&limit=50}
     */
    @GetMapping("/by-ip")
    public Map<String, Object> byIp(@RequestParam("ip") String ip,
                                    @RequestParam(value = "limit", defaultValue = "50") int limit) {
        int n = clamp(limit, 1, MAX_LIMIT);
        String target = ip == null ? "" : ip.trim();
        List<?> items = target.isEmpty() ? List.of() : suricata.connectionsByIp(target, n);

        Map<String, Object> data = new HashMap<>();
        data.put("mode", suricata.mode());
        data.put("ip", target);
        data.put("limit", n);
        data.put("total", items.size());
        data.put("connections", items);
        return ok(data);
    }

    /**
     * 最近 N 分钟被访问最多的目标端口。
     *
     * <p>示例：{@code GET /api/sec/conn/top-ports?minutes=15&limit=10}
     */
    @GetMapping("/top-ports")
    public Map<String, Object> topPorts(@RequestParam(value = "minutes", defaultValue = "15") int minutes,
                                        @RequestParam(value = "limit", defaultValue = "10") int limit) {
        int m = clamp(minutes, 1, MAX_MINUTES);
        int n = clamp(limit, 1, MAX_LIMIT);
        List<PortCount> ports = suricata.topDestPorts(m, n);

        Map<String, Object> data = new HashMap<>();
        data.put("mode", suricata.mode());
        data.put("minutes", m);
        data.put("total", ports.size());
        data.put("ports", ports);
        return ok(data);
    }

    /**
     * 最近 N 分钟的 TLS SNI 与 JA3 分布。
     *
     * <p>两个榜放在同一个响应里：排障时"连了哪个域名"和"客户端指纹是否可疑"通常一起看，
     * 分两次请求反而会让两组统计落在不同的时间点上。
     *
     * <p>示例：{@code GET /api/sec/conn/tls-stats?minutes=60&limit=10}
     */
    @GetMapping("/tls-stats")
    public Map<String, Object> tlsStats(@RequestParam(value = "minutes", defaultValue = "60") int minutes,
                                        @RequestParam(value = "limit", defaultValue = "10") int limit) {
        int m = clamp(minutes, 1, MAX_MINUTES);
        int n = clamp(limit, 1, MAX_LIMIT);
        List<SniCount> sni = suricata.topSni(m, n);
        List<Ja3Count> ja3 = suricata.ja3Stats(m, n);

        Map<String, Object> data = new HashMap<>();
        data.put("mode", suricata.mode());
        data.put("minutes", m);
        data.put("topSni", sni);
        data.put("ja3", ja3);
        return ok(data);
    }

    /** 参数收敛到合理区间：前端传 0 / 负数 / 超大值时退化成默认语义，而不是报 400 或扫全缓冲 */
    private static int clamp(int value, int min, int max) {
        if (value < min) {
            return min;
        }
        return Math.min(value, max);
    }

    private static Map<String, Object> ok(Object data) {
        Map<String, Object> body = new HashMap<>();
        body.put("code", 200);
        body.put("message", "success");
        body.put("data", data);
        return body;
    }
}
