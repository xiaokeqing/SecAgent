package org.example.notify;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.example.config.OutboundTimeouts;
import org.example.llm.OutboundGuard;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;

/**
 * 真实 webhook 出站：<b>复用既有出站约束</b>（统一超时矩阵 + {@link OutboundGuard}），
 * 不自己造裸 OkHttp。
 *
 * <h3>为什么必须纳进守卫</h3>
 * 通知是旁路，但旁路一样会把线程和网络拖死：对端（IM 机器人网关）限流或挂起时，
 * 一个裸 OkHttp 调用会让每个告警线程各等满一次超时；而在告警风暴里，
 * 那就是"通知把研判线程池占满"的雪崩路径。
 * 所以这里与 Wazuh / SSH 用同一套值（connect 3s / read 12s / call 15s）
 * 与同一个 {@link OutboundGuard}（有界等待 + 每依赖冷却 + 半开）。
 *
 * <p>依赖标识是 {@link NotificationService#DEP_WEBHOOK}，冷却独立 ——
 * webhook 挂了不影响 Wazuh 与处置链路（也不该被它们拖累）。
 */
public class HttpWebhookTransport implements NotificationService.Transport {

    private static final Logger logger = LoggerFactory.getLogger(HttpWebhookTransport.class);
    private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");

    private final OkHttpClient http;
    private final OutboundGuard guard;
    private final long callTimeoutMs;

    public HttpWebhookTransport(OutboundTimeouts timeouts, OutboundGuard guard, long timeoutMs) {
        OutboundTimeouts t = (timeouts == null) ? OutboundTimeouts.defaults() : timeouts;
        this.guard = guard;
        long call = t.getCallTimeoutMs();
        // 允许按 app.notify.timeout-ms 收紧，但绝不放大到统一预算之上
        if (timeoutMs > 0 && timeoutMs < call) {
            call = timeoutMs;
        }
        this.callTimeoutMs = call;
        this.http = new OkHttpClient.Builder()
                .connectTimeout(Duration.ofMillis(t.getConnectTimeoutMs()))
                .readTimeout(Duration.ofMillis(t.getReadTimeoutMs()))
                .writeTimeout(Duration.ofMillis(t.getReadTimeoutMs()))
                .callTimeout(Duration.ofMillis(call))
                .build();
    }

    /** 出站守卫是否接入（启动自检用：false 表示只有传输层超时） */
    public boolean guardEnabled() {
        return guard != null;
    }

    /** 单次调用的生效预算（启动自检用） */
    public long effectiveCallTimeoutMs() {
        return callTimeoutMs;
    }

    @Override
    public long timeoutMs() {
        return callTimeoutMs;
    }

    @Override
    public NotificationService.Delivery post(String requestUrl, String jsonBody) {
        if (requestUrl == null || requestUrl.isBlank()) {
            return NotificationService.Delivery.fail(-1, "webhook 地址为空");
        }
        Request req = new Request.Builder()
                .url(requestUrl)
                .post(RequestBody.create(jsonBody, JSON))
                .build();

        if (guard == null) {
            // 无守卫（单测/旧构造）：仍然有传输层超时，只是没有冷却与有界等待
            return execute(req);
        }
        try {
            return guard.call(NotificationService.DEP_WEBHOOK, callTimeoutMs, () -> execute(req));
        } catch (Exception e) {
            // 传输层失败也要打开冷却（read timeout 往往先于守卫的 callTimeout 触发，
            // 不在这里开熔断的话，60s 冷却永远不会生效 —— 与 Wazuh 客户端同一个教训）
            guard.openCircuit(NotificationService.DEP_WEBHOOK);
            logger.warn("webhook 出站被终止（依赖={}）：{}", NotificationService.DEP_WEBHOOK, e.getMessage());
            return NotificationService.Delivery.fail(-1, "出站被终止：" + e.getMessage());
        }
    }

    private NotificationService.Delivery execute(Request req) {
        try (Response resp = http.newCall(req).execute()) {
            String body = resp.body() == null ? "" : resp.body().string();
            if (resp.isSuccessful()) {
                return NotificationService.Delivery.ok(resp.code());
            }
            // 对端返回错误码时必须带上响应片段：地址配错（404）、token 失效（401）、
            // 载荷被拒（400）的排障方式完全不同，只回一个数字等于没说
            return NotificationService.Delivery.fail(resp.code(),
                    "HTTP " + resp.code() + " " + snippet(body));
        } catch (Exception e) {
            return NotificationService.Delivery.fail(-1,
                    e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private static String snippet(String s) {
        if (s == null) {
            return "";
        }
        String t = s.trim().replaceAll("\\s+", " ");
        return t.length() > 200 ? t.substring(0, 200) + "..." : t;
    }
}
