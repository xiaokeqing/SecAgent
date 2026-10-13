package org.example.notify;

import com.sun.net.httpserver.HttpServer;
import org.example.config.OutboundTimeouts;
import org.example.llm.OutboundGuard;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 真实 HTTP 出站的测试：<b>起一个本地假对端</b>，验证"发出去的是什么字节"。
 *
 * <h3>为什么不用 mock 掉 HTTP 层，也不用引第三方测试服务器</h3>
 * 通知链路上最容易错的两处都在 HTTP 这一层：
 * <ol>
 *   <li><b>载荷形状</b>：JSON 是不是真的合法、Content-Type 对不对 —— mock 掉就看不见了；</li>
 *   <li><b>对端返回错误时的行为</b>：404/401/400 必须被识别成失败并触发重试，
 *       而不是"HTTP 调用没抛异常就算成功"（这正是"以为发了、其实没发"的经典来源）。</li>
 * </ol>
 * 所以这里用 JDK 自带的 {@code com.sun.net.httpserver.HttpServer} 起一个真端口：
 * 真收 POST、真回 500。它不需要任何新依赖 —— 比引 mockwebserver 更符合本项目的纪律
 * （而且离线构建也能跑）。
 */
class HttpWebhookTransportTest {

    private HttpServer server;
    private final List<String> receivedBodies = new CopyOnWriteArrayList<>();
    private final List<String> receivedContentTypes = new CopyOnWriteArrayList<>();
    private volatile int respondCode = 200;
    private volatile String respondBody = "ok";
    private String url;

    @BeforeEach
    void setUp() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/sink", exchange -> {
            receivedBodies.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            receivedContentTypes.add(String.valueOf(exchange.getRequestHeaders().getFirst("Content-Type")));
            byte[] out = respondBody.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(respondCode, out.length);
            exchange.getResponseBody().write(out);
            exchange.close();
        });
        server.start();
        url = "http://127.0.0.1:" + server.getAddress().getPort() + "/sink";
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    private static HttpWebhookTransport transport(OutboundGuard guard, long notifyTimeoutMs) {
        return new HttpWebhookTransport(new OutboundTimeouts(3000, 12000, 15000), guard, notifyTimeoutMs);
    }

    @Test
    @DisplayName("POST 出去的是一份合法 JSON，Content-Type 为 application/json（真端口收到）")
    void postsJsonToSink() {
        respondCode = 200;
        NotificationService.Delivery d = transport(null, 10000).post(url, "{\"text\":\"真实告警\"}");

        assertTrue(d.success(), d.message());
        assertEquals(200, d.httpCode());
        assertEquals(1, receivedBodies.size(), "假对端必须真的收到一次 POST");
        assertEquals("{\"text\":\"真实告警\"}", receivedBodies.get(0));
        assertTrue(receivedContentTypes.get(0).contains("application/json"),
                "Content-Type 必须声明 JSON：" + receivedContentTypes.get(0));
    }

    @Test
    @DisplayName("对端 500/404 → 识别为失败并带上响应片段（不是「没抛异常就算成功」）")
    void nonSuccessIsFailureWithSnippet() {
        respondCode = 500;
        respondBody = "{\"err\":\"boom\"}";
        NotificationService.Delivery d = transport(null, 10000).post(url, "{}");
        assertFalse(d.success(), "500 必须判为失败");
        assertEquals(500, d.httpCode());
        assertTrue(d.message().contains("boom"), "失败信息要带对端响应片段，否则排障只能猜：" + d.message());

        respondCode = 404;
        respondBody = "not found";
        NotificationService.Delivery d2 = transport(null, 10000).post(url, "{}");
        assertFalse(d2.success());
        assertTrue(d2.message().contains("404"), d2.message());
    }

    @Test
    @DisplayName("空地址不发出站；接上 OutboundGuard 后冷却按 notify-webhook 隔离并 fail-closed")
    void rejectsEmptyUrlAndUsesGuard() throws IOException {
        OutboundGuard guard = new OutboundGuard();
        ReflectionTestUtils.setField(guard, "defaultCooldownMs", 60000L);
        ReflectionTestUtils.setField(guard, "maxInflightPerDependency", 2);
        HttpWebhookTransport t = transport(guard, 10000);
        assertTrue(t.guardEnabled(), "接了守卫就要如实暴露");

        NotificationService.Delivery d = t.post("", "{}");
        assertFalse(d.success());
        assertTrue(d.message().contains("为空"), d.message());

        // 打开通知链路的冷却后，守卫必须立刻 fail-closed（不再真的出网等超时）
        guard.openCircuit(NotificationService.DEP_WEBHOOK);
        NotificationService.Delivery d2 = t.post(url, "{}");
        assertFalse(d2.success());
        assertTrue(d2.message().contains("冷却") || d2.message().contains("终止"), d2.message());
        assertTrue(guard.cooldownRemainingMs(NotificationService.DEP_WEBHOOK) > 0);
        assertEquals(0, receivedBodies.size(), "冷却期内不许再出网");
    }

    @Test
    @DisplayName("调用预算按 app.notify.timeout-ms 收紧，但绝不会超过统一出站预算")
    void callTimeoutNeverExceedsUnifiedBudget() {
        assertEquals(10000, transport(null, 10000).effectiveCallTimeoutMs());
        // 配得比统一预算还大时，取统一预算（15s）而不是放大到 60s
        assertEquals(15000, transport(null, 60000).effectiveCallTimeoutMs());
    }
}
