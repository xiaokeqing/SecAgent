package org.example.llm;

import com.sun.net.httpserver.HttpServer;
import org.example.config.DeepSeekConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * DeepSeek 对话 provider 的出站行为测试（<b>真端口 + 真字节</b>）。
 *
 * <h3>为什么必须起一个真 HTTP 服务端，而不是 mock 掉 HTTP 层</h3>
 * 这条链路最容易错的三处全在 HTTP 这一层，mock 掉就全看不见了：
 * <ol>
 *   <li><b>请求形状</b>：是不是 POST 到 {@code /v1/chat/completions}、Bearer 头在不在、
 *       JSON 体里 {@code model/messages/stream} 对不对 —— 这些错了对端只会返回 400，
 *       而"400 → 未生成"在上层看起来和"模型不可用"一模一样；</li>
 *   <li><b>失败必须真的被识别成失败</b>：非 200 / 非法 JSON / content 为空
 *       都<b>不得</b>变成"空回答"或任何形态的兜底文本；</li>
 *   <li><b>超时与熔断</b>：对端挂起时必须在有限时间内失败，并且冷却期内<b>不再出网</b>。</li>
 * </ol>
 * 用 JDK 自带的 {@code com.sun.net.httpserver.HttpServer}（<b>零新增依赖</b>，
 * 离线构建也能跑）—— 与 webhook 出站测试同一套办法。
 */
class DeepSeekLlmProviderTest {

    private HttpServer server;
    private final List<String> receivedBodies = new CopyOnWriteArrayList<>();
    private final List<String> receivedAuth = new CopyOnWriteArrayList<>();
    private final List<String> receivedPaths = new CopyOnWriteArrayList<>();
    private final List<String> receivedMethods = new CopyOnWriteArrayList<>();

    /** 响应状态码；200 = 正常 */
    private volatile int respondCode = 200;
    /** 响应体原文 */
    private volatile String respondBody = "{\"choices\":[{\"message\":{\"content\":\"真实模型输出\"}}]}";
    /** 服务端处理前先睡多久（用来复现"对端挂起"） */
    private volatile long stallMs = 0;

    private OutboundGuard guard;

    @BeforeEach
    void setUp() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            receivedBodies.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            receivedAuth.add(String.valueOf(exchange.getRequestHeaders().getFirst("Authorization")));
            receivedPaths.add(exchange.getRequestURI().getPath());
            receivedMethods.add(exchange.getRequestMethod());
            if (stallMs > 0) {
                try {
                    Thread.sleep(stallMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            byte[] out = respondBody.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(respondCode, out.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(out);
            }
            exchange.close();
        });
        server.start();

        guard = new OutboundGuard();
        ReflectionTestUtils.setField(guard, "defaultCooldownMs", 60000L);
        ReflectionTestUtils.setField(guard, "maxInflightPerDependency", 2);
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    private String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    /** 构造一个"已选中 deepseek 且 Key 已配"的 provider（全部字段注入，与 Spring 一致） */
    private DeepSeekLlmProvider provider(DeepSeekConfig timeouts) {
        DeepSeekLlmProvider p = new DeepSeekLlmProvider();
        ReflectionTestUtils.setField(p, "selectedProvider", "deepseek");
        ReflectionTestUtils.setField(p, "baseUrl", baseUrl());
        ReflectionTestUtils.setField(p, "model", "deepseek-chat");
        ReflectionTestUtils.setField(p, "apiKey", "test-key-not-a-real-credential");
        ReflectionTestUtils.setField(p, "temperature", 0.0);
        ReflectionTestUtils.setField(p, "maxTokens", 800);
        ReflectionTestUtils.setField(p, "timeouts", timeouts);
        ReflectionTestUtils.setField(p, "guard", guard);
        return p;
    }

    // ==================== 1) 请求形状与成功路径 ====================

    @Test
    @Timeout(30)
    @DisplayName("POST 到 /v1/chat/completions，Bearer 头与 OpenAI 兼容 JSON 体形状正确")
    void postsOpenAiCompatibleRequest() throws Exception {
        respondCode = 200;
        DeepSeekLlmProvider p = provider(DeepSeekConfig.defaults());

        String out = p.generate("你是安全研判分析员，只输出 JSON。", "问题：什么是 SSRF？");

        assertEquals("真实模型输出", out, "必须原样返回 choices[0].message.content");
        assertEquals(List.of("/v1/chat/completions"), receivedPaths, "路径必须是 OpenAI 兼容的那个");
        assertEquals(List.of("POST"), receivedMethods);
        assertTrue(receivedAuth.get(0).startsWith("Bearer "),
                "必须是 Bearer 鉴权（否则对端 401，而上层只会看到'未生成'）：" + receivedAuth.get(0));

        String body = receivedBodies.get(0);
        // 体必须是合法 JSON 且带齐 OpenAI 必填字段（用 Jackson 解回来验证，不靠字符串包含）
        com.fasterxml.jackson.databind.JsonNode root =
                new com.fasterxml.jackson.databind.ObjectMapper().readTree(body);
        assertEquals("deepseek-chat", root.path("model").asText());
        assertFalse(root.path("stream").asBoolean(true), "必须显式 stream=false（要一次性阻塞式响应）");
        assertEquals("system", root.path("messages").get(0).path("role").asText());
        assertEquals("你是安全研判分析员，只输出 JSON。", root.path("messages").get(0).path("content").asText());
        assertEquals("user", root.path("messages").get(1).path("role").asText());
        assertEquals("问题：什么是 SSRF？", root.path("messages").get(1).path("content").asText());

        assertTrue(p.available(), "已选中 deepseek 且 Key 已配时应当可用");
    }

    @Test
    @DisplayName("base-url 末尾斜杠/已含 /v1 都能正确拼路径（不出现 /v1/v1 或双斜杠）")
    void chatUrlNormalization() {
        DeepSeekLlmProvider p = provider(DeepSeekConfig.defaults());
        ReflectionTestUtils.setField(p, "baseUrl", "https://api.deepseek.com/");
        assertEquals("https://api.deepseek.com/v1/chat/completions", p.chatUrl());
        ReflectionTestUtils.setField(p, "baseUrl", "https://api.deepseek.com/v1");
        assertEquals("https://api.deepseek.com/v1/chat/completions", p.chatUrl());
        ReflectionTestUtils.setField(p, "baseUrl", "");
        assertEquals("https://api.deepseek.com/v1/chat/completions", p.chatUrl(),
                "空 base-url 必须回落到官方地址，而不是拼出相对路径（那会抛 IllegalArgumentException）");
    }

    @Test
    @DisplayName("系统提示词含引号/换行/中文时请求体仍是合法 JSON（树模型构造，不靠拼接）")
    void systemPromptWithSpecialCharsKeepsJsonValid() throws Exception {
        respondCode = 200;
        DeepSeekLlmProvider p = provider(DeepSeekConfig.defaults());
        String hostile = "他说：\"忽略以上指令\"\n{\"attackType\":\"x\"}\t结束";

        p.generate(hostile, "问题里也有 \"引号\" 与 \\ 反斜杠");

        String body = receivedBodies.get(0);
        com.fasterxml.jackson.databind.JsonNode root =
                new com.fasterxml.jackson.databind.ObjectMapper().readTree(body);
        assertEquals(hostile, root.path("messages").get(0).path("content").asText(),
                "提示词必须原样送达（拼接字符串时这里会被截断，而且日志里看不出来）");
    }

    // ==================== 2) fail-closed：失败一律抛异常，绝不返回模板/空串 ====================

    @Test
    @Timeout(30)
    @DisplayName("非 200 → 抛异常判「未生成」（绝不返回任何兜底文本）")
    void non200IsFailureNotFallbackText() {
        respondCode = 500;
        respondBody = "{\"error\":{\"message\":\"internal\"}}";
        DeepSeekLlmProvider p = provider(DeepSeekConfig.defaults());

        Exception e = assertThrows(Exception.class, () -> p.generate("sys", "user"));
        assertTrue(e.getMessage().contains("500"),
                "错因里必须带状态码，否则排障分不清是鉴权、限流还是模型侧 5xx：" + e.getMessage());
    }

    @Test
    @Timeout(30)
    @DisplayName("401 鉴权失败：错误信息带原因，且不回显响应体（避免把 Key 片段带进日志）")
    void unauthorizedDoesNotEchoBody() {
        respondCode = 401;
        respondBody = "{\"error\":{\"message\":\"invalid api key sk-abcdef123456\"}}";
        DeepSeekLlmProvider p = provider(DeepSeekConfig.defaults());

        Exception e = assertThrows(Exception.class, () -> p.generate("sys", "user"));
        assertTrue(e.getMessage().contains("鉴权失败"), e.getMessage());
        assertFalse(e.getMessage().contains("sk-abcdef123456"),
                "日志会被长期采集，绝不能把对端回显的密钥材料写进去：" + e.getMessage());
    }

    @Test
    @Timeout(30)
    @DisplayName("非法 JSON / 缺 choices / content 非字符串 / content 为空 → 全部判「未生成」")
    void malformedBodiesAreAllFailures() {
        DeepSeekLlmProvider p = provider(DeepSeekConfig.defaults());

        respondCode = 200;
        respondBody = "not json at all";
        assertThrows(Exception.class, () -> p.generate("sys", "user"), "非 JSON 必须失败");

        respondBody = "{\"id\":\"x\"}";
        assertThrows(Exception.class, () -> p.generate("sys", "user"), "缺 choices 必须失败");

        respondBody = "{\"choices\":[]}";
        assertThrows(Exception.class, () -> p.generate("sys", "user"), "空 choices 必须失败");

        respondBody = "{\"choices\":[{\"message\":{\"content\":null}}]}";
        assertThrows(Exception.class, () -> p.generate("sys", "user"), "content 为 null 必须失败");

        respondBody = "{\"choices\":[{\"message\":{\"reasoning_content\":\"思考中\"}}]}";
        assertThrows(Exception.class, () -> p.generate("sys", "user"),
                "只有 reasoning_content 的响应（推理型模型）必须失败，不得拿思考过程冒充结论");

        respondBody = "{\"choices\":[{\"message\":{\"content\":{\"a\":1}}}]}";
        assertThrows(Exception.class, () -> p.generate("sys", "user"),
                "content 是结构化对象时必须失败（不 toString 出一段假文本）");

        respondBody = "{\"choices\":[{\"message\":{\"content\":\"\"}}]}";
        Exception blank = assertThrows(Exception.class, () -> p.generate("sys", "user"),
                "空正文必须失败：它是'未生成'，不是'回答为空'");
        assertTrue(blank.getMessage().contains("为空"), blank.getMessage());
    }

    @Test
    @Timeout(30)
    @DisplayName("响应体超过上限 → 按非法处理（声明长度与实际读取两条路径都拦住）")
    void oversizedBodyIsRejected() throws Exception {
        // 路径 ①：Content-Length 声明就超限 → 直接拒绝，不读 body
        okhttp3.Response response = new okhttp3.Response.Builder()
                .request(new okhttp3.Request.Builder().url("http://127.0.0.1:1/x").build())
                .protocol(okhttp3.Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .header("Content-Length", String.valueOf(DeepSeekLlmProvider.MAX_RESPONSE_BYTES + 1))
                .body(okhttp3.ResponseBody.create("x", okhttp3.MediaType.get("application/json")))
                .build();
        assertThrows(IOException.class, () -> DeepSeekLlmProvider.readBodyBounded(response));

        // 路径 ②：声明缺失/撒谎时，靠真实读取的字节数兜住（这是"对端不是 DeepSeek"的最后一道闸）
        byte[] huge = new byte[DeepSeekLlmProvider.MAX_RESPONSE_BYTES + 1024];
        java.util.Arrays.fill(huge, (byte) 'a');
        okhttp3.Response lying = new okhttp3.Response.Builder()
                .request(new okhttp3.Request.Builder().url("http://127.0.0.1:1/x").build())
                .protocol(okhttp3.Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .body(okhttp3.ResponseBody.create(huge, okhttp3.MediaType.get("application/json")))
                .build();
        assertThrows(IOException.class, () -> DeepSeekLlmProvider.readBodyBounded(lying),
                "没有 Content-Length 时也必须按字节数截住，不能无限读进内存");
    }

    // ==================== 3) 超时 / 冷却 / 依赖键隔离 ====================

    @Test
    @Timeout(30)
    @DisplayName("对端挂起 → 有限时间内失败（read 超时先触发），并打开 deepseek-chat 的冷却")
    void stalledEndpointFailsBoundedAndOpensCircuit() {
        stallMs = 5000;
        DeepSeekLlmProvider p = provider(new DeepSeekConfig(1000, 500, 1500));

        long start = System.nanoTime();
        assertThrows(Exception.class, () -> p.generate("sys", "user"));
        long elapsedMs = (System.nanoTime() - start) / 1_000_000L;

        assertTrue(elapsedMs < 4500, "挂起的对端必须被有界截断，实际 " + elapsedMs + " ms");
        assertTrue(guard.coolingDown(DeepSeekLlmProvider.DEP_CHAT),
                "传输层失败也必须打开冷却（否则 60s 熔断永远不会生效）");
    }

    @Test
    @Timeout(30)
    @DisplayName("冷却期内立刻 fail-closed 且不再出网")
    void cooldownShortCircuitsWithoutNetworkIo() {
        DeepSeekLlmProvider p = provider(new DeepSeekConfig(1000, 500, 1500));
        guard.openCircuit(DeepSeekLlmProvider.DEP_CHAT);

        int before = receivedBodies.size();
        long start = System.nanoTime();
        Exception e = assertThrows(Exception.class, () -> p.generate("sys", "user"));
        long elapsedMs = (System.nanoTime() - start) / 1_000_000L;

        assertTrue(e.getMessage().contains("冷却"), e.getMessage());
        assertTrue(elapsedMs < 300, "冷却期必须秒回，实际 " + elapsedMs + " ms");
        assertEquals(before, receivedBodies.size(), "冷却期内不许再出网");
    }

    @Test
    @DisplayName("依赖键与 dashscope 分开：DeepSeek 故障不会把 DashScope 通道一起熔断")
    void dependencyKeyIsIsolatedFromDashScope() {
        assertEquals("deepseek-chat", DeepSeekLlmProvider.DEP_CHAT);
        guard.openCircuit(DeepSeekLlmProvider.DEP_CHAT, 60000);
        assertTrue(guard.coolingDown(DeepSeekLlmProvider.DEP_CHAT));
        assertFalse(guard.coolingDown(DashScopeLlmProvider.DEP_CHAT),
                "这两条链路必须各自熔断 —— 共用键会让一家故障误伤另一家");
        assertFalse(guard.coolingDown("dashscope-embedding"),
                "embedding 那条更不该被对话通道的故障影响");
    }

    // ==================== 4) 超时只许收紧不许放大 ====================

    @Test
    @DisplayName("超时配置只许收紧：放大被夹回统一矩阵 3s/12s/15s，非法值不变成永不超时")
    void timeoutsCanOnlyBeTightened() {
        // 放大：一律夹回上限
        DeepSeekConfig widened = new DeepSeekConfig(60000, 600000, 180000);
        assertEquals(DeepSeekConfig.MAX_CONNECT_MS, widened.getEffectiveConnectTimeoutMs());
        assertEquals(DeepSeekConfig.MAX_READ_MS, widened.getEffectiveReadTimeoutMs());
        assertEquals(DeepSeekConfig.MAX_CALL_MS, widened.getEffectiveCallTimeoutMs());
        assertEquals(3000L, widened.getEffectiveConnectTimeoutMs());
        assertEquals(12000L, widened.getEffectiveReadTimeoutMs());
        assertEquals(15000L, widened.getEffectiveCallTimeoutMs());

        // 收紧：允许（这就是"可按依赖给更短预算"的正当用法）
        DeepSeekConfig tightened = new DeepSeekConfig(1000, 2000, 3000);
        assertEquals(1000L, tightened.getEffectiveConnectTimeoutMs());
        assertEquals(2000L, tightened.getEffectiveReadTimeoutMs());
        assertEquals(3000L, tightened.getEffectiveCallTimeoutMs());

        // 非法值（0/负数）不能变成"永不超时"——那正是本项目要修的故障形态
        DeepSeekConfig broken = new DeepSeekConfig(0, -1, 0);
        assertEquals(3000L, broken.getEffectiveConnectTimeoutMs());
        assertEquals(12000L, broken.getEffectiveReadTimeoutMs());
        assertEquals(15000L, broken.getEffectiveCallTimeoutMs());

        // 客户端真正拿到的值 = 已钳制的值（断言对象，而不是只断言常量）
        DeepSeekLlmProvider p = provider(widened);
        assertEquals(3000L, p.effectiveTimeouts().getEffectiveConnectTimeoutMs());
        assertEquals(12000L, p.effectiveTimeouts().getEffectiveReadTimeoutMs());
        assertEquals(15000L, p.effectiveTimeouts().getEffectiveCallTimeoutMs());
        assertNotNull(p.buildClient(), "放大后的配置也必须能正常构造客户端（不抛异常）");
    }

    /**
     * 收敛后的上限是<b>行为可验证</b>的：把配置放大到 60s，真实请求仍在 15s 内被截断。
     *
     * <p>为什么不靠读 OkHttp 的私有字段断言：那既脆弱（版本一升就红）又不证明"真的会截断"。
     * 这里用一个只在关闭时才回包的 <b>auto-close</b> 服务端，让对端一直挂到 callTimeout(15s)：
     * OkHttp 的 {@code Call.timeout} 会中断调用并抛 {@code InterruptedIOException}。
     * 若钳制失效（真按 60s 等），本测试会在 {@link Timeout} 上限被杀掉 —— 那就是失败。
     */
    @Test
    @Timeout(60)
    @DisplayName("【行为验证】配置放大到 60s，真实请求仍在 15s（callTimeout 上限）内被截断")
    void widenedConfigStillCutsOffWithinDefaultCallBudget() throws Exception {
        // 受控对端：收到请求后不写任何响应，直到客户端断开才关闭（accept 后一直挂着）
        HttpServer silent = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        // 【为什么要一个可释放的开关而不是直接 Thread.sleep(120_000)】
        // HttpServer.stop(0) 会一直等到当前 exchange handler 跑完才返回，
        // 于是 handler 睡多久、@AfterEach 就跟着阻塞多久 —— 客户端其实 12s 就超时了，
        // 测试却会被 @Timeout(60) 判失败（这曾让本用例报"timed out after 60 seconds"）。
        // 这里改成"可被提前唤醒的等待"：服务端仍然是【一直不吐响应】，
        // 但测试结束能立刻让它退出。
        java.util.concurrent.atomic.AtomicBoolean releaseSilent = new java.util.concurrent.atomic.AtomicBoolean(false);
        silent.createContext("/", exchange -> {
            try {
                // 不发送响应头、不写 body：客户端会一直等到自己的超时
                long deadline = System.currentTimeMillis() + 120_000;
                while (!releaseSilent.get() && System.currentTimeMillis() < deadline) {
                    Thread.sleep(100);
                }
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            } finally {
                exchange.close();
            }
        });
        silent.start();
        try {
            DeepSeekLlmProvider p = provider(new DeepSeekConfig(60_000, 60_000, 60_000));
            ReflectionTestUtils.setField(p, "baseUrl",
                    "http://127.0.0.1:" + silent.getAddress().getPort());

            long start = System.nanoTime();
            assertThrows(Exception.class, () -> p.generate("sys", "user"));
            long elapsedMs = (System.nanoTime() - start) / 1_000_000L;

            assertTrue(elapsedMs < 15_000,
                    "配置写 60s 也不能真的等 60s（入口预算 15s/25s 会先被拖死），实际 " + elapsedMs + " ms");
            assertTrue(elapsedMs > 1000,
                    "但也不该瞬间失败 —— 瞬间失败说明请求根本没发出去，测的不是超时路径，实际 " + elapsedMs + " ms");
        } finally {
            releaseSilent.set(true);
            silent.stop(0);
        }
    }

    // ==================== 5) 可选性与 Key 缺失 ====================

    @Test
    @DisplayName("Key 缺失 → provider 不可用，且 generate 明确失败（不静默、不出网）")
    void missingKeyMakesProviderUnavailable() {
        DeepSeekLlmProvider p = provider(DeepSeekConfig.defaults());
        ReflectionTestUtils.setField(p, "apiKey", "");

        assertFalse(p.available(), "Key 为空必须判不可用");
        assertFalse(p.keyConfigured());
        int before = receivedBodies.size();
        assertThrows(Exception.class, () -> p.generate("sys", "user"));
        assertEquals(before, receivedBodies.size(), "不可用时绝不出网（不能先试一下再说）");
    }

    @Test
    @DisplayName("未选中 deepseek 时本实现不可用（由选择器接管），且不在自检里谎报可用")
    void notSelectedMeansUnavailable() {
        DeepSeekLlmProvider p = provider(DeepSeekConfig.defaults());
        ReflectionTestUtils.setField(p, "selectedProvider", "dashscope");
        assertFalse(p.available());
        assertTrue(p.keyConfigured(), "Key 已配这一事实与'是否被选中'无关，自检要能分辨二者");
        // Key 已配但不可用：describe() 必须如实反映（不让运维以为切了就好）
        assertTrue(p.describe().contains("key=SET"), p.describe());
        assertTrue(p.describe().contains("model=deepseek-chat"), p.describe());
        assertFalse(p.describe().contains("test-key-not-a-real-credential"),
                "describe() 绝不打印密钥内容：" + p.describe());
    }

    @Test
    @DisplayName("生成的请求体对空提示词也不崩（null 归一成空串）")
    void nullPromptsAreTolerated() throws Exception {
        String body = DeepSeekLlmProvider.buildRequestBody("deepseek-chat", null, null, 0.0, 800);
        com.fasterxml.jackson.databind.JsonNode root =
                new com.fasterxml.jackson.databind.ObjectMapper().readTree(body);
        assertEquals("", root.path("messages").get(0).path("content").asText());
        assertEquals("", root.path("messages").get(1).path("content").asText());
    }
}
