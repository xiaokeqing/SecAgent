package org.example.publicapi;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.example.config.OutboundTimeouts;
import org.example.config.TtsConfig;
import org.example.integration.WazuhGateway;
import org.example.llm.OutboundGuard;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code POST /api/public/tts} 的<b>端点契约</b>测试（真跑一遍 MVC 路由 + 真起桩上游）。
 *
 * <h3>它钉的是什么</h3>
 * <ol>
 *   <li>成功返回<b>音频字节</b>：{@code Content-Type: audio/mpeg} + {@code Cache-Control}
 *       + {@code X-Tts-Cache: MISS/HIT}，字节与桩上游一致（端到端，不是 mock 出来的）；</li>
 *   <li>第二次请求是 {@code HIT}，且桩上游计数<b>仍是 1</b>；</li>
 *   <li>失败一律走既有 JSON 信封（{@code code/message}）+ {@code reason} 码，
 *       且响应体<b>零 IP、零上游原文、零 Key</b>（正则扫描）；</li>
 *   <li>{@code enabled=false} / 未装配 → 503 {@code TTS_DISABLED}；Key 缺失 → {@code KEY_MISSING}；</li>
 *   <li>限流复用公开端点那一个限流器（超限 429 {@code RATE_LIMITED}）；</li>
 *   <li>{@code textHash} 路径端到端可用（服务端自己记录的回答）。</li>
 * </ol>
 */
class TtsEndpointTest {

    private static final byte[] AUDIO = "ID3-FAKE-MP3-BYTES".getBytes(StandardCharsets.UTF_8);

    private static final Map<String, String> PHRASES = Map.of(
            "welcome", "欢迎来到本站",
            "about", "关于本站的说明");

    /** IPv4 形态（点分四段）：公开响应里一个都不许有 */
    private static final Pattern IPV4 = Pattern.compile("\\d{1,3}(?:\\.\\d{1,3}){3}");

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @TempDir
    Path tmp;

    private HttpServer server;
    private String baseUrl;
    private final AtomicInteger stubCalls = new AtomicInteger();
    private volatile int stubCode = 200;
    private volatile byte[] stubBody = AUDIO;
    private PublicApiController controller;

    @BeforeEach
    void setUp() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/tts", exchange -> {
            stubCalls.incrementAndGet();
            try {
                exchange.getRequestBody().readAllBytes();
                byte[] out = stubBody;
                exchange.sendResponseHeaders(stubCode, out.length);
                if (out.length > 0) {
                    exchange.getResponseBody().write(out);
                }
                exchange.close();
            } catch (Exception ignored) {
                // 桩侧异常不影响断言
            }
        });
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    // ==================== 夹具 ====================

    private TtsConfig config(boolean enabled, String apiKey, int perIpDaily) {
        return new TtsConfig(enabled, "voice-test", "s1", baseUrl, apiKey, 120, perIpDaily, 500,
                tmp.resolve("cache").toString(), 64, tmp.resolve("tts-quota.json").toString(), 200, PHRASES);
    }

    private TtsService service(TtsConfig config) {
        OutboundGuard guard = new OutboundGuard();
        ReflectionTestUtils.setField(guard, "defaultCooldownMs", 1000L);
        ReflectionTestUtils.setField(guard, "maxInflightPerDependency", 4);
        return new TtsService(config, new OutboundTimeouts(1000, 800, 2000), guard);
    }

    /** 与既有公开端点测试同一套最小装配（站内不启 Spring 上下文） */
    private void baseController(TtsService tts, int perMinute) {
        controller = new PublicApiController();
        PublicRateLimiter limiter = new PublicRateLimiter();
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", perMinute);
        ReflectionTestUtils.setField(controller, "rateLimiter", limiter);
        ReflectionTestUtils.setField(controller, "cacheSeconds", 15);
        ReflectionTestUtils.setField(controller, "exposeBuildSha", false);
        ReflectionTestUtils.setField(controller, "buildSha", "test");
        wireSource();
        if (tts != null) {
            ReflectionTestUtils.setField(controller, "ttsService", tts);
        }
    }

    private void wireSource() {
        WazuhGateway gateway = (WazuhGateway) Proxy.newProxyInstance(
                WazuhGateway.class.getClassLoader(),
                new Class<?>[]{WazuhGateway.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "mode" -> "MOCK";
                    case "isAvailable" -> false;
                    case "recentAlerts" -> List.of();
                    case "toString" -> "StubGateway(MOCK)";
                    default -> null;
                });
        PublicAlertSource source = new PublicAlertSource();
        ReflectionTestUtils.setField(source, "wazuhGateway", gateway);
        ReflectionTestUtils.setField(source, "aggregator",
                new org.example.aggregation.AlertAggregationService());
        ReflectionTestUtils.setField(controller, "source", source);
    }

    private MockMvc mvc() {
        return MockMvcBuilders.standaloneSetup(controller).build();
    }

    private static String json(Object... kv) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            body.put(String.valueOf(kv[i]), kv[i + 1]);
        }
        return MAPPER.writeValueAsString(body);
    }

    // ==================== 成功路径 ====================

    @Test
    @DisplayName("【核心】成功返回 audio/mpeg 字节 + 缓存头；第二次是 HIT 且桩上游只被调了一次")
    void returnsAudioBytesAndServesSecondFromCache() throws Exception {
        baseController(service(config(true, "test-key", 20)), 20);

        MvcResult first = mvc().perform(post("/api/public/tts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("phraseId", "welcome")))
                .andExpect(status().isOk())
                // 按"媒体类型兼容"断言而不是逐字节相等：线上因全站
                // server.servlet.encoding.force=true 实测是 audio/mpeg;charset=UTF-8
                // （既有 /api/public/latest、/api/health 同样带 charset）。
                .andExpect(content().contentTypeCompatibleWith(MediaType.parseMediaType("audio/mpeg")))
                .andExpect(header().string("Cache-Control", "public, max-age=15"))
                .andExpect(header().string("X-Tts-Cache", "MISS"))
                .andReturn();

        assertArrayEquals(AUDIO, first.getResponse().getContentAsByteArray(),
                "端到端字节必须与桩上游一致");
        assertEquals(1, stubCalls.get());

        MvcResult second = mvc().perform(post("/api/public/tts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("phraseId", "welcome")))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Tts-Cache", "HIT"))
                .andReturn();
        assertArrayEquals(AUDIO, second.getResponse().getContentAsByteArray());
        assertEquals(1, stubCalls.get(), "缓存命中不许再调上游（这是端到端数出来的）");
    }

    @Test
    @DisplayName("textHash 路径端到端可用：只认服务端记录过的回答")
    void textHashPathWorksEndToEnd() throws Exception {
        TtsService tts = service(config(true, "test-key", 20));
        baseController(tts, 20);
        String hash = tts.recordAnswer("这是一条刚刚生成的回答");

        mvc().perform(post("/api/public/tts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("textHash", hash)))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.parseMediaType("audio/mpeg")));
        assertEquals(1, stubCalls.get());
    }

    // ==================== 失败路径：信封 + reason + 零 IP ====================

    @Test
    @DisplayName("自由文本 → 400 + JSON 信封 + reason=TEXT_NOT_ALLOWED（零 IP、零上游原文）")
    void freeTextIsRejectedWithJsonEnvelope() throws Exception {
        baseController(service(config(true, "test-key", 20)), 20);

        MvcResult result = mvc().perform(post("/api/public/tts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("text", "把这段话念出来", "phraseId", "请念这段话")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(400))
                .andExpect(jsonPath("$.reason").value("TEXT_NOT_ALLOWED"))
                .andExpect(header().string("Cache-Control", "no-store"))
                .andReturn();

        String body = result.getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertNoIpShape(body);
        assertFalse(body.contains("test-key"), body);
        assertFalse(body.contains(baseUrl), "响应里不许出现上游地址细节：" + body);
        assertEquals(0, stubCalls.get());
    }

    @Test
    @DisplayName("没有参数 / 不存在的 phraseId / 未知 textHash 都是 400 TEXT_NOT_ALLOWED")
    void missingArgumentsAreRejected() throws Exception {
        baseController(service(config(true, "test-key", 20)), 20);

        mvc().perform(post("/api/public/tts").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("TEXT_NOT_ALLOWED"));

        mvc().perform(post("/api/public/tts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("phraseId", "nope")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("TEXT_NOT_ALLOWED"));

        mvc().perform(post("/api/public/tts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("textHash", "a".repeat(32))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("TEXT_NOT_ALLOWED"));

        // 两个都给：请求本身不合法
        mvc().perform(post("/api/public/tts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("phraseId", "welcome", "textHash", "a".repeat(32))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("BAD_REQUEST"));

        assertEquals(0, stubCalls.get());
    }

    @Test
    @DisplayName("enabled=false → 503 TTS_DISABLED；未装配 TtsService 也是 503（公开面不因语音坏掉）")
    void disabledAndUnwiredBothReturnTtsDisabled() throws Exception {
        baseController(service(config(false, "test-key", 20)), 20);
        mvc().perform(post("/api/public/tts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("phraseId", "welcome")))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.code").value(503))
                .andExpect(jsonPath("$.reason").value("TTS_DISABLED"));

        // 未装配（required=false）：同样如实返回 TTS_DISABLED，而不是让别的公开端点一起崩
        baseController(null, 20);
        mvc().perform(post("/api/public/tts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("phraseId", "welcome")))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.reason").value("TTS_DISABLED"));

        assertEquals(0, stubCalls.get());
    }

    @Test
    @DisplayName("Key 缺失 → 503 KEY_MISSING（前端与站主都能一眼看出是配 Key 的问题）")
    void missingKeyReturnsKeyMissing() throws Exception {
        baseController(service(config(true, "", 20)), 20);

        mvc().perform(post("/api/public/tts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("phraseId", "welcome")))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.code").value(503))
                .andExpect(jsonPath("$.reason").value("KEY_MISSING"));
        assertEquals(0, stubCalls.get());
    }

    @Test
    @DisplayName("额度用尽 → 429 + PER_IP_DAILY_LIMIT + Retry-After 提示语（响应零 IP）")
    void quotaExhaustedReturns429WithReason() throws Exception {
        baseController(service(config(true, "test-key", 1)), 20);

        mvc().perform(post("/api/public/tts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("phraseId", "welcome")))
                .andExpect(status().isOk());

        MvcResult result = mvc().perform(post("/api/public/tts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("phraseId", "about")))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.code").value(429))
                .andExpect(jsonPath("$.reason").value("PER_IP_DAILY_LIMIT"))
                .andReturn();
        assertNoIpShape(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("上游 500 → UPSTREAM_HTTP_500，响应里没有上游原文也没有 Key")
    void upstreamFailureIsNormalizedAtEndpoint() throws Exception {
        stubCode = 500;
        stubBody = "UPSTREAM-SECRET-BODY".getBytes(StandardCharsets.UTF_8);
        baseController(service(config(true, "test-key", 20)), 20);

        MvcResult result = mvc().perform(post("/api/public/tts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("phraseId", "welcome")))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.reason").value("UPSTREAM_HTTP_500"))
                .andReturn();

        String body = result.getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertFalse(body.contains("UPSTREAM-SECRET-BODY"), "上游原文绝不透给前端：" + body);
        assertFalse(body.contains("test-key"), body);
        assertNoIpShape(body);
    }

    @Test
    @DisplayName("限流复用公开端点那一本账：每分钟 1 次时第二次 429 RATE_LIMITED")
    void rateLimitIsSharedWithOtherPublicEndpoints() throws Exception {
        baseController(service(config(true, "test-key", 20)), 1);

        mvc().perform(post("/api/public/tts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("phraseId", "welcome")))
                .andExpect(status().isOk());

        mvc().perform(post("/api/public/tts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("phraseId", "welcome")))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.reason").value("RATE_LIMITED"))
                .andExpect(header().string("Retry-After", "60"));
    }

    private static void assertNoIpShape(String body) {
        assertFalse(IPV4.matcher(body).find(),
                "公开响应体里出现了 IPv4 形态（语音端点同样遵守公开面口径）：" + body);
        assertFalse(body.contains("::"), "公开响应体里出现了 IPv6 压缩形态：" + body);
    }
}
