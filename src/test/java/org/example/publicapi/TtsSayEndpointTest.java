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
 * {@code POST /api/public/tts/say}（自由文本）的端点契约测试。
 *
 * <h3>它钉的是什么</h3>
 * <ol>
 *   <li>合法日语 ⇒ 200 + {@code audio/wav} 字节（CosyVoice 两跳：先拿 JSON 里的
 *       {@code output.audio.url}，再 GET 回 wav）—— 端到端，桩上游数得出来；</li>
 *   <li><b>同句只有一次上游调用</b>：第二次是 {@code X-Tts-Cache: HIT}，桩计数仍是 1；</li>
 *   <li>超长 / 非日语 ⇒ 400 + JSON 信封 + {@code reason} 码（不是 500、不是空 body）；</li>
 *   <li>每日额度用尽 ⇒ 429，且<b>不再调上游</b>（钱不是花在报错上的）；</li>
 *   <li>失败响应里<b>零 IP、零上游原文、零 Key</b>（正则扫描）。</li>
 * </ol>
 *
 * <p>与 {@link TtsEndpointTest}（短语表那条线）刻意分开：两套闸门不一样，
 * 混在一个类里最容易出现的错是"用短语表的参数去验自由文本"，那样两条线都会被验松。
 */
class TtsSayEndpointTest {

    private static final byte[] AUDIO = "RIFF-FAKE-WAV-BYTES".getBytes(StandardCharsets.UTF_8);

    /** 公开响应里一个 IPv4 都不许有（既有口径） */
    private static final Pattern IPV4 = Pattern.compile("\\d{1,3}(?:\\.\\d{1,3}){3}");

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @TempDir
    Path tmp;

    private HttpServer server;
    private String baseUrl;
    /** 只数"合成请求"（/synth），不数下游取音频（/audio.wav） */
    private final AtomicInteger synthCalls = new AtomicInteger();
    private PublicApiController controller;

    @BeforeEach
    void setUp() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        // CosyVoice：POST 端点直接就是 base-url（代码不拼路径），返回 JSON 里给音频地址
        server.createContext("/synth", exchange -> {
            synthCalls.incrementAndGet();
            try {
                exchange.getRequestBody().readAllBytes();
                String json = "{\"output\":{\"audio\":{\"url\":\"" + baseUrl + "/audio.wav\"}}}";
                byte[] out = json.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, out.length);
                exchange.getResponseBody().write(out);
                exchange.close();
            } catch (Exception ignored) {
                // 桩侧异常不影响断言（被测端会归一成 502）
            }
        });
        server.createContext("/audio.wav", exchange -> {
            try {
                exchange.getRequestBody().readAllBytes();
                exchange.sendResponseHeaders(200, AUDIO.length);
                exchange.getResponseBody().write(AUDIO);
                exchange.close();
            } catch (Exception ignored) {
                // 同上
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

    private TtsConfig config(int perIpDaily, int globalDaily) {
        return new TtsConfig(true, "voice-ja", "cosyvoice-v3.5-plus", baseUrl + "/synth", "test-key",
                120, perIpDaily, globalDaily,
                tmp.resolve("cache").toString(), 64, tmp.resolve("tts-quota.json").toString(), 200,
                Map.of(), "cosyvoice");
    }

    private TtsService service(TtsConfig config) {
        OutboundGuard guard = new OutboundGuard();
        ReflectionTestUtils.setField(guard, "defaultCooldownMs", 1000L);
        ReflectionTestUtils.setField(guard, "maxInflightPerDependency", 4);
        return new TtsService(config, new OutboundTimeouts(1000, 800, 2000), guard);
    }

    private MockMvc mvc(TtsService tts, int sayPerIpDaily, int sayGlobalDaily) {
        controller = new PublicApiController();
        PublicRateLimiter limiter = new PublicRateLimiter();
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 20);
        ReflectionTestUtils.setField(controller, "rateLimiter", limiter);
        ReflectionTestUtils.setField(controller, "cacheSeconds", 15);
        ReflectionTestUtils.setField(controller, "exposeBuildSha", false);
        ReflectionTestUtils.setField(controller, "buildSha", "test");
        ReflectionTestUtils.setField(controller, "ttsSayPerIpDaily", sayPerIpDaily);
        ReflectionTestUtils.setField(controller, "ttsSayGlobalDaily", sayGlobalDaily);
        wireSource();
        if (tts != null) {
            ReflectionTestUtils.setField(controller, "ttsService", tts);
        }
        return MockMvcBuilders.standaloneSetup(controller).build();
    }

    /** 与既有公开端点测试同一套最小装配（站内不启 Spring 上下文） */
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

    private static String json(Object... kv) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            body.put(String.valueOf(kv[i]), kv[i + 1]);
        }
        return MAPPER.writeValueAsString(body);
    }

    private static void assertNoIpShape(String body) {
        assertFalse(IPV4.matcher(body).find(), "公开响应里不许出现 IPv4 形状：" + body);
        assertFalse(body.contains("test-key"), "公开响应里不许回显 Key：" + body);
        assertFalse(body.contains("127.0.0.1"), "公开响应里不许回显上游地址：" + body);
    }

    // ==================== 成功路径 ====================

    @Test
    @DisplayName("【核心】合法日语 → 200 + audio/wav 字节；英文标签/缓存头齐全")
    void speaksShortJapaneseEndToEnd() throws Exception {
        MvcResult result = mvc(service(config(30, 300)), 30, 300)
                .perform(post("/api/public/tts/say")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("text", "この攻撃はブルートフォースです。")))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.parseMediaType("audio/wav")))
                .andExpect(header().string("Cache-Control", "public, max-age=15"))
                .andExpect(header().string("X-Tts-Cache", "MISS"))
                .andReturn();

        assertArrayEquals(AUDIO, result.getResponse().getContentAsByteArray(),
                "端到端字节必须与桩上游一致");
        assertEquals(1, synthCalls.get());
    }

    @Test
    @DisplayName("同句只合成一次：第二次 X-Tts-Cache=HIT 且上游计数仍是 1")
    void secondRequestHitsCacheAndSpendsNothing() throws Exception {
        MockMvc mvc = mvc(service(config(30, 300)), 30, 300);
        String body = json("text", "この攻撃はブルートフォースです。");

        mvc.perform(post("/api/public/tts/say").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Tts-Cache", "MISS"));
        assertEquals(1, synthCalls.get());

        MvcResult second = mvc.perform(post("/api/public/tts/say")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Tts-Cache", "HIT"))
                .andReturn();
        assertArrayEquals(AUDIO, second.getResponse().getContentAsByteArray());
        assertEquals(1, synthCalls.get(), "缓存命中不许再调上游（这是端到端数出来的）");
    }

    // ==================== 失败路径 ====================

    @Test
    @DisplayName("超过 60 字 → 400 TEXT_TOO_LONG，且一次上游都没调")
    void tooLongTextIsRejected() throws Exception {
        String tooLong = "あ".repeat(JapaneseSpeakText.SAY_MAX_CHARS + 1);
        MvcResult result = mvc(service(config(30, 300)), 30, 300)
                .perform(post("/api/public/tts/say")
                        .contentType(MediaType.APPLICATION_JSON).content(json("text", tooLong)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(400))
                .andExpect(jsonPath("$.reason").value("TEXT_TOO_LONG"))
                .andExpect(header().string("Cache-Control", "no-store"))
                .andReturn();

        assertNoIpShape(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
        assertEquals(0, synthCalls.get(), "被闸下来的文本不该花上游的钱");
    }

    @Test
    @DisplayName("非日语字符集（英文/emoji）→ 400 TEXT_CHARSET_NOT_ALLOWED")
    void nonJapaneseTextIsRejected() throws Exception {
        MockMvc mvc = mvc(service(config(30, 300)), 30, 300);

        MvcResult english = mvc.perform(post("/api/public/tts/say")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("text", "This is an SSH brute force attack.")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("TEXT_CHARSET_NOT_ALLOWED"))
                .andReturn();
        assertNoIpShape(english.getResponse().getContentAsString(StandardCharsets.UTF_8));

        mvc.perform(post("/api/public/tts/say")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("text", "攻撃です 😀")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("TEXT_CHARSET_NOT_ALLOWED"));

        assertEquals(0, synthCalls.get());
    }

    @Test
    @DisplayName("空文本 → 400 TEXT_EMPTY")
    void blankTextIsRejected() throws Exception {
        mvc(service(config(30, 300)), 30, 300)
                .perform(post("/api/public/tts/say")
                        .contentType(MediaType.APPLICATION_JSON).content(json("text", "   ")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("TEXT_EMPTY"));
    }

    @Test
    @DisplayName("本 IP 每日额度用尽 → 429 PER_IP_DAILY_LIMIT（换句子也绕不过）")
    void perIpDailyQuotaIsEnforced() throws Exception {
        MockMvc mvc = mvc(service(config(1, 300)), 1, 300);

        mvc.perform(post("/api/public/tts/say")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("text", "最初の質問です。")))
                .andExpect(status().isOk());
        assertEquals(1, synthCalls.get());

        // 故意换一句（不同缓存键）：证明挡下来的是额度，不是缓存
        MvcResult second = mvc.perform(post("/api/public/tts/say")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("text", "二回目の質問です。")))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.code").value(429))
                .andExpect(jsonPath("$.reason").value(TtsQuotaStore.REASON_PER_IP))
                .andExpect(header().string("Cache-Control", "no-store"))
                .andReturn();

        assertNoIpShape(second.getResponse().getContentAsString(StandardCharsets.UTF_8));
        assertEquals(1, synthCalls.get(), "额度已尽时不该再调上游");
    }

    @Test
    @DisplayName("全局额度用尽 → 429 GLOBAL_DAILY_LIMIT")
    void globalDailyQuotaIsEnforced() throws Exception {
        MockMvc mvc = mvc(service(config(30, 1)), 30, 1);

        mvc.perform(post("/api/public/tts/say")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("text", "最初の質問です。")))
                .andExpect(status().isOk());

        mvc.perform(post("/api/public/tts/say")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("text", "二回目の質問です。")))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.reason").value(TtsQuotaStore.REASON_GLOBAL));
    }

    @Test
    @DisplayName("未装配 TtsService → 503 TTS_DISABLED（而不是 500）")
    void disabledIsExplicit() throws Exception {
        MvcResult result = mvc(null, 30, 300)
                .perform(post("/api/public/tts/say")
                        .contentType(MediaType.APPLICATION_JSON).content(json("text", "攻撃です。")))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.reason").value("TTS_DISABLED"))
                .andReturn();
        assertTrue(result.getResponse().getContentAsString(StandardCharsets.UTF_8).contains("TTS_DISABLED"));
    }
}
