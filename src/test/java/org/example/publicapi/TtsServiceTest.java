package org.example.publicapi;

import com.sun.net.httpserver.HttpServer;
import org.example.config.OutboundTimeouts;
import org.example.config.TtsConfig;
import org.example.llm.OutboundGuard;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link TtsService} 的<b>端到端</b>测试：真起一个本地桩上游（JDK 自带的
 * {@code com.sun.net.httpserver.HttpServer}，零新增依赖），验证三道闸 + 缓存 + 错误归一化。
 *
 * <h3>为什么用真端口而不是 mock 掉 HTTP 层</h3>
 * 这个端点最容易错的地方恰好都在 HTTP 这一层：请求体形状、{@code Authorization} 头、
 * 非 200 怎么处理、空 body 怎么处理、超时会不会把线程占死。
 * mock 掉就看不见这些。桩上游同时充当<b>调用计数器</b>：
 * "缓存命中不许再调上游"这条断言，数的是桩<b>真的收到几次请求</b>，不是数代码里的计数器。
 *
 * <h3>它钉住的验收清单</h3>
 * <ol>
 *   <li>短语命中成功（正文/头形状正确）；</li>
 *   <li>自由文本被拒 400 {@code TEXT_NOT_ALLOWED}（一次上游都没调）；</li>
 *   <li>长度超限 400 {@code TEXT_TOO_LONG}；</li>
 *   <li>单 IP 日额度 429 {@code PER_IP_DAILY_LIMIT}；全局日额度 429 {@code GLOBAL_DAILY_LIMIT}
 *       —— 且账本落盘、换一个进程实例仍然生效；</li>
 *   <li>缓存命中第二次<b>不调上游</b>、也不吃每日额度；超上限按最旧淘汰；</li>
 *   <li>{@code enabled=false} → 503 {@code TTS_DISABLED}；Key 缺失 → 503 {@code KEY_MISSING}；</li>
 *   <li>上游超时/非 200/空 body → 归一化 reason，且响应里没有 Key、没有上游原文；</li>
 *   <li>textHash 只认服务端记录过的回答（LRU 容量可配）。</li>
 * </ol>
 */
class TtsServiceTest {

    /** 桩上游返回的"音频"字节（不是真 mp3：本测试只关心字节是否原样透传） */
    private static final byte[] AUDIO = "ID3-FAKE-MP3-BYTES".getBytes(StandardCharsets.UTF_8);

    /** 服务端短语表（测试用）：四个各不相同的文本，便于"不同文本 = 不同缓存键" */
    private static final Map<String, String> PHRASES = Map.of(
            "welcome", "欢迎来到本站",
            "about", "关于本站的说明",
            "third", "第三个短语",
            "fourth", "第四个短语内容");

    private static final String IP = "203.0.113.7";

    @TempDir
    Path tmp;

    private HttpServer server;
    private String baseUrl;
    private final AtomicInteger stubCalls = new AtomicInteger();
    private final List<String> stubBodies = new CopyOnWriteArrayList<>();
    private final List<String> stubAuthHeaders = new CopyOnWriteArrayList<>();
    private final List<String> stubModelHeaders = new CopyOnWriteArrayList<>();
    private final List<TtsService> services = new ArrayList<>();
    private volatile int stubCode = 200;
    private volatile byte[] stubBody = AUDIO;
    private volatile long stubDelayMs = 0L;

    @BeforeEach
    void setUp() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/tts", exchange -> {
            stubCalls.incrementAndGet();
            try {
                stubBodies.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                stubAuthHeaders.add(String.valueOf(exchange.getRequestHeaders().getFirst("Authorization")));
                stubModelHeaders.add(String.valueOf(exchange.getRequestHeaders().getFirst("model")));
                if (stubDelayMs > 0) {
                    try {
                        Thread.sleep(stubDelayMs);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    }
                }
                byte[] out = stubBody;
                exchange.sendResponseHeaders(stubCode, out.length);
                if (out.length > 0) {
                    exchange.getResponseBody().write(out);
                }
                exchange.close();
            } catch (Exception ignored) {
                // 超时用例里客户端会提前断开：桩这边不做断言，也不让异常冒到测试框架
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

    private TtsConfig config(boolean enabled, String apiKey, int maxChars, int perIpDaily, int globalDaily) {
        return config(enabled, apiKey, maxChars, perIpDaily, globalDaily, PHRASES, 64, 200);
    }

    private TtsConfig config(boolean enabled, String apiKey, int maxChars, int perIpDaily, int globalDaily,
                             Map<String, String> phrases, int maxCacheMb, int historySize) {
        return new TtsConfig(enabled, "voice-test", "s1", baseUrl, apiKey, maxChars, perIpDaily, globalDaily,
                tmp.resolve("cache").toString(), maxCacheMb, tmp.resolve("tts-quota.json").toString(),
                historySize, phrases, "fish");
    }

    private TtsConfig enabled() {
        return config(true, "test-key", 120, 20, 500);
    }

    private TtsService service(TtsConfig config) {
        return service(config, new OutboundTimeouts(1000, 800, 2000));
    }

    private TtsService service(TtsConfig config, OutboundTimeouts timeouts) {
        OutboundGuard guard = new OutboundGuard();
        // OutboundGuard 的这两个字段平时由 @Value 注入；单测里显式给上（与既有出站测试同一做法）
        ReflectionTestUtils.setField(guard, "defaultCooldownMs", 1000L);
        ReflectionTestUtils.setField(guard, "maxInflightPerDependency", 4);
        TtsService svc = new TtsService(config, timeouts, guard);
        services.add(svc);
        return svc;
    }

    private static TtsService.TtsException rejected(org.junit.jupiter.api.function.Executable call) {
        return assertThrows(TtsService.TtsException.class, call);
    }

    // ==================== 闸 1：只认服务端给过的文本 ====================

    @Test
    @DisplayName("短语命中：桩上游真收到一次 POST，正文是服务端短语表的文本，Bearer/model 头形状正确")
    void phraseHitCallsStubOnceWithExpectedShape() {
        TtsService svc = service(enabled());

        TtsService.Result result = svc.synthesize("welcome", null, IP);

        assertFalse(result.cacheHit(), "第一次必须是未命中");
        assertArrayEquals(AUDIO, result.audio(), "上游字节必须原样透传");
        assertEquals(1, stubCalls.get(), "桩上游必须真的收到一次请求");
        assertEquals(1, svc.upstreamCallCount());
        assertTrue(stubBodies.get(0).contains("欢迎来到本站"), stubBodies.get(0));
        assertTrue(stubBodies.get(0).contains("\"format\":\"mp3\""), stubBodies.get(0));
        assertTrue(stubBodies.get(0).contains("\"reference_id\":\"voice-test\""), stubBodies.get(0));
        assertEquals("Bearer test-key", stubAuthHeaders.get(0));
        assertEquals("s1", stubModelHeaders.get(0));
    }

    @Test
    @DisplayName("【核心】自由文本/未知 phraseId/没给参数/不存在的 textHash 一律 400 TEXT_NOT_ALLOWED，一次上游都没调")
    void freeTextAndUnknownInputsAreRejectedWithoutUpstream() {
        TtsService svc = service(enabled());

        TtsService.TtsException freeText = rejected(() -> svc.synthesize("请把这段话念出来", null, IP));
        assertEquals("TEXT_NOT_ALLOWED", freeText.reason(), "自由文本不能被当成 phraseId");
        assertEquals(400, freeText.httpStatus(), "被拒必须是 400，不是 500/503");
        assertEquals("TEXT_NOT_ALLOWED",
                rejected(() -> svc.synthesize(null, null, IP)).reason(), "必须给 phraseId 或 textHash");
        assertEquals("TEXT_NOT_ALLOWED",
                rejected(() -> svc.synthesize("unknown-phrase", null, IP)).reason(), "短语表里没有的 id 不许回落");
        assertEquals("TEXT_NOT_ALLOWED",
                rejected(() -> svc.synthesize(null, "not-a-hash", IP)).reason(), "形态不符的 textHash");
        assertEquals("TEXT_NOT_ALLOWED",
                rejected(() -> svc.synthesize(null, "a".repeat(32), IP)).reason(), "形态对但服务端没记录过");

        TtsService.TtsException both = rejected(() -> svc.synthesize("welcome", "a".repeat(32), IP));
        assertEquals("BAD_REQUEST", both.reason(), "两个都给 = 请求本身不合法");

        assertEquals(0, stubCalls.get(), "被闸门挡下的请求绝不许出网");
    }

    @Test
    @DisplayName("textHash 命中：只接受服务端记录过的回答，合成的是记录时的原文；与短语共享同一份缓存")
    void textHashOfRecordedAnswerIsAccepted() {
        TtsService svc = service(enabled());

        String hash = svc.recordAnswer("这是一条刚刚生成的回答，含标点。");
        assertEquals(32, hash.length(), "textHash 是 sha512 十六进制的前 32 位");
        assertTrue(hash.matches("[0-9a-f]{32}"), hash);
        assertNull(svc.recordAnswer("   "), "空白回答不记录，也就不可能被合成");

        TtsService.Result viaHash =
                svc.synthesize(null, hash.toUpperCase(Locale.ROOT), IP);
        assertEquals(1, stubCalls.get());
        assertTrue(stubBodies.get(0).contains("这是一条刚刚生成的回答"), stubBodies.get(0));
        assertArrayEquals(AUDIO, viaHash.audio());

        // 短语路径与 textHash 路径是同一份缓存：把短语原文当作"刚生成的回答"记下来，
        // 再走 textHash 取同一段文本 —— 必须命中缓存，不再调上游。
        TtsService svc2 = service(enabled());
        svc2.synthesize("welcome", null, IP);
        assertEquals(2, stubCalls.get());
        String phraseHash = svc2.recordAnswer("欢迎来到本站");
        TtsService.Result cached = svc2.synthesize(null, phraseHash, IP);
        assertTrue(cached.cacheHit(), "同一段文本必须命中同一份缓存（键里只有 voiceId+text）");
        assertEquals(2, stubCalls.get(), "缓存命中不许再调上游");
    }

    // ==================== 闸 2：长度 ====================

    @Test
    @DisplayName("长度超限：400 TEXT_TOO_LONG（短语路径与 textHash 路径都受同一把尺子）")
    void tooLongTextIsRejected() {
        TtsService svc = service(config(true, "test-key", 5, 20, 500));

        TtsService.TtsException byPhrase = rejected(() -> svc.synthesize("about", null, IP));
        assertEquals(400, byPhrase.httpStatus());
        assertEquals("TEXT_TOO_LONG", byPhrase.reason());

        String hash = svc.recordAnswer("x".repeat(50));
        TtsService.TtsException byHash = rejected(() -> svc.synthesize(null, hash, IP));
        assertEquals("TEXT_TOO_LONG", byHash.reason());

        assertEquals(0, stubCalls.get());
    }

    // ==================== 闸 3：每日额度（落盘） ====================

    @Test
    @DisplayName("单 IP 日额度：第 3 次 429 PER_IP_DAILY_LIMIT，换一个来源仍有额度")
    void perIpDailyQuotaBlocksOnlyThatSource() {
        TtsService svc = service(config(true, "test-key", 120, 2, 500));

        svc.synthesize("welcome", null, "198.51.100.1");
        svc.synthesize("about", null, "198.51.100.1");

        TtsService.TtsException e = rejected(() -> svc.synthesize("third", null, "198.51.100.1"));
        assertEquals(429, e.httpStatus());
        assertEquals("PER_IP_DAILY_LIMIT", e.reason());
        assertTrue(e.userMessage().contains("2"), "文案里要写清上限：" + e.userMessage());

        // 另一个来源不受影响（额度是分桶的），全局账也还在动
        svc.synthesize("third", null, "198.51.100.2");
        assertEquals(3, stubCalls.get());
        assertEquals(3, svc.quotaSnapshot().globalUsed());
    }

    @Test
    @DisplayName("全局日额度：换 IP 也绕不过 —— 第 3 个来源 429 GLOBAL_DAILY_LIMIT")
    void globalDailyQuotaCannotBeBypassedByChangingIp() {
        TtsService svc = service(config(true, "test-key", 120, 10, 2));

        svc.synthesize("welcome", null, "192.0.2.1");
        svc.synthesize("about", null, "192.0.2.2");

        TtsService.TtsException e = rejected(() -> svc.synthesize("third", null, "192.0.2.3"));
        assertEquals(429, e.httpStatus());
        assertEquals("GLOBAL_DAILY_LIMIT", e.reason());
        assertTrue(e.userMessage().contains("全局"), e.userMessage());
        assertEquals(2, stubCalls.get());
    }

    @Test
    @DisplayName("额度落盘：同一个账本文件的新实例（= 重启）仍然挡得住，且文件真的写出来了")
    void quotaSurvivesProcessRestart() {
        TtsConfig cfg = config(true, "test-key", 120, 1, 500);
        service(cfg).synthesize("welcome", null, "192.0.2.9");

        TtsService afterRestart = service(cfg);
        TtsService.TtsException e = rejected(() -> afterRestart.synthesize("about", null, "192.0.2.9"));
        assertEquals("PER_IP_DAILY_LIMIT", e.reason(), "重启后额度必须还在（否则重启 = 免费重置额度）");

        Path quotaFile = Path.of(cfg.getQuotaFile());
        assertTrue(Files.exists(quotaFile), "额度账本必须落盘：" + quotaFile);
    }

    // ==================== 缓存 ====================

    @Test
    @DisplayName("【核心】缓存命中第二次不调上游（桩计数不变），且命中不吃每日额度")
    void cacheHitDoesNotCallUpstreamNorConsumeQuota() {
        TtsService svc = service(config(true, "test-key", 120, 1, 1));

        TtsService.Result first = svc.synthesize("welcome", null, "203.0.113.10");
        assertFalse(first.cacheHit());
        assertEquals(1, stubCalls.get());

        TtsService.Result second = svc.synthesize("welcome", null, "203.0.113.10");
        assertTrue(second.cacheHit(), "第二次必须命中缓存");
        assertArrayEquals(first.audio(), second.audio());
        assertEquals(1, stubCalls.get(), "缓存命中绝不许再调上游");
        assertEquals(1, svc.upstreamCallCount());

        // 甚至换成别的来源：额度已经用尽（1/天），但缓存命中与额度无关
        TtsService.Result third = svc.synthesize("welcome", null, "203.0.113.11");
        assertTrue(third.cacheHit());
        assertEquals(1, stubCalls.get());
        assertEquals(1, svc.cacheFileCount(), "同样的文本只应有一份缓存文件");
        assertEquals(1, svc.quotaSnapshot().globalUsed(), "缓存命中不该吃额度");
    }

    @Test
    @DisplayName("缓存超上限：按最旧淘汰（最旧那条再合成会重新调上游），且总量回到上限内")
    void cacheEvictsOldestWhenOverLimit() throws Exception {
        stubBody = new byte[600_000];
        for (int i = 0; i < stubBody.length; i++) {
            stubBody[i] = (byte) (i % 251);
        }
        TtsService svc = service(config(true, "test-key", 120, 20, 500, PHRASES, 1, 200));

        svc.synthesize("welcome", null, IP);
        Thread.sleep(15);
        svc.synthesize("about", null, IP);
        assertEquals(2, stubCalls.get());

        assertTrue(svc.cacheTotalBytes() <= 1024L * 1024L,
                "一次写入后总量必须回到上限内，实际 " + svc.cacheTotalBytes());
        long before = stubCalls.get();
        svc.synthesize("welcome", null, IP);
        assertEquals(before + 1, stubCalls.get(), "最旧的一条（welcome）应已被淘汰，必须重新调上游");
        assertTrue(svc.cacheFileCount() <= 2, "上限 1MB、每个 600KB ⇒ 最多留 2 个");
    }

    // ==================== 开关与 Key ====================

    @Test
    @DisplayName("enabled=false → 503 TTS_DISABLED（前端据此隐藏 🔊），一次上游都没调")
    void disabledReturnsTtsDisabled() {
        TtsService svc = service(config(false, "test-key", 120, 20, 500));

        TtsService.TtsException e = rejected(() -> svc.synthesize("welcome", null, IP));
        assertEquals(503, e.httpStatus());
        assertEquals("TTS_DISABLED", e.reason());
        assertEquals(0, stubCalls.get());
        assertEquals(0, svc.quotaSnapshot().globalUsed());
    }

    @Test
    @DisplayName("Key 缺失 → 503 KEY_MISSING；且不吃额度（没 Key 就不该记这笔账）")
    void missingKeyReturnsKeyMissing() {
        TtsService svc = service(config(true, "", 120, 20, 500));

        TtsService.TtsException e = rejected(() -> svc.synthesize("welcome", null, IP));
        assertEquals(503, e.httpStatus());
        assertEquals("KEY_MISSING", e.reason());
        assertEquals(0, stubCalls.get());
        assertEquals(0, svc.quotaSnapshot().globalUsed());
    }

    // ==================== 上游错误归一化 ====================

    @Test
    @DisplayName("上游非 200 → UPSTREAM_HTTP_<code>；响应里没有上游原文、也没有 Key")
    void upstreamHttpErrorIsNormalizedWithoutLeaking() {
        TtsService svc = service(enabled());

        stubCode = 500;
        stubBody = "UPSTREAM-SECRET-BODY".getBytes(StandardCharsets.UTF_8);
        TtsService.TtsException e500 = rejected(() -> svc.synthesize("welcome", null, IP));
        assertEquals(502, e500.httpStatus());
        assertEquals("UPSTREAM_HTTP_500", e500.reason());
        assertFalse(e500.userMessage().contains("UPSTREAM-SECRET-BODY"), e500.userMessage());
        assertFalse(e500.userMessage().contains("test-key"), e500.userMessage());

        stubCode = 401;
        TtsService.TtsException e401 = rejected(() -> svc.synthesize("about", null, IP));
        assertEquals("UPSTREAM_HTTP_401", e401.reason());
        assertEquals(502, e401.httpStatus());
    }

    @Test
    @DisplayName("上游 200 但空 body → UPSTREAM_BAD_BODY（绝不把空字节当音频发出去）")
    void emptyUpstreamBodyIsBadBody() {
        TtsService svc = service(enabled());
        stubCode = 200;
        stubBody = new byte[0];

        TtsService.TtsException e = rejected(() -> svc.synthesize("welcome", null, IP));
        assertEquals(502, e.httpStatus());
        assertEquals("UPSTREAM_BAD_BODY", e.reason());
        assertEquals(0, svc.cacheFileCount(), "失败的响应不许进缓存");
    }

    @Test
    @DisplayName("上游超时 → UPSTREAM_TIMEOUT，且在统一出站预算内返回（不等桩睡完）")
    void upstreamTimeoutIsNormalized() {
        stubDelayMs = 2000;
        TtsService svc = service(enabled(), new OutboundTimeouts(500, 300, 700));

        long started = System.currentTimeMillis();
        TtsService.TtsException e = rejected(() -> svc.synthesize("welcome", null, IP));
        long elapsed = System.currentTimeMillis() - started;

        assertEquals(504, e.httpStatus());
        assertEquals("UPSTREAM_TIMEOUT", e.reason());
        assertTrue(elapsed < 1500, "必须在有界预算内返回，实测 " + elapsed + " ms");
        assertFalse(e.userMessage().contains("timeout"), "给前端的是人话，不是异常原文：" + e.userMessage());
    }

    // ==================== textHash 闸的容量 ====================

    @Test
    @DisplayName("最近回答的 LRU 容量可配：被挤出去的 textHash 立刻失效（400 TEXT_NOT_ALLOWED）")
    void recentAnswerHistoryIsBoundedLru() {
        TtsService svc = service(config(true, "test-key", 120, 20, 500, PHRASES, 64, 2));

        String first = svc.recordAnswer("第一条回答");
        svc.recordAnswer("第二条回答");
        String third = svc.recordAnswer("第三条回答");

        assertEquals(2, svc.recentAnswerCount(), "容量 2 就必须只剩 2 条");
        assertEquals("TEXT_NOT_ALLOWED", rejected(() -> svc.synthesize(null, first, IP)).reason());
        assertArrayEquals(AUDIO, svc.synthesize(null, third, IP).audio());
    }
}
