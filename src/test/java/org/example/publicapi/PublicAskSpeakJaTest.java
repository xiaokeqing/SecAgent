package org.example.publicapi;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.agent.multi.MultiAgentResult;
import org.example.security.EvalIdentity;
import org.example.security.PromptInjectionGuard;
import org.example.service.ModelQuotaService;
import org.example.service.OrchestrationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code /api/public/ask} 上的 {@code speakJa} 三条契约：
 *
 * <ol>
 *   <li><b>不要就不做</b>：请求体不带 {@code speakJa} ⇒ 响应里 {@code speakJa = null}，
 *       并且模型<b>一次都没被多调</b>（钱只花在访客真的要听的时候）；</li>
 *   <li><b>要了就得合格</b>：带了 {@code speakJa:true} ⇒ 非空、≤40 字、纯日语字符集；</li>
 *   <li><b>坏了自己扛</b>：改写失败 ⇒ {@code speakJa = null}，回答本体与状态码<b>一个字都不变</b>
 *       （仍 HTTP 200 / {@code code=200}）。</li>
 * </ol>
 *
 * <p>第 3 条是本类里最重要的一条：它是"语音是锦上添花"这句话的可执行版本。
 */
class PublicAskSpeakJaTest {

    /** 编排替身：固定给一段中文正文，并记下被调了几次 */
    private static class StubOrchestration extends OrchestrationService {
        final List<String> seen = new ArrayList<>();
        String answer = "攻撃概要：SSH のブルートフォース試行です。認証失敗が短時間に集中しています。";

        @Override
        public MultiAgentResult run(String question, List<Map<String, String>> history, long deadlineMs) {
            seen.add(question);
            MultiAgentResult r = new MultiAgentResult(question);
            r.setFinalAnswer(answer);
            return r;
        }
    }

    /** 知识库替身：返回空片段（状态走 no-retrieval，正文不受影响） */
    private static class StubKbService extends PublicKbService {
        @Override
        public List<Map<String, Object>> search(String query) {
            return List.of();
        }
    }

    /** 改写器替身：数被调了几次，并按需返回/失败 */
    private static class StubSpeakJaWriter extends PublicSpeakJaWriter {
        int calls;
        String output = "攻撃を検知しました。";
        boolean boom;

        @Override
        public String rewrite(String chineseAnswer) {
            calls++;
            if (boom) {
                throw new IllegalStateException("测试：改写器炸了");
            }
            return output;
        }
    }

    @TempDir
    Path tmp;

    private PublicAskService service;
    private StubOrchestration orchestration;
    private StubSpeakJaWriter writer;

    @BeforeEach
    void setUp() {
        service = new PublicAskService();
        orchestration = new StubOrchestration();
        writer = new StubSpeakJaWriter();
        ReflectionTestUtils.setField(service, "orchestrationService", orchestration);
        ReflectionTestUtils.setField(service, "promptInjectionGuard", new PromptInjectionGuard());
        ReflectionTestUtils.setField(service, "outputGuard", new PublicOutputGuard());
        ReflectionTestUtils.setField(service, "kbService", new StubKbService());
        ReflectionTestUtils.setField(service, "maxQuestionChars", 600);
        ReflectionTestUtils.setField(service, "deadlineMs", 20000L);
        ReflectionTestUtils.setField(service, "modelQuotaService", quotaWith(3));
        ReflectionTestUtils.setField(service, "speakJaWriter", writer);
    }

    @AfterEach
    void cleanup() {
        EvalIdentity.endEvalRequest();
    }

    private ModelQuotaService quotaWith(int publicDaily) {
        ModelQuotaService q = new ModelQuotaService();
        ReflectionTestUtils.setField(q, "enabled", true);
        ReflectionTestUtils.setField(q, "dailyLimit", 50);
        ReflectionTestUtils.setField(q, "storeFile", tmp.resolve("model-quota.json").toString());
        ReflectionTestUtils.setField(q, "evalDailyLimit", 60);
        ReflectionTestUtils.setField(q, "evalStoreFile", tmp.resolve("model-quota-eval.json").toString());
        ReflectionTestUtils.setField(q, "publicDailyLimit", publicDaily);
        ReflectionTestUtils.setField(q, "publicStoreFile", tmp.resolve("model-quota-public.json").toString());
        return q;
    }

    // ==================== 三条契约（服务层） ====================

    @Test
    @DisplayName("【核心】不带 speakJa ⇒ 字段为 null 且改写器一次都没被调")
    void withoutFlagNoRewriteCall() {
        Map<String, Object> data = service.ask("SSH 暴力破解是什么？", "10.0.0.1");

        assertTrue(data.containsKey("speakJa"), "字段必须存在（前端只判真假，不判缺失）");
        assertNull(data.get("speakJa"));
        assertEquals(0, writer.calls, "没要语音就不该多花一次模型调用");
        assertNotNull(data.get("answer"));
    }

    @Test
    @DisplayName("带 speakJa:true ⇒ 非空、≤40 字、纯日语字符集；回答本体照旧")
    void withFlagProducesShortJapanese() {
        Map<String, Object> data = service.ask("SSH 暴力破解是什么？", "10.0.0.1", true);

        Object speakJa = data.get("speakJa");
        assertNotNull(speakJa);
        String ja = String.valueOf(speakJa);
        assertTrue(JapaneseSpeakText.length(ja) <= JapaneseSpeakText.SPEAK_JA_MAX_CHARS,
                "speakJa 必须 ≤40 字，实际 " + JapaneseSpeakText.length(ja));
        assertTrue(JapaneseSpeakText.isSpeakableJa(ja), "speakJa 必须是纯日语字符集：" + ja);
        assertEquals(1, writer.calls);
        assertNotNull(data.get("answer"));
        assertFalse(String.valueOf(data.get("answer")).isBlank(), "回答本体不能因为语音而变空");
    }

    @Test
    @DisplayName("改写器抛异常 ⇒ speakJa=null，回答本体与 state 一个字都不变")
    void rewriteFailureNeverTouchesAnswer() {
        Map<String, Object> ok = service.ask("SSH 暴力破解是什么？", "10.0.0.1");

        writer.boom = true;
        Map<String, Object> bad = service.ask("SSH 暴力破解是什么？", "10.0.0.1", true);

        assertNull(bad.get("speakJa"));
        assertEquals(ok.get("answer"), bad.get("answer"), "改写失败绝不许改回答正文");
        assertEquals(ok.get("state"), bad.get("state"), "改写失败绝不许改状态");
        assertEquals(Boolean.TRUE, bad.get("publicDemo"));
    }

    // ==================== 信封层（MVC）：失败也是 200 ====================

    /** 只回一个固定 data 的替身：用来单独验"注解 + 信封 + ship()"这一层 */
    private static class FixedAskService extends PublicAskService {
        Map<String, Object> data = new LinkedHashMap<>();
        Boolean sawWantSpeakJa;
        boolean boom;

        @Override
        public Map<String, Object> ask(String question, String clientIp, boolean wantSpeakJa) {
            sawWantSpeakJa = wantSpeakJa;
            if (boom) {
                throw new IllegalStateException("测试：问答炸了（应变成 500 信封）");
            }
            Map<String, Object> out = new LinkedHashMap<>(data);
            out.put("speakJa", null);
            return out;
        }
    }

    private MockMvc mvc(PublicAskService svc) {
        PublicApiController controller = new PublicApiController();
        ReflectionTestUtils.setField(controller, "rateLimiter", new PublicRateLimiter());
        ReflectionTestUtils.setField(controller, "publicAskRateLimiter", new PublicAskRateLimiter(6));
        ReflectionTestUtils.setField(controller, "publicConcurrencyGuard", new PublicConcurrencyGuard());
        ReflectionTestUtils.setField(controller, "publicAskService", svc);
        ReflectionTestUtils.setField(controller, "cacheSeconds", 15);
        ReflectionTestUtils.setField(controller, "exposeBuildSha", false);
        ReflectionTestUtils.setField(controller, "buildSha", "test");
        return MockMvcBuilders.standaloneSetup(controller).build();
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static String json(Object... kv) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            body.put(String.valueOf(kv[i]), kv[i + 1]);
        }
        return MAPPER.writeValueAsString(body);
    }

    @Test
    @DisplayName("speakJa 为 null 时信封仍是 code=200（语音失败不许改状态码）")
    void envelopeStays200WhenSpeakJaIsNull() throws Exception {
        FixedAskService stub = new FixedAskService();
        stub.data.put("answer", "攻撃概要：SSH のブルートフォース試行です。");
        stub.data.put("state", "model");

        mvc(stub).perform(post("/api/public/ask")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("question", "SSH 是什么？", "speakJa", true)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(200))
                .andExpect(jsonPath("$.data.speakJa").value(nullValue()))
                .andExpect(jsonPath("$.data.answer").isNotEmpty());

        assertEquals(Boolean.TRUE, stub.sawWantSpeakJa, "请求体里的 speakJa:true 必须被解析出来");
    }

    @Test
    @DisplayName("请求体不带 speakJa ⇒ 传到服务层的是 false（不额外调模型）")
    void flagDefaultsToFalseWhenAbsent() throws Exception {
        FixedAskService stub = new FixedAskService();
        stub.data.put("answer", "攻撃概要：SSH のブルートフォース試行です。");
        stub.data.put("state", "model");

        mvc(stub).perform(post("/api/public/ask")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("question", "SSH 是什么？")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.speakJa").value(nullValue()));

        assertEquals(Boolean.FALSE, stub.sawWantSpeakJa);
    }

    @Test
    @DisplayName("speakJa:1 / \"yes\" 也算要（前后端字段形态容错）")
    void truthyFlagVariants() throws Exception {
        FixedAskService stub = new FixedAskService();
        stub.data.put("answer", "攻撃概要：SSH のブルートフォース試行です。");

        mvc(stub).perform(post("/api/public/ask")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("question", "q", "speakJa", "yes")))
                .andExpect(status().isOk());

        assertEquals(Boolean.TRUE, stub.sawWantSpeakJa);
    }
}
