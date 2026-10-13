package org.example.llm;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 供应商选择 / 备用回退 / <b>如实标注</b> 的测试。
 *
 * <h3>这里测的三件事，每件都有对应的真实故障形态</h3>
 * <ol>
 *   <li><b>未知 provider 值必须明确失败</b>：{@code app.llm.provider=deepsek} 若静默回落，
 *       运营以为切了家、实际没切，而页面 {@code generatedBy} 如实写着实际那家 ——
 *       "配置"与"现象"对不上，排障时无从下手（而且不会报错）；</li>
 *   <li><b>Key 缺失 = 不可用且不静默</b>：忘了注入 {@code DEEPSEEK_API_KEY} 的表现是
 *       "页面什么都不生成"，第一反应是"模型/提示词坏了"，真正的原因（少一个环境变量）
 *       在任何一行日志里都看不见；</li>
 *   <li><b>回退发生时必须如实署名</b>：回答里写 {@code generatedBy=dashscope/qwen-plus}
 *       而实际由 DeepSeek 产出，是"如实标注"这件事上最不该出现的错 —— 它看起来更具体，
 *       其实是假的。这是本类存在的核心理由，必须被钉住。</li>
 * </ol>
 *
 * <p>用桩实现（而不是真网络）测本类：选择与回退是纯逻辑，桩能精确构造
 * "主超时 / 备用成功 / 配额用尽"这些分支。真链路的字节形状由
 * {@code DeepSeekLlmProviderTest} 用真端口覆盖。
 */
class LlmProviderSelectorTest {

    /** 可编排的桩实现 */
    private static final class Stub implements LlmProvider {
        private final String id;
        private final String model;
        private final boolean available;
        private final String answer;
        private final Exception failure;
        private final AtomicInteger calls = new AtomicInteger();

        Stub(String id, String model, boolean available, String answer, Exception failure) {
            this.id = id;
            this.model = model;
            this.available = available;
            this.answer = answer;
            this.failure = failure;
        }

        static Stub ok(String id, String model, String answer) {
            return new Stub(id, model, true, answer, null);
        }

        static Stub broken(String id, String model, Exception failure) {
            return new Stub(id, model, true, null, failure);
        }

        static Stub unavailable(String id, String model) {
            return new Stub(id, model, false, null, null);
        }

        @Override public String id() { return id; }
        @Override public String modelName() { return model; }
        @Override public boolean available() { return available; }

        @Override
        public String generate(String systemPrompt, String userPrompt) throws Exception {
            calls.incrementAndGet();
            if (failure != null) {
                throw failure;
            }
            return answer;
        }

        int calls() {
            return calls.get();
        }
    }

    private static LlmProviderSelector selectorOf(Stub primary, Stub fallback, boolean useFallback) {
        LlmProviderSelector selector = new LlmProviderSelector(
                new DashScopeLlmProvider(), new DeepSeekLlmProvider());
        Map<String, LlmProvider> stubs = new LinkedHashMap<>();
        stubs.put(primary.id(), primary);
        if (fallback != null) {
            stubs.put(fallback.id(), fallback);
        }
        selector.replaceProvidersForTest(stubs);
        ReflectionTestUtils.setField(selector, "primaryId", primary.id());
        ReflectionTestUtils.setField(selector, "fallbackId", useFallback && fallback != null ? fallback.id() : "");
        return selector;
    }

    // ==================== 1) 选择语义 ====================

    @Test
    @DisplayName("默认选中 dashscope（保持现状）；配置成 deepseek 就选 deepseek")
    void selectsConfiguredProvider() {
        LlmProviderSelector d = selectorOf(Stub.ok("dashscope", "qwen-plus", "a"), null, false);
        assertEquals("dashscope", d.id());
        assertEquals("qwen-plus", d.modelName());

        LlmProviderSelector ds = selectorOf(Stub.ok("deepseek", "deepseek-chat", "a"), null, false);
        assertEquals("deepseek", ds.id());
        assertEquals("deepseek-chat", ds.modelName());
    }

    @Test
    @DisplayName("未知 provider 值 → 明确失败并列出可取值（绝不静默回落）")
    void unknownProviderFailsLoudly() {
        // 注册表里两家都要在：报错文案要能列出【全部】合法取值，
        // 只放一家的话这条断言测的是"桩注册了几个"，不是"报错有没有写清可取值"。
        LlmProviderSelector selector = selectorOf(Stub.ok("dashscope", "qwen-plus", "a"),
                Stub.ok("deepseek", "deepseek-chat", "a"), false);
        ReflectionTestUtils.setField(selector, "primaryId", "deepsek");   // 拼错一个字母

        IllegalStateException e = assertThrows(IllegalStateException.class, selector::primary);
        assertTrue(e.getMessage().contains("deepsek"), e.getMessage());
        assertTrue(e.getMessage().contains("dashscope") && e.getMessage().contains("deepseek"),
                "报错必须列出合法取值，否则运维只能翻代码：" + e.getMessage());

        // 自检也必须把问题打印出来（不能自己先崩，否则只剩一条启动失败栈）
        assertTrue(selector.describe().contains("INVALID"), selector.describe());
    }

    @Test
    @DisplayName("主与备用配置成同一家 → 明确失败（否则一次失败被放大成两次调用）")
    void sameFallbackAsPrimaryFailsLoudly() {
        LlmProviderSelector selector =
                selectorOf(Stub.ok("deepseek", "deepseek-chat", "a"), null, false);
        ReflectionTestUtils.setField(selector, "fallbackId", "deepseek");

        IllegalStateException e = assertThrows(IllegalStateException.class, selector::fallbackOrNull);
        assertTrue(e.getMessage().contains("没有意义"), e.getMessage());
    }

    // ==================== 2) Key 缺失 ====================

    @Test
    @DisplayName("Key 缺失 → 不可用；没有备用时不做任何调用（不静默、不兜底）")
    void missingKeyIsUnavailableAndSilentNoCall() {
        Stub primary = Stub.unavailable("deepseek", "deepseek-chat");
        LlmProviderSelector selector = selectorOf(primary, null, false);

        assertFalse(selector.available(), "主不可用且无备用时必须如实报不可用");
        assertThrows(IllegalStateException.class, () -> selector.generate("s", "u"));
        assertEquals(0, primary.calls(), "不可用时一次都不该调用");
    }

    @Test
    @DisplayName("默认不配置备用（空值）= 关闭回退：主不可用时如实判未生成")
    void fallbackDisabledByDefault() {
        Stub primary = Stub.broken("dashscope", "qwen-plus", new java.io.IOException("超时"));
        LlmProviderSelector selector = selectorOf(primary, Stub.ok("deepseek", "deepseek-chat", "备用答案"), false);

        assertThrows(Exception.class, () -> selector.generate("s", "u"),
                "关闭回退时主失败必须原样抛出（上层据此判未生成）");
    }

    // ==================== 3) 回退与如实标注 ====================

    @Test
    @DisplayName("【核心】主失败 + 开了回退 → 用备用，且 generatedBy 如实写成备用那家")
    void fallbackIsUsedAndAttributedHonestly() throws Exception {
        Stub primary = Stub.broken("dashscope", "qwen-plus", new java.io.IOException("DashScope 超时"));
        Stub fallback = Stub.ok("deepseek", "deepseek-chat", "备用生成的结论");
        LlmProviderSelector selector = selectorOf(primary, fallback, true);

        assertTrue(selector.available(), "主不可用时，只要备用可用就算'有可用通道'");
        String out = selector.generate("sys", "user");

        assertEquals("备用生成的结论", out);
        assertEquals(1, primary.calls());
        assertEquals(1, fallback.calls(), "主失败后必须真的试了备用");
        assertEquals("deepseek / deepseek-chat", selector.generatedBy(),
                "回退发生时必须如实署名备用 —— 写主供应商就是假的署名（比明确报错更糟）");
    }

    @Test
    @DisplayName("主可用时不碰备用，署名仍是主供应商（改造前行为逐字不变）")
    void noFallbackWhenPrimaryWorks() throws Exception {
        Stub primary = Stub.ok("dashscope", "qwen-plus", "主生成的结论");
        Stub fallback = Stub.ok("deepseek", "deepseek-chat", "不该被用到");
        LlmProviderSelector selector = selectorOf(primary, fallback, true);

        assertEquals("主生成的结论", selector.generate("sys", "u"));
        assertEquals("dashscope / qwen-plus", selector.generatedBy());
        assertEquals(0, fallback.calls(), "主可用时不该花第二家的钱");
    }

    @Test
    @DisplayName("备用也失败 → 抛原始异常（不让后一个错误盖掉真正的原因）")
    void fallbackFailureKeepsOriginalCause() {
        Stub primary = Stub.broken("dashscope", "qwen-plus", new java.io.IOException("主：连接超时"));
        Stub fallback = Stub.broken("deepseek", "deepseek-chat", new java.io.IOException("备用：鉴权失败"));
        LlmProviderSelector selector = selectorOf(primary, fallback, true);

        Exception e = assertThrows(Exception.class, () -> selector.generate("s", "u"));
        assertTrue(e.getMessage().contains("主：连接超时"),
                "真实原因不能被备用的错误盖掉，否则排障会被带偏：" + e.getMessage());
    }

    @Test
    @DisplayName("【核心】配额用尽【不触发】跨供应商回退（换一家不能把额度绕过）")
    void quotaExhaustionNeverFallsBack() {
        Stub primary = Stub.broken("dashscope", "qwen-plus",
                new IllegalStateException("模型额度已用完（今日）：本次不调用模型，由上层降级处理"));
        Stub fallback = Stub.ok("deepseek", "deepseek-chat", "不该被用到");
        LlmProviderSelector selector = selectorOf(primary, fallback, true);

        assertThrows(Exception.class, () -> selector.generate("s", "u"));
        assertEquals(0, fallback.calls(),
                "配额用尽是'这一步不能做'，不是'这家坏了'：回退等于把评测/公开/用户的额度绕过");
    }

    @Test
    @DisplayName("主不可用但备用可用且开了回退 → 直接走备用，署名如实")
    void unavailablePrimaryUsesFallbackDirectly() throws Exception {
        Stub primary = Stub.unavailable("dashscope", "qwen-plus");
        Stub fallback = Stub.ok("deepseek", "deepseek-chat", "备用答案");
        LlmProviderSelector selector = selectorOf(primary, fallback, true);

        assertEquals("备用答案", selector.generate("s", "u"));
        assertEquals(0, primary.calls(), "已经判不可用就不该再试一次");
        assertEquals("deepseek / deepseek-chat", selector.generatedBy());
    }

    @Test
    @DisplayName("默认 generatedBy 与 id/modelName 拼法一致（只新增契约，不改动既有实现）")
    void generatedByDefaultMatchesLegacyText() {
        LlmProvider stub = Stub.ok("dashscope", "qwen-plus", "x");
        assertEquals("dashscope / qwen-plus", stub.generatedBy());
        assertEquals(stub.id() + " / " + stub.modelName(), stub.generatedBy());
    }
}
