package org.example.publicapi;

import org.example.llm.LlmProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code speakJa} 改写器的测试：它<b>只负责锦上添花</b>，所以每条失败用例断言的都是
 * "返回 null，而不是抛异常"。
 *
 * <h3>为什么这几条必须存在</h3>
 * 这条链路最容易犯的错是"把润色做成了依赖"。一旦改写失败会抛出去，公开问答就从 200 变 500 ——
 * 而访客明明已经拿到答案正文了。所以这里逐条把失败形态钉死：
 * 超时、上游异常、产出英文、产出超长、产出带解释，<b>五条路都必须安静地变成 null</b>。
 */
class PublicSpeakJaWriterTest {

    private PublicSpeakJaWriter writer;
    private StubLlm llm;

    /** 模型替身：可控的"返回什么/抛什么/慢多久"，并数被调了几次 */
    private static class StubLlm implements LlmProvider {
        int calls;
        boolean available = true;
        String output = "攻撃を検知しました。";
        RuntimeException boom;
        long sleepMs;

        @Override
        public String id() {
            return "stub";
        }

        @Override
        public String modelName() {
            return "stub-1";
        }

        @Override
        public boolean available() {
            return available;
        }

        @Override
        public String generate(String systemPrompt, String userPrompt) throws Exception {
            calls++;
            if (sleepMs > 0) {
                Thread.sleep(sleepMs);
            }
            if (boom != null) {
                throw boom;
            }
            return output;
        }
    }

    @BeforeEach
    void setUp() {
        writer = new PublicSpeakJaWriter();
        llm = new StubLlm();
        ReflectionTestUtils.setField(writer, "llmProvider", llm);
    }

    @Test
    @DisplayName("正常改写：原样返回一句合格日语（长度 ≤40、字符集合法）")
    void rewritesToUsableJapanese() {
        String out = writer.rewrite("这是一条关于 SSH 暴力破解的回答。");

        assertEquals("攻撃を検知しました。", out);
        assertEquals(1, llm.calls);
        assertTrue(JapaneseSpeakText.length(out) <= JapaneseSpeakText.SPEAK_JA_MAX_CHARS);
        assertTrue(JapaneseSpeakText.isSpeakableJa(out));
    }

    @Test
    @DisplayName("模型返回英文 / emoji → null（音色念不了，不如不出声）")
    void nonJapaneseOutputBecomesNull() {
        llm.output = "This is an SSH brute force attack.";
        assertNull(writer.rewrite("这是一条回答。"));

        llm.output = "攻撃です 😀";
        assertNull(writer.rewrite("这是一条回答。"));
    }

    @Test
    @DisplayName("模型返回超长句 → null（不截断念半句）")
    void tooLongOutputBecomesNull() {
        llm.output = "あ".repeat(JapaneseSpeakText.SPEAK_JA_MAX_CHARS + 1);
        assertNull(writer.rewrite("这是一条回答。"));

        llm.output = "あ".repeat(JapaneseSpeakText.SPEAK_JA_MAX_CHARS);
        assertTrue(writer.rewrite("这是一条回答。") != null, "正好 40 字必须放行（边界不能写反）");
    }

    @Test
    @DisplayName("模型多给一行解释 / 把整句包在「」里 → 只取那一句，不念解释")
    void stripsExplanationAndQuotes() {
        llm.output = "「攻撃を検知しました。」\n（解説：SSH の総当たりです）";
        assertEquals("攻撃を検知しました。", writer.rewrite("这是一条回答。"));
    }

    @Test
    @DisplayName("上游抛异常（含额度用完）→ null，且不把异常抛给调用方")
    void upstreamFailureBecomesNull() {
        llm.boom = new IllegalStateException("公开模型额度已用完（今日）");
        assertNull(writer.rewrite("这是一条回答。"));
        assertEquals(1, llm.calls);
    }

    @Test
    @DisplayName("provider 不可用 → null，一次都不调（不花没意义的钱）")
    void unavailableProviderIsNotCalled() {
        llm.available = false;
        assertNull(writer.rewrite("这是一条回答。"));
        assertEquals(0, llm.calls);
    }

    @Test
    @DisplayName("超出 3 秒预算 → null（硬超时，不拖慢回答上屏）")
    void timeoutBecomesNull() {
        llm.sleepMs = PublicSpeakJaWriter.TIMEOUT_MS + 300;
        long start = System.currentTimeMillis();
        assertNull(writer.rewrite("这是一条回答。"));
        long spent = System.currentTimeMillis() - start;
        assertTrue(spent >= PublicSpeakJaWriter.TIMEOUT_MS,
                "必须真的等到了预算边界，不能提前返回（实测 " + spent + " ms）");
        assertTrue(spent < PublicSpeakJaWriter.TIMEOUT_MS + 2000,
                "超时后要立刻放弃，不能跟着上游一起慢（实测 " + spent + " ms）");
    }

    @Test
    @DisplayName("空回答 → null（没有正文就没有句子可念）")
    void blankAnswerBecomesNull() {
        assertNull(writer.rewrite(null));
        assertNull(writer.rewrite("   \n  "));
        assertEquals(0, llm.calls);
    }
}
