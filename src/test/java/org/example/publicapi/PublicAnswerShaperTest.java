package org.example.publicapi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 「公开问答首句 ≤8 字」这条硬约束的回归用例。
 *
 * <h3>这条约束为什么必须由服务端兜底</h3>
 * 前端字幕/语音按短句播放，出声延迟 ≈ {@code 1.0s + 0.21s × 首句字数}。首句 18 字 ≈ 4.8s，
 * 访客等的就是这一句。提示词里写了"首句 8 字内"，模型照做几轮会漂 —— 所以
 * {@link PublicAnswerShaper} 做确定性兜底，这里用<b>假的模型输出</b>直接把兜底规则测掉。
 *
 * <h3>判据</h3>
 * <ol>
 *   <li>首句（用 {@link PublicAnswerShaper#firstSentence(String)} 量）可见字数 ≤ 8；</li>
 *   <li>截断后仍是个句子：以句末标点收尾，不留半截标点/悬空括号；</li>
 *   <li>截断点之后的内容不许丢（宁可读起来像断句，也不许把答案截没了）；</li>
 *   <li>首句本来就合规时，<b>一个字符都不动</b>（不做无谓改写）。</li>
 * </ol>
 */
class PublicAnswerShaperTest {

    /** 首句字数（测试自己的口径：句末标点不算字、空白不算字）。 */
    private static int chars(String text) {
        String fs = PublicAnswerShaper.firstSentence(text);
        int end = fs.length();
        while (end > 0 && "。！？!?；;…\n".indexOf(fs.charAt(end - 1)) >= 0) {
            end--;
        }
        return PublicAnswerShaper.visibleLength(fs.substring(0, end));
    }

    /** 首句可见字数 ≤ limit。 */
    private static void assertOpeningWithin(String capped, int limit) {
        int vis = chars(capped);
        assertTrue(vis <= limit, "首句必须 ≤" + limit + " 字，实测 " + vis + " 字：" + capped);
    }

    /** 不许出现半截标点 / 重复标点 / 以标点开头。 */
    private static void assertNoHalfPunctuation(String s) {
        for (String bad : new String[] {"，，", "，。", "。，", "、。", "；。", "。。", "；；"}) {
            assertFalse(s.contains(bad), "出现半截/重复标点「" + bad + "」：" + s);
        }
        assertFalse(s.startsWith("，"), "不能以逗号开头：" + s);
        assertFalse(s.startsWith("。"), "不能以句号开头：" + s);
    }

    private static int count(String s, char c) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == c) {
                n++;
            }
        }
        return n;
    }

    // ==================== ① 首句合规：一个字都不动 ====================

    @Test
    @DisplayName("首句已经 8 字以内：原样返回，不补标点、不折叠空白")
    void openingUnderLimitIsUntouched() {
        String s = "A07 是认证失效。补上多因素认证和登录失败锁定，这类问题就堵掉大半。";
        assertEquals(8, chars(s));
        assertEquals(s, PublicAnswerShaper.capOpeningSentence(s), "首句合规时一个字符都不许动");
    }

    @Test
    @DisplayName("首句合规但整段很长：也只因为「首句合规」而原样返回（不按全文长度乱动）")
    void longBodyWithShortOpeningIsUntouched() {
        String s = "这块读不到。公开知识库里没有能对上的片段，我不给你编一个数出来。"
                + "换个更具体的问法，比如带上系统名或攻击类型，我再检索一次。";
        assertOpeningWithin(s, 8);
        assertEquals(s, PublicAnswerShaper.capOpeningSentence(s));
    }

    // ==================== ② 超长首句：截断 + 接回，内容不丢 ====================

    @Test
    @DisplayName("首句 17 字：在 8 字处断开成句，残句接回正文，后面的句子一个字都不丢")
    void longOpeningIsCappedWithoutLosingTheRest() {
        String s = "A07 说的是身份认证和会话管理失效，多半栽在弱口令上。先上多因素认证，再补登录失败锁定。";
        String out = PublicAnswerShaper.capOpeningSentence(s);

        assertOpeningWithin(out, 8);
        assertTrue(out.startsWith("A07 说的是身份。"), "超长首句必须在第 8 个字后断开：" + out);
        assertNoHalfPunctuation(out);
        assertTrue(out.contains("多半栽在弱口令上"), "残句必须接回正文，不能吞掉：" + out);
        assertTrue(out.contains("先上多因素认证，再补登录失败锁定"), "后面的句子一个字都不能丢：" + out);
    }

    @Test
    @DisplayName("首句没有分句标点：硬切到 8 字，再补句号（不会上屏一句没有标点的长句）")
    void hardCutWithoutAnyPunctuationStillEndsAsASentence() {
        String s = "弱口令会直接拿下一台主机因为大家都用默认口令。";
        String out = PublicAnswerShaper.capOpeningSentence(s);

        assertOpeningWithin(out, 8);
        assertTrue(out.startsWith("弱口令会直接拿下。"), "硬切之后必须补一个句号：" + out);
        assertTrue(out.endsWith("。"), "整段仍要以句末标点收尾：" + out);
        assertTrue(out.contains("因为大家都用默认口令"), "截断点之后的内容不许丢：" + out);
        assertNoHalfPunctuation(out);
    }

    @Test
    @DisplayName("残句只落一个字：丢掉那一个字，不拼出「验证失。败，多半…」")
    void halfCharRemnantIsNotGluedBack() {
        String s = "身份认证与验证失败，多半栽在弱口令上。";
        String out = PublicAnswerShaper.capOpeningSentence(s);

        assertEquals("身份认证与验证失。多半栽在弱口令上。", out,
                "残下的「败」必须丢掉，残句与正文不许粘连");
        assertOpeningWithin(out, 8);
        assertNoHalfPunctuation(out);
    }

    @Test
    @DisplayName("括号被截断：配平补齐右半边，不留悬空开括号")
    void unbalancedBracketIsClosed() {
        String s = "「钓鱼」多是骗你点链接，别点。";
        String out = PublicAnswerShaper.capOpeningSentence(s);

        assertOpeningWithin(out, 8);
        assertEquals(count(out, '「'), count(out, '」'), "左右引号必须成对：" + out);
        assertNoHalfPunctuation(out);
        assertTrue(out.startsWith("「钓鱼」"), "断点前的引号要留住：" + out);
    }

    @Test
    @DisplayName("[EMO:xxx] 前缀不占首句字数，截断后原样保留在最前面")
    void emoTagIsPrefixNotPartOfOpeningSentence() {
        String s = "[EMO:angry]身份认证与验证失败，先堵弱口令。";
        String out = PublicAnswerShaper.capOpeningSentence(s);

        assertTrue(out.startsWith("[EMO:angry]"), "情绪标签必须还在最前面：" + out);
        assertOpeningWithin(out, 8);
        assertEquals(8, chars(out), "8 个字要真的用满，不许因为标签被吃掉几个字");
        assertNoHalfPunctuation(out);
    }

    @Test
    @DisplayName("首句里带 IP：绝不把 IP 切成两半（切半了脱敏就认不出来，会漏一截残 IP）")
    void asciiTokensAreNeverSplit() {
        String s = "建议封禁 106.37.205.248，并检查 10.0.0.7 的登录。";
        String out = PublicAnswerShaper.capOpeningSentence(s);

        assertOpeningWithin(out, 8);
        assertTrue(out.contains("106.37.205.248"),
                "IP 必须完整留在断点之后，不能变成「106.」：" + out);
        assertFalse(out.contains("106。"), "IP 不许被切成「106.」：" + out);
    }

    @Test
    @DisplayName("多段正文：首句超长只压首句，第二段照旧")
    void multilineAnswerKeepsItsSecondParagraph() {
        String s = "A07 说的是身份认证和会话管理失效。\n先上多因素认证，再补登录失败锁定。";
        String out = PublicAnswerShaper.capOpeningSentence(s);

        assertOpeningWithin(out, 8);
        assertTrue(out.contains("先上多因素认证，再补登录失败锁定"), "第二段不许丢：" + out);
        assertTrue(out.contains("\n") || out.contains("先上多因素认证"), "段落结构别拍平：" + out);
    }

    // ==================== ③ 幂等 / 边界 ====================

    @Test
    @DisplayName("幂等：压过一次的正文再压一次，结果不变")
    void cappingIsIdempotent() {
        String s = "A07 说的是身份认证和会话管理失效，多半栽在弱口令上。先上多因素认证。";
        String once = PublicAnswerShaper.capOpeningSentence(s);
        assertEquals(once, PublicAnswerShaper.capOpeningSentence(once), "再压一次不应继续变形");
    }

    @Test
    @DisplayName("边界：null / 空串 / 纯空白 / 上限≤0 都不炸")
    void degenerateInputsAreSafe() {
        assertNull(PublicAnswerShaper.capOpeningSentence(null));
        assertEquals("", PublicAnswerShaper.capOpeningSentence(""));
        assertEquals("   ", PublicAnswerShaper.capOpeningSentence("   "));
        assertEquals("身份认证与验证失败，多半栽在弱口令上。",
                PublicAnswerShaper.capOpeningSentence("身份认证与验证失败，多半栽在弱口令上。", 0),
                "上限 ≤0 表示不处理");
        assertNotNull(PublicAnswerShaper.capOpeningSentence("[EMO:normal]"));
    }

    @Test
    @DisplayName("上限可指定：limit=4 时首句压到 4 字（供后续调参）")
    void limitIsConfigurable() {
        String out = PublicAnswerShaper.capOpeningSentence("一二三四五六七八九十，后面还有内容。", 4);
        assertTrue(out.startsWith("一二三四。"), "应压到 4 字：" + out);
        assertOpeningWithin(out, 4);
    }

    @Test
    @DisplayName("可见字数不计空白：空格与全角空格都不算首句的字")
    void visibleLengthIgnoresWhitespace() {
        assertEquals(8, PublicAnswerShaper.visibleLength("A07 是认证失效"));
        assertEquals(8, PublicAnswerShaper.visibleLength("A07\u3000是认证失效"));
        assertEquals(0, PublicAnswerShaper.visibleLength("　 \t"));
        assertEquals(5, PublicAnswerShaper.visibleLength("这块读不到"));
    }

    // ==================== ④ 与 PublicAskService 的接线 ====================

    @Test
    @DisplayName("接线：PublicAskService.withCitations 走的就是这条兜底规则")
    void publicAskServiceUsesTheShaper() {
        // withCitations 是 private，这里用反射验证它确实调用了 capOpeningSentence：
        // 喂一句 17 字的首句，出来必须是 ≤8 字的首句 + 一行依据
        PublicAskService service = new PublicAskService();
        org.springframework.test.util.ReflectionTestUtils.setField(service, "outputGuard", new PublicOutputGuard());
        java.util.Map<String, Object> data = new java.util.HashMap<>();
        Object out = org.springframework.test.util.ReflectionTestUtils.invokeMethod(
                service, "withCitations",
                "A07 说的是身份认证和会话管理失效，多半栽在弱口令上。",
                java.util.List.of(), data);
        String answer = String.valueOf(out);
        assertOpeningWithin(answer, 8);
        assertTrue(answer.startsWith("A07 说的是身份。"), "上屏正文必须是压过的首句：" + answer);
        assertEquals(true, data.get("openingCapped"), "截断过就必须在响应里如实标出来");
        assertTrue(String.valueOf(data.get("openingCappedNote")).contains("8"),
                "截断说明要写清上限：" + data.get("openingCappedNote"));
        assertTrue(answer.contains("依据：0 条 ›"), "依据行照给：" + answer);
    }

    @Test
    @DisplayName("接线：[EMO:xxx] 情绪标签要能活着穿过整条后处理（剥痕迹 → 压首句 → 输出护栏）")
    void emoTagSurvivesTheWholePostProcessingChain() {
        PublicAskService service = new PublicAskService();
        org.springframework.test.util.ReflectionTestUtils.setField(service, "outputGuard", new PublicOutputGuard());
        java.util.Map<String, Object> data = new java.util.HashMap<>();
        Object out = org.springframework.test.util.ReflectionTestUtils.invokeMethod(
                service, "withCitations",
                "[EMO:angry]身份认证与验证失败，先堵弱口令。",
                java.util.List.of(), data);
        String answer = String.valueOf(out);
        assertTrue(answer.contains("[EMO:angry]"),
                "情绪标签不许被输出护栏吃掉（前端要靠它映射情绪）：" + answer);
        assertOpeningWithin(answer, 8);
    }
}
