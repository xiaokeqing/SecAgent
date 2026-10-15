package org.example.agent.multi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 研判结论的 schema 校验 + 代码层定级约束的单测（<b>不调模型，进每次 CI</b>）。
 *
 * <h3>为什么必须有这些用例</h3>
 * 改造前只验证过"顺利路径"（模型正常返回），项目在这上面栽过两次（MOCK 冒充 REAL）。
 * 这里把三条负向路径和定级约束都钉成回归用例：
 * <ul>
 *   <li>枚举越界 / 置信度越界 / 半截 JSON → 一律判"未生成"（返回 null，不展示半截结果）；</li>
 *   <li>概念问答（无事件要素）不得产出事件定级 —— 实测问"什么是 SSH 暴力破解"曾被判 CRITICAL；</li>
 *   <li>缺源 IP 不得高于 LOW；低置信度不得直接给最高级；</li>
 *   <li>渲染必须用校验过的字段重建，不回贴模型原文（防输出格式注入）。</li>
 * </ul>
 */
class AnalystVerdictTest {

    private final MultiAgentCoordinatorImpl coordinator = new MultiAgentCoordinatorImpl();

    private static String verdict(String attackType, double confidence, String severity,
                                 String evidence, String recommendation, boolean unknown) {
        return "{\"attackType\":\"" + attackType + "\",\"confidence\":" + confidence
                + ",\"severity\":\"" + severity + "\",\"evidence\":" + evidence
                + ",\"recommendation\":\"" + recommendation + "\",\"unknown\":" + unknown
                + ",\"reason\":\"基于片段\"}";
    }

    @Test
    @DisplayName("合法输入 + 有源 IP + 高置信度：保留定级，不触发下调")
    void validVerdictWithIpKeepsSeverity() {
        String out = coordinator.validateVerdict(
                verdict("SSH暴力破解", 0.92, "HIGH", "[\"Failed password for root\"]", "封禁源IP", false),
                "2026-10-12 10:00 来源 45.83.91.55 多次登录失败 root");
        assertNotNull(out);
        assertTrue(out.contains("HIGH"), "应保留 HIGH");
        assertFalse(out.contains("已下调"), "有 IP 的高置信度结论不应被下调");
        assertTrue(out.contains("45.83.91.55") || out.contains("Failed password"), "应带证据引用");
    }

    @Test
    @DisplayName("概念问答（无事件要素）：不得产出事件定级，必须降到 INFO 并标注")
    void conceptQuestionIsNotAnIncident() {
        String out = coordinator.validateVerdict(
                verdict("SSH暴力破解", 0.79, "CRITICAL", "[\"## 一、SSH 暴力破解（OWASP A07）\"]", "封禁源IP", false),
                "用一句话说明什么是SSH暴力破解");
        assertNotNull(out);
        assertTrue(out.contains("概念问答"), "必须标注输入类型为概念问答");
        assertTrue(out.contains("INFO"), "概念问答的严重度必须是 INFO");
        assertTrue(out.contains("已下调"), "应说明定级被代码层下调");
        assertFalse(out.contains("严重度**：CRITICAL"), "绝不能输出 CRITICAL");
        assertFalse(out.contains("&#39;"), "本层不得做 HTML 转义（转义只在渲染 sink 做一次）");
    }

    @Test
    @DisplayName("缺源 IP：严重度不得高于 LOW")
    void missingIpCapsAtLow() {
        String out = coordinator.validateVerdict(
                verdict("可疑扫描", 0.9, "HIGH", "[\"大量 SYN\"]", "排查", false),
                "服务器上出现了大量扫描行为，但没有记录来源");
        assertNotNull(out);
        assertTrue(out.contains("LOW"), "无源 IP 应降到 LOW");
        assertTrue(out.contains("缺少源 IP"), "应说明下调原因");
    }

    @Test
    @DisplayName("置信度不足：不得直接给最高级")
    void lowConfidenceCannotBeCritical() {
        String out = coordinator.validateVerdict(
                verdict("疑似外联", 0.41, "CRITICAL", "[\"conn to 1.2.3.4\"]", "隔离主机", false),
                "2026-10-12 10:00 主机 10.0.0.5 疑似外联 1.2.3.4");
        assertNotNull(out);
        assertTrue(out.contains("MEDIUM"), "低置信度应降到 MEDIUM");
    }

    @Test
    @DisplayName("枚举越界：判为未生成")
    void invalidSeverityEnumRejected() {
        assertNull(coordinator.validateVerdict(
                verdict("X", 0.9, "SEVERE", "[\"a\"]", "b", false), "来源 1.2.3.4 的攻击"));
    }

    @Test
    @DisplayName("置信度越界：判为未生成")
    void confidenceOutOfRangeRejected() {
        assertNull(coordinator.validateVerdict(
                verdict("X", 1.5, "HIGH", "[\"a\"]", "b", false), "来源 1.2.3.4 的攻击"));
        assertNull(coordinator.validateVerdict(
                verdict("X", -0.2, "HIGH", "[\"a\"]", "b", false), "来源 1.2.3.4 的攻击"));
    }

    @Test
    @DisplayName("半截/非法 JSON：判为未生成（不展示半截结果）")
    void malformedJsonRejected() {
        assertNull(coordinator.validateVerdict("{\"attackType\":\"X\",", "来源 1.2.3.4"));
        assertNull(coordinator.validateVerdict("模型觉得这是攻击，但没按 JSON 输出", "来源 1.2.3.4"));
        assertNull(coordinator.validateVerdict("", "来源 1.2.3.4"));
        assertNull(coordinator.validateVerdict(null, "来源 1.2.3.4"));
    }

    @Test
    @DisplayName("evidence 不是字符串数组：判为未生成")
    void evidenceMustBeStringArray() {
        assertNull(coordinator.validateVerdict(
                verdict("X", 0.9, "HIGH", "\"一段话\"", "b", false), "来源 1.2.3.4"));
        assertNull(coordinator.validateVerdict(
                verdict("X", 0.9, "HIGH", "[{\"doc\":\"a\"}]", "b", false), "来源 1.2.3.4"));
    }

    @Test
    @DisplayName("模型自述 unknown=true：不给攻击类型与处置建议")
    void unknownVerdictHasNoConclusion() {
        String out = coordinator.validateVerdict(
                verdict("unknown", 0.2, "INFO", "[]", "无", true), "来源 1.2.3.4 的模糊现象");
        assertNotNull(out);
        assertTrue(out.contains("依据不足"), "应明确表示依据不足");
        assertFalse(out.contains("**攻击类型**"), "unknown 时不得给攻击类型");
    }

    @Test
    @DisplayName("渲染用校验字段重建：不把模型原文整段回贴（防输出格式注入）")
    void renderedTextIsRebuiltNotPasted() {
        String out = coordinator.validateVerdict(
                verdict("暴力破解", 0.9, "HIGH", "[\"证据A\"]", "封禁", false), "来源 1.2.3.4");
        assertNotNull(out);
        assertTrue(out.contains("**攻击类型**：暴力破解"));
        assertFalse(out.contains("\"attackType\""), "不应回贴原始 JSON 字段名");
        assertFalse(out.contains("{\"attackType\""), "不应回贴原始 JSON 文本");
    }

    @Test
    @DisplayName("模型用 ```json 代码块包裹输出：能剥离并解析")
    void codeFenceWrappedJsonAccepted() {
        String out = coordinator.validateVerdict(
                "```json\n" + verdict("暴力破解", 0.9, "HIGH", "[\"证据A\"]", "封禁", false) + "\n```",
                "来源 1.2.3.4");
        assertNotNull(out);
        assertTrue(out.contains("HIGH"));
    }

    // ==================================================================
    // T14 情绪决策：失败注入（不调模型、不烧额度、进每次 CI）
    //
    // 为什么是这 8 条：每一条都对应一种"模型会说但白名单不认"的真实写法 ——
    // 剪辑名幻觉 / 素材里有但不在状态机内（clips_not_in_graph）/ 台词还没入库（60 句计划）/
    // 把状态机宿主键当契约值（surprised）/ 把台词库标签当契约值（shy）/ 数值越界。
    // 断言三件事：① 正文没被连坐丢掉 ② 非法字段被替换成语义安全值 ③ rejectReason 命中预期。
    // ==================================================================

    private static DecisionWhitelist whitelist() {
        DecisionWhitelist w = new DecisionWhitelist();
        ReflectionTestUtils.setField(w, "resource",
                new ClassPathResource("kurisu/decision-whitelist.json"));
        w.load();
        assertTrue(w.loaded(), "白名单资源必须能加载：读不到会让所有决策用例静默退化");
        return w;
    }

    private static MultiAgentCoordinatorImpl coordinatorWithWhitelist() {
        MultiAgentCoordinatorImpl c = new MultiAgentCoordinatorImpl();
        ReflectionTestUtils.setField(c, "decisionWhitelist", whitelist());
        return c;
    }

    private static String verdictWithDecision(String action, String lineId, String emoTo, double urgency) {
        return "{\"attackType\":\"SSH暴力破解\",\"confidence\":0.9,\"severity\":\"INFO\","
                + "\"evidence\":[\"片段原句\"],\"recommendation\":\"只看公开知识库\",\"unknown\":false,"
                + "\"reason\":\"概念问答\",\"emotionFrom\":\"normal\",\"emotionTo\":\"" + emoTo + "\","
                + "\"action\":\"" + action + "\",\"lineId\":\"" + lineId + "\",\"urgency\":" + urgency + "}";
    }

    private static Map<String, Object> decide(MultiAgentCoordinatorImpl c, String action, String lineId,
                                             String emoTo, double urgency) {
        String out = c.validateVerdict(verdictWithDecision(action, lineId, emoTo, urgency),
                "什么是SSH暴力破解", true);
        assertNotNull(out, "决策字段非法绝不能把正文一起丢掉（否则 state=model-failed，代价过大）");
        Map<String, Object> d = c.currentDecision();
        assertNotNull(d, "公开面必须产出决策");
        assertEquals(DecisionWhitelist.SCHEMA_VERSION, d.get("schemaVersion"));
        return d;
    }

    @Test
    @DisplayName("T14 ①：全字段合法 ⇒ fallbackUsed=false、rejectReason 为空、六字段齐全")
    void decisionAllWhitelisted() {
        MultiAgentCoordinatorImpl c = coordinatorWithWhitelist();
        Map<String, Object> d = decide(c, "thinking_trans", "nav_monitor", "sided_thinking", 0.6);
        assertEquals("normal", d.get("emotionFrom"));
        assertEquals("sided_thinking", d.get("emotionTo"));
        assertEquals("thinking_trans", d.get("action"));
        assertEquals("nav_monitor", d.get("lineId"));
        assertEquals(0.6, (Double) d.get("urgency"), 1e-9);
        assertEquals(Boolean.FALSE, d.get("fallbackUsed"));
        assertEquals("", d.get("rejectReason"));
        assertEquals(java.util.List.of("片段原句"), d.get("citations"));
    }

    @Test
    @DisplayName("T14 ②：lineId=空串是【合法值】（只出字幕不出声），不是错误")
    void decisionEmptyLineIdIsLegal() {
        MultiAgentCoordinatorImpl c = coordinatorWithWhitelist();
        Map<String, Object> d = decide(c, "thinking_trans", "", "sided_thinking", 0.6);
        assertEquals("", d.get("lineId"));
        assertEquals(Boolean.FALSE, d.get("fallbackUsed"), "空串是契约里的合法值，不该触发回退");
    }

    @Test
    @DisplayName("T14 ③：action 幻觉 ⇒ 丢弃并由 emotionTo 反推（sided_thinking → thinking_trans）")
    void decisionHallucinatedActionIsReplaced() {
        MultiAgentCoordinatorImpl c = coordinatorWithWhitelist();
        Map<String, Object> d = decide(c, "angry_ultra_trans", "nav_monitor", "sided_thinking", 0.6);
        assertEquals("thinking_trans", d.get("action"));
        assertEquals(Boolean.TRUE, d.get("fallbackUsed"));
        assertTrue(DecisionWhitelist.rejectsOf(d).contains("ACTION_NOT_IN_WHITELIST"),
                String.valueOf(d.get("rejectReason")));
    }

    @Test
    @DisplayName("T14 ④：action 命中素材但不在状态机（clips_not_in_graph 的 smile）⇒ 判非法")
    void decisionClipNotInGraphRejected() {
        MultiAgentCoordinatorImpl c = coordinatorWithWhitelist();
        Map<String, Object> d = decide(c, "smile", "nav_monitor", "happy", 0.6);
        assertEquals(Boolean.TRUE, d.get("fallbackUsed"));
        assertTrue(DecisionWhitelist.rejectsOf(d).contains("ACTION_NOT_IN_GRAPH"),
                "smile 在素材里有、但不在 38 节点内，必须与'纯幻觉'区分开：" + d.get("rejectReason"));
        assertEquals("trans_smile", d.get("action"), "happy 的回退动作是 trans_smile");
    }

    @Test
    @DisplayName("T14 ⑤：lineId 命中「60 句计划但未入库」⇒ 回退空串，原因是 LINE_PLANNED_NOT_SHIPPED")
    void decisionPlannedButNotShippedLineRejected() {
        MultiAgentCoordinatorImpl c = coordinatorWithWhitelist();
        Map<String, Object> d = decide(c, "thinking_trans", "event_bruteforce", "sided_thinking", 0.6);
        assertEquals("", d.get("lineId"));
        assertTrue(DecisionWhitelist.rejectsOf(d).contains("LINE_PLANNED_NOT_SHIPPED"),
                String.valueOf(d.get("rejectReason")));
    }

    @Test
    @DisplayName("T14 ⑥：emotionTo=surprised（状态机宿主键，不是契约值）⇒ 回退 normal")
    void decisionStateMachineKeyIsNotContractValue() {
        MultiAgentCoordinatorImpl c = coordinatorWithWhitelist();
        Map<String, Object> d = decide(c, "surprise_trans", "nav_monitor", "surprised", 0.6);
        assertEquals("normal", d.get("emotionTo"));
        assertTrue(DecisionWhitelist.rejectsOf(d).contains("EMOTION_TO_UNKNOWN"),
                String.valueOf(d.get("rejectReason")));
    }

    @Test
    @DisplayName("T14 ⑦：emotionTo=shy（台词库标签，不是契约值）⇒ 回退 normal")
    void decisionVoiceBankLabelIsNotContractValue() {
        MultiAgentCoordinatorImpl c = coordinatorWithWhitelist();
        Map<String, Object> d = decide(c, "shy_trans", "nav_monitor", "shy", 0.6);
        assertEquals("normal", d.get("emotionTo"));
        assertTrue(DecisionWhitelist.rejectsOf(d).contains("EMOTION_TO_UNKNOWN"),
                String.valueOf(d.get("rejectReason")));
    }

    @Test
    @DisplayName("T14 ⑧：urgency 越界 ⇒ 钳到 [0,1] 并记 URGENCY_CLAMPED")
    void decisionUrgencyClamped() {
        MultiAgentCoordinatorImpl c = coordinatorWithWhitelist();
        Map<String, Object> d = decide(c, "thinking_trans", "nav_monitor", "sided_thinking", 1.4);
        assertEquals(1.0, (Double) d.get("urgency"), 1e-9);
        assertTrue(DecisionWhitelist.rejectsOf(d).contains("URGENCY_CLAMPED"),
                String.valueOf(d.get("rejectReason")));
    }

    @Test
    @DisplayName("T14 ⑨：白名单读不到 ⇒ fail-closed（全字段回退），绝不静默放行模型自创值")
    void decisionFailsClosedWhenWhitelistMissing() {
        MultiAgentCoordinatorImpl c = new MultiAgentCoordinatorImpl();   // 不注入白名单
        Map<String, Object> d = decide(c, "thinking_trans", "nav_monitor", "sided_thinking", 0.6);
        assertEquals("normal", d.get("emotionTo"));
        assertEquals("idle", d.get("action"));
        assertEquals("", d.get("lineId"));
        assertEquals(Boolean.TRUE, d.get("fallbackUsed"));
        assertTrue(DecisionWhitelist.rejectsOf(d).contains("WHITELIST_UNLOADED"),
                String.valueOf(d.get("rejectReason")));
    }

    @Test
    @DisplayName("T14 ⑩：内部研判面不产出决策（决策只在公开面落地）")
    void decisionOnlyOnPublicFace() {
        MultiAgentCoordinatorImpl c = coordinatorWithWhitelist();
        // 先跑一次公开面，制造线程局部残留
        decide(c, "thinking_trans", "nav_monitor", "sided_thinking", 0.6);
        String out = c.validateVerdict(
                verdict("SSH暴力破解", 0.92, "HIGH", "[\"Failed password for root\"]", "封禁源IP", false),
                "2026-10-12 10:00 来源 45.83.91.55 多次登录失败 root");
        assertNotNull(out);
        assertNull(c.currentDecision(), "内部面必须没有任何决策残留（否则同线程串决策）");
    }

    @Test
    @DisplayName("T14 ⑪：进 prompt 的白名单清单不能失控（38 个剪辑名 + 12 句 id 的可读上限）")
    void promptHintIsBounded() {
        String hint = whitelist().promptHint();
        assertTrue(hint.contains("thinking_trans"), "清单里必须有真实剪辑名");
        assertTrue(hint.contains("nav_monitor"), "清单里必须有真实台词 id");
        assertTrue(hint.length() < 900, "清单长度失控会把 prompt 预算吃掉：" + hint.length());
    }
}
