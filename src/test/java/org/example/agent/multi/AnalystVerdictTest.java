package org.example.agent.multi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

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
}
