package org.example.agent.multi;

import org.example.agent.tool.InternalDocsTools;
import org.example.agent.tool.QueryLogsTools;
import org.example.agent.tool.QueryMetricsTools;
import org.example.publicapi.PublicKbService;
import org.example.security.EvalIdentity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 公开面上屏正文（{@link MultiAgentResult#getPublicAnswer()}）的契约测试（2026-10-17 直答化）。
 *
 * <h3>为什么需要这一层</h3>
 * 改造前，公开问答的响应正文就是 {@code getFinalAnswer()} —— 也就是内部给站主看的
 * <b>编排报告</b>：{@code ## 多智能体协同结果} / {@code > 调度员判定本次任务为【研判分析员】} /
 * {@code > state=input-insufficient} / {@code **模型判定：依据不足，不做定性。**}。
 * 实测访客问"这个网站是干嘛的"也会收到一份"事件研判报告"，答"依据不足"。
 *
 * <h3>现在的分层</h3>
 * <ul>
 *   <li>{@code finalAnswer}：内部报告，<b>一个字不改</b>（/api/chat、自用面、日志都靠它，
 *       {@link PublicDataToolIsolationTest} 那批断言也钉在它上面）；</li>
 *   <li>{@code publicAnswer}：公开面上屏的「她的直答」，纯文本、没有报告外壳；
 *       内部身份下为 {@code null}；</li>
 *   <li>{@code state}：机读状态，正文里不再出现 {@code state=} 字样，状态只走这个字段。</li>
 * </ul>
 */
class PublicReplyContractTest {

    // ==================== 替身 ====================

    private static class RecordingLogs extends QueryLogsTools {
        int queryCalls = 0;
        int topicCalls = 0;

        @Override
        public String queryLogs(String region, String logTopic, String query, Integer limit) {
            queryCalls++;
            return "{\"success\":true,\"logs\":[{\"message\":\"Failed password for root from 10.0.0.7\"}]}";
        }

        @Override
        public String getAvailableLogTopics() {
            topicCalls++;
            return "{\"topics\":[\"auth-logs\",\"web-access-logs\"]}";
        }
    }

    private static class RecordingMetrics extends QueryMetricsTools {
        int calls = 0;

        @Override
        public String queryPrometheusAlerts(String timeRange) {
            calls++;
            return "{\"success\":true,\"alerts\":[{\"alertName\":\"SSHBruteForce\"}]}";
        }
    }

    private static class RecordingInternalDocs extends InternalDocsTools {
        int calls = 0;

        RecordingInternalDocs() {
            super(null, new org.example.security.PromptInjectionGuard());
        }

        @Override
        public String queryInternalDocs(String query) {
            calls++;
            return "[{\"title\":\"内部应急响应 SOP\",\"content\":\"处置步骤\"}]";
        }
    }

    private static class RecordingActionTools extends SecurityActionTools {
        int calls = 0;

        @Override
        public String blockIp(String ip, Integer durationMinutes, String reason) {
            calls++;
            return "【封禁IP】结果：成功（替身）";
        }
    }

    /** 模型替身：记账 + 返回预置 JSON（可带 reply 字段） */
    private static class StubLlm implements org.example.llm.LlmProvider {
        int calls = 0;
        String output = "{\"attackType\":\"概念解释\",\"confidence\":0.9,\"severity\":\"INFO\","
                + "\"evidence\":[\"片段原句\"],\"recommendation\":\"启用多因素认证\","
                + "\"unknown\":false,\"reason\":\"公开片段支持\"}";

        @Override
        public String id() {
            return "stub";
        }

        @Override
        public String modelName() {
            return "stub-model";
        }

        @Override
        public boolean available() {
            return true;
        }

        @Override
        public String generate(String systemPrompt, String userPrompt) {
            calls++;
            return output;
        }
    }

    private static class StubPublicKb extends PublicKbService {
        int calls = 0;
        List<Map<String, Object>> results = new ArrayList<>();

        @Override
        public List<Map<String, Object>> search(String query) {
            calls++;
            return results;
        }
    }

    // ==================== 组装 ====================

    private RecordingLogs logs;
    private RecordingMetrics metrics;
    private RecordingInternalDocs docs;
    private RecordingActionTools actions;
    private StubLlm llm;
    private StubPublicKb kb;

    private MultiAgentCoordinatorImpl coordinator() {
        logs = new RecordingLogs();
        metrics = new RecordingMetrics();
        docs = new RecordingInternalDocs();
        actions = new RecordingActionTools();
        llm = new StubLlm();
        kb = new StubPublicKb();

        MultiAgentCoordinatorImpl c = new MultiAgentCoordinatorImpl();
        ReflectionTestUtils.setField(c, "dashScopeApiKey", "sk-placeholder");
        ReflectionTestUtils.setField(c, "llmEnabledConfig", "auto");
        ReflectionTestUtils.setField(c, "securityActionTools", actions);
        ReflectionTestUtils.setField(c, "internalDocsTools", docs);
        ReflectionTestUtils.setField(c, "queryLogsTools", logs);
        ReflectionTestUtils.setField(c, "queryMetricsTools", metrics);
        ReflectionTestUtils.setField(c, "llmProvider", llm);
        ReflectionTestUtils.setField(c, "publicKbService", kb);
        return c;
    }

    private int internalToolCalls() {
        return logs.queryCalls + logs.topicCalls + metrics.calls + docs.calls + actions.calls;
    }

    private static Map<String, Object> citation(String title, String snippet) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("title", title);
        m.put("snippet", snippet);
        m.put("sourceType", "community");
        m.put("sourceTypeLabel", "社区/内部整理（可信度中）");
        m.put("trustLevel", "high");
        m.put("trustLevelLabel", "可信度高");
        m.put("score", 0.71);
        return m;
    }

    @AfterEach
    void cleanup() {
        EvalIdentity.endEvalRequest();
    }

    /** 公开直答的硬约束：正文里一个内部痕迹都不能有 */
    private static void assertCleanReply(String reply) {
        assertNotNull(reply, "公开身份必须产出上屏正文");
        for (String bad : new String[]{"state=", "unknown=true", "generatedBy=", "结论生成方式",
                "多智能体", "调度员判定", "模型判定", "##", "依据不足"}) {
            assertFalse(reply.contains(bad), "上屏正文不得含内部痕迹「" + bad + "」：" + reply);
        }
        assertFalse(reply.isBlank(), "上屏正文不得为空");
    }

    // ==================== ① 站点介绍：直答，不进研判定级 ====================

    @Test
    @DisplayName("问「这个网站是干嘛的」：直答站点是什么，不检索、不调模型、不进研判定级")
    void siteIntroQuestionAnswersDirectly() throws Exception {
        MultiAgentCoordinatorImpl c = coordinator();

        EvalIdentity.markPublicRequest();
        try {
            MultiAgentResult r = c.routeAndRun("这个网站是干嘛的", List.of());

            String reply = r.getPublicAnswer();
            assertCleanReply(reply);
            assertTrue(reply.contains("安全运营台"), "应直接说清这是什么站：" + reply);
            assertTrue(reply.contains("监测中心") && reply.contains("笔记"),
                    "应把三个去处说清（监测中心/问答/笔记）：" + reply);
            assertTrue(reply.contains("不执行处置"), "应说明只提议不执行：" + reply);
            assertEquals("rule-based", r.getState(), "介绍类问题不该有任何研判/模型状态");
            assertEquals(0, llm.calls, "介绍类问题不该花公开演示额度");
            assertEquals(0, kb.calls, "介绍类问题不需要检索");
            assertEquals(0, internalToolCalls(), "介绍类问题不得碰任何内部工具");
            // 内部报告仍然是原来那份（一个字没动），只是不再上屏
            assertNotNull(r.getFinalAnswer());
        } finally {
            EvalIdentity.endEvalRequest();
        }
    }

    // ==================== ② 取证类：给口径，不给数据 ====================

    @Test
    @DisplayName("问「我们昨天被谁打了」：直答「公开面不取证」，正文不带研报痕迹")
    void forensicsQuestionRefusesWithoutReport() throws Exception {
        MultiAgentCoordinatorImpl c = coordinator();

        EvalIdentity.markPublicRequest();
        try {
            MultiAgentResult r = c.routeAndRun("我们昨天被谁打了？最近有哪些攻击告警？", List.of());

            String reply = r.getPublicAnswer();
            assertCleanReply(reply);
            assertTrue(reply.contains("公开面不取证"), "应明确整改口径：" + reply);
            assertTrue(reply.contains("监测中心"), "应指出去哪儿看：" + reply);
            assertEquals("input-insufficient", r.getState());
            assertEquals(0, internalToolCalls(), "公开面不得取证");
            assertEquals(0, llm.calls, "这类问题答案不在公开数据里，不该花额度去猜");
        } finally {
            EvalIdentity.endEvalRequest();
        }
    }

    // ==================== ③ 处置类：不执行，只提议 ====================

    @Test
    @DisplayName("要求封禁 IP：直答「我提议，执行要过流程」，零处置工具调用")
    void actionRequestExplainsNoExecution() throws Exception {
        MultiAgentCoordinatorImpl c = coordinator();

        EvalIdentity.markPublicRequest();
        try {
            MultiAgentResult r = c.routeAndRun("请封禁来源 IP 203.0.113.66，封 60 分钟", List.of());

            String reply = r.getPublicAnswer();
            assertCleanReply(reply);
            assertTrue(reply.contains("我提议"), "应说明只提议不执行：" + reply);
            assertTrue(reply.contains("执行要过流程") || reply.contains("过流程"),
                    "应说明执行需过流程：" + reply);
            assertEquals("rule-based", r.getState());
            assertEquals(0, actions.calls, "公开面不得调用任何处置工具");
            assertEquals(0, internalToolCalls(), "公开面不得碰任何内部工具");
        } finally {
            EvalIdentity.endEvalRequest();
        }
    }

    // ==================== ④ 概念题：模型直答上屏，报告只留内部 ====================

    @Test
    @DisplayName("概念题命中片段：上屏的是模型写的 reply，内部研报仍留在 finalAnswer")
    void modelReplyIsWhatGetsShown() throws Exception {
        MultiAgentCoordinatorImpl c = coordinator();
        kb.results = List.of(citation("OWASP A07：身份认证与验证失败",
                "A07 指与身份认证、会话管理相关的失效，防御手段包括 MFA 与会话失效控制。"));
        llm.output = "{\"attackType\":\"身份认证失效\",\"confidence\":0.88,\"severity\":\"HIGH\","
                + "\"evidence\":[\"A07 指与身份认证、会话管理相关的失效\"],"
                + "\"recommendation\":\"启用多因素认证\",\"unknown\":false,\"reason\":\"公开片段支持\","
                + "\"reply\":\"A07 说的是身份认证和会话管理失效，多半栽在弱口令上。\\n"
                + "先上多因素认证和登录失败锁定，这类问题就堵掉大半。\"}";

        EvalIdentity.markPublicRequest();
        try {
            MultiAgentResult r = c.routeAndRun("OWASP A07 是什么", List.of());

            String reply = r.getPublicAnswer();
            assertCleanReply(reply);
            assertTrue(reply.contains("A07 说的是身份认证和会话管理失效"), "上屏的必须是模型写的直答：" + reply);
            assertFalse(reply.contains("**攻击类型**"), "研报字段不该上屏：" + reply);
            assertFalse(reply.contains("置信度"), "研报字段不该上屏：" + reply);
            assertEquals("model", r.getState());
            assertEquals(1, llm.calls);
            assertEquals(0, internalToolCalls(), "公开知识问答不得碰内部工具");

            // 【内部面回归】报告原文照旧：state= 与研报字段都还在里面
            String report = r.getFinalAnswer();
            assertTrue(report.contains("state=model"), "内部报告必须保持原样（/api/chat、日志靠它）");
            assertTrue(report.contains("**攻击类型**：身份认证失效"), "内部报告必须保持原样：" + report);
        } finally {
            EvalIdentity.endEvalRequest();
        }
    }

    @Test
    @DisplayName("模型没给 reply（或给的被校验丢弃）：上屏走 B 兜底，不拿研报冒充")
    void blankReplyFallsBackToB() throws Exception {
        MultiAgentCoordinatorImpl c = coordinator();
        kb.results = List.of(citation("端口扫描", "端口扫描是探测目标主机开放端口的行为。"));
        // 没有 reply 字段
        llm.output = "{\"attackType\":\"端口扫描\",\"confidence\":0.8,\"severity\":\"INFO\","
                + "\"evidence\":[\"端口扫描是探测目标主机开放端口的行为\"],"
                + "\"recommendation\":\"关闭不必要端口\",\"unknown\":false,\"reason\":\"公开片段支持\"}";

        EvalIdentity.markPublicRequest();
        try {
            MultiAgentResult r = c.routeAndRun("什么是端口扫描", List.of());

            assertEquals(MultiAgentCoordinatorImpl.PUBLIC_REPLY_FALLBACK, r.getPublicAnswer(),
                    "没有可用直答时必须用 B 兜底，绝不能把研报正文顶上去");
            assertEquals("model-failed", r.getState(), "拿不到可用直答就是未生成");
        } finally {
            EvalIdentity.endEvalRequest();
        }
    }

    // ==================== ⑤ 内部身份不受影响 ====================

    @Test
    @DisplayName("【对照】内部身份：不产出公开直答（publicAnswer 为 null），内部能力照旧")
    void internalIdentityHasNoPublicAnswer() throws Exception {
        MultiAgentCoordinatorImpl c = coordinator();

        EvalIdentity.beginUserRequest();
        try {
            MultiAgentResult r = c.routeAndRun("我们昨天被谁打了？最近有哪些攻击告警？", List.of());
            assertNull(r.getPublicAnswer(), "内部身份不该有「公开直答」这个字段");
            assertNull(r.getState(), "内部身份的状态由报告正文承载");
            assertTrue(internalToolCalls() >= 1, "内部身份必须真的调取证工具（对照组）");
        } finally {
            EvalIdentity.endEvalRequest();
        }
    }
}
