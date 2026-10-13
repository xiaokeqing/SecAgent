package org.example.agent.multi;

import org.example.agent.tool.InternalDocsTools;
import org.example.agent.tool.QueryLogsTools;
import org.example.agent.tool.QueryMetricsTools;
import org.example.publicapi.PublicKbService;
import org.example.security.EvalIdentity;
import org.example.security.PromptInjectionGuard;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 公开路径「绝不读取内部事件数据」的测试（F2 收紧，2026-10-13）。
 *
 * <h3>为什么必须有这条测试</h3>
 * 修复前的实测：匿名访客问"我们昨天被谁打了"这类问题时，编排层会判定为<b>取证任务</b>，
 * 于是真的去查内部日志与活动告警，并把原文（内部资产名 web-01/web-02、内部接口路径
 * {@code /api/order/detail}、{@code /upload/files/}、告警描述）带回公开回答。
 * 处置动作没有执行 —— 但"不执行处置"和"不泄露内部事件数据"是两件事，
 * {@link PublicResponderIsolationTest} 只证明了前者。
 *
 * <h3>测试方法：记账替身 + 对照</h3>
 * 四个"读/写内部数据"的工具全部换成会记账的替身，然后：
 * <ul>
 *   <li>公开身份 → <b>零调用</b>（日志、告警、内部知识库、处置动作一个都不许碰）；</li>
 *   <li>内部身份 → <b>必须被调到</b>（证明替身真的能看见调用，否则上面那条断言毫无意义）。</li>
 * </ul>
 * 另外断言回答文本里不含任何内部痕迹（资产名 / 内部路径 / 内部标记 / 日志原文特征）。
 */
class PublicDataToolIsolationTest {

    // ==================== 会记账的工具替身 ====================

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
            return "{\"success\":true,\"alerts\":[{\"alertName\":\"SSHBruteForce\",\"description\":\"web-01 大量登录失败\"}]}";
        }
    }

    private static class RecordingInternalDocs extends InternalDocsTools {
        int calls = 0;

        RecordingInternalDocs() {
            super(null, new PromptInjectionGuard());
        }

        @Override
        public String queryInternalDocs(String query) {
            calls++;
            return "[{\"title\":\"内部应急响应 SOP\",\"content\":\"内网资产 /api/order/detail 处置步骤\"}]";
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

    /** 模型替身：只记账并返回预置 JSON，不联网 */
    private static class StubLlm implements org.example.llm.LlmProvider {
        int calls = 0;
        boolean available = true;
        String output = "{\"attackType\":\"概念解释\",\"confidence\":0.9,\"severity\":\"INFO\","
                + "\"evidence\":[\"片段原句\"],\"recommendation\":\"启用 MFA 与最小权限\","
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
            return available;
        }

        @Override
        public String generate(String systemPrompt, String userPrompt) throws Exception {
            calls++;
            return output;
        }
    }

    /** 公开知识库替身：返回固定的白名单片段 */
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
        // 占位 Key → 离线规则路由（不依赖任何模型即可考察"路由与工具边界"）
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

    // ==================== ① 事件类提问：公开面零工具调用、零内部痕迹 ====================

    @Test
    @DisplayName("【红线】公开身份问「我们昨天被谁打了」：四个内部工具零调用，回答如实说 input-insufficient")
    void publicEventQuestionTouchesNoInternalTool() throws Exception {
        MultiAgentCoordinatorImpl c = coordinator();

        EvalIdentity.markPublicRequest();
        try {
            MultiAgentResult r = c.routeAndRun("我们昨天被谁打了？最近有哪些攻击告警？", List.of());

            assertEquals(0, internalToolCalls(),
                    "公开身份不得调用任何读内部数据的工具（日志/告警/内部知识库/处置），实测修复前这里会真取证");
            assertEquals(0, llm.calls, "这类问题答案不在公开数据里，不该花公开演示额度去猜");
            assertEquals(0, kb.calls, "明确依赖内部事件数据的问题连公开检索都不必做");

            String answer = r.getFinalAnswer();
            assertNotNull(answer);
            assertTrue(answer.contains("state=input-insufficient"), "应如实标为「依据不足」：" + answer);
            assertTrue(answer.contains("公开面只基于公开知识库回答，不读取内部事件数据"),
                    "必须明说口径与原因：" + answer);
            assertNoInternalTraces(answer);
        } finally {
            EvalIdentity.endEvalRequest();
        }
    }

    @Test
    @DisplayName("公开身份问「最近的攻击源是谁」：同样零调用、零内部痕迹（另一种说法也要拦住）")
    void publicAttributionQuestionIsAlsoRefused() throws Exception {
        MultiAgentCoordinatorImpl c = coordinator();
        EvalIdentity.markPublicRequest();
        try {
            String answer = c.routeAndRun("最近的攻击源是谁？帮我看一下攻击者 IP", List.of()).getFinalAnswer();
            assertEquals(0, internalToolCalls(), "归属类提问（谁在打我们）必须零工具调用");
            assertTrue(answer.contains("state=input-insufficient"));
            assertNoInternalTraces(answer);
        } finally {
            EvalIdentity.endEvalRequest();
        }
    }

    @Test
    @DisplayName("【对照】内部身份问同一条问题：真的会取证（证明替身能看见调用）")
    void internalEventQuestionStillForensics() throws Exception {
        MultiAgentCoordinatorImpl c = coordinator();
        llm.available = false;      // 只看工具边界，不让模型参与

        EvalIdentity.beginUserRequest();
        try {
            c.routeAndRun("我们昨天被谁打了？最近有哪些攻击告警？", List.of());
            assertTrue(logs.queryCalls + metrics.calls >= 1,
                    "内部身份必须真的调取证工具（否则公开那条断言没有意义）");
        } finally {
            EvalIdentity.endEvalRequest();
        }
    }

    // ==================== ② 知识类提问：仍然有用，但只走公开知识库 ====================

    @Test
    @DisplayName("公开身份问概念题：仍能给出带依据的模型结论，但只用了公开白名单片段")
    void publicKnowledgeQuestionStillAnswersFromPublicKb() throws Exception {
        MultiAgentCoordinatorImpl c = coordinator();
        kb.results = List.of(citation("OWASP A07：身份认证与验证失败",
                "A07 指与身份认证、会话管理相关的失效，防御手段包括 MFA、弱口令排查与会话失效控制。"));

        EvalIdentity.markPublicRequest();
        try {
            String answer = c.routeAndRun("OWASP A07 是什么", List.of()).getFinalAnswer();

            assertEquals(1, kb.calls, "公开知识问答必须走公开白名单出口");
            assertEquals(0, internalToolCalls(), "公开知识问答不得碰任何内部工具");
            assertEquals(1, llm.calls, "命中公开片段后由模型生成解释（这正是「公开面仍然有用」的部分）");

            assertTrue(answer.contains("state=model"), "有依据时应能生成结论：" + answer);
            assertTrue(answer.contains("公开面只基于公开知识库回答，不读取内部事件数据"), "应带公开口径：" + answer);
            assertTrue(answer.contains("防护建议"), "公开面只给防护建议：" + answer);
            assertTrue(answer.contains("**严重度**：INFO"),
                    "公开面不做事件定级（模型报 HIGH 也必须被代码压到 INFO）：" + answer);
            assertNoInternalTraces(answer);
        } finally {
            EvalIdentity.endEvalRequest();
        }
    }

    @Test
    @DisplayName("公开身份问概念题但公开库无命中：如实说 no-retrieval，不拿别的数据顶替")
    void publicKnowledgeQuestionWithoutHitsIsHonest() throws Exception {
        MultiAgentCoordinatorImpl c = coordinator();
        kb.results = List.of();

        EvalIdentity.markPublicRequest();
        try {
            String answer = c.routeAndRun("什么是端口扫描", List.of()).getFinalAnswer();
            assertTrue(answer.contains("state=no-retrieval"), "无命中要如实标注：" + answer);
            assertEquals(0, llm.calls, "没有依据就不该调模型（不许编）");
            assertEquals(0, internalToolCalls());
            assertNoInternalTraces(answer);
        } finally {
            EvalIdentity.endEvalRequest();
        }
    }

    @Test
    @DisplayName("公开身份问概念题但公开库检索不可用：如实说 retrieval-failed")
    void publicKnowledgeRetrievalFailureIsHonest() throws Exception {
        MultiAgentCoordinatorImpl c = coordinator();
        kb = new StubPublicKb() {
            @Override
            public List<Map<String, Object>> search(String query) {
                throw new PublicKbService.PublicKbUnavailableException("测试：embedding 不可用",
                        new RuntimeException("x"));
            }
        };
        ReflectionTestUtils.setField(c, "publicKbService", kb);

        EvalIdentity.markPublicRequest();
        try {
            String answer = c.routeAndRun("什么是端口扫描", List.of()).getFinalAnswer();
            assertTrue(answer.contains("state=retrieval-failed"), "检索不可用要如实标注：" + answer);
            assertEquals(0, internalToolCalls(), "公开知识库不可用时，也不许回落到内部知识库");
            assertNoInternalTraces(answer);
        } finally {
            EvalIdentity.endEvalRequest();
        }
    }

    @Test
    @DisplayName("【对照】内部身份问同一条概念题：走的是内部知识库，不是公开出口")
    void internalKnowledgeQuestionUsesInternalDocs() throws Exception {
        MultiAgentCoordinatorImpl c = coordinator();
        llm.available = false;

        EvalIdentity.beginUserRequest();
        try {
            // 刻意选一条不含"日志/告警/扫描/攻击"等取证关键词的概念题：
            // 内部规则路由才会把它判给 ANALYST（走内部知识库工具）
            c.routeAndRun("什么是 SSH 暴力破解？", List.of());
            assertEquals(1, docs.calls, "内部身份走内部知识库工具（证明替身能看见调用）");
            assertEquals(0, kb.calls, "内部身份不该走公开知识库出口");
        } finally {
            EvalIdentity.endEvalRequest();
        }
    }

    // ==================== ③ 工具层二次拒绝（不靠编排层一处把关）====================

    @Test
    @DisplayName("工具层：公开身份直接调用读内部数据的工具，一律被拒并留痕")
    void toolLayerRefusesPublicIdentity() {
        // 用真实工具类（不是记账替身）：这条测试要验的正是工具层自己那道闸门
        InternalDocsTools realDocs = new InternalDocsTools(null, new PromptInjectionGuard());
        QueryLogsTools realLogs = new QueryLogsTools();
        QueryMetricsTools realMetrics = new QueryMetricsTools();

        EvalIdentity.markPublicRequest();
        try {
            String logsOut = realLogs.queryLogs(null, "auth-logs", "Failed password", 10);
            String topicsOut = realLogs.getAvailableLogTopics();
            String metricsOut = realMetrics.queryPrometheusAlerts("1h");
            String docsOut = realDocs.queryInternalDocs("SSH 暴力破解");

            for (String out : List.of(logsOut, topicsOut, metricsOut, docsOut)) {
                assertTrue(out.contains("public-identity-no-internal-data"),
                        "公开身份必须被工具层直接拒绝：" + out);
            }
            assertFalse(logsOut.contains("Failed password"), "拒绝时不得回显任何日志内容");
            assertFalse(topicsOut.contains("auth-logs"), "拒绝时不得暴露内部日志主题面");
            assertFalse(metricsOut.contains("SSHBruteForce"), "拒绝时不得暴露告警名");
        } finally {
            EvalIdentity.endEvalRequest();
        }

        // 对照：身份清掉后，同一批工具不再被这条闸门拦（不是"工具坏了"）
        String after = realLogs.queryLogs(null, "auth-logs", "Failed password", 10);
        assertFalse(after.contains("public-identity-no-internal-data"),
                "清理身份后不该继续被拒：" + after);
    }

    // ==================== 断言工具 ====================

    /**
     * 断言回答里没有任何内部痕迹。
     *
     * <p>清单是"实测泄露过的东西"而不是想象出来的：内部资产名、内部接口路径、
     * 内部标记、日志原文特征、示例内网 IP。
     */
    private static void assertNoInternalTraces(String answer) {
        String[] forbidden = {
                "web-01", "web-02", "web-03",              // 内部资产名（实测泄露过）
                "/api/order/detail", "/upload/files/",      // 内部接口路径（实测泄露过）
                "UNTRUSTED_DATA", "SECURITY_WARNING",       // 内部治理标记
                "F:/", "F:\\", "/opt/secagent",             // 内部路径
                "Failed password", "Accepted password",     // 日志原文特征
                "10.0.0.7", "172.16.0.1",                   // 内网 IP（掩码后应为「内部地址」）
        };
        for (String bad : forbidden) {
            assertFalse(answer.contains(bad),
                    "公开回答出现了内部痕迹「" + bad + "」@index=" + answer.indexOf(bad)
                            + "（length=" + answer.length() + "）：" + answer);
        }
        // "eval-" 不能按字面断言：机读状态 retrieval-failed 里天然含有 "eval-" 这几个字母。
        // 要拦的是【评测/审计标识】本身（EVAL-<runId>，见 EvalIdentity.normalizeRunId），
        // 所以带上词边界 —— 与 PublicOutputGuard 里那条内部标记规则同一形状。
        assertFalse(EVAL_ID.matcher(answer).find(),
                "公开回答出现了审计/评测标识（EVAL-xxx）：" + answer);
    }

    private static final java.util.regex.Pattern EVAL_ID =
            java.util.regex.Pattern.compile("(?i)\\beval-[A-Za-z0-9_\\-]{2,}");
}
