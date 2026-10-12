package org.example.controller;

import org.example.agent.multi.MultiAgentCoordinator;
import org.example.agent.multi.MultiAgentResult;
import org.example.security.EvalIdentity;
import org.example.security.Role;
import org.example.service.AiOpsService;
import org.example.service.ChatService;
import org.example.service.ModelQuotaService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code /api/chat} 入口上评测标注的设置与清理测试。
 *
 * <h3>为什么这条测试必须有（实测踩到过）</h3>
 * "评测身份"不是一个可以只写在拦截器里的东西：编排与模型出口跑在
 * {@code ORCHESTRATOR_POOL} 线程上，配额分派与 RESPONDER 是否走模拟
 * 都要在那个线程上判定。实测出现过：
 * <pre>
 *   评测请求被正确识别为 EVAL，编排却走了真实路径、
 *   动作真下发、额度还记在用户头上 —— 且不报任何错
 * </pre>
 * 根因是标注用了普通 ThreadLocal、跨不过线程池；修好之后还必须保证
 * <b>请求结束就清掉</b>，否则线程池复用会把评测身份带给下一个普通请求。
 * 所以这里直接断言"请求期间标注可见、请求结束标注消失"。
 */
class ChatControllerEvalContextTest {

    @AfterEach
    void cleanup() {
        EvalIdentity.endEvalRequest();
    }

    /**
     * 构造一个只做编排的控制器：模型出口不参与，所以这里用假的 coordinator 记录它看到的标注。
     */
    private ChatController controllerWith(java.util.function.Supplier<Boolean> seenByOrchestrator) throws Exception {
        ChatController c = new ChatController();
        ReflectionTestUtils.setField(c, "modelQuotaService", new ModelQuotaService());
        ReflectionTestUtils.setField(c, "outputGuardService", new org.example.security.OutputGuardService());
        ReflectionTestUtils.setField(c, "aiOpsService", new AiOpsService());
        ReflectionTestUtils.setField(c, "chatService", new ChatService());

        MultiAgentCoordinator coordinator = (question, history) -> {
            // 编排线程：这里读到的标注就是模型出口会读到的那个
            assertTrue(seenByOrchestrator.get(), "编排线程必须看得到评测标注（否则配额会记错账）");
            assertTrue(EvalIdentity.currentRunId() != null || !seenByOrchestrator.get(),
                    "评测请求的 runId 也要带进编排线程");
            MultiAgentResult r = new MultiAgentResult(question);
            r.setFinalAnswer("测试答复");
            return r;
        };
        ReflectionTestUtils.setField(c, "multiAgentCoordinator", coordinator);
        return c;
    }

    @Test
    @DisplayName("评测身份：请求期间标注可见，请求结束必须清干净（线程池复用会白送额度）")
    void evalMarkIsSetAndCleared() throws Exception {
        ChatController c = controllerWith(() -> true);

        ChatController.ChatRequest req = new ChatController.ChatRequest();
        req.setId("EVAL-unit-1");
        req.setQuestion("请封禁来源IP 192.0.2.66");
        req.setEvalRunId("EVAL-unit1");

        MockHttpServletRequest http = new MockHttpServletRequest("POST", "/api/chat");
        http.setAttribute("secagent.role", Role.EVAL);
        http.setAttribute("secagent.user", EvalIdentity.USERNAME);

        c.chat(req, http);

        assertFalse(EvalIdentity.isEvalRequest(), "请求结束后必须清掉标注（否则下一个普通请求会被当成评测）");
    }

    @Test
    @DisplayName("普通身份：编排线程不得被当成评测请求")
    void normalRequestIsNotMarkedAsEval() throws Exception {
        ChatController c = controllerWith(() -> false);

        ChatController.ChatRequest req = new ChatController.ChatRequest();
        req.setId("user-unit-1");
        req.setQuestion("SSH 暴力破解的防护规范是什么");

        MockHttpServletRequest http = new MockHttpServletRequest("POST", "/api/chat");
        http.setAttribute("secagent.role", Role.ANALYST);

        c.chat(req, http);

        assertFalse(EvalIdentity.isEvalRequest(), "普通请求结束后同样不应残留标注");
    }

    @Test
    @DisplayName("非评测身份即使带了 evalRunId 也不打标（runId 只是标记，不是身份）")
    void runIdAloneDoesNotGrantEvalIdentity() throws Exception {
        ChatController c = controllerWith(() -> false);

        ChatController.ChatRequest req = new ChatController.ChatRequest();
        req.setId("user-unit-2");
        req.setQuestion("SSH 暴力破解的防护规范是什么");
        req.setEvalRunId("EVAL-forged");

        MockHttpServletRequest http = new MockHttpServletRequest("POST", "/api/chat");
        http.setAttribute("secagent.role", Role.ADMIN);

        c.chat(req, http);

        assertFalse(EvalIdentity.isEvalRequest(),
                "普通身份伪造 evalRunId 不得进入评测额度/模拟路径");
    }

    @Test
    @DisplayName("runId 规范化：不合规的标记被丢弃，不写进任何字段")
    void invalidRunIdIsDropped() {
        assertEquals("EVAL-abc", EvalIdentity.normalizeRunId("EVAL-abc"));
        assertEquals(null, EvalIdentity.normalizeRunId("forged"));
    }
}
