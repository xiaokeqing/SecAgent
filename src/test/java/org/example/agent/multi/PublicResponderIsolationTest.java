package org.example.agent.multi;

import org.example.security.EvalIdentity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 公开路径「绝不触发真实处置」的测试（P4 最硬的一条红线）。
 *
 * <h3>为什么必须在编排层单独测一次</h3>
 * {@code POST /api/public/ask} 是<b>匿名</b>可达的。编排层的 RESPONDER 会调
 * {@code SecurityActionTools}，而它内部会真的封 IP / 锁账号 / 杀进程。
 * 也就是说：只要公开路径能走到 RESPONDER 的真实分支，任何访客说一句
 * "请封禁 1.2.3.4"就能让这台机器对外下发处置动作。
 *
 * <p>这条不能只靠"公开包本地源码里没有写能力"来证明（那只覆盖了反编译不出来的间接引用），
 * 所以这里直接把一个<b>会记账的替身工具</b>注入编排器：公开身份下它必须是
 * <b>零调用</b>，而普通身份下必须被调到 —— 后者是为了证明"这条测试真的能看见调用"，
 * 否则一个写坏的替身会让测试永远绿。
 */
class PublicResponderIsolationTest {

    /** 会记账的处置工具替身：任何一次真实下发路径都会在这里留下痕迹 */
    private static class RecordingActionTools extends org.example.agent.multi.SecurityActionTools {
        int calls = 0;

        @Override
        public String blockIp(String ip, Integer durationMinutes, String reason) {
            calls++;
            return "【封禁IP】结果：成功（替身）";
        }

        @Override
        public String lockAccount(String account, String host, String reason) {
            calls++;
            return "【锁定账号】结果：成功（替身）";
        }

        @Override
        public String killProcess(String pid, String processName, String host, String reason) {
            calls++;
            return "【结束进程】结果：成功（替身）";
        }
    }

    private MultiAgentCoordinatorImpl coordinatorWith(RecordingActionTools tools) {
        MultiAgentCoordinatorImpl c = new MultiAgentCoordinatorImpl();
        // 离线模式：走规则路由（不依赖任何模型 Key），这样测试只考察"分叉是否生效"
        ReflectionTestUtils.setField(c, "dashScopeApiKey", "sk-placeholder");
        ReflectionTestUtils.setField(c, "llmEnabledConfig", "auto");
        ReflectionTestUtils.setField(c, "securityActionTools", tools);
        return c;
    }

    @AfterEach
    void cleanup() {
        EvalIdentity.endEvalRequest();
    }

    @Test
    @DisplayName("【红线】公开身份下的处置请求：只解释，工具零调用")
    void publicRequestNeverTouchesActionTools() throws Exception {
        RecordingActionTools tools = new RecordingActionTools();
        MultiAgentCoordinatorImpl coordinator = coordinatorWith(tools);

        EvalIdentity.markPublicRequest();
        try {
            MultiAgentResult result = coordinator.routeAndRun("请封禁来源 IP 203.0.113.66，封 60 分钟", List.of());

            assertEquals(0, tools.calls, "匿名公开请求绝不能调用任何处置工具（实测这里会真下发）");
            String answer = result.getFinalAnswer();
            assertNotNull(answer);
            assertTrue(answer.contains("公开演示"), "回答应说明这是公开演示：" + answer);
            assertTrue(answer.contains("不执行") || answer.contains("不会执行"),
                    "回答应明确说明不执行处置：" + answer);
            assertTrue(answer.contains("state=rule-based"), "应带机读 state：" + answer);
            assertFalse(answer.contains("结果：成功"), "不得出现任何「看起来已下发」的执行结果：" + answer);
        } finally {
            EvalIdentity.endEvalRequest();
        }
    }

    @Test
    @DisplayName("对照：非公开身份下同一条请求会走到工具（证明替身真的能看见调用）")
    void internalRequestStillReachesActionTools() throws Exception {
        RecordingActionTools tools = new RecordingActionTools();
        MultiAgentCoordinatorImpl coordinator = coordinatorWith(tools);

        EvalIdentity.beginUserRequest();
        try {
            coordinator.routeAndRun("请封禁来源 IP 203.0.113.66，封 60 分钟", List.of());
            assertEquals(1, tools.calls,
                    "内部身份的处置请求必须走到工具（否则本测试的替身是坏的，公开那条断言就没有意义）");
        } finally {
            EvalIdentity.endEvalRequest();
        }
    }

    @Test
    @DisplayName("公开身份优先级高于评测身份（两个标注同时存在时也不会真下发）")
    void publicMarkerWinsOverEvalMarker() throws Exception {
        RecordingActionTools tools = new RecordingActionTools();
        MultiAgentCoordinatorImpl coordinator = coordinatorWith(tools);

        // 先标评测、再标公开：markPublicRequest 会把评测标注清掉（两个身份互斥）
        EvalIdentity.beginEvalRequest("EVAL-x");
        EvalIdentity.markPublicRequest();
        try {
            assertTrue(EvalIdentity.isPublicRequest());
            assertFalse(EvalIdentity.isEvalRequest(), "公开与评测互斥：不得同时成立");

            coordinator.routeAndRun("请封禁来源 IP 203.0.113.66", List.of());
            assertEquals(0, tools.calls, "身份重叠时也必须保证零下发");
        } finally {
            EvalIdentity.endEvalRequest();
        }
    }

    @Test
    @DisplayName("公开身份的回答不暴露内部动作形状（没有「封禁IP/模式/审计ID」这类执行细节）")
    void publicAnswerDoesNotLeakInternalActionShape() throws Exception {
        RecordingActionTools tools = new RecordingActionTools();
        MultiAgentCoordinatorImpl coordinator = coordinatorWith(tools);

        EvalIdentity.markPublicRequest();
        try {
            MultiAgentResult result = coordinator.routeAndRun("锁定账号 guest，主机 web-01", List.of());
            String answer = result.getFinalAnswer();

            assertEquals(0, tools.calls);
            assertFalse(answer.contains("审计 ID") || answer.contains("审计ID"),
                    "公开回答不得暴露内部审计 ID 形状：" + answer);
            assertFalse(answer.contains("模式：BLOCKED") || answer.contains("模式：SIMULATED"),
                    "公开回答不得回显内部动作模式：" + answer);
        } finally {
            EvalIdentity.endEvalRequest();
        }
    }

    @Test
    @DisplayName("公开身份标注：设置即可见、清理后归零（配额分派就靠这条判定）")
    void markerIsVisibleAndCleared() {
        EvalIdentity.markPublicRequest();
        try {
            assertTrue(EvalIdentity.isPublicRequest());
        } finally {
            EvalIdentity.endEvalRequest();
        }
        assertFalse(EvalIdentity.isPublicRequest(), "清理后必须归零（否则下一个请求会记错账）");
        assertFalse(EvalIdentity.isEvalRequest());
    }
}
