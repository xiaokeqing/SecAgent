package org.example.selfapi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * `GET /api/user/status` 的<b>响应字段契约</b>测试。
 *
 * <h3>为什么这条要单独钉</h3>
 * 这个端点是前端唯一的"令牌是否有效"判据，它的<b>字段名就是前端契约</b>：
 * 少一个字段、或改一个名字，前端不会编译失败、也不会在服务端报错 ——
 * 只会让页面显示成"未登录"或空白。而站主的自检脚本（以及站主口径里点名的
 * `loggedIn:true`）也依赖这两个键。
 *
 * <p>所以这里把"成功响应必须含哪些键"变成断言：改动键名会立刻构建失败，
 * 而不是等到有人照着旧契约写完前端才发现。
 *
 * <p>失败响应的形状由 {@link SelfApiControllerGuardTest} 覆盖（那里判 401/429 与 `Retry-After`）。
 */
class SelfApiStatusContractTest {

    private final SelfApiController controller = new SelfApiController();

    /** 拦截器通过标记 + 已装配的最小依赖，构造一个"成功路径"的请求 */
    private Map<String, Object> statusData() {
        UserConversationStore store = new UserConversationStore();
        ReflectionTestUtils.setField(store, "maxRounds", 5);
        ReflectionTestUtils.setField(store, "ttlMinutes", 30);
        ReflectionTestUtils.setField(store, "maxConversations", 200);

        SelfPoolPolicy policy = new SelfPoolPolicy();
        ReflectionTestUtils.setField(policy, "maxBodyChars", 4000);
        ReflectionTestUtils.setField(policy, "deadlineMs", 60000L);
        ReflectionTestUtils.setField(policy, "maxTokens", 4000);
        // quotaService 刻意留空：配额未接入时快照必须如实给 available=false，
        // 而不是假装有额度（这一条也在断言里）
        ReflectionTestUtils.setField(controller, "policy", policy);
        ReflectionTestUtils.setField(controller, "conversationStore", store);

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/user/status");
        req.setAttribute(SelfTokenInterceptor.ATTR_SELF_OK, Boolean.TRUE);
        MockHttpServletResponse res = new MockHttpServletResponse();

        ResponseEntity<Map<String, Object>> entity = controller.status(req, res);
        assertNotNull(entity);
        assertEquals(200, entity.getStatusCode().value(), "拦截器已标记通过时应当 200");
        @SuppressWarnings("unchecked")
        Map<String, Object> body = entity.getBody();
        assertNotNull(body);
        assertEquals(200, body.get("code"));
        assertTrue(String.valueOf(res.getHeader("Cache-Control")).contains("no-store"),
                "登录态响应不得被缓存（否则退出登录后页面仍是已登录）");

        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) body.get("data");
        assertNotNull(data, "成功响应必须带 data");
        return data;
    }

    @Test
    @DisplayName("【契约】成功响应必须含 loggedIn / authenticated / pool / 额度 / 窗口口径 / limits")
    void successPayloadHasContractFields() {
        Map<String, Object> data = statusData();

        assertEquals(Boolean.TRUE, data.get("loggedIn"),
                "站主自检口径点名的字段：200 且 loggedIn:true");
        assertEquals(Boolean.TRUE, data.get("authenticated"), "自述字段（服务端无会话，指令牌校验通过）");
        assertEquals("self", data.get("pool"), "前端据此显示「自用池」而不是「公开演示」");
        assertNotNull(data.get("generatedAt"));

        @SuppressWarnings("unchecked")
        Map<String, Object> quota = (Map<String, Object>) data.get("quota");
        assertNotNull(quota, "必须回显自用池额度状态");
        assertEquals("self", quota.get("pool"));
        assertEquals(Boolean.TRUE, quota.get("softLimit"), "软上限语义必须显式标注");
        assertEquals(Boolean.FALSE, quota.get("available"), "配额服务未接入时如实说未接入，不假装有额度");

        @SuppressWarnings("unchecked")
        Map<String, Object> conversation = (Map<String, Object>) data.get("conversation");
        assertNotNull(conversation, "必须回显窗口口径（3~5 轮 / 30 分钟）");
        assertEquals(5, conversation.get("maxRounds"));
        assertEquals(30, conversation.get("ttlMinutes"));

        @SuppressWarnings("unchecked")
        Map<String, Object> limits = (Map<String, Object>) data.get("limits");
        assertNotNull(limits, "必须回显入口口径，便于站主核对生效值");
        assertEquals(4000, limits.get("maxBodyChars"));
        assertEquals(60000L, limits.get("deadlineMs"));
        assertEquals(4000, limits.get("maxTokens"));
    }

    @Test
    @DisplayName("响应里不得出现疑似令牌值或哈希字段（只登记'是否通过'，不登记凭据本身）")
    void successPayloadNeverLeaksToken() {
        Map<String, Object> data = statusData();
        String flat = data.toString();
        // 注意：不能一刀切地禁 "token" 这个词 —— 文案里会出现"令牌"这类说明是正常的；
        // 要防的是【值/字段】：令牌哈希、令牌本身、以及任何 64 位十六进制串。
        assertTrue(!flat.toLowerCase().contains("sha256"), "响应里不该出现哈希字段：" + flat);
        assertTrue(!flat.contains("APP_USER_TOKEN"), "响应里不该出现配置键名：" + flat);
        assertTrue(!flat.matches("(?s).*\\b[0-9a-fA-F]{64}\\b.*"), "响应里不该出现 64 位十六进制串：" + flat);
    }
}
