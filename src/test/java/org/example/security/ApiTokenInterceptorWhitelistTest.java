package org.example.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 免鉴权白名单的判定测试。
 *
 * <p>对应一次真实的修正：{@code isWhiteListed} 原来用 {@code path.startsWith(entry)}
 * 做前缀匹配，后来改成精确匹配 {@code entry.equals(path)}。
 *
 * <p>为什么这个改动值得写测试：
 * 前缀匹配在当时<b>没有造成任何问题</b> —— 因为恰好没有别的端点以白名单前缀开头。
 * 也就是说它靠"碰巧"安全。而它的失败模式特别隐蔽：
 * 以后谁新增一个 {@code /api/health-details}，会被<b>静默放行</b>，
 * 不报错、不告警，只是那个接口悄悄变成公开的。
 * <p>
 * 所以这组测试防的不是"现在有没有 bug"，而是"以后别人加端点时会不会踩坑"。
 */
class ApiTokenInterceptorWhitelistTest {

    private ApiTokenInterceptor interceptor;

    @BeforeEach
    void setUp() {
        interceptor = new ApiTokenInterceptor();
        ReflectionTestUtils.setField(interceptor, "enabled", true);
        ReflectionTestUtils.setField(interceptor, "whiteList", "/api/health,/api/playground/check");
        // 非白名单路径会走到 token 校验，这里给个不会匹配上的值
        ReflectionTestUtils.setField(interceptor, "expectedToken", "unused-system-token");
    }

    private boolean preHandle(String method, String uri) throws Exception {
        HttpServletRequest req = new MockHttpServletRequest(method, uri);
        HttpServletResponse res = new MockHttpServletResponse();
        return interceptor.preHandle(req, res, new Object());
    }

    @Test
    @DisplayName("白名单里的精确路径放行")
    void exactWhitelistedPathsPass() throws Exception {
        assertTrue(preHandle("GET", "/api/health"), "/api/health 应放行");
        assertTrue(preHandle("POST", "/api/playground/check"), "/api/playground/check 应放行");
    }

    @Test
    @DisplayName("【核心】以白名单前缀开头的其他路径不再被放行")
    void prefixedPathsAreNotWhitelisted() throws Exception {
        // 这几条是前缀匹配会误放行的典型形态。
        // 它们现在没有对应的端点（所以返回 404），但一旦有人加上，
        // 前缀匹配会让它变成公开接口 —— 这条测试就是防这个。
        assertFalse(preHandle("GET", "/api/health-details"),
                "/api/health-details 不该因为以 /api/health 开头而被放行");
        assertFalse(preHandle("GET", "/api/health/verbose"),
                "/api/health/verbose 不该被放行");
        assertFalse(preHandle("POST", "/api/playground/checkAnything"),
                "/api/playground/checkAnything 不该被放行");
        assertFalse(preHandle("GET", "/api/playground/check/../response/block"),
                "路径穿越形态不该被放行");
    }

    @Test
    @DisplayName("受保护的业务接口一律需要鉴权")
    void protectedEndpointsRequireAuth() throws Exception {
        assertFalse(preHandle("GET", "/api/alerts/list"), "/api/alerts/list 需要鉴权");
        assertFalse(preHandle("POST", "/api/response/block"), "/api/response/block 需要鉴权");
        assertFalse(preHandle("GET", "/api/kb/pending"), "/api/kb/pending 需要鉴权");
        assertFalse(preHandle("GET", "/api/response/audit"), "/api/response/audit 需要鉴权");
    }

    @Test
    @DisplayName("登录接口特殊放行（否则拿不到 Token）")
    void loginPathAlwaysPasses() throws Exception {
        assertTrue(preHandle("POST", "/api/auth/login"), "登录接口必须放行");
    }

    @Test
    @DisplayName("CORS 预检请求放行（否则浏览器跨域全部失败）")
    void optionsRequestsPass() throws Exception {
        assertTrue(preHandle("OPTIONS", "/api/alerts/list"), "OPTIONS 预检应放行");
    }

    @Test
    @DisplayName("空白名单配置不炸，且不放行任何东西")
    void emptyWhitelistIsSafe() throws Exception {
        ReflectionTestUtils.setField(interceptor, "whiteList", "");
        assertFalse(preHandle("GET", "/api/health"), "白名单为空时不该放行");
        ReflectionTestUtils.setField(interceptor, "whiteList", ",  ,");
        assertFalse(preHandle("GET", "/api/health"), "只有逗号和空格时不该放行");
    }

    @Test
    @DisplayName("鉴权总开关关闭时全部放行（本地开发用）")
    void disabledAuthPassesEverything() throws Exception {
        ReflectionTestUtils.setField(interceptor, "enabled", false);
        assertTrue(preHandle("GET", "/api/response/audit"), "关闭鉴权时应全部放行");
    }
}
