package org.example.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.HashMap;
import java.util.Map;

/**
 * 轻量 API Token 鉴权拦截器。
 *
 * <p>原始系统所有 /api/** 接口完全无鉴权，任意人可调用对话、上传文件并消耗模型额度。
 * 这里通过可配置开关 {@code app.auth.enabled} 增加统一的 Token 校验：
 * 默认关闭以方便本地演示；开启后所有 /api/** 请求需携带
 * {@code X-API-Token} 头（或 token 参数），否则返回 401。
 */
@Component
public class ApiTokenInterceptor implements HandlerInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(ApiTokenInterceptor.class);
    private static final String TOKEN_HEADER = "X-API-Token";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${app.auth.enabled:false}")
    private boolean enabled;

    @Value("${app.auth.token:secagent-demo-token}")
    private String expectedToken;

    /** 开启鉴权后也放行的路径（如健康检查） */
    @Value("${app.auth.white-list:/api/health}")
    private String whiteList;

    /** 登录接口本身不做 Token 校验，否则无法登录 */
    private static final String LOGIN_PATH = "/api/auth/login";

    @org.springframework.beans.factory.annotation.Autowired
    private AuthService authService;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {

        // 未开启鉴权：直接放行
        if (!enabled) {
            return true;
        }

        // 放行 CORS 预检请求
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return true;
        }

        String path = request.getRequestURI();

        // 登录接口直接放行，否则无法获取 Token
        if (LOGIN_PATH.equals(path)) {
            return true;
        }
        if (isWhiteListed(path)) {
            return true;
        }

        // 1) 优先校验登录会话 Token（Authorization: Bearer <token>）
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")
                && authService.validate(authHeader.substring(7))) {
            String loginToken = authHeader.substring(7);
            // 写入当前请求的用户与角色，供 RBAC 拦截器、控制器使用
            request.setAttribute("secagent.user", authService.getUsername(loginToken));
            request.setAttribute("secagent.role", authService.getRole(loginToken));
            return true;
        }

        // 2) 再校验系统级 API Token（X-API-Token 头或 token 参数）
        String token = request.getHeader(TOKEN_HEADER);
        if (token == null || token.isEmpty()) {
            token = request.getParameter("token");
        }

        // 常量时间比较，降低时序侧信道风险
        if (token != null && constantTimeEquals(token, expectedToken)) {
            // 系统级 Token 视为管理员（服务到服务调用）
            request.setAttribute("secagent.user", "api-token");
            request.setAttribute("secagent.role", Role.ADMIN);
            return true;
        }

        logger.warn("拒绝未授权访问: {} {}", request.getMethod(), path);
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        Map<String, Object> body = new HashMap<>();
        body.put("code", 401);
        body.put("message", "未授权访问：缺少或错误的 API Token");
        objectMapper.writeValue(response.getWriter(), body);
        return false;
    }

    /**
     * 免鉴权路径判定 —— <b>精确匹配，不是前缀匹配</b>。
     *
     * <h3>为什么从 startsWith 改成 equals</h3>
     * 原实现是 {@code path.startsWith(p)}。当时没出事，是因为恰好没有
     * 别的端点以这两个白名单前缀开头 —— 也就是说，它靠"碰巧"安全。
     * <p>
     * 前缀匹配的隐患很具体：白名单里有 {@code /api/health}，
     * 那么以后谁新增一个 {@code /api/health-details}（比如返回更详细的
     * 运行时信息），它会被<b>静默放行</b> —— 而写这个端点的人根本不会想到
     * 自己去查白名单前缀。
     * <p>
     * 更要紧的是这个失败模式：<b>它不会报错、不会告警，只是让一个本该
     * 鉴权的接口变成公开的。</b>安全相关的默认行为必须是"不匹配就不放行"，
     * 而不是"看起来像就放行"。
     * <p>
     * 顺带说明为什么不做成"前缀 + 精确都支持"的宽松版：白名单是安全边界，
     * 边界越简单越容易验证。两个端点就写两个完整路径，没有歧义。
     *
     * @param path 请求 URI（{@code request.getRequestURI()}）
     * @return true 表示该路径无需鉴权
     */
    private boolean isWhiteListed(String path) {
        if (whiteList == null || whiteList.isEmpty()) {
            return false;
        }
        for (String p : whiteList.split(",")) {
            String entry = p.trim();
            if (entry.isEmpty()) {
                continue;
            }
            if (entry.endsWith("/**")) {
                // 显式通配：白名单写 "/api/public/**" 才放行 /api/public 下的所有路径。
                // 关键点是【必须带边界】—— 用 "/api/public" 做前缀，
                // 不能写成裸 startsWith(entry)，否则将来出现
                // /api/public-admin/xxx 这类路径会被静默放行。
                String prefix = entry.substring(0, entry.length() - 3);
                if (path.equals(prefix) || path.startsWith(prefix + "/")) {
                    return true;
                }
                continue;
            }
            // 其余一律【精确匹配】：不做前缀推断，边界越简单越可验证
            if (entry.equals(path)) {
                return true;
            }
        }
        return false;
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }
}
