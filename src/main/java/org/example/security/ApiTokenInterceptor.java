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

    /**
     * 评测身份（可空注入，便于单测；未配置 {@code app.eval.token} 时它自己就是关闭的）。
     */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private EvalIdentity evalIdentity;

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

        // 自用面（/api/user/**）由 SelfTokenInterceptor 独占负责：本拦截器不做任何判定，
        // 也不把它当"匿名可访问"（见 isSelfPath 的注释）。
        if (isSelfPath(path)) {
            return true;
        }

        // 0) 评测身份（app.eval.token）：必须在会话校验【之前】判定。
        //    如果放在之后，"评测 token 恰好等于某个会话 token"这种极端巧合会走成管理员，
        //    而这个身份的设计前提就是"权限比分析员更小"，不能被任何路径提升。
        if (evalIdentity != null && evalIdentity.matches(request)) {
            if (!EvalIdentity.pathAllowed(path)) {
                logger.warn("拒绝评测身份访问受限端点: {} {}（评测身份只允许 {}）",
                        request.getMethod(), path, EvalIdentity.ALLOWED_PATH);
                return writeError(response, HttpStatus.FORBIDDEN,
                        "评测身份只允许调用 " + EvalIdentity.ALLOWED_PATH + "，不能执行处置/审批/策略/数据写入操作");
            }
            request.setAttribute("secagent.user", EvalIdentity.USERNAME);
            request.setAttribute("secagent.role", Role.EVAL);
            return true;
        }

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
        return writeError(response, HttpStatus.UNAUTHORIZED, "未授权访问：缺少或错误的 API Token");
    }

    /**
     * 是否属于<b>自用面</b>（{@code /api/user/**}）。
     *
     * <h3>为什么这里要显式让开，而不是把它写进白名单</h3>
     * 白名单的语义是"<b>无需鉴权</b>即放行"。自用面恰恰相反——它需要鉴权，
     * 只是用另一套凭据（{@code X-User-Token}）。把它列进白名单会让
     * "这个路径为什么不需要鉴权"与"它其实由另一个拦截器鉴权"两件事混淆，
     * 而后者一旦顺序被改动（{@code WebMvcConfig}）就没有第二道锁。
     *
     * <p>这里的让开是<b>协作声明</b>：{@code /api/user/**} 由
     * {@link org.example.selfapi.SelfTokenInterceptor} 独占负责。两个拦截器都保留
     * "只认自己的面"的结构，任一被单独改动都不会让自用面变成匿名可访问。
     */
    private static boolean isSelfPath(String path) {
        return path != null && (path.equals("/api/user") || path.startsWith("/api/user/"));
    }

    /** 统一的失败响应（401 未授权 / 403 越权共用同一形状，避免两套错误体） */
    private boolean writeError(HttpServletResponse response, HttpStatus status, String message) throws Exception {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        Map<String, Object> body = new HashMap<>();
        body.put("code", status.value());
        body.put("message", message);
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
