package org.example.selfapi;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * 自用面鉴权拦截器：把 {@code /api/user/**} 交给 {@link UserTokenService}。
 *
 * <h3>为什么是独立拦截器，而不是塞进 {@code ApiTokenInterceptor}</h3>
 * {@code ApiTokenInterceptor} 管的是"登录会话 / 系统级 API Token / 评测身份 / 公开白名单"，
 * 它已经是<b>四条判定的合集</b>；把自用面再加进去，会让"某个被放行的路径到底是被哪条规则放行的"
 * 变得需要通读整个类才能回答。安全边界的可验证性依赖于"一条面一个入口"。
 *
 * <p>顺序上它必须排在 {@code ApiTokenInterceptor} <b>之后</b>（见 {@code WebMvcConfig}）：
 * 先让既有规则判定（评测身份 / 系统 Token / 公开白名单），本类只处理"前一条没放行、
 * 但路径属于自用面"的情形。这样自用面<b>不会</b>顺手把既有路径放开。
 *
 * <h3>失败时为什么不只写响应，还要写请求属性</h3>
 * 响应体由本类直接写（这样未通过鉴权的请求<b>根本不会进入控制器</b>，控制器代码里少一层分支）。
 * 同时把原因写进请求属性，是为了让控制器在"拦截器配置被改动"的情况下仍能兜底拒绝
 * （防御纵深，见 {@code SelfApiController.authFailure}）。
 */
@Component
public class SelfTokenInterceptor implements HandlerInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(SelfTokenInterceptor.class);

    /** 自用面路径前缀（带边界，兼容带 context-path 的部署） */
    private static final Pattern SELF_PATH = Pattern.compile("^(?:/[^/]+)?/api/user(?:/.*)?$");

    /** 请求头名（站主口径，前端契约逐字依赖） */
    public static final String TOKEN_HEADER = "X-User-Token";

    /**
     * 鉴权<b>通过</b>标记的请求属性名。
     *
     * <p>控制器以"有没有这个标记"作为放行判据（而不是"有没有失败标记"）——
     * 这样即使将来 {@code /api/user/**} 被从本拦截器的路径里删掉，
     * 控制器也会 fail-closed 拒绝，而不会让自用面变成匿名可访问。
     */
    public static final String ATTR_SELF_OK = "secagent.self.authenticated";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private UserTokenService userTokenService;

    /** 自用面总开关（默认 true：真正的开关是"有没有配令牌哈希"，空哈希时登录面自然关闭） */
    @Value("${app.user.enabled:true}")
    private boolean enabled;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        if (!enabled) {
            return reject(request, response, 401, "USER_LOGIN_DISABLED", "自用入口未启用", 0);
        }
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return true;   // 预检不鉴权（与既有拦截器同一处理）
        }
        String path = request.getRequestURI();
        if (!isSelfPath(path)) {
            return true;   // 不是自用面：交给其它拦截器 / 既有规则，本类不参与
        }

        String ip = SelfClientIp.resolve(request);
        UserTokenService.Result result = userTokenService.check(ip, request.getHeader(TOKEN_HEADER));
        if (!result.ok()) {
            logger.warn("自用面拒绝访问: {} {} reason={}（来源 {}，不记录令牌内容）",
                    request.getMethod(), path, result.reason(), UserTokenService.maskIp(ip));
            return reject(request, response, result.httpStatus(), result.reason(), result.message(),
                    result.retryAfter());
        }

        // 命中：写入身份属性（供控制器/审计读取）并打标当前线程。
        // SelfIdentity 的清理由控制器在 finally 里负责 —— 因为编排/模型调用发生在控制器调用栈内。
        request.setAttribute("secagent.user", SelfIdentity.USERNAME);
        request.setAttribute("secagent.role", "SELF");
        request.setAttribute(ATTR_SELF_OK, Boolean.TRUE);
        SelfIdentity.markSelfRequest();
        return true;
    }

    /** 带边界的自用面路径判定（不做裸 startsWith，避免 /api/user-admin 被静默放行） */
    static boolean isSelfPath(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        return SELF_PATH.matcher(path).matches();
    }

    /**
     * 写失败响应（不发请求属性给"拒绝"路径以外的语义 —— 控制器在成功路径上不会看到这些属性）。
     */
    private boolean reject(HttpServletRequest request, HttpServletResponse response, int status,
                           String reason, String message, int retryAfter) throws Exception {
        // 供控制器兜底（若将来拦截器路径配置被改动，控制器仍会按同一原因拒绝）
        request.setAttribute(SelfApiController.ATTR_FAIL_STATUS, status);
        request.setAttribute(SelfApiController.ATTR_FAIL_REASON, reason);
        request.setAttribute(SelfApiController.ATTR_FAIL_MESSAGE, message);
        request.setAttribute(SelfApiController.ATTR_FAIL_RETRY_AFTER, retryAfter);

        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        if (retryAfter > 0) {
            response.setHeader(HttpHeaders.RETRY_AFTER, String.valueOf(retryAfter));
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", status);
        body.put("message", message);
        body.put("reason", reason);
        objectMapper.writeValue(response.getWriter(), body);
        return false;
    }

    /** 供诊断：把 401/429 的标准状态码收敛到一个地方（避免各处写魔数） */
    static HttpStatus statusOf(int code) {
        return HttpStatus.resolve(code) == null ? HttpStatus.UNAUTHORIZED : HttpStatus.valueOf(code);
    }
}
