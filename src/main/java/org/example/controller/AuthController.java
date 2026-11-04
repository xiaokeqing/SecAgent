package org.example.controller;

import lombok.Getter;
import lombok.Setter;
import org.example.security.AuthCodeService;
import org.example.security.AuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * 登录 / 登出 / 会话校验接口。
 *
 * <h3>两条登录链路，一套会话</h3>
 * <ul>
 *   <li>{@code POST /api/auth/login} —— 账号 + 口令（原有逻辑，未改动）；</li>
 *   <li>{@code POST /api/auth/code} + {@code POST /api/auth/code-login} —— 邮箱验证码，
 *       <b>只服务站主本人</b>（白名单 {@code app.auth.owner-email}，没有注册）。</li>
 * </ul>
 * 两条链路最终都由 {@link AuthService} 签发会话，响应体也由同一个
 * {@link #sessionBody(String)} 拼出来 —— 前端不必为验证码登录写第二套解析。
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private AuthService authService;

    @Autowired
    private AuthCodeService authCodeService;

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody(required = false) LoginRequest req) {
        String token = authService.login(req == null ? null : req.getUsername(), req == null ? null : req.getPassword());
        if (token == null) {
            Map<String, Object> body = new HashMap<>();
            body.put("code", 401);
            body.put("message", "账号或密码错误");
            return ResponseEntity.status(401).body(body);
        }
        return ResponseEntity.ok(sessionBody(token));
    }

    /**
     * 申请登录验证码（匿名可访问）。
     *
     * <p><b>永远 HTTP 200</b>，用 body 里的 {@code ok} 表达结果：
     * <ul>
     *   <li>成功：{@code {"ok":true,"expiresInSeconds":300}}</li>
     *   <li>邮箱不在白名单 / 白名单为空 / SMTP 没配好或发信失败：{@code {"ok":false,"reason":"unavailable"}}</li>
     *   <li>发得太频繁：{@code {"ok":false,"reason":"rate_limited","retryAfterSeconds":N}}</li>
     * </ul>
     * 前三种失败对外不可区分 —— 否则这个端点就成了"哪些邮箱是站主的"查询接口。
     * 状态码也不能拿来区分：401/403/404/500 每一种都在泄露不同的信息。
     */
    @PostMapping("/code")
    public ResponseEntity<Map<String, Object>> requestCode(@RequestBody(required = false) CodeRequest req) {
        AuthCodeService.SendResult result = authCodeService.requestCode(req == null ? null : req.getEmail());
        Map<String, Object> body = new HashMap<>();
        body.put("ok", result.ok());
        if (result.ok()) {
            body.put("expiresInSeconds", result.expiresInSeconds());
        } else {
            body.put("reason", result.reason());
            if ("rate_limited".equals(result.reason())) {
                body.put("retryAfterSeconds", result.retryAfterSeconds());
            }
        }
        return ResponseEntity.ok(body);
    }

    /**
     * 邮箱验证码登录（匿名可访问）。
     *
     * <p>成功响应与 {@code POST /api/auth/login} <b>逐字段一致</b>
     * （{@code code/message/data{token,expiresIn,username,role,roleLabel}}），
     * 失败统一 {@code {"ok":false,"reason":"invalid"}} —— 不区分"过期""错码""已用过"，
     * 区分它们只会告诉试探者"这个码曾经存在"。
     */
    @PostMapping("/code-login")
    public ResponseEntity<Map<String, Object>> codeLogin(@RequestBody(required = false) CodeLoginRequest req) {
        String email = req == null ? null : req.getEmail();
        String code = req == null ? null : req.getCode();
        // 顺序很重要：只有 verify 返回 true（码已消费）才去签发会话，签发逻辑不对外可达
        String token = authCodeService.verify(email, code) ? authService.issueSessionForOwner() : null;
        if (token == null) {
            Map<String, Object> body = new HashMap<>();
            body.put("ok", false);
            body.put("reason", "invalid");
            return ResponseEntity.ok(body);
        }
        return ResponseEntity.ok(sessionBody(token));
    }

    /**
     * 登录成功的响应体 —— 密码登录与验证码登录共用这一份，字段只在这里定义一次。
     *
     * <p>为什么抽出来：前端按 {@code data.token} 解析。两份拼装代码一旦分叉
     * （多一个字段、少一个 roleLabel），验证码登录就会在浏览器里表现成"登录成功但页面白屏"。
     */
    private Map<String, Object> sessionBody(String token) {
        Map<String, Object> data = new HashMap<>();
        data.put("token", token);
        data.put("expiresIn", authService.getTtlSeconds());
        data.put("username", authService.getUsername(token));
        data.put("role", authService.getRole(token).name());
        data.put("roleLabel", authService.getRole(token).getLabel());
        Map<String, Object> body = new HashMap<>();
        body.put("code", 200);
        body.put("message", "success");
        body.put("data", data);
        return body;
    }

    /** 用户列表（仅管理员，权限由 RBAC 拦截器控制） */
    @GetMapping("/users")
    public ResponseEntity<Map<String, Object>> users() {
        Map<String, Object> body = new HashMap<>();
        body.put("code", 200);
        body.put("message", "success");
        body.put("data", authService.listUsers());
        return ResponseEntity.ok(body);
    }

    /** 新增用户（仅管理员） */
    @PostMapping("/users")
    public ResponseEntity<Map<String, Object>> createUser(@RequestBody CreateUserRequest req) {
        Map<String, Object> body = new HashMap<>();
        try {
            org.example.security.Role role = org.example.security.Role.parse(req == null ? null : req.getRole());
            authService.addUser(req == null ? null : req.getUsername(),
                    req == null ? null : req.getPassword(), role);
            body.put("code", 200);
            body.put("message", "用户创建成功");
            return ResponseEntity.ok(body);
        } catch (IllegalArgumentException e) {
            body.put("code", 400);
            body.put("message", e.getMessage());
            return ResponseEntity.badRequest().body(body);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(@RequestHeader(value = "Authorization", required = false) String auth) {
        authService.logout(bearer(auth));
        Map<String, Object> body = new HashMap<>();
        body.put("code", 200);
        body.put("message", "success");
        return ResponseEntity.ok(body);
    }

    @GetMapping("/check")
    public ResponseEntity<Map<String, Object>> check(@RequestHeader(value = "Authorization", required = false) String auth) {
        String token = bearer(auth);
        boolean ok = authService.validate(token);
        Map<String, Object> body = new HashMap<>();
        body.put("code", ok ? 200 : 401);
        body.put("message", ok ? "success" : "会话已失效");
        if (ok) {
            Map<String, Object> data = new HashMap<>();
            data.put("username", authService.getUsername(token));
            data.put("role", authService.getRole(token).name());
            data.put("roleLabel", authService.getRole(token).getLabel());
            body.put("data", data);
        }
        return ResponseEntity.status(ok ? 200 : 401).body(body);
    }

    private static String bearer(String auth) {
        if (auth != null && auth.startsWith("Bearer ")) {
            return auth.substring(7);
        }
        return auth;
    }

    @Setter
    @Getter
    public static class LoginRequest {
        private String username;
        private String password;
    }

    @Setter
    @Getter
    public static class CreateUserRequest {
        private String username;
        private String password;
        private String role;
    }

    /** 申请验证码的请求体：只要一个邮箱 */
    @Setter
    @Getter
    public static class CodeRequest {
        private String email;
    }

    /** 验证码登录的请求体 */
    @Setter
    @Getter
    public static class CodeLoginRequest {
        private String email;
        private String code;
    }
}
