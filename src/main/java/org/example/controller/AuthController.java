package org.example.controller;

import lombok.Getter;
import lombok.Setter;
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
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody(required = false) LoginRequest req) {
        Map<String, Object> body = new HashMap<>();
        String token = authService.login(req == null ? null : req.getUsername(), req == null ? null : req.getPassword());
        if (token == null) {
            body.put("code", 401);
            body.put("message", "账号或密码错误");
            return ResponseEntity.status(401).body(body);
        }
        Map<String, Object> data = new HashMap<>();
        data.put("token", token);
        data.put("expiresIn", authService.getTtlSeconds());
        data.put("username", authService.getUsername(token));
        data.put("role", authService.getRole(token).name());
        data.put("roleLabel", authService.getRole(token).getLabel());
        body.put("code", 200);
        body.put("message", "success");
        body.put("data", data);
        return ResponseEntity.ok(body);
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
}
