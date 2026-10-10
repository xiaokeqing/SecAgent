package org.example.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 固定窗口限流（按客户端 IP），缓解高频调用与暴力请求。
 * 登录接口使用更严格的独立窗口，防止登录爆破。
 */
@Component
public class RateLimitInterceptor implements HandlerInterceptor {

    private static final long WINDOW_MS = 60_000L;

    @Value("${app.ratelimit.enabled:true}")
    private boolean enabled;

    @Value("${app.ratelimit.requests-per-minute:60}")
    private int limit;

    @Value("${app.ratelimit.login-per-minute:10}")
    private int loginLimit;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Map<String, Window> windows = new ConcurrentHashMap<>();
    private final Map<String, Window> loginWindows = new ConcurrentHashMap<>();

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (!enabled || "OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return true;
        }
        String ip = clientIp(request);
        boolean isLogin = request.getRequestURI().endsWith("/api/auth/login");
        int max = isLogin ? loginLimit : limit;
        Map<String, Window> store = isLogin ? loginWindows : windows;

        long now = System.currentTimeMillis();
        Window w = store.compute(ip, (k, v) -> (v == null || now - v.start >= WINDOW_MS) ? new Window(now) : v);
        synchronized (w) {
            if (w.count >= max) {
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setCharacterEncoding("UTF-8");
                Map<String, Object> body = new HashMap<>();
                body.put("code", 429);
                body.put("message", "请求过于频繁，请稍后再试");
                objectMapper.writeValue(response.getWriter(), body);
                return false;
            }
            w.count++;
        }
        return true;
    }

    private static String clientIp(HttpServletRequest r) {
        String h = r.getHeader("X-Forwarded-For");
        if (h != null && !h.isEmpty()) {
            return h.split(",")[0].trim();
        }
        h = r.getHeader("X-Real-IP");
        if (h != null && !h.isEmpty()) {
            return h.trim();
        }
        return r.getRemoteAddr();
    }

    private static class Window {
        final long start;
        int count;

        Window(long start) {
            this.start = start;
        }
    }
}
