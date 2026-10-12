package org.example.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 基于角色的访问控制拦截器（RBAC）。
 * 在鉴权拦截器之后运行，依据请求路径前缀要求最低角色：
 * 处置动作、知识库审核、用户管理等"写/控"类操作仅管理员可执行；
 * 查看、对话、提交知识等分析员也可执行。
 */
@Component
public class RbacInterceptor implements HandlerInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(RbacInterceptor.class);

    private final ObjectMapper objectMapper = new ObjectMapper();

    /** 仅管理员可访问的路径前缀（处置、审核、用户管理） */
    private static final List<String> ADMIN_PREFIXES = List.of(
            "/api/response",          // 自动处置：封IP/锁账号/杀进程/审批
            "/api/kb/pending",        // 待审核队列
            "/api/kb/approve",        // 审核通过
            "/api/kb/reject",         // 审核驳回
            "/api/auth/users"         // 用户管理
    );

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {

        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return true;
        }

        String path = request.getRequestURI();
        boolean adminRequired = false;
        for (String prefix : ADMIN_PREFIXES) {
            if (path.startsWith(prefix)) {
                adminRequired = true;
                break;
            }
        }
        if (!adminRequired) {
            return true;
        }

        Object roleObj = request.getAttribute("secagent.role");
        Role role = roleObj instanceof Role ? (Role) roleObj : null;

        if (role == null) {
            return writeError(response, HttpStatus.UNAUTHORIZED, "未授权访问：请先登录");
        }
        if (role != Role.ADMIN) {
            // EVAL（评测身份）走的也是这条：它的调用范围在 ApiTokenInterceptor 里已收敛到
            // /api/chat，这里是第二道锁 —— 万一将来放开路径，处置类端点仍然进不来。
            logger.warn("角色 {}（用户 {}）尝试访问管理员接口 {}，已拒绝",
                    role, request.getAttribute("secagent.user"), path);
            return writeError(response, HttpStatus.FORBIDDEN, "权限不足：该操作仅管理员可执行");
        }
        return true;
    }

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
}
