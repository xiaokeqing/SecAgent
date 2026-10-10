package org.example.security;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 登录、会话与用户/角色服务（RBAC 基础）。
 *
 * <p>不依赖数据库：账号与 Token 保存在内存，应用重启后需重新登录。
 * 内置两个角色账号：管理员 admin（ADMIN）、分析员 analyst（ANALYST）。
 *
 * <p>安全说明：默认密码为弱口令，仅用于本地演示。凭据强度由
 * {@link CredentialGuard} 在启动期统一校验：生产环境必须通过环境变量
 * {@code SECAGENT_PASSWORD}（管理员）/ {@code SECAGENT_ANALYST_PASSWORD}（分析员）
 * 注入强密码，并开启 {@code app.security.enforce-strong-credentials} 以防止
 * 带着默认口令对外启动。
 */
@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    @Value("${app.security.login.username:admin}")
    private String adminUsername;

    @Value("${app.security.login.password:${SECAGENT_PASSWORD:admin123}}")
    private String adminPassword;

    @Value("${app.security.analyst.username:${SECAGENT_ANALYST_USERNAME:analyst}}")
    private String analystUsername;

    @Value("${app.security.analyst.password:${SECAGENT_ANALYST_PASSWORD:analyst123}}")
    private String analystPassword;

    @Value("${app.security.login.ttl-minutes:120}")
    private long ttlMinutes;

    private final SecureRandom secureRandom = new SecureRandom();

    /** 账号：username -> 账号信息 */
    private final Map<String, Account> accounts = new ConcurrentHashMap<>();

    /** 会话：token -> 会话信息（含用户名与角色） */
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    @PostConstruct
    public void init() {
        accounts.put(adminUsername, new Account(adminUsername, adminPassword, Role.ADMIN));
        if (!adminUsername.equals(analystUsername)) {
            accounts.put(analystUsername, new Account(analystUsername, analystPassword, Role.ANALYST));
        }

        // 凭据强度校验统一交由 CredentialGuard 在启动期完成（fail-closed），此处不再重复告警
        logger.info("登录服务初始化完成，内置账号 {} 个，会话有效期 {} 分钟", accounts.size(), ttlMinutes);
    }

    /** 登录成功返回 token；账号或密码错误返回 null */
    public String login(String inputUser, String inputPass) {
        if (inputUser == null || inputPass == null) {
            return null;
        }
        Account account = accounts.get(inputUser.trim());
        if (account == null || !constantTimeEquals(inputPass, account.password)) {
            return null;
        }
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        String token = toHex(bytes);
        sessions.put(token, new Session(account.username, account.role,
                System.currentTimeMillis() + ttlMinutes * 60_000L));
        evictExpired();
        logger.info("用户 {}（角色 {}）登录成功，已签发会话 Token", account.username, account.role);
        return token;
    }

    /** 校验 token 是否有效（存在且未过期） */
    public boolean validate(String token) {
        Session session = getValidSession(token);
        return session != null;
    }

    /** 取 token 对应角色；无效返回 null */
    public Role getRole(String token) {
        Session session = getValidSession(token);
        return session == null ? null : session.role;
    }

    /** 取 token 对应用户名；无效返回 null */
    public String getUsername(String token) {
        Session session = getValidSession(token);
        return session == null ? null : session.username;
    }

    public void logout(String token) {
        if (token != null) {
            sessions.remove(token);
        }
    }

    public long getTtlSeconds() {
        return ttlMinutes * 60L;
    }

    /** 列出全部用户（不含密码），供管理员查看 */
    public List<Map<String, String>> listUsers() {
        List<Map<String, String>> list = new ArrayList<>();
        for (Account a : accounts.values()) {
            list.add(Map.of(
                    "username", a.username,
                    "role", a.role.name(),
                    "roleLabel", a.role.getLabel()));
        }
        return list;
    }

    /**
     * 管理员新增用户（内存，重启失效）。
     * @throws IllegalArgumentException 用户名为空/已存在/密码过弱
     */
    public synchronized void addUser(String username, String rawPassword, Role role) {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("用户名不能为空");
        }
        String u = username.trim();
        if (accounts.containsKey(u)) {
            throw new IllegalArgumentException("用户已存在: " + u);
        }
        if (rawPassword == null || rawPassword.length() < CredentialGuard.MIN_LENGTH) {
            throw new IllegalArgumentException("密码至少 " + CredentialGuard.MIN_LENGTH + " 位");
        }
        accounts.put(u, new Account(u, rawPassword, role == null ? Role.ANALYST : role));
        logger.info("管理员新增用户 {}，角色 {}", u, role);
    }

    private Session getValidSession(String token) {
        if (token == null || token.isEmpty()) {
            return null;
        }
        Session session = sessions.get(token);
        if (session == null) {
            return null;
        }
        if (System.currentTimeMillis() > session.expire) {
            sessions.remove(token);
            return null;
        }
        return session;
    }

    private void evictExpired() {
        long now = System.currentTimeMillis();
        Iterator<Map.Entry<String, Session>> it = sessions.entrySet().iterator();
        while (it.hasNext()) {
            if (now > it.next().getValue().expire) {
                it.remove();
            }
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) {
            return false;
        }
        int r = 0;
        for (int i = 0; i < a.length(); i++) {
            r |= a.charAt(i) ^ b.charAt(i);
        }
        return r == 0;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /** 账号 */
    private static class Account {
        final String username;
        final String password;
        final Role role;

        Account(String username, String password, Role role) {
            this.username = username;
            this.password = password;
            this.role = role;
        }
    }

    /** 会话 */
    private static class Session {
        final String username;
        final Role role;
        final long expire;

        Session(String username, Role role, long expire) {
            this.username = username;
            this.role = role;
            this.expire = expire;
        }
    }
}
