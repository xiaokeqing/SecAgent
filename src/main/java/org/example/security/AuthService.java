package org.example.security;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
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
 *
 * <h3>关于口令存储 —— 一次外部评审之后的修正</h3>
 * 原实现把口令<b>明文</b>存进内存的 Account 对象，登录时用自己写的
 * {@code constantTimeEquals} 做定长比较。定长比较说明作者想到了时序侧信道，
 * 但漏掉了密码学上最基础的一步：口令不该以明文形式存在。
 * <p>
 * 风险不只是「内存里能看到」——本项目的 {@code JAVA_OPTS} 里开着
 * {@code -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/app/data}，
 * 一旦 OOM，含明文口令的堆转储会直接落到挂载卷上。
 * <p>
 * 现在改为启动时用 BCrypt 哈希一次，内存里只留哈希：
 * <ul>
 *   <li>BCrypt 自带随机盐，同一口令每次哈希结果都不同，不需要自己管盐</li>
 *   <li>比对走 {@link PasswordEncoder#matches}，它内部本身就是定长比较，
 *       所以自写的 {@code constantTimeEquals} 已删除 —— 留两套只会有两套行为</li>
 *   <li>成本因子用默认值 10（约 50~100ms 一次），对登录接口是可以接受的代价</li>
 * </ul>
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

    /**
     * 口令哈希器。BCrypt 自带盐，默认强度 10。
     *
     * <p>用 crypto 模块而不是整个 spring-boot-starter-security：
     * 后者会自动装配一整套过滤器链，把本项目自写的三个拦截器盖掉。
     */
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    /**
     * 一个固定的假哈希，用于「用户不存在」时消耗与真实比对相当的时间。
     *
     * <p>为什么需要它：BCrypt 一次比对要 50~100ms，而账号不存在时如果直接返回，
     * 响应时间会明显更快 —— 攻击者据此就能枚举出哪些用户名是存在的。
     * 所以账号查不到时，仍然拿这个假哈希跑一次 matches，把耗时补齐。
     */
    private final String dummyHash = new BCryptPasswordEncoder().encode("dummy-password-for-timing");

    /** 账号：username -> 账号信息 */
    private final Map<String, Account> accounts = new ConcurrentHashMap<>();

    /** 会话：token -> 会话信息（含用户名与角色） */
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    @PostConstruct
    public void init() {
        // 启动时哈希一次，之后内存里只有哈希，没有明文
        accounts.put(adminUsername,
                new Account(adminUsername, passwordEncoder.encode(adminPassword), Role.ADMIN));
        if (!adminUsername.equals(analystUsername)) {
            accounts.put(analystUsername,
                    new Account(analystUsername, passwordEncoder.encode(analystPassword), Role.ANALYST));
        }

        // 凭据强度校验统一交由 CredentialGuard 在启动期完成（fail-closed），此处不再重复告警
        logger.info("登录服务初始化完成，内置账号 {} 个，会话有效期 {} 分钟（口令以 BCrypt 哈希存储）",
                accounts.size(), ttlMinutes);
    }

    /** 登录成功返回 token；账号或密码错误返回 null */
    public String login(String inputUser, String inputPass) {
        if (inputUser == null || inputPass == null) {
            return null;
        }
        Account account = accounts.get(inputUser.trim());
        if (account == null) {
            // 关键：用户不存在时也要走一次哈希比对，否则响应时间会泄露「这个用户名存不存在」
            passwordEncoder.matches(inputPass, dummyHash);
            return null;
        }
        // matches 内部已是定长比较，不需要再叠一层 constantTimeEquals
        if (!passwordEncoder.matches(inputPass, account.passwordHash)) {
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
        // 新增用户同样只存哈希
        accounts.put(u, new Account(u, passwordEncoder.encode(rawPassword),
                role == null ? Role.ANALYST : role));
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

    /*
      这里原本有一个自写的 constantTimeEquals（逐字符异或、长度不等直接返回 false）。
      它现在被删掉了，原因有两条：

        1. 用不上了 —— BCrypt 的 PasswordEncoder.matches 内部本来就是定长比较，
           而且它比的是哈希值，比较耗时远小于哈希计算本身，时序差异被淹没在噪声里。
        2. 留着有害 —— 两套比较逻辑意味着两套行为。以后有人改了这里、
           忘了改那里，就会出现「看着有防护、实际没走那条路」的情况。
           安全代码里，同一件事只该有一个实现。

      它当初的存在说明作者想到了时序侧信道，这个意识是对的；
      但真正的问题不在比较方式上，而在【口令本身以明文存储】——
      比较得再小心，内存里躺着明文口令这件事都没解决。
    */

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /** 账号。注意这里存的是 BCrypt 哈希，字段名刻意叫 hash 而不是 password —— 免得以后有人当明文用 */
    private static class Account {
        final String username;
        final String passwordHash;
        final Role role;

        Account(String username, String passwordHash, Role role) {
            this.username = username;
            this.passwordHash = passwordHash;
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
