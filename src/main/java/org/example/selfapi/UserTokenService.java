package org.example.selfapi;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 自用令牌（{@code X-User-Token}）的校验与登录面限速。
 *
 * <h3>红线：明文绝不入库</h3>
 * 服务器只配置 {@code APP_USER_TOKEN_SHA256}（令牌的 sha256，小写十六进制）。
 * 明文令牌只出现在站主自己的设备上（密码管理器 / localStorage）。
 * 本类<b>不提供任何"生成令牌"的方法</b> —— 生成在 srv1 上用 {@code python3 -c 'import secrets...'}
 * 完成，服务器拿到的是哈希。这样"仓库里能不能翻出令牌"这个问题永远只有一个答案：不能。
 *
 * <h3>四道门（顺序即优先级）</h3>
 * <ol>
 *   <li><b>未配置</b>（{@code APP_USER_TOKEN_SHA256} 空 / 不是 64 位十六进制）⇒ 一律拒绝，
 *       reason={@code USER_LOGIN_DISABLED}。<b>fail-closed</b>：配置缺失时登录面关闭，
 *       绝不"没配就当不需要校验"。</li>
 *   <li><b>本 IP 处于封禁窗口</b> ⇒ 拒绝（429 语义），reason={@code IP_TEMPORARILY_BANNED}。</li>
 *   <li><b>登录面限速超限</b>（默认 10 次/分钟，status 与 ask 共用一本账）⇒ 拒绝，
 *       reason={@code LOGIN_RATE_LIMITED}。</li>
 *   <li><b>令牌形状 / 内容</b>：长度不在 [32,200] ⇒ 直接拒绝；否则
 *       <b>sha256 恒定时间比较</b>。</li>
 * </ol>
 *
 * <h3>为什么比较的是"明文的 sha256"而不是"明文"</h3>
 * 服务器根本不持有明文，只持有哈希 —— 所以比较双方都是哈希。
 * 明文长度本身不泄露任何关于哈希的信息（哈希是定长的），
 * 长度校验只是"明显不可能有效时省掉一次哈希"。
 * 真正的比较一律走 {@link #constantTimeEquals}，不用 {@code String.equals}
 * （后者逐字节提前返回，会把"对了几位前缀"漏出去）。
 *
 * <h3>失败计数与短时封禁</h3>
 * 每 IP 一份滑动窗口计数；10 分钟内失败 ≥ 阈值（默认 10）⇒ 封 10 分钟。
 * 成功一次即清空该 IP 的失败计数。这样暴力枚举的代价从"无限次/秒"变成"每 10 分钟 9 次"。
 *
 * <h3>它的边界（写在代码里，避免被当成"完整认证系统"）</h3>
 * 这是<b>进程内</b>限速：重启即清零，且挡不住分布式换 IP 爆破。
 * 真正的防线是令牌本身的熵（≥32 字符 ≈ 192 bit）——
 * 限速只是把"理论不可行"变成"实际很贵"。
 */
@Service
public class UserTokenService {

    private static final Logger logger = LoggerFactory.getLogger(UserTokenService.class);

    /** sha256 十六进制长度（服务器只存这个长度的哈希） */
    public static final int SHA256_HEX_LEN = 64;

    /** 明文令牌最小长度：32 字符（与站主口径一致）；短于此直接拒绝启用 */
    public static final int MIN_TOKEN_CHARS = 32;

    /** 明文令牌最大长度：挡"用超长串撑哈希"的低成本 DoS */
    public static final int MAX_TOKEN_CHARS = 200;

    /** 登录面限速与失败封禁的跟踪表上限（防伪造来源撑内存） */
    private static final int MAX_TRACKED_KEYS = 5000;

    /**
     * 令牌的 sha256。<b>刻意不设默认值</b>：默认空 ⇒ 登录面关闭。
     * 写死一个默认值等于把自用池变成公开后门。
     */
    @Value("${app.user.token-sha256:}")
    private String tokenSha256;

    /** 登录面每 IP 每分钟上限（status 与 ask 共用） */
    @Value("${app.user.login.requests-per-minute:10}")
    private int loginPerMinute;

    /** 触发短时封禁的失败次数 */
    @Value("${app.user.login.fail-threshold:10}")
    private int failThreshold;

    /** 失败计数窗口（秒） */
    @Value("${app.user.login.fail-window-seconds:600}")
    private int failWindowSeconds;

    /** 封禁时长（秒） */
    @Value("${app.user.login.ban-seconds:600}")
    private int banSeconds;

    /**
     * 审计落盘文件（JSONL 追加写）。
     *
     * <p>默认空 = <b>不落盘</b>（单测与裁剪部署下只会打日志）。生产由
     * {@code APP_USER_AUDIT_FILE} 指向 {@code data/user-token-audit.jsonl}。
     * 为什么允许为空而不是给一个默认路径：单测里跑一遍不该往仓库目录写文件。
     */
    @Value("${app.user.audit-file:}")
    private String auditFile;

    private final Map<String, Window> loginWindows = new ConcurrentHashMap<>();
    private final Map<String, FailureWindow> failures = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> bans = new ConcurrentHashMap<>();

    private final UserTokenAuditWriter auditWriter = new UserTokenAuditWriter();

    @PostConstruct
    public void init() {
        auditWriter.configure(auditFile);
        if (!configured()) {
            logger.info("自用登录面：未配置 app.user.token-sha256（APP_USER_TOKEN_SHA256）→ 功能关闭，"
                    + "/api/user/** 一律 401（USER_LOGIN_DISABLED），行为与改造前一致");
            return;
        }
        logger.info("自用登录面：已启用（令牌 sha256 已配置，长度={}；明文不落库、不落日志），"
                        + "登录面限速={}/分钟，失败 {} 次/{}s 封 {}s",
                SHA256_HEX_LEN, loginPerMinute, failThreshold, failWindowSeconds, banSeconds);
    }

    /**
     * 登录面是否配置好。
     *
     * <p>判定口径：非空 <b>且</b> 长度为 64 <b>且</b> 全是十六进制字符。
     * 配置写错（例如误把明文粘进来）时按"未配置"处理 ——
     * 把明文当哈希用会让所有请求都失败，而报"配置无效"比报"令牌错误"诚实得多。
     */
    public boolean configured() {
        return isSha256Hex(tokenSha256);
    }

    /** 是否把审计落盘（供状态自查与测试如实断言，不假装有审计） */
    public boolean auditEnabled() {
        return auditWriter.enabled();
    }

    /** 校验请求头里的令牌（会记一次失败 / 记一次限速 / 记审计）。 */
    public Result check(String clientIp, String presentedToken) {
        String ip = normalizeIp(clientIp);
        long now = System.currentTimeMillis();

        if (!configured()) {
            audit("login", "fail", "USER_LOGIN_DISABLED", ip, null, null, null);
            return Result.reject(401, "USER_LOGIN_DISABLED", "自用入口未启用（服务端未配置令牌）", 0);
        }

        Long bannedUntil = bans.get(ip) == null ? null : bans.get(ip).get();
        if (bannedUntil != null && bannedUntil > now) {
            long retryAfter = Math.max(1, (bannedUntil - now) / 1000);
            audit("login", "fail", "IP_TEMPORARILY_BANNED", ip, null, null, retryAfter);
            return Result.reject(429, "IP_TEMPORARILY_BANNED",
                    "来源尝试过于频繁，已临时封禁，请稍后再试", (int) retryAfter);
        }

        if (!allowLogin(ip, now)) {
            audit("login", "fail", "LOGIN_RATE_LIMITED", ip, null, null, 60L);
            return Result.reject(429, "LOGIN_RATE_LIMITED",
                    "自用入口请求过于频繁（每 IP 每分钟 " + loginPerMinute + " 次），请稍后再试", 60);
        }

        if (presentedToken == null || presentedToken.isEmpty()) {
            int count = recordFailure(ip, now);
            audit("login", "fail", "TOKEN_MISSING", ip, null, count, null);
            return Result.reject(401, "TOKEN_MISSING", "缺少自用令牌（请求头 X-User-Token）", 0);
        }

        // 形状先判：明文长度必须落在 [MIN, MAX]。
        // 【注意】服务器不持有明文，所以这里【不】校验"是不是十六进制"——
        // 站主粘贴的是明文令牌（URL-safe base64 等），服务器只比它的 sha256。
        if (presentedToken.length() < MIN_TOKEN_CHARS || presentedToken.length() > MAX_TOKEN_CHARS) {
            int count = recordFailure(ip, now);
            audit("login", "fail", "TOKEN_SHAPE_INVALID", ip, presentedToken.length(), count, null);
            return Result.reject(401, "TOKEN_INVALID", "令牌无效（长度不合法）", 0);
        }

        String presentedHash = sha256Hex(presentedToken);
        if (presentedHash == null || !constantTimeEquals(presentedHash, expectedHash())) {
            int count = recordFailure(ip, now);
            audit("login", "fail", "TOKEN_MISMATCH", ip, presentedToken.length(), count, null);
            return Result.reject(401, "TOKEN_INVALID", "令牌无效或已轮换", 0);
        }

        // 成功：清掉该 IP 的失败计数与封禁（一次成功即恢复正常）
        failures.remove(ip);
        bans.remove(ip);
        audit("login", "ok", null, ip, presentedToken.length(), null, null);
        return Result.pass();
    }

    /** 记一次自用调用（成功/失败都记，用于审计）。 */
    public void auditAsk(String clientIp, String conversationId, int round, int quotaUsed, String state,
                         String result, String reason) {
        audit("ask", result, reason, normalizeIp(clientIp), null,
                null, null, conversationIdHash(conversationId), round, quotaUsed, state);
    }

    /** 记一次登录封禁事件（与 check 内部的 fail 记录区分：这条只在"刚刚触发封禁"时写一次）。 */
    public void auditBan(String clientIp, int failCount) {
        audit("ban", "fail", "IP_TEMPORARILY_BANNED", normalizeIp(clientIp), null, failCount,
                (long) banSeconds);
    }

    // ==================== 内部 ====================

    /** 登录面固定窗口限速（每分钟）。@return true 放行 */
    private boolean allowLogin(String ip, long now) {
        long minute = now / 60000L;
        if (loginWindows.size() > MAX_TRACKED_KEYS) {
            int before = loginWindows.size();
            loginWindows.entrySet().removeIf(e -> e.getValue().minute < minute - 1);
            logger.warn("自用登录面限速来源表过大（{}），已清理到 {}", before, loginWindows.size());
        }
        Window w = loginWindows.compute(ip,
                (k, cur) -> (cur == null || cur.minute != minute) ? new Window(minute) : cur);
        return w.count.incrementAndGet() <= Math.max(1, loginPerMinute);
    }

    /**
     * 记一次失败；达到阈值则封禁。
     *
     * @return 当前窗口内的失败次数（写进审计，便于事后判断"是被爆破还是站主自己粘错了"）
     */
    private int recordFailure(String ip, long now) {
        long window = Math.max(1, failWindowSeconds) * 1000L;
        FailureWindow f = failures.computeIfAbsent(ip, k -> new FailureWindow());
        synchronized (f) {
            if (now - f.windowStart > window) {
                f.windowStart = now;
                f.count.set(0);
            }
            int count = f.count.incrementAndGet();
            if (count >= Math.max(1, failThreshold) && !bans.containsKey(ip)) {
                // 只有"第一次触发"才写 ban 事件与 WARN，避免每请求刷屏
                bans.put(ip, new AtomicLong(now + Math.max(1, banSeconds) * 1000L));
                auditBan(ip, count);
                logger.warn("自用登录面：来源 {} 在 {}s 内失败 {} 次，已临时封禁 {}s"
                                + "（令牌校验失败，未记录任何令牌内容）",
                        ip, failWindowSeconds, count, banSeconds);
            }
            return count;
        }
    }

    private String expectedHash() {
        return tokenSha256 == null ? "" : tokenSha256.trim().toLowerCase(Locale.ROOT);
    }

    /** 是否为 64 位十六进制（配置合法性判定） */
    public static boolean isSha256Hex(String s) {
        if (s == null) {
            return false;
        }
        String v = s.trim();
        if (v.length() != SHA256_HEX_LEN) {
            return false;
        }
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex) {
                return false;
            }
        }
        return true;
    }

    /** sha256 → 小写十六进制；任何异常返回 null（调用方按"不匹配"处理） */
    public static String sha256Hex(String plain) {
        if (plain == null) {
            return null;
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(plain.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (Exception e) {
            logger.error("sha256 不可用（JVM 异常）：{}", e.getMessage());
            return null;
        }
    }

    /**
     * 恒定时间比较（逐字节 XOR 累加）。
     *
     * <p>与 {@code ApiTokenInterceptor.constantTimeEquals} 同一写法 ——
     * 不用 {@code MessageDigest.isEqual}：那会引入"是不是恒定时间"的第二份依据，
     * 而这里比较的本来就是哈希，两份实现的差异没有价值。
     */
    static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length(); i++) {
            diff |= a.charAt(i) ^ b.charAt(i);
        }
        return diff == 0;
    }

    /** 审计里的会话标识：只记哈希前 8 位，绝不记原值（原值可能含站主自定的可识别串） */
    static String conversationIdHash(String conversationId) {
        String h = sha256Hex(conversationId == null ? "" : conversationId);
        return h == null ? null : h.substring(0, 8);
    }

    private static String normalizeIp(String ip) {
        return (ip == null || ip.isBlank()) ? "unknown" : ip.trim();
    }

    private void audit(String event, String result, String reason, String ip, Integer tokenLen,
                       Integer failCount, Long retryAfter) {
        audit(event, result, reason, ip, tokenLen, failCount, retryAfter, null, null, null, null);
    }

    private void audit(String event, String result, String reason, String ip, Integer tokenLen,
                       Integer failCount, Long retryAfter, String conversationIdHash,
                       Integer round, Integer quotaUsed, String state) {
        auditWriter.write(event, result, reason, maskIp(ip),
                tokenLen, failCount, retryAfter, conversationIdHash, round, quotaUsed, state);
    }

    /**
     * 审计里的 IP 掩码（只保留网段，隐去主机位）。
     *
     * <p><b>为什么本包自带一份，而不是复用公开面的 {@code PublicIpMask}</b>：
     * 两条面要求<b>互相隔离</b>（见 {@code SelfApiIsolationTest} 与 {@code PublicApiIsolationTest}）。
     * 复用会让"自用面改动"有可能牵动公开面的脱敏口径 —— 那是两条本该各自可验证的边界。
     *
     * <p>与公开面口径的差别（有意为之）：公开面把内网地址写成「内部地址」；
     * 这里服务的是<b>站主自己的审计文件</b>，写「***」即可 ——
     * 它不需要让任何人从审计里读出内网段。
     */
    static String maskIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return "***";
        }
        String v = ip.trim();
        // 【顺序很重要】先判 IPv4（含带端口形态），再判 IPv6。
        // 反过来的话 "203.0.113.77:1234" 会先命中"含冒号 ⇒ 当 IPv6 处理"，
        // 于是掩码结果变成 "203.0.113.77:1234:****:****" —— 主机位原样透出。
        boolean hasDot = v.indexOf('.') > 0;
        boolean hasColon = v.indexOf(':') > 0;
        if (hasDot && hasColon) {
            String hostOnly = v.substring(0, v.indexOf(':'));
            String[] p = hostOnly.split("\\.");
            return p.length == 4 ? p[0] + "." + p[1] + ".***.***" : "***";
        }
        if (!hasColon) {
            String[] parts = v.split("\\.");
            if (parts.length == 4) {
                return parts[0] + "." + parts[1] + ".***.***";
            }
            return "***";
        }
        // 纯 IPv6：只留前两组
        String[] groups = v.split(":");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < groups.length && i < 2; i++) {
            if (!groups[i].isEmpty()) {
                sb.append(groups[i]).append(':');
            }
        }
        return sb.length() == 0 ? "***" : sb + "****:****";
    }

    private static final class Window {
        private final long minute;
        private final AtomicInteger count = new AtomicInteger();

        private Window(long minute) {
            this.minute = minute;
        }
    }

    private static final class FailureWindow {
        private volatile long windowStart = System.currentTimeMillis();
        private final AtomicInteger count = new AtomicInteger();
    }

    /**
     * 校验结果。
     *
     * <p><b>为什么工厂方法叫 {@code pass()} / {@code reject()} 而不是 {@code ok()} / {@code fail()}</b>：
     * record 会自动生成访问器 {@code ok()}，同名静态方法与它冲突（Java 直接报
     * "记录中的读取方法无效"）—— 命名上避开，比靠"签名不同"去赌编译器宽容更可靠。
     *
     * @param ok         是否通过
     * @param httpStatus 失败时的 HTTP 状态（401 / 429）
     * @param reason     机读原因码（前端按它决定文案与是否清 localStorage）
     * @param message    人话（不含任何令牌信息）
     * @param retryAfter 建议重试秒数（>0 时下发 Retry-After）
     */
    public record Result(boolean ok, int httpStatus, String reason, String message, int retryAfter) {

        static Result pass() {
            return new Result(true, 200, null, null, 0);
        }

        static Result reject(int httpStatus, String reason, String message, int retryAfter) {
            return new Result(false, httpStatus, reason, message, retryAfter);
        }
    }
}
