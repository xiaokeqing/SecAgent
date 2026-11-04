package org.example.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * 邮箱验证码：生成、存储、校验。<b>只服务一个人</b>。
 *
 * <h3>这不是"邮箱登录"，是"站主本人的第二个入口"</h3>
 * 全站只有一个白名单地址（{@code app.auth.owner-email}）。白名单为空 = 功能整体关闭
 * （fail-closed）：谁都不能用，而不是谁都能用。没有注册、没有找回密码、也没有发第二封信
 * 去改地址 —— 改地址只能改配置 + 重建容器。
 *
 * <h3>对"扫描"的回答：不区分原因</h3>
 * 请求一个不在白名单里的邮箱、白名单为空、SMTP 没配置、SMTP 发送失败 —— 对外<b>一律</b>
 * {@code {"ok":false,"reason":"unavailable"}}，不发信、状态码也不变。
 * 唯一例外是限流：命中限流才回 {@code rate_limited} —— 它必须可区分，否则前端没法告诉
 * 站主"等 42 秒"，而限流只对<b>白名单内</b>的邮箱生效，探测者永远走不到这条分支。
 *
 * <h3>存储与并发</h3>
 * <ul>
 *   <li>内存 {@link ConcurrentHashMap}（与 {@link AuthService} 的会话一致：重启即失效）；</li>
 *   <li>每个邮箱一个 {@link CodeEntry}，校验全程在 {@code synchronized(entry)} 内 ——
 *       "验证成功即删除"与"并发请求"之间不会出现双花；</li>
 *   <li>条目自带 {@code consumed} 标志：即使两个线程都拿到了旧引用，
 *       后到的那个也只能看到"已消费"。</li>
 * </ul>
 *
 * <h3>过期 / 作废 / 重放</h3>
 * <ul>
 *   <li>有效期 {@value #CODE_TTL_SECONDS} 秒；</li>
 *   <li>最多 {@value #MAX_ATTEMPTS} 次校验尝试，超过即作废该码（不是"锁账户"——
 *       默认口令那条链路不受影响）；</li>
 *   <li>成功即删除，重放必然失败；新码会覆盖旧码，旧码立即失效。</li>
 * </ul>
 *
 * <p>日志里有邮箱打码、没有验证码本身：验证码在那几分钟里就是凭据。
 */
@Service
public class AuthCodeService {

    private static final Logger logger = LoggerFactory.getLogger(AuthCodeService.class);

    /** 验证码有效期（秒）。任务要求 5 分钟。 */
    static final int CODE_TTL_SECONDS = 300;

    /** 单个验证码允许的最大校验尝试次数。 */
    static final int MAX_ATTEMPTS = 5;

    /** 同一邮箱两次发信的最小间隔（毫秒）：1 封/分钟。 */
    static final long MIN_INTERVAL_MS = 60_000L;

    /** 同一邮箱每小时最多发几封。 */
    static final int MAX_PER_HOUR = 5;

    private static final long HOUR_MS = 3_600_000L;

    /** 站主邮箱白名单：默认空 = 功能关闭（fail-closed）。 */
    @Value("${app.auth.owner-email:}")
    private String ownerEmail;

    private final AuthCodeSender sender;

    private final SecureRandom random = new SecureRandom();

    /** 归一化邮箱 → 当前有效的验证码 */
    private final Map<String, CodeEntry> codes = new ConcurrentHashMap<>();

    /** 归一化邮箱 → 发信时间窗（限流用） */
    private final Map<String, SendWindow> windows = new ConcurrentHashMap<>();

    /**
     * 可注入的时钟，单测用它把"5 分钟"压缩成"毫秒"。
     *
     * <p>不用 {@code Clock} 是因为这里只需要"现在多少毫秒"，一个 {@link LongSupplier}
     * 比包一个 {@code Clock} 少一层间接。
     */
    private LongSupplier clock = System::currentTimeMillis;

    public AuthCodeService(AuthCodeSender sender) {
        this.sender = sender;
    }

    /**
     * 申请验证码。
     *
     * @param rawEmail 请求里的邮箱（大小写/前后空格会被归一，其余原样比对）
     * @return 永远非 null；{@code ok=false} 时 {@code reason} 只会是 {@code unavailable}
     *         或 {@code rate_limited}
     */
    public SendResult requestCode(String rawEmail) {
        String email = normalize(rawEmail);
        if (!isOwner(email)) {
            // 刻意不记邮箱：日志是给站主看的排障材料，不该变成"谁在试探"的收集器
            logger.debug("验证码请求被忽略：邮箱不在白名单内（或白名单为空）");
            return SendResult.UNAVAILABLE;
        }

        long now = clock.getAsLong();
        long retryAfterMs = reserveSendSlot(email, now);
        if (retryAfterMs > 0) {
            int retryAfterSeconds = (int) Math.max(1, Math.ceil(retryAfterMs / 1000.0));
            logger.warn("验证码请求被限流（邮箱 {}），{} 秒后可再试", mask(email), retryAfterSeconds);
            return new SendResult(false, "rate_limited", retryAfterSeconds, 0);
        }

        String code = sixDigits();
        CodeEntry entry = new CodeEntry(code, now + CODE_TTL_SECONDS * 1000L);
        // 新码覆盖旧码：同一时刻一个邮箱只该有一个"活着的"验证码
        codes.put(email, entry);

        boolean sent = sender.send(email, code, CODE_TTL_SECONDS);
        if (!sent) {
            // 发不出去就把刚放进去的码撤掉：否则会出现"点了发送、没收到信，但码已经在后台生效"
            codes.remove(email, entry);
            logger.warn("验证码邮件未能发出（邮箱 {}），本次请求按不可用处理", mask(email));
            return SendResult.UNAVAILABLE;
        }
        logger.info("验证码邮件已发出（邮箱 {}，{} 秒内有效，最多 {} 次尝试）",
                mask(email), CODE_TTL_SECONDS, MAX_ATTEMPTS);
        return new SendResult(true, null, 0, CODE_TTL_SECONDS);
    }

    /**
     * 校验验证码。<b>返回 true 就已经把码消费掉了</b>，调用方可以放心签发会话。
     *
     * <p>所有失败（过期、错码、次数用尽、已用过、邮箱不在白名单）都返回 false，
     * 且对外不可区分 —— 区分它们只会告诉攻击者"这个码是存在过的"。
     */
    public boolean verify(String rawEmail, String rawCode) {
        String email = normalize(rawEmail);
        if (!isOwner(email) || rawCode == null) {
            return false;
        }
        String code = rawCode.trim();
        if (code.length() != 6 || !code.chars().allMatch(Character::isDigit)) {
            // 形状不对就早退，但不消耗尝试次数：这不是"猜码"，是前端传了个空格/空串
            return false;
        }

        CodeEntry entry = codes.get(email);
        if (entry == null) {
            return false;
        }
        synchronized (entry) {
            long now = clock.getAsLong();
            if (entry.consumed || now >= entry.expiresAt) {
                codes.remove(email, entry);
                logger.info("验证码校验失败（{}）", entry.consumed ? "已使用" : "已过期");
                return false;
            }
            if (entry.attempts >= MAX_ATTEMPTS) {
                codes.remove(email, entry);
                return false;
            }

            entry.attempts++;
            if (constantTimeEquals(entry.code, code)) {
                entry.consumed = true;
                codes.remove(email, entry);
                return true;
            }

            if (entry.attempts >= MAX_ATTEMPTS) {
                codes.remove(email, entry);
                logger.warn("验证码连续错 {} 次，已作废该码（邮箱 {}）", MAX_ATTEMPTS, mask(email));
            } else {
                logger.info("验证码校验失败（错误码，剩余尝试 {} 次）", MAX_ATTEMPTS - entry.attempts);
            }
            return false;
        }
    }

    /** 站主邮箱是否就是这一个（归一化后精确比对）。 */
    boolean isOwner(String normalizedEmail) {
        String owner = normalize(ownerEmail);
        return !owner.isEmpty() && owner.equals(normalizedEmail);
    }

    /** 归一化：去前后空格、转小写。邮件地址的本地部分严格说区分大小写，但现实里不区分。 */
    static String normalize(String email) {
        return email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
    }

    /**
     * 占一个发信槽位。返回 0 = 允许发送；&gt;0 = 需要等待的毫秒数（限流）。
     *
     * <p>时间窗内做两件事：记录每次发信的时间戳，顺带丢掉一小时前的。1 封/分钟与
     * 5 封/小时都从同一份时间戳算 —— 两个计数器迟早会打架，一份就不会。
     */
    private long reserveSendSlot(String email, long now) {
        SendWindow window = windows.computeIfAbsent(email, k -> new SendWindow());
        synchronized (window) {
            while (!window.sends.isEmpty() && window.sends.peekFirst() <= now - HOUR_MS) {
                window.sends.pollFirst();
            }
            Long last = window.sends.peekLast();
            if (last != null && now - last < MIN_INTERVAL_MS) {
                return MIN_INTERVAL_MS - (now - last);
            }
            if (window.sends.size() >= MAX_PER_HOUR) {
                return window.sends.peekFirst() + HOUR_MS - now;
            }
            window.sends.addLast(now);
            return 0;
        }
    }

    /** 测试注入时钟（包级可见：生产代码走系统时间）。 */
    void useClock(LongSupplier clock) {
        this.clock = clock;
    }

    private String sixDigits() {
        return String.format("%06d", random.nextInt(1_000_000));
    }

    /**
     * 定长比较。
     *
     * <p>这里其实不是"必须"的（码只有 6 位数字、5 次就作废，时序上猜不出什么），
     * 但"验证码比对"和"口令比对"是同一类操作，写成普通 {@code equals} 就是在教后来者
     * 用错比较方式 —— 与 {@link AuthService} 里那段删掉自写比较的注释是同一个道理。
     */
    private static boolean constantTimeEquals(String expected, String actual) {
        if (expected == null || actual == null) {
            return false;
        }
        int diff = expected.length() ^ actual.length();
        int n = Math.max(expected.length(), actual.length());
        for (int i = 0; i < n; i++) {
            char a = i < expected.length() ? expected.charAt(i) : 0;
            char b = i < actual.length() ? actual.charAt(i) : 0;
            diff |= a ^ b;
        }
        return diff == 0;
    }

    /** 日志打码：保留前两位与域名。 */
    private static String mask(String email) {
        int at = email.indexOf('@');
        if (at <= 0) {
            return "***";
        }
        String local = email.substring(0, at);
        String keep = local.length() <= 2 ? local.substring(0, 1) : local.substring(0, 2);
        return keep + "***" + email.substring(at);
    }

    /** 一次申请的结果。控制器照着它拼 JSON，成功/失败分支的键就固定在这里。 */
    public record SendResult(boolean ok, String reason, int retryAfterSeconds, int expiresInSeconds) {

        static final SendResult UNAVAILABLE = new SendResult(false, "unavailable", 0, 0);
    }

    /** 一个邮箱当前的验证码。字段只在 {@code synchronized(entry)} 内改。 */
    private static final class CodeEntry {
        final String code;
        final long expiresAt;
        int attempts;
        boolean consumed;

        CodeEntry(String code, long expiresAt) {
            this.code = code;
            this.expiresAt = expiresAt;
        }
    }

    /** 发信时间窗（一小时内的时间戳，升序）。 */
    private static final class SendWindow {
        final Deque<Long> sends = new ArrayDeque<>();
    }
}
