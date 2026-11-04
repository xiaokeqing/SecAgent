package org.example.security;

import org.example.controller.AuthController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 邮箱验证码登录：契约与边界。
 *
 * <p>几条贯穿全文件的纪律：
 * <ul>
 *   <li><b>绝不真发信</b>：{@link FakeSender} 记下"发给了谁、内容是什么"，测试断言的是它，
 *       不是 SMTP 服务器。真发一次就是给站主收件箱里塞一封测试邮件，而且测试会因为网络变得不稳定。</li>
 *   <li><b>失败不区分原因</b>：白名单外、白名单为空、发信失败、过期、错码、重放，
 *       对外都必须长成同一个样子 —— 区分它们等于告诉试探者哪一次"猜对了方向"。</li>
 *   <li><b>时钟注入</b>：5 分钟过期、1 封/分钟、5 封/小时都是用 {@link #ms} 推着走的，
 *       测试不 sleep。</li>
 * </ul>
 */
class AuthCodeTest {

    private static final String OWNER = "3053970237@qq.com";

    /** 可推进的时钟（毫秒），从某个固定起点开始。 */
    private final AtomicLong nowMs = new AtomicLong(1_780_000_000_000L);

    private FakeSender sender;
    private AuthCodeService service;
    private AuthService authService;
    private AuthController controller;

    @BeforeEach
    void setUp() {
        sender = new FakeSender();
        service = new AuthCodeService(sender);
        ReflectionTestUtils.setField(service, "ownerEmail", OWNER);
        service.useClock(nowMs::get);

        authService = new AuthService();
        ReflectionTestUtils.setField(authService, "adminUsername", "admin");
        ReflectionTestUtils.setField(authService, "adminPassword", "admin123");
        ReflectionTestUtils.setField(authService, "analystUsername", "analyst");
        ReflectionTestUtils.setField(authService, "analystPassword", "analyst123");
        ReflectionTestUtils.setField(authService, "ttlMinutes", 120L);
        authService.init();

        controller = new AuthController();
        ReflectionTestUtils.setField(controller, "authService", authService);
        ReflectionTestUtils.setField(controller, "authCodeService", service);
    }

    // ==================== 1) 白名单：不命中就不发信、不区分原因 ====================

    @Test
    @DisplayName("白名单外的邮箱：不发信、回 unavailable（不能让人探出站主邮箱）")
    void strangerEmailNeverReceivesMail() {
        AuthCodeService.SendResult r = service.requestCode("attacker@example.com");

        assertFalse(r.ok(), "白名单外的邮箱不能申请验证码");
        assertEquals("unavailable", r.reason(), "对外只能说 unavailable，不能透出'这个邮箱不对'");
        assertTrue(sender.recipients.isEmpty(), "白名单外必须一封都不发 —— 否则这个端点就是免费发信机");
    }

    @Test
    @DisplayName("白名单为空（APP_AUTH_OWNER_EMAIL 没配）：fail-closed，连站主自己也进不去")
    void emptyOwnerEmailFailsClosed() {
        ReflectionTestUtils.setField(service, "ownerEmail", "");

        AuthCodeService.SendResult r = service.requestCode(OWNER);

        assertFalse(r.ok(), "白名单为空 = 功能关闭，不能退化成'谁都能用'");
        assertEquals("unavailable", r.reason());
        assertTrue(sender.recipients.isEmpty(), "白名单为空时也不能发信");
        assertFalse(service.verify(OWNER, "123456"), "白名单为空时校验也必须失败");
    }

    @Test
    @DisplayName("发信失败：回 unavailable，并且刚生成的码要撤掉（不能'没收到信但码已生效'）")
    void sendFailureRevokesCode() {
        sender.fail = true;

        AuthCodeService.SendResult r = service.requestCode(OWNER);

        assertFalse(r.ok());
        assertEquals("unavailable", r.reason(), "发信失败与白名单外必须不可区分");
        assertEquals(1, sender.attempts, "确实尝试发了一次");
        assertNull(sender.lastCode(), "发送失败时不会有可用的码被记下来");
        assertFalse(service.verify(OWNER, "123456"), "发送失败时码不能留在内存里生效");
    }

    // ==================== 2) 成功路径 ====================

    @Test
    @DisplayName("码正确：验证通过，且用同一个 AuthService 签发出来的 token 能被 /api/auth/check 认可")
    void correctCodeLogsInWithExistingSession() {
        assertTrue(service.requestCode(OWNER).ok(), "白名单内发信应成功");
        String code = sender.lastCode();
        assertNotNull(code);
        assertEquals(6, code.length(), "必须是 6 位数字码");

        String token = service.verify(OWNER, code) ? authService.issueSessionForOwner() : null;

        assertNotNull(token, "码正确必须签发会话");
        assertTrue(authService.validate(token), "验证码登录签发的 token 与密码登录是同一套会话");
        assertEquals("admin", authService.getUsername(token), "站主登录 = 管理员身份");
        assertEquals(Role.ADMIN, authService.getRole(token));
    }

    @Test
    @DisplayName("邮箱大小写与前后空格：归一化后仍能命中白名单（否则手机上自动大写就登不进去）")
    void emailNormalization() {
        AuthCodeService.SendResult r = service.requestCode("  3053970237@QQ.com  ");

        assertTrue(r.ok(), "大小写/空格不应导致" + OWNER + " 被当成陌生人");
        assertTrue(service.verify("3053970237@qq.com ", sender.lastCode()), "校验侧也要归一化");
    }

    // ==================== 3) 作废与过期 ====================

    @Test
    @DisplayName("码错 5 次：该码作废，之后连正确的码也不再通过（防在线猜 6 位）")
    void fiveWrongAttemptsBurnTheCode() {
        service.requestCode(OWNER);
        String code = sender.lastCode();

        for (int i = 1; i <= AuthCodeService.MAX_ATTEMPTS; i++) {
            assertFalse(service.verify(OWNER, wrong(code)), "第 " + i + " 次错码必须失败");
        }

        assertFalse(service.verify(OWNER, code), "5 次用尽后，正确的码也已作废");
    }

    @Test
    @DisplayName("过期：300 秒后正确的码也不认（有效期不靠前端倒计时）")
    void expiredCodeIsRejected() {
        service.requestCode(OWNER);
        String code = sender.lastCode();

        ms(AuthCodeService.CODE_TTL_SECONDS * 1000L);

        assertFalse(service.verify(OWNER, code), "过期码必须失败，哪怕一个字符都没错");
    }

    @Test
    @DisplayName("重放：同一个码只能用一次，第二次必须失败")
    void replayIsRejected() {
        service.requestCode(OWNER);
        String code = sender.lastCode();

        assertTrue(service.verify(OWNER, code), "第一次应成功");
        assertFalse(service.verify(OWNER, code), "同一个码第二次必须失败（成功即消费）");
    }

    @Test
    @DisplayName("重新申请：新码生效、旧码立即失效（一个邮箱同时只该有一个活码）")
    void newCodeSupersedesOldOne() {
        service.requestCode(OWNER);
        String first = sender.lastCode();

        ms(61_000L);
        service.requestCode(OWNER);
        String second = sender.lastCode();

        assertFalse(first.equals(second), "两次的码不该相同（否则等于没换）");
        assertFalse(service.verify(OWNER, first), "旧码必须失效，否则等于同时开了两个入口");
        assertTrue(service.verify(OWNER, second), "新码应当可用");
    }

    // ==================== 4) 限流 ====================

    @Test
    @DisplayName("限流：1 封/分钟 —— 立刻再申请会拿到 rate_limited + 合理的 retryAfterSeconds")
    void rateLimitPerMinute() {
        assertTrue(service.requestCode(OWNER).ok());

        AuthCodeService.SendResult second = service.requestCode(OWNER);

        assertFalse(second.ok());
        assertEquals("rate_limited", second.reason(), "限流是唯一可以区分的失败原因（前端要显示倒计时）");
        assertTrue(second.retryAfterSeconds() > 0 && second.retryAfterSeconds() <= 60,
                "retryAfterSeconds 应在 (0,60]，实际 " + second.retryAfterSeconds());
        assertEquals(1, sender.recipients.size(), "被限流的请求不能再发信");

        ms(61_000L);
        assertTrue(service.requestCode(OWNER).ok(), "过了 1 分钟应当恢复");
    }

    @Test
    @DisplayName("限流：5 封/小时 —— 第 6 封要等到最早那封过期，retryAfterSeconds 指向它")
    void rateLimitPerHour() {
        // 每 61 秒一封，正好绕过"1 封/分钟"，把小时额度打满
        for (int i = 1; i <= AuthCodeService.MAX_PER_HOUR; i++) {
            assertTrue(service.requestCode(OWNER).ok(), "第 " + i + " 封应发出");
            ms(61_000L);
        }

        AuthCodeService.SendResult blocked = service.requestCode(OWNER);

        assertFalse(blocked.ok(), "一小时第 6 封必须被挡");
        assertEquals("rate_limited", blocked.reason());
        assertTrue(blocked.retryAfterSeconds() > 60 && blocked.retryAfterSeconds() <= 3600,
                "小时限流的等待时间应明显长于分钟限流，实际 " + blocked.retryAfterSeconds());
        assertEquals(AuthCodeService.MAX_PER_HOUR, sender.recipients.size(), "被挡住的那封不能真发出去");
    }

    // ==================== 5) 并发 ====================

    @Test
    @DisplayName("并发：8 个线程同时提交同一个正确的码，只能有 1 个成功（码只能被消费一次）")
    void concurrentVerifyConsumesCodeOnce() throws Exception {
        service.requestCode(OWNER);
        String code = sender.lastCode();

        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger success = new AtomicInteger();
        try {
            for (int i = 0; i < threads; i++) {
                pool.submit(() -> {
                    try {
                        start.await();
                        if (service.verify(OWNER, code)) {
                            success.incrementAndGet();
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        done.countDown();
                    }
                });
            }
            start.countDown();
            assertTrue(done.await(10, TimeUnit.SECONDS), "并发校验没有在 10 秒内结束（死锁？）");
        } finally {
            pool.shutdownNow();
        }

        assertEquals(1, success.get(), "同一个码被成功消费了 " + success.get() + " 次 —— 会话会被签发多份");
    }

    // ==================== 6) 控制器契约 ====================

    @Test
    @DisplayName("POST /api/auth/code：成功/失败都必须是 HTTP 200（状态码本身不能成为探测信号）")
    void codeEndpointAlwaysReturns200() {
        ResponseEntity<Map<String, Object>> ok = controller.requestCode(req(OWNER));
        ResponseEntity<Map<String, Object>> stranger = controller.requestCode(req("attacker@example.com"));
        ResponseEntity<Map<String, Object>> limited = controller.requestCode(req(OWNER));

        assertEquals(200, ok.getStatusCode().value());
        assertEquals(200, stranger.getStatusCode().value(), "白名单外也必须是 200");
        assertEquals(200, limited.getStatusCode().value(), "限流也必须是 200（不能用 429 泄露'这个邮箱是真的'）");

        assertEquals(true, ok.getBody().get("ok"));
        assertEquals(AuthCodeService.CODE_TTL_SECONDS, ((Number) ok.getBody().get("expiresInSeconds")).intValue(),
                "expiresInSeconds 必须与后端真实有效期一致，不能前端写死");

        assertEquals(false, stranger.getBody().get("ok"));
        assertEquals("unavailable", stranger.getBody().get("reason"));
        assertFalse(stranger.getBody().containsKey("retryAfterSeconds"), "unavailable 分支不该带重试信息");

        assertEquals("rate_limited", limited.getBody().get("reason"));
        assertTrue(limited.getBody().containsKey("retryAfterSeconds"));
    }

    @Test
    @DisplayName("POST /api/auth/code-login 成功体与 POST /api/auth/login 逐字段一致（前端不用改解析）")
    void codeLoginBodyMatchesPasswordLogin() throws Exception {
        // 密码登录作为基准
        AuthController.LoginRequest login = new AuthController.LoginRequest();
        login.setUsername("admin");
        login.setPassword("admin123");
        Map<String, Object> passwordBody = controller.login(login).getBody();
        assertNotNull(passwordBody);

        // 验证码登录
        service.requestCode(OWNER);
        AuthController.CodeLoginRequest codeLogin = new AuthController.CodeLoginRequest();
        codeLogin.setEmail(OWNER);
        codeLogin.setCode(sender.lastCode());
        ResponseEntity<Map<String, Object>> resp = controller.codeLogin(codeLogin);

        assertEquals(200, resp.getStatusCode().value());
        Map<String, Object> codeBody = resp.getBody();
        assertNotNull(codeBody);

        assertEquals(passwordBody.keySet(), codeBody.keySet(), "顶层字段集合必须完全一致");
        assertEquals(200, codeBody.get("code"), "前端按 code===200 判成功，这一项不能变");
        assertEquals("success", codeBody.get("message"));

        @SuppressWarnings("unchecked")
        Map<String, Object> passwordData = (Map<String, Object>) passwordBody.get("data");
        @SuppressWarnings("unchecked")
        Map<String, Object> codeData = (Map<String, Object>) codeBody.get("data");
        assertEquals(passwordData.keySet(), codeData.keySet(), "data 里的字段（token/expiresIn/username/role/roleLabel）必须一致");
        assertEquals("admin", codeData.get("username"));
        assertEquals("ADMIN", codeData.get("role"));
        assertEquals(passwordData.get("expiresIn"), codeData.get("expiresIn"), "两种登录的会话有效期必须相同");

        String token = (String) codeData.get("token");
        assertTrue(authService.validate(token), "返回的 token 必须能直接用于后续请求");
    }

    @Test
    @DisplayName("POST /api/auth/code-login 失败：统一 invalid，不区分过期/错码/已用过")
    void codeLoginFailuresAreIndistinguishable() {
        service.requestCode(OWNER);
        String code = sender.lastCode();

        // 错码（消耗 1 次尝试）
        assertEquals("invalid", controller.codeLogin(codeLogin(OWNER, wrong(code))).getBody().get("reason"));
        // 形状不对的脏输入（早退，不消耗尝试次数）
        assertEquals("invalid", controller.codeLogin(codeLogin(OWNER, " 12 34 ")).getBody().get("reason"));
        // 请求体缺失
        assertEquals("invalid", controller.codeLogin(null).getBody().get("reason"));
        // 白名单外：走 isOwner 分支，既不发信也不消耗站主那个码
        assertEquals("invalid", controller.codeLogin(codeLogin("attacker@example.com", code))
                .getBody().get("reason"));
        // 过期
        ms(AuthCodeService.CODE_TTL_SECONDS * 1000L + 1);
        assertEquals("invalid", controller.codeLogin(codeLogin(OWNER, code)).getBody().get("reason"));
    }

    // ==================== 7) 配置面：默认值必须 fail-closed ====================

    @Test
    @DisplayName("application.yml：owner-email 的默认值为空（没配 = 功能关闭，不是默认开放）")
    void applicationYmlKeepsOwnerEmailEmptyByDefault() throws Exception {
        String yml = Files.readString(Path.of("src/main/resources/application.yml"), StandardCharsets.UTF_8);

        assertTrue(yml.contains("owner-email: ${APP_AUTH_OWNER_EMAIL:}"),
                "必须写成 ${APP_AUTH_OWNER_EMAIL:}（默认空）。写个默认邮箱 = 把站主身份硬编码进镜像");
        assertFalse(yml.contains("owner-email: ${APP_AUTH_OWNER_EMAIL:3053970237@qq.com}"),
                "默认邮箱不许写进代码仓库");
    }

    // ==================== 8) 不回归：密码登录照旧 ====================

    @Test
    @DisplayName("密码登录行为不变：错口令仍是 401，对口令仍是 200 + 原字段")
    void passwordLoginUnchanged() {
        AuthController.LoginRequest bad = new AuthController.LoginRequest();
        bad.setUsername("admin");
        bad.setPassword("wrong-password");
        assertEquals(401, controller.login(bad).getStatusCode().value(),
                "新增验证码不应顺手放松原有口令校验");

        AuthController.LoginRequest good = new AuthController.LoginRequest();
        good.setUsername("admin");
        good.setPassword("admin123");
        ResponseEntity<Map<String, Object>> resp = controller.login(good);
        assertEquals(200, resp.getStatusCode().value());
        assertEquals(200, resp.getBody().get("code"));
        assertNotNull(((Map<?, ?>) resp.getBody().get("data")).get("token"));
    }

    // ==================== helpers ====================

    private void ms(long delta) {
        nowMs.addAndGet(delta);
    }

    private AuthController.CodeRequest req(String email) {
        AuthController.CodeRequest r = new AuthController.CodeRequest();
        r.setEmail(email);
        return r;
    }

    private AuthController.CodeLoginRequest codeLogin(String email, String code) {
        AuthController.CodeLoginRequest r = new AuthController.CodeLoginRequest();
        r.setEmail(email);
        r.setCode(code);
        return r;
    }

    /** 造一个"肯定不对"的 6 位码。 */
    private static String wrong(String correct) {
        int n = Integer.parseInt(correct);
        return String.format("%06d", (n + 1) % 1_000_000);
    }

    /** 发信替身：记下每次真正"发出去"的收件人与验证码，绝不碰网络。 */
    private static final class FakeSender implements AuthCodeSender {

        final List<String> recipients = new ArrayList<>();
        final List<String> codes = new ArrayList<>();
        /** 调用次数：失败也要计数（"有没有尝试发"与"有没有发成功"是两件事） */
        int attempts;
        boolean fail;

        @Override
        public boolean send(String toEmail, String code, int expiresInSeconds) {
            attempts++;
            if (fail) {
                return false;
            }
            recipients.add(toEmail);
            codes.add(code);
            return true;
        }

        String lastCode() {
            return codes.isEmpty() ? null : codes.get(codes.size() - 1);
        }
    }
}
