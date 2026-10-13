package org.example.notify;

import org.example.core.model.AlertSeverity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 通知中枢的行为测试：<b>模板 / 冷却 / 同 IP 合并 / 夜间静默 / 未配置降级 / 失败重试</b>。
 *
 * <h3>为什么这些必须自动化，而不能"手工发一条看看"</h3>
 * 降噪规则有个共同特征：写错了<b>不会报错</b>，只表现为"手机上多收了几百条"或
 * "该收的没收到"。前者会让人把通知关掉（于是彻底没有通知），
 * 后者要等到出事才发现。所以每条规则都得有一个断言钉住。
 *
 * <p>时间一律用可控时钟推进，不 sleep —— 需要睡 300 秒才跑得完的测试，
 * 最后一定会被从 CI 里拿掉。
 */
class NotificationServiceTest {

    // ==================== 工具 ====================

    /** 记录每次实际发出的 HTTP 请求（断言"到底发了几条"） */
    private static final class RecordingTransport implements NotificationService.Transport {
        final List<String> urls = new CopyOnWriteArrayList<>();
        final List<String> bodies = new CopyOnWriteArrayList<>();
        /** 前 N 次调用返回失败，之后成功（重试用） */
        int failFirstN = 0;
        int calls = 0;
        int httpCode = 200;

        @Override
        public NotificationService.Delivery post(String requestUrl, String jsonBody) {
            calls++;
            if (calls <= failFirstN) {
                return NotificationService.Delivery.fail(500, "模拟对端 500");
            }
            urls.add(requestUrl);
            bodies.add(jsonBody);
            return NotificationService.Delivery.ok(httpCode);
        }

        int sent() {
            return bodies.size();
        }
    }

    /** 可控时钟：单测里拨动它，而不是让测试真的等 */
    private static final class FakeClock {
        LocalDateTime now = LocalDateTime.of(2026, 10, 13, 14, 0, 0);
        long epochMs = 1_700_000_000_000L;

        void advanceSeconds(long s) {
            now = now.plusSeconds(s);
            epochMs += s * 1000L;
        }
    }

    private static NotificationService service(RecordingTransport transport, NotificationAudit audit,
                                               FakeClock clock) {
        NotificationService svc = new NotificationService(transport, audit);
        svc.setClock(() -> clock.now, () -> clock.epochMs);
        return svc;
    }

    private static void configure(NotificationService svc, String url, String template,
                                  long cooldownSec, long mergeSec, String nightQuiet, int maxAttempts) {
        ReflectionTestUtils.setField(svc, "webhookUrl", url);
        ReflectionTestUtils.setField(svc, "webhookTemplate", template);
        ReflectionTestUtils.setField(svc, "cooldownSeconds", cooldownSec);
        ReflectionTestUtils.setField(svc, "sameIpMergeSeconds", mergeSec);
        ReflectionTestUtils.setField(svc, "nightQuiet", nightQuiet);
        ReflectionTestUtils.setField(svc, "maxAttempts", maxAttempts);
        ReflectionTestUtils.setField(svc, "retryBackoffMs", 0L);
        ReflectionTestUtils.setField(svc, "mergeFlushDelayMs", 3_600_000L);   // 合并窗口内不自动 flush
        ReflectionTestUtils.setField(svc, "minSeverityRaw", "HIGH");
    }

    private static NotifyEvent alert(String id, String ip, AlertSeverity sev) {
        return NotifyEvent.of(NotifyEvent.Type.HIGH_ALERT, sev,
                "[" + sev.getLabel() + "] SSH 暴力破解 #" + id,
                "规则=sshd；来源=" + ip,
                "alert:" + id, ip, "system");
    }

    // ==================== 1) 模板渲染 ====================

    @Test
    @DisplayName("默认模板渲染出合法通用 JSON，且变量里的引号被正确转义")
    void defaultTemplateRendersValidJson() throws Exception {
        String json = NotificationTemplate.render(null, Map.of(
                "title", "高危告警",
                "body", "规则=\"5712\" 含引号与换行\n第二行",
                "severity", "HIGH"));

        assertTrue(json.startsWith("{\"text\":\""), "默认模板要 POST 通用 {\"text\":...}：" + json);
        // 关键：值里的引号必须转义，否则拼出来是非法 JSON，对端 400 而日志只写"发送失败"
        assertTrue(json.contains("\\\"5712\\\""), "引号未转义：" + json);
        assertTrue(json.contains("\\n第二行"), "换行必须是 JSON 转义而不是真实换行：" + json);
        assertFalse(json.contains("\n"), "渲染结果里不许有真实换行：" + json);
        // 渲染后必须仍是合法 JSON（本方法内部也会校验一次，这里显式断言更直观）
        new com.fasterxml.jackson.databind.ObjectMapper().readTree(json);
    }

    @Test
    @DisplayName("Telegram/飞书式自定义模板可渲染，未知变量直接失败（不静默替换成空串）")
    void customTemplateAndUnknownVariable() {
        String feishu = "{\"msg_type\":\"text\",\"content\":{\"text\":\"{{title}} / {{count}} 次\"}}";
        String out = NotificationTemplate.render(feishu, Map.of("title", "系统降级", "count", "3"));
        assertTrue(out.contains("\"系统降级 / 3 次\""), out);

        // 写错变量名必须抛错：否则通知会"看起来发出去了"，只是正文少一截
        IllegalArgumentException e = org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> NotificationTemplate.render(feishu, Map.of("titel", "x", "count", "1")));
        assertTrue(e.getMessage().contains("titel"), e.getMessage());
    }

    // ==================== 2) 未配置时如实降级 ====================

    @Test
    @DisplayName("未配置 webhook：不出网、返回 NOT_CONFIGURED 并写审计（不假装成功）")
    void notConfiguredDegradesHonestly(@TempDir Path dir) throws Exception {
        RecordingTransport t = new RecordingTransport();
        Path auditFile = dir.resolve("notify-audit.jsonl");
        NotificationAudit audit = new NotificationAudit();
        ReflectionTestUtils.setField(audit, "auditFile", auditFile.toString());

        FakeClock clock = new FakeClock();
        NotificationService svc = service(t, audit, clock);
        configure(svc, "", null, 300, 600, "22:00-07:00", 3);

        NotificationService.Outcome o = svc.send(alert("a1", "203.0.113.9", AlertSeverity.HIGH));
        assertEquals(NotificationService.Outcome.NOT_CONFIGURED, o);
        assertEquals(0, t.sent(), "未配置时绝不允许出网");

        // 必须留痕：谁在什么时候想通知、结果如何
        assertTrue(Files.exists(auditFile), "未配置也要写审计：" + auditFile);
        String line = Files.readString(auditFile, StandardCharsets.UTF_8);
        assertTrue(line.contains("NOT_CONFIGURED"), line);
        assertTrue(line.contains("HIGH_ALERT"), line);
        assertTrue(line.contains("203.0.113.x"), "审计里的 IP 必须掩码：" + line);
        assertFalse(line.contains("203.0.113.9"), "审计里不许出现完整 IP：" + line);
        assertFalse(svc.configured(), "空 URL 时 configured() 必须为 false");
        assertTrue(svc.describe().contains("NOT-CONFIGURED"), svc.describe());
    }

    // ==================== 3) 冷却去重 ====================

    @Test
    @DisplayName("冷却期内同类事件不重复发，冷却结束后再发（默认 300s）")
    void cooldownSuppressesRepeats() {
        RecordingTransport t = new RecordingTransport();
        FakeClock clock = new FakeClock();
        NotificationService svc = service(t, new NotificationAudit(), clock);
        configure(svc, "http://127.0.0.1:18099/sink", null, 300, 0, "", 3);

        // 同一个 dedupKey（同一 IP 的同类封禁失败）在冷却期内连发三次
        for (int i = 0; i < 3; i++) {
            svc.send(NotifyEvent.of(NotifyEvent.Type.BLOCK_FAILED, null,
                    "自动封禁失败：198.51.100.7", "第 " + i + " 次",
                    "block:fail:198.51.100.7", "198.51.100.7", "admin"));
        }
        assertEquals(1, t.sent(), "冷却期内只允许发一条");

        clock.advanceSeconds(301);
        svc.send(NotifyEvent.of(NotifyEvent.Type.BLOCK_FAILED, null,
                "自动封禁失败：198.51.100.7", "冷却已过",
                "block:fail:198.51.100.7", "198.51.100.7", "admin"));
        assertEquals(2, t.sent(), "冷却结束后应再发一条");
    }

    // ==================== 4) 同 IP 合并 ====================

    @Test
    @DisplayName("同 IP 多类事件在合并窗口内只发一条「聚合 N 次」")
    void sameIpEventsMergeIntoOne() {
        RecordingTransport t = new RecordingTransport();
        FakeClock clock = new FakeClock();
        NotificationService svc = service(t, new NotificationAudit(), clock);
        // 冷却置 0，只考察合并行为本身
        configure(svc, "http://127.0.0.1:18099/sink", null, 0, 600, "", 3);

        String ip = "45.83.91.12";
        assertEquals(NotificationService.Outcome.MERGED,
                svc.send(alert("m1", ip, AlertSeverity.HIGH)));
        assertEquals(NotificationService.Outcome.MERGED,
                svc.send(NotifyEvent.of(NotifyEvent.Type.BLOCK_IP, null,
                        "自动封禁成功：" + ip, "", "block:ok:" + ip, ip, "auto")));
        assertEquals(NotificationService.Outcome.MERGED,
                svc.send(alert("m2", ip, AlertSeverity.CRITICAL)));
        assertEquals(0, t.sent(), "合并窗口内先不发，等窗口汇合（否则就是换标题刷屏）");
        assertEquals(1, svc.pendingMerges(), "同一个 IP 只应有一个待发聚合条目");

        int flushed = svc.flushPending();
        assertEquals(1, flushed);
        assertEquals(1, t.sent(), "三条同类事件必须只发一条");
        String body = t.bodies.get(0);
        assertTrue(body.contains("聚合 3 次"), "聚合条数要写进正文：" + body);
        assertTrue(body.contains(ip), body);

        // 已发过的那一条不再重复：窗口内第 4 条只累加计数
        svc.send(alert("m3", ip, AlertSeverity.HIGH));
        svc.flushPending();
        assertEquals(1, t.sent(), "同一窗口内不允许再发第二条聚合通知");
    }

    // ==================== 5) 夜间静默 ====================

    @Test
    @DisplayName("夜间静默只压 INFO/MEDIUM；HIGH 照发（跨零点窗口）")
    void nightQuietOnlySuppressesLowSeverity() {
        RecordingTransport t = new RecordingTransport();
        FakeClock clock = new FakeClock();
        NotificationService svc = service(t, new NotificationAudit(), clock);
        // 门槛放到 INFO，这样"被压制"只能来自夜间静默，而不会是等级门槛
        configure(svc, "http://127.0.0.1:18099/sink", null, 0, 0, "22:00-07:00", 3);
        ReflectionTestUtils.setField(svc, "minSeverityRaw", "INFO");

        clock.now = LocalDateTime.of(2026, 10, 13, 23, 30, 0);      // 夜间
        assertEquals(NotificationService.Outcome.SUPPRESSED,
                svc.send(NotifyEvent.of(NotifyEvent.Type.UNBLOCK_IP, AlertSeverity.LOW,
                        "已解封：203.0.113.5", "", "unblock:203.0.113.5", "203.0.113.5", "scheduler")));
        assertEquals(0, t.sent(), "夜间 LOW 应被静默");

        assertEquals(NotificationService.Outcome.SENT,
                svc.send(alert("night1", "203.0.113.6", AlertSeverity.HIGH)));
        assertEquals(1, t.sent(), "夜间 HIGH 必须照发 —— 呼救与时间无关");

        clock.now = LocalDateTime.of(2026, 10, 14, 3, 0, 0);        // 凌晨（跨零点窗口的另一端）
        assertEquals(NotificationService.Outcome.SENT,
                svc.send(alert("night2", "203.0.113.7", AlertSeverity.CRITICAL)));
        assertEquals(2, t.sent());

        clock.now = LocalDateTime.of(2026, 10, 14, 9, 0, 0);        // 白天
        assertEquals(NotificationService.Outcome.SENT,
                svc.send(NotifyEvent.of(NotifyEvent.Type.UNBLOCK_IP, AlertSeverity.LOW,
                        "已解封：203.0.113.8", "", "unblock:203.0.113.8", "203.0.113.8", "scheduler")));
        assertEquals(3, t.sent(), "白天 LOW 不该被压制");
    }

    @Test
    @DisplayName("等级门槛：低于 NOTIFY_MIN_SEVERITY 的事件不出网")
    void belowMinSeverityIsNotSent() {
        RecordingTransport t = new RecordingTransport();
        FakeClock clock = new FakeClock();
        NotificationService svc = service(t, new NotificationAudit(), clock);
        svc.setClock(() -> clock.now, () -> clock.epochMs);
        configure(svc, "http://127.0.0.1:18099/sink", null, 0, 0, "", 3);
        clock.now = LocalDateTime.of(2026, 10, 13, 10, 0, 0);      // 白天，排除夜间静默干扰

        assertEquals(NotificationService.Outcome.SUPPRESSED,
                svc.send(NotifyEvent.of(NotifyEvent.Type.UNBLOCK_IP, AlertSeverity.LOW,
                        "已解封", "", "unblock:1", "203.0.113.20", "scheduler")));
        assertEquals(0, t.sent());

        assertEquals(NotificationService.Outcome.SENT,
                svc.send(alert("sev1", "203.0.113.21", AlertSeverity.HIGH)));
        assertEquals(1, t.sent());
    }

    // ==================== 6) 发送失败重试 ====================

    @Test
    @DisplayName("发送失败会有限次重试，失败结果如实写审计；带 IP 的事件还会收到聚合形态")
    void retriesThenSucceedsOrFailsHonestly(@TempDir Path dir) throws Exception {
        Path auditFile = dir.resolve("notify-audit.jsonl");
        NotificationAudit audit = new NotificationAudit();
        ReflectionTestUtils.setField(audit, "auditFile", auditFile.toString());

        // 前两次 500，第三次成功 → 应该 SENT，且审计里 attempts=3
        RecordingTransport t = new RecordingTransport();
        t.failFirstN = 2;
        FakeClock clock = new FakeClock();
        NotificationService svc = service(t, audit, clock);
        configure(svc, "http://127.0.0.1:18099/sink", null, 300, 0, "", 3);

        assertEquals(NotificationService.Outcome.SENT,
                svc.send(NotifyEvent.of(NotifyEvent.Type.WATCHDOG_ROLLBACK, null,
                        "看门狗已回滚", "abc → def", "rollback:def", null, "watchdog")));
        assertEquals(3, t.calls, "必须是 3 次尝试（两次失败 + 一次成功）");
        assertEquals(1, t.sent());
        String written = Files.readString(auditFile, StandardCharsets.UTF_8);
        assertTrue(written.contains("SENT"), written);
        assertTrue(written.contains("\"attempts\":3"), "重试次数必须留痕：" + written);
    }

    @Test
    @DisplayName("重试用尽仍失败：FAILED 写审计 + 通知通道异常单独告警一次（且不递归）")
    void exhaustedRetriesRecordedAndReported() {
        RecordingTransport t = new RecordingTransport();
        t.failFirstN = 100;      // 永远失败
        FakeClock clock = new FakeClock();
        NotificationService svc = service(t, new NotificationAudit(), clock);
        configure(svc, "http://127.0.0.1:18099/sink", null, 300, 0, "", 2);

        assertEquals(NotificationService.Outcome.FAILED,
                svc.send(NotifyEvent.of(NotifyEvent.Type.SYSTEM_DEGRADED, null,
                        "系统降级", "数据源 MOCK", "degraded:MOCK", null, "system")));
        // 2 次原事件重试 + 1 次"通知通道异常"告警（它自己只试一次，不再重试）
        assertEquals(3, t.calls, "原事件重试 2 次 + 通道异常告警 1 次");
        assertEquals(0, t.sent());

        // 再看 NOTIFY_FAILED 自身：不许再触发递归告警。
        // 期望恰好 +2 = 只有本次 sender 自己的 2 次尝试；
        // 若递归守卫失效，这里会额外多出"通道异常告警"的尝试（>2）
        int before = t.calls;
        assertEquals(NotificationService.Outcome.FAILED,
                svc.send(NotifyEvent.of(NotifyEvent.Type.NOTIFY_FAILED, null,
                        "通知通道异常", "又一次", "notify-failed:x", null, "system")));
        assertEquals(2, t.calls - before,
                "NOTIFY_FAILED 自身失败不得再触发一层告警（防自我放大）");
    }

    // ==================== 7) 多路由地址 ====================

    @Test
    @DisplayName("webhook 地址支持按事件类型分流，回滚与告警可发给不同机器人")
    void webhookUrlRoutesByEventType() {
        FakeClock clock = new FakeClock();
        NotificationService svc = service(new RecordingTransport(), new NotificationAudit(), clock);
        configure(svc,
                "https://hook.example/default|WATCHDOG_ROLLBACK=https://hook.example/ops",
                null, 0, 0, "", 1);

        assertEquals("https://hook.example/ops",
                svc.resolveWebhookUrl(NotifyEvent.of(NotifyEvent.Type.WATCHDOG_ROLLBACK, null,
                        "回滚", "", "r:1", null, "watchdog")));
        assertEquals("https://hook.example/default",
                svc.resolveWebhookUrl(alert("r1", "203.0.113.1", AlertSeverity.HIGH)));
    }

    // ==================== 8) 领域门面：只推新高危、跳过已封禁源 ====================

    @Test
    @DisplayName("高危告警只推一次、跳过已被封禁的源，并如实统计")
    void highSeverityAlertsDeduplicatedByAlertId() {
        RecordingTransport t = new RecordingTransport();
        FakeClock clock = new FakeClock();
        NotificationService svc = service(t, new NotificationAudit(), clock);
        configure(svc, "http://127.0.0.1:18099/sink", null, 0, 0, "", 3);
        SecurityEventNotifier notifier = new SecurityEventNotifier(svc);

        List<org.example.core.model.SecurityAlert> alerts = new ArrayList<>();
        alerts.add(secAlert("wz-1", "SSH 暴力破解", AlertSeverity.HIGH, "203.0.113.31"));
        alerts.add(secAlert("wz-2", "目录扫描", AlertSeverity.MEDIUM, "203.0.113.32"));   // 低于 HIGH
        alerts.add(secAlert("wz-3", "Webshell 上传", AlertSeverity.CRITICAL, "203.0.113.33"));

        assertEquals(2, notifier.highSeverityAlerts(alerts, "poller"), "只有 HIGH/CRITICAL 进通知中枢");
        assertEquals(2, t.sent());

        // 同一批再来一次：按 alertId 去重，不再重复推送
        assertEquals(0, notifier.highSeverityAlerts(alerts, "poller"));
        assertEquals(2, t.sent());

        // 已封禁的源不再刷通知（处置完了还在推，只会训练人忽略通知）
        SecurityEventNotifier n2 = new SecurityEventNotifier(svc);
        n2.blockIp("203.0.113.40", true, "REAL", "手动封禁", "admin", 60);
        int before = t.sent();
        assertEquals(0, n2.highSeverityAlerts(
                List.of(secAlert("wz-9", "继续攻击", AlertSeverity.HIGH, "203.0.113.40")), "poller"));
        assertEquals(before, t.sent(), "已封禁 IP 的告警不再推送");
    }

    @Test
    @DisplayName("降级/恢复成对通知，且模式未变化时不重复推（恢复是 MEDIUM，门槛需放宽才可见）")
    void degradeAndRecoverArePaired() {
        RecordingTransport t = new RecordingTransport();
        FakeClock clock = new FakeClock();
        NotificationService svc = service(t, new NotificationAudit(), clock);
        configure(svc, "http://127.0.0.1:18099/sink", null, 0, 0, "", 3);
        // 恢复事件是 MEDIUM：默认门槛 HIGH 下<b>它会被门槛挡住</b>（这是设计，
        // 见 NotifyEvent.defaultSeverity —— 恢复不是呼救）。
        // 本条测试要验证的是"成对通知"的机制本身，所以把门槛放宽到 MEDIUM 再看。
        ReflectionTestUtils.setField(svc, "minSeverityRaw", "MEDIUM");
        SecurityEventNotifier notifier = new SecurityEventNotifier(svc);

        assertFalse(notifier.observeMode("REAL"), "首次只记录，不通知（启动时的初始值不是「变化」）");
        assertEquals(0, t.sent());

        assertTrue(notifier.observeMode("MOCK"));
        assertTrue(t.bodies.get(0).contains("系统降级"), t.bodies.get(0));

        assertFalse(notifier.observeMode("MOCK"), "模式没变就不该再推");
        assertEquals(1, t.sent());

        assertTrue(notifier.observeMode("REAL"));
        assertTrue(t.bodies.get(1).contains("系统已恢复"), t.bodies.get(1));
        assertEquals(2, t.sent());
    }

    @Test
    @DisplayName("默认门槛 HIGH 下「系统恢复」（MEDIUM）被门槛挡住 —— 恢复不是呼救")
    void recoveryIsBelowDefaultThreshold() {
        RecordingTransport t = new RecordingTransport();
        FakeClock clock = new FakeClock();
        NotificationService svc = service(t, new NotificationAudit(), clock);
        configure(svc, "http://127.0.0.1:18099/sink", null, 0, 0, "", 3);
        SecurityEventNotifier notifier = new SecurityEventNotifier(svc);

        notifier.observeMode("MOCK");            // 首次记录
        assertEquals(NotificationService.Outcome.SUPPRESSED,
                svc.send(NotifyEvent.of(NotifyEvent.Type.SYSTEM_RECOVERED, null,
                        "系统已恢复", "回到 REAL", "recovered:REAL", null, "system")));
        assertEquals(0, t.sent(), "MEDIUM 的恢复事件在默认门槛下不发");
    }

    private static org.example.core.model.SecurityAlert secAlert(String id, String title,
                                                                 AlertSeverity sev, String ip) {
        org.example.core.model.SecurityAlert a = new org.example.core.model.SecurityAlert(
                id, title, sev, org.example.core.model.AlertType.SCAN,
                org.example.core.model.AlertSource.WAZUH);
        a.setRuleName("rule-" + id);
        a.setSrcIp(ip);
        a.setDstAsset("web-01");
        a.setOccurredAt("2026-10-13 14:00:00");
        assertNotNull(a.getExtra());
        return a;
    }
}
