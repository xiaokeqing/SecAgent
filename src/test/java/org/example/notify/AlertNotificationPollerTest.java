package org.example.notify;

import org.example.core.model.AlertSeverity;
import org.example.core.model.AlertSource;
import org.example.core.model.AlertType;
import org.example.core.model.SecurityAlert;
import org.example.integration.WazuhGateway;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 高危告警巡检的测试。
 *
 * <h3>这里最重要的一条：内置样本绝不能被当成真告警推给手机</h3>
 * {@code WazuhService} 在"连得上但查询失败"时会回退成内置样本，而样本长得<b>非常像真的</b>
 * （SSH 暴力破解、SQL 注入、Webshell，IP 用文档保留地址）—— 只看手机上的通知完全分辨不出来。
 * 这个项目已经在这类"看着成功、实际是假的"上吃过多次亏，所以巡检必须
 * 按 {@code extra.mock} 逐条剔除、且模式非 REAL 时整轮跳过。
 */
class AlertNotificationPollerTest {

    private static final class Recorder implements NotificationService.Transport {
        final List<String> bodies = new java.util.concurrent.CopyOnWriteArrayList<>();

        @Override
        public NotificationService.Delivery post(String url, String jsonBody) {
            bodies.add(jsonBody);
            return NotificationService.Delivery.ok(200);
        }
    }

    private static ObjectProvider<WazuhGateway> provider(WazuhGateway gw) {
        return new ObjectProvider<>() {
            @Override
            public WazuhGateway getObject() {
                return gw;
            }

            @Override
            public WazuhGateway getObject(Object... args) {
                return gw;
            }

            @Override
            public WazuhGateway getIfAvailable() {
                return gw;
            }

            @Override
            public WazuhGateway getIfUnique() {
                return gw;
            }
        };
    }

    private static SecurityAlert alert(String id, AlertSeverity sev, String ip, boolean mock) {
        SecurityAlert a = new SecurityAlert(id, "SSH 暴力破解", sev, AlertType.BRUTE_FORCE, AlertSource.WAZUH);
        a.setSrcIp(ip);
        a.setRuleName("sshd 5712");
        a.setOccurredAt("2026-10-13 14:00:00");
        if (mock) {
            a.getExtra().put("mock", true);
        }
        return a;
    }

    /**
     * 用动态代理造网关替身。
     *
     * <p>不用 Mockito：本机 JDK 25 + Mockito 5.7（Spring Boot 3.2 管理版本）会对部分类报
     * "Mockito cannot mock this class"，而本仓库既有的替身写法就是动态代理
     * （见 {@code PublicAlertSourceFailClosedTest}）—— 保持一致比换工具重要。
     */
    private static WazuhGateway gateway(String mode, List<SecurityAlert> alerts) {
        return (WazuhGateway) java.lang.reflect.Proxy.newProxyInstance(
                WazuhGateway.class.getClassLoader(),
                new Class<?>[]{WazuhGateway.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "mode" -> mode;
                    case "isAvailable" -> "REAL".equalsIgnoreCase(mode);
                    case "recentAlerts" -> alerts;
                    case "toString" -> "StubGateway(" + mode + ")";
                    default -> null;
                });
    }

    /** 网关查询抛异常的替身（模拟 indexer 超时） */
    private static WazuhGateway brokenGateway() {
        return (WazuhGateway) java.lang.reflect.Proxy.newProxyInstance(
                WazuhGateway.class.getClassLoader(),
                new Class<?>[]{WazuhGateway.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "mode" -> "REAL";
                    case "isAvailable" -> true;
                    case "recentAlerts" -> throw new IllegalStateException("indexer 超时");
                    case "toString" -> "BrokenGateway";
                    default -> null;
                });
    }

    private static NotificationService configuredService(Recorder rec) {
        NotificationService svc = new NotificationService(rec, new NotificationAudit());
        ReflectionTestUtils.setField(svc, "webhookUrl", "http://127.0.0.1:18099/sink");
        ReflectionTestUtils.setField(svc, "cooldownSeconds", 0L);
        ReflectionTestUtils.setField(svc, "sameIpMergeSeconds", 0L);
        ReflectionTestUtils.setField(svc, "nightQuiet", "");
        ReflectionTestUtils.setField(svc, "minSeverityRaw", "HIGH");
        return svc;
    }

    @Test
    @DisplayName("REAL 模式下只推真实高危告警，内置样本(mock=true)与低等级一律剔除")
    void pushesOnlyRealHighSeverityAlerts() {
        Recorder rec = new Recorder();
        NotificationService svc = configuredService(rec);
        SecurityEventNotifier notifier = new SecurityEventNotifier(svc);
        AlertNotificationPoller poller = new AlertNotificationPoller(
                provider(gateway("REAL", List.of(
                        alert("real-1", AlertSeverity.HIGH, "45.83.91.12", false),
                        alert("mock-1", AlertSeverity.HIGH, "203.0.113.5", true),
                        alert("real-2", AlertSeverity.MEDIUM, "45.83.91.13", false)))),
                notifier, svc);
        ReflectionTestUtils.setField(poller, "enabled", true);
        ReflectionTestUtils.setField(poller, "limit", 100);

        poller.poll();

        assertEquals(1, rec.bodies.size(), "只应推 1 条：样本与 MEDIUM 都不该进通知：" + rec.bodies);
        assertTrue(rec.bodies.get(0).contains("45.83.91.12"), rec.bodies.get(0));
        assertTrue(rec.bodies.get(0).contains("SSH"), rec.bodies.get(0));
        assertTrue(!rec.bodies.get(0).contains("203.0.113.5"), "内置样本不得出现：" + rec.bodies.get(0));
    }

    @Test
    @DisplayName("模式非 REAL 时整轮不推（不拿内置样本发真告警）")
    void doesNotPushWhenModeIsNotReal() {
        Recorder rec = new Recorder();
        NotificationService svc = configuredService(rec);
        SecurityEventNotifier notifier = new SecurityEventNotifier(svc);
        AlertNotificationPoller poller = new AlertNotificationPoller(
                provider(gateway("MOCK", List.of(alert("mock-1", AlertSeverity.CRITICAL, "203.0.113.5", true)))),
                notifier, svc);
        ReflectionTestUtils.setField(poller, "enabled", true);
        ReflectionTestUtils.setField(poller, "limit", 100);

        poller.poll();
        assertEquals(0, rec.bodies.size(), "MOCK 模式下一条都不该推");
    }

    @Test
    @DisplayName("通知未配置时完全不巡检（不做无用功，也不制造假巡检日志）")
    void doesNotPollWhenNotConfigured() {
        Recorder rec = new Recorder();
        NotificationService svc = new NotificationService(rec, new NotificationAudit());
        // 刻意不设 webhookUrl → 未配置
        SecurityEventNotifier notifier = new SecurityEventNotifier(svc);
        AlertNotificationPoller poller = new AlertNotificationPoller(
                provider(gateway("REAL", List.of(alert("real-1", AlertSeverity.CRITICAL, "45.83.91.12", false)))),
                notifier, svc);
        ReflectionTestUtils.setField(poller, "enabled", true);

        poller.poll();
        assertEquals(0, rec.bodies.size());
    }

    @Test
    @DisplayName("网关抛异常时巡检不炸（只记日志，等下一轮）")
    void gatewayFailureDoesNotBreakScheduling() {
        Recorder rec = new Recorder();
        NotificationService svc = configuredService(rec);
        SecurityEventNotifier notifier = new SecurityEventNotifier(svc);
        AlertNotificationPoller poller = new AlertNotificationPoller(provider(brokenGateway()), notifier, svc);
        ReflectionTestUtils.setField(poller, "enabled", true);

        poller.poll();      // 不应抛异常
        assertEquals(0, rec.bodies.size());
    }

    @Test
    @DisplayName("isMock 判定：extra.mock=true（布尔或字符串）与「无标记」都要认对")
    void mockDetection() {
        assertTrue(AlertNotificationPoller.isMock(alert("a", AlertSeverity.HIGH, "1.1.1.1", true)));
        SecurityAlert str = alert("b", AlertSeverity.HIGH, "1.1.1.1", false);
        str.getExtra().put("mock", "true");
        assertTrue(AlertNotificationPoller.isMock(str));
        assertEquals(false, AlertNotificationPoller.isMock(alert("c", AlertSeverity.HIGH, "1.1.1.1", false)));
        assertTrue(AlertNotificationPoller.isMock(null));
    }

    /** 空列表不算失败路径，只是"这轮没东西"，不该报错也不该推 */
    @Test
    @DisplayName("空候选列表：不推、不报错")
    void emptyAlertsIsNoop() {
        Recorder rec = new Recorder();
        NotificationService svc = configuredService(rec);
        AlertNotificationPoller poller = new AlertNotificationPoller(
                provider(gateway("REAL", new ArrayList<>())),
                new SecurityEventNotifier(svc), svc);
        ReflectionTestUtils.setField(poller, "enabled", true);

        poller.poll();
        assertEquals(0, rec.bodies.size());
    }
}
