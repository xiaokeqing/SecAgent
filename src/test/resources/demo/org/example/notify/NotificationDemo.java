package org.example.notify;

import org.example.core.model.AlertSeverity;

import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 通知中枢的<b>本地可验证</b>驱动程序（不是生产代码，只用来"让手机之外的人也能看见"）。
 *
 * <h3>为什么需要它</h3>
 * "通知"这件事有个很麻烦的验证特性：它的成功表现是<b>手机响了</b>，
 * 而这台机器上没人能看见手机。于是最容易被当成"我配好了、应该能用"。
 * 这个类把同一条链路（模板 → 降噪 → HTTP POST）跑一遍，
 * 目标指向本机的一个 sink（{@code python3 -m http.server} / {@code nc -l}），
 * 于是"到底发出去几条、被降噪挡掉几条"变成屏幕上看得见的输出。
 *
 * <h3>用法（见 RUNBOOK §19）</h3>
 * <pre>
 * # 终端 1：起一个本地 sink（把 POST 请求体打出来）
 * python3 scripts/notify-sink.py 18099
 *
 * # 终端 2：build-classpath 之后编译并运行本类
 * mvn -B -o dependency:build-classpath -Dmdep.outputFile=target/cp.txt -q
 * javac -encoding UTF-8 -d target/demo -cp "target/classes;$(cat target/cp.txt)" \
 *       src/test/resources/demo/org/example/notify/NotificationDemo.java
 * # 用独立 java 进程运行（不加载整个 Spring 上下文，因此不需要任何真实配置）
 * java -cp "target/demo;target/classes;$(cat target/cp.txt)" \
 *      org.example.notify.NotificationDemo http://127.0.0.1:18099/
 * </pre>
 *
 * <p>它刻意用 {@code out.println} 把每一次调用的返回结果（SENT / SUPPRESSED / MERGED / …）
 * 逐条打出来 —— 这些返回值就是"降噪规则此刻的判断"，比看 sink 里收到了几条更能说明问题。
 */
public final class NotificationDemo {

    private NotificationDemo() {
    }

    public static void main(String[] args) throws Exception {
        String url = (args != null && args.length > 0 && !args[0].isBlank())
                ? args[0] : "http://127.0.0.1:18099/";

        NotificationAudit audit = new NotificationAudit();
        NotificationDemoSupport.setField(audit, "auditFile", "notify-demo-audit.jsonl");

        HttpWebhookTransport transport = new HttpWebhookTransport(
                org.example.config.OutboundTimeouts.defaults(), null, 5000);
        NotificationService svc = new NotificationService(transport, audit);

        Map<String, Object> cfg = new LinkedHashMap<>();
        cfg.put("app.notify.webhook-url", url);
        cfg.put("app.notify.webhook-template", "(默认) " + NotificationTemplate.DEFAULT_TEMPLATE);
        cfg.put("app.notify.min-severity", "HIGH");
        cfg.put("app.notify.cooldown-seconds", 300L);
        cfg.put("app.notify.night-quiet", "22:00-07:00");
        cfg.put("app.notify.same-ip-merge-seconds", 600L);
        cfg.put("app.notify.max-attempts", 3);

        // 固定的"夜间"时刻：一条 MEDIUM 演示夜间静默；HIGH/CRITICAL 不受影响
        LocalDateTime night = LocalDateTime.of(2026, 10, 13, 23, 30, 0);
        AtomicLong ms = new AtomicLong(System.currentTimeMillis());
        NotificationDemoSupport.setField(svc, "webhookUrl", url);
        NotificationDemoSupport.setField(svc, "cooldownSeconds", 300L);
        NotificationDemoSupport.setField(svc, "nightQuiet", "22:00-07:00");
        NotificationDemoSupport.setField(svc, "maxAttempts", 3);
        NotificationDemoSupport.setField(svc, "retryBackoffMs", 100L);
        NotificationDemoSupport.setField(svc, "mergeFlushDelayMs", 800L);
        NotificationDemoSupport.setClock(svc, () -> night, ms::get);

        System.out.println("=== 通知中枢本地验证 ===");
        System.out.println("目标 sink      : " + url);
        System.out.println("（时钟固定在夜间 " + night + "，用来演示夜间静默只压低等级）");
        System.out.println();

        // 第 1 组：关掉"同 IP 合并"，单看 冷却 是不是按 dedupKey 生效。
        // 为什么要分两组：合并窗口会把"带 IP 的事件"整体接管（那是对的），
        // 于是冷却的效果在带 IP 的事件上根本显不出来 —— 混在一起演示等于没演示。
        NotificationDemoSupport.setField(svc, "sameIpMergeSeconds", 0L);
        System.out.println("--- 第 1 组：同类事件冷却（NOTIFY SAME_IP_MERGE=0，关掉合并）---");
        System.out.println("    生效配置   : " + svc.describe());
        step(svc, "A 高危告警（HIGH，带 IP）—— 预期 SENT",
                NotifyEvent.of(NotifyEvent.Type.HIGH_ALERT, AlertSeverity.HIGH,
                        "[高危] SSH 暴力破解尝试", "规则=5712；来源=45.83.91.12；触发=poller",
                        "alert:demo-1", "45.83.91.12", "system"));
        for (int i = 2; i <= 3; i++) {
            step(svc, "B 同一 dedupKey 的第 " + i + " 次（300s 冷却内）—— 预期 SUPPRESSED",
                    NotifyEvent.of(NotifyEvent.Type.HIGH_ALERT, AlertSeverity.HIGH,
                            "[高危] SSH 暴力破解尝试", "重复上报",
                            "alert:demo-1", "45.83.91.12", "system"));
        }
        step(svc, "C 无 IP 的降级事件（低等级门槛外/同键重复）—— 预期 SENT",
                NotifyEvent.of(NotifyEvent.Type.SYSTEM_DEGRADED, AlertSeverity.HIGH,
                        "系统降级：数据源不再是 REAL", "当前 MOCK",
                        "degraded:MOCK", null, "system"));
        step(svc, "D 同上降级事件再报一次（同键，冷却内）—— 预期 SUPPRESSED",
                NotifyEvent.of(NotifyEvent.Type.SYSTEM_DEGRADED, AlertSeverity.HIGH,
                        "系统降级：数据源不再是 REAL", "当前 MOCK",
                        "degraded:MOCK", null, "system"));

        // 第 2 组：打开"同 IP 合并"，看多条同类事件汇合成一条「聚合 N 次」
        System.out.println();
        System.out.println("--- 第 2 组：同 IP 合并（NOTIFY SAME_IP_MERGE=600）---");
        NotificationDemoSupport.setField(svc, "sameIpMergeSeconds", 600L);
        System.out.println("    生效配置   : " + svc.describe());
        step(svc, "E 同一来源第 1 条（进入合并窗口）—— 预期 MERGED",
                NotifyEvent.of(NotifyEvent.Type.HIGH_ALERT, AlertSeverity.HIGH,
                        "[高危] Web 目录扫描", "来源=198.51.100.7", "alert:demo-9", "198.51.100.7", "system"));
        step(svc, "F 同一来源第 2 条（并入）—— 预期 MERGED",
                NotifyEvent.of(NotifyEvent.Type.BLOCK_IP, AlertSeverity.HIGH,
                        "自动封禁成功：198.51.100.7", "时长=60min", "block:ok:198.51.100.7",
                        "198.51.100.7", "auto"));
        step(svc, "G 同一来源第 3 条（并入）—— 预期 MERGED",
                NotifyEvent.of(NotifyEvent.Type.HIGH_ALERT, AlertSeverity.CRITICAL,
                        "[严重] SQL 注入尝试", "来源=198.51.100.7", "alert:demo-10", "198.51.100.7", "system"));

        // 第 3 组：等级门槛与夜间静默
        System.out.println();
        System.out.println("--- 第 3 组：夜间静默（22:00-07:00 只压 INFO/MEDIUM）---");
        step(svc, "H 夜间 MEDIUM 解封事件 —— 预期 SUPPRESSED（低等级被静默）",
                NotifyEvent.of(NotifyEvent.Type.UNBLOCK_IP, AlertSeverity.MEDIUM,
                        "已解封：203.0.113.77", "到期自动解封", "unblock:203.0.113.77",
                        "203.0.113.77", "scheduler"));
        step(svc, "I 夜间 CRITICAL 看门狗回滚 —— 预期 SENT（呼救不受时间影响）",
                NotifyEvent.of(NotifyEvent.Type.WATCHDOG_ROLLBACK, AlertSeverity.CRITICAL,
                        "看门狗已回滚：c4f3f24 → a1b2c3d", "原因=连续 3 次不健康",
                        "rollback:a1b2c3d", null, "watchdog"));

        System.out.println();
        System.out.println("等待同 IP 聚合窗口汇合（merge-flush-delay: 800ms）……");
        Thread.sleep(1500);

        System.out.println();
        System.out.println("=== 汇总 ===");
        System.out.println("审计结果计数         : " + audit.countsByOutcome()
                + "（SENT 的条数就是 sink 应该收到的 POST 条数）");
        System.out.println("待发聚合             : " + svc.configSummary().get("pendingMerges"));
        System.out.println("审计文件             : " + Path.of(audit.auditFilePath()).toAbsolutePath());
        System.out.println("（sink 侧收到几条 POST = 上面 SENT 的条数；这就是「真发出 + 降噪生效」的证据）");
        svc.shutdown();
    }

    private static void step(NotificationService svc, String label, NotifyEvent e) {
        NotificationService.Outcome o = svc.send(e);
        System.out.printf("  %-58s → %s%n", label, o);
    }

    /**
     * 反射设私有字段的小工具。
     *
     * <p>这里刻意不用 {@code org.springframework.test.util.ReflectionTestUtils}：
     * 那个类在 test 作用域里，而这个 demo 要能被 {@code java -cp target/classes} 直接跑；
     * 引它就得把 spring-test 也放进 classpath，对一个"本地验证脚本"来说不划算。
     */
    static final class NotificationDemoSupport {
        private NotificationDemoSupport() {
        }

        static void setField(Object target, String name, Object value) {
            try {
                java.lang.reflect.Field f = target.getClass().getDeclaredField(name);
                f.setAccessible(true);
                f.set(target, value);
            } catch (Exception ex) {
                throw new IllegalStateException("设置字段失败 " + name + ": " + ex.getMessage(), ex);
            }
        }

        static void setClock(NotificationService svc, java.util.function.Supplier<LocalDateTime> clock,
                             java.util.function.Supplier<Long> millis) {
            try {
                java.lang.reflect.Method m = NotificationService.class
                        .getDeclaredMethod("setClock", java.util.function.Supplier.class,
                                java.util.function.Supplier.class);
                m.setAccessible(true);
                m.invoke(svc, clock, millis);
            } catch (Exception ex) {
                throw new IllegalStateException("设置时钟失败: " + ex.getMessage(), ex);
            }
        }
    }
}
