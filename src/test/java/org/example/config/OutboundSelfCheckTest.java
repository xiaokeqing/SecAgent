package org.example.config;

import org.example.integration.wazuh.SshBlockExecutor;
import org.example.integration.wazuh.WazuhService;
import org.example.llm.OutboundGuard;
import org.example.service.VectorEmbeddingService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 出站超时"启动自检"与统一配置的测试。
 *
 * <h3>为什么这两件事要一起测</h3>
 * 自检的价值在于"打印的就是实际生效值"。所以断言不能只看"日志里有几行"，
 * 必须同时钉住：
 * <ul>
 *   <li>统一配置确实是 3s / 12s / 15s（写错就没人发现的那种静默问题）；</li>
 *   <li>自检覆盖<b>每一个</b>出站依赖（漏掉一个 = 事后核对时以为"没这个依赖"）；</li>
 *   <li>没配的项显式写 {@code MISSING}，不是留空（留空会被读成"没超时"）。</li>
 * </ul>
 */
class OutboundSelfCheckTest {

    /** 期望被自检覆盖的出站依赖（少一个就失败，防"新加了客户端但忘了登记"） */
    private static final List<String> EXPECTED_DEPENDENCIES = List.of(
            "dashscope-chat",
            "dashscope-embedding",
            "wazuh-api",
            "wazuh-indexer",
            "public-indexer",
            "ssh-block",
            "prometheus",
            "milvus",
            // 通知中枢的 webhook 出站：它也必须出现在自检里，
            // 否则"通知没配"这件事在运行期完全不可见（URL 为空的表现就是什么都没发生）
            "notify-webhook");

    private static OutboundSelfCheck selfCheck(long connect, long read, long call) {
        OutboundTimeouts timeouts = new OutboundTimeouts(connect, read, call);

        DashScopeConfig dashScope = new DashScopeConfig();
        ReflectionTestUtils.setField(dashScope, "connectTimeout", connect);
        ReflectionTestUtils.setField(dashScope, "readTimeout", read);
        ReflectionTestUtils.setField(dashScope, "callTimeout", call);

        VectorEmbeddingService embedding = new VectorEmbeddingService();
        ReflectionTestUtils.setField(embedding, "embeddingTimeoutMs", 8000L);

        OutboundGuard guard = new OutboundGuard();
        ReflectionTestUtils.setField(guard, "defaultCooldownMs", 60000L);
        ReflectionTestUtils.setField(guard, "maxInflightPerDependency", 2);
        SshBlockExecutor ssh = new SshBlockExecutor(guard, timeouts);

        WazuhService wazuh = new WazuhService();
        ReflectionTestUtils.setField(wazuh, "outboundTimeouts", timeouts);

        OutboundSelfCheck check = new OutboundSelfCheck(timeouts, dashScope, embedding, ssh, wazuh);
        ReflectionTestUtils.setField(check, "vectorStore", "memory");
        ReflectionTestUtils.setField(check, "milvusConnectMs", 10000L);
        ReflectionTestUtils.setField(check, "prometheusMock", true);
        ReflectionTestUtils.setField(check, "prometheusTimeoutSeconds", 10);
        ReflectionTestUtils.setField(check, "cooldownMs", 60000L);
        ReflectionTestUtils.setField(check, "maxInflight", 2);
        return check;
    }

    @Test
    @DisplayName("默认统一超时是 connect 3s / read 12s / call 15s，且非法值不会退化成永不超时")
    void defaultsAreBounded() {
        OutboundTimeouts d = OutboundTimeouts.defaults();
        assertEquals(3000L, d.getConnectTimeoutMs());
        assertEquals(12000L, d.getReadTimeoutMs());
        assertEquals(15000L, d.getCallTimeoutMs());

        // 配置写成 0/负数时不能变成"永不超时"（那正是本项要修的故障形态）
        OutboundTimeouts broken = new OutboundTimeouts(0, -1, 0);
        assertEquals(3000L, broken.getConnectTimeoutMs());
        assertEquals(12000L, broken.getReadTimeoutMs());
        assertEquals(15000L, broken.getCallTimeoutMs());
    }

    @Test
    @DisplayName("启动自检一行里覆盖每个出站依赖，并给出 connect/read/callTimeout/circuit")
    void selfCheckCoversEveryDependency() {
        OutboundSelfCheck check = selfCheck(3000, 12000, 15000);
        List<OutboundSelfCheck.Dependency> rows = check.dependencies();

        List<String> names = rows.stream().map(OutboundSelfCheck.Dependency::name).toList();
        for (String expected : EXPECTED_DEPENDENCIES) {
            assertTrue(names.contains(expected),
                    "启动自检漏了出站依赖 " + expected + "（现有：" + names + "）");
        }

        String line = check.buildLine();
        assertTrue(line.startsWith(OutboundSelfCheck.MARKER), "自检日志缺少可 grep 的标记：" + line);
        assertFalse(line.contains("\n"), "自检必须是【一行】日志，不能被日志采集拆散");
        for (String expected : EXPECTED_DEPENDENCIES) {
            assertTrue(line.contains(expected), "自检行里没有 " + expected + "：" + line);
        }

        // 每个依赖都必须给出四项（缺项写 MISSING，而不是留空）
        for (OutboundSelfCheck.Dependency d : rows) {
            assertNotNull(d.connect(), d.name() + " 缺 connect");
            assertNotNull(d.read(), d.name() + " 缺 read");
            assertNotNull(d.callTimeout(), d.name() + " 缺 callTimeout");
            assertNotNull(d.circuitBreaker(), d.name() + " 缺熔断字段");
            assertFalse(d.connect().isBlank(), d.name() + " connect 为空（应当显式写 MISSING）");
            assertFalse(d.read().isBlank(), d.name() + " read 为空（应当显式写 MISSING）");
            assertFalse(d.callTimeout().isBlank(), d.name() + " callTimeout 为空（应当显式写 MISSING）");
        }
    }

    @Test
    @DisplayName("Wazuh / SSH 三类链路的实际生效值与统一配置一致，且标明复用 OutboundGuard")
    void wazuhAndSshShowUnifiedValues() {
        OutboundSelfCheck check = selfCheck(3000, 12000, 15000);
        String line = check.buildLine();

        for (String dep : List.of("wazuh-api", "wazuh-indexer", "public-indexer", "ssh-block")) {
            String row = rowOf(line, dep);
            assertTrue(row.contains("connect=3000ms"), dep + " 的 connect 不是统一值：" + row);
            assertTrue(row.contains("read=12000ms"), dep + " 的 read 不是统一值：" + row);
            assertTrue(row.contains("callTimeout=15000ms"), dep + " 的 callTimeout 不是统一值：" + row);
        }
        assertTrue(rowOf(line, "ssh-block").contains("OutboundGuard"),
                "SSH 链路必须复用 OutboundGuard：" + rowOf(line, "ssh-block"));

        // LLM 两条链路：chat 走 DashScopeConfig 的 OkHttp；embedding 的 SDK 没有显式 connect/read，
        // 必须如实标 MISSING（不能编一个数出来）
        String chat = rowOf(line, "dashscope-chat");
        assertTrue(chat.contains("connect=3000ms") && chat.contains("read=12000ms")
                && chat.contains("callTimeout=15000ms"), "chat 生效值不对：" + chat);
        String embedding = rowOf(line, "dashscope-embedding");
        assertTrue(embedding.contains("connect=" + OutboundSelfCheck.MISSING), embedding);
        assertTrue(embedding.contains("read=" + OutboundSelfCheck.MISSING), embedding);
        assertTrue(embedding.contains("callTimeout=8000ms"), embedding);
    }

    @Test
    @DisplayName("被 mock 关掉的依赖显式写 DISABLED，不许静默")
    void disabledDependenciesAreExplicit() {
        String line = selfCheck(3000, 12000, 15000).buildLine();
        assertTrue(rowOf(line, "prometheus").contains("DISABLED(mock)"),
                "prometheus 本次不发请求，必须显式标注：" + rowOf(line, "prometheus"));
        assertTrue(rowOf(line, "milvus").contains("DISABLED(vector.store=memory)"),
                "未启用 Milvus 必须显式标注：" + rowOf(line, "milvus"));
    }

    /**
     * 通知未配置时，启动自检必须显式写出来。
     *
     * <p>这条断言的意义不在于"日志好看"：{@code NOTIFY_WEBHOOK_URL} 留空的表现是
     * <b>什么都没发生</b> —— 高危告警不会来，但也没有任何报错。如果自检不写，
     * 运维会一直以为通知在工作，直到真的出事那天才发现手机从来没响过。
     */
    @Test
    @DisplayName("通知未配置时自检显式写 DISABLED(通知未配置)，不许静默")
    void notificationNotConfiguredIsExplicit() throws Exception {
        OutboundSelfCheck check = selfCheck(3000, 12000, 15000);
        org.example.notify.NotificationService notify =
                new org.example.notify.NotificationService((url, body) -> null,
                        new org.example.notify.NotificationAudit());
        // webhook-url 保持空（默认值），即"功能关闭"
        ReflectionTestUtils.setField(check, "notificationService", notify);

        String row = rowOf(check.buildLine(), "notify-webhook");
        assertTrue(row.contains("DISABLED(通知未配置"),
                "配置为空时必须显式打印「通知未配置」，而不是留空：" + row);
        assertTrue(row.contains("NOTIFY_WEBHOOK_URL"),
                "要写清楚是哪个配置项没配，否则运维不知道该填什么：" + row);
    }

    /** 配了 webhook 时，自检要打出实际生效的调用预算与守卫（值取自传送器对象） */
    @Test
    @DisplayName("通知已配置时自检给出 webhook 的 connect/read/callTimeout 与 OutboundGuard")
    void notificationConfiguredShowsEffectiveValues() throws Exception {
        OutboundSelfCheck check = selfCheck(3000, 12000, 15000);
        org.example.notify.NotificationService notify =
                new org.example.notify.NotificationService((url, body) -> null,
                        new org.example.notify.NotificationAudit());
        ReflectionTestUtils.setField(notify, "webhookUrl", "https://example.invalid/hook");
        ReflectionTestUtils.setField(notify, "minSeverityRaw", "HIGH");
        ReflectionTestUtils.setField(check, "notificationService", notify);

        org.example.llm.OutboundGuard guard = new org.example.llm.OutboundGuard();
        ReflectionTestUtils.setField(guard, "defaultCooldownMs", 60000L);
        ReflectionTestUtils.setField(guard, "maxInflightPerDependency", 2);
        org.example.notify.HttpWebhookTransport transport =
                new org.example.notify.HttpWebhookTransport(new OutboundTimeouts(3000, 12000, 15000), guard, 10000);
        ReflectionTestUtils.setField(check, "notificationTransport", transport);

        String row = rowOf(check.buildLine(), "notify-webhook");
        assertTrue(row.contains("connect=3000ms"), row);
        assertTrue(row.contains("read=12000ms"), row);
        assertTrue(row.contains("callTimeout=10000ms"),
                "调用预算要取自真正建 OkHttpClient 的传送器（这里被 app.notify.timeout-ms 收紧了）：" + row);
        assertTrue(row.contains("OutboundGuard"), "webhook 出站必须复用 OutboundGuard：" + row);
    }

    /** 从一行自检里取出某个依赖的片段（到下一个依赖之前） */
    private static String rowOf(String line, String name) {
        String key = name + "{";
        int i = line.indexOf(key);
        assertTrue(i >= 0, "自检行里找不到依赖 " + name + "：" + line);
        int j = line.indexOf(" | ", i);
        return (j < 0) ? line.substring(i) : line.substring(i, j);
    }
}
