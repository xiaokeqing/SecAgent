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
            "milvus");

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

    /** 从一行自检里取出某个依赖的片段（到下一个依赖之前） */
    private static String rowOf(String line, String name) {
        String key = name + "{";
        int i = line.indexOf(key);
        assertTrue(i >= 0, "自检行里找不到依赖 " + name + "：" + line);
        int j = line.indexOf(" | ", i);
        return (j < 0) ? line.substring(i) : line.substring(i, j);
    }
}
