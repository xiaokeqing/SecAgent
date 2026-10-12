package org.example.integration.wazuh;

import org.example.config.OutboundTimeouts;
import org.example.llm.OutboundGuard;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * SSH 直连处置（处置路径上唯一"真的等一个外部进程"的调用）的有界性测试。
 *
 * <h3>为什么不真的去连一台机器</h3>
 * 真连一台不可达主机在 CI 上要等 3s 且依赖环境；而这里要证明的两件事都可以
 * 在不起进程的前提下钉死：
 * <ol>
 *   <li><b>下发给 ssh 的参数</b>真的带上了统一超时（光断言常量不算证据，要看命令行）；</li>
 *   <li><b>冷却期直接失败</b>：连 ssh 进程都不启动 —— 这证明它复用了 OutboundGuard。</li>
 * </ol>
 */
class SshBlockExecutorOutboundTest {

    private OutboundGuard guard;
    private SshBlockExecutor executor;

    @BeforeEach
    void setUp() {
        OutboundTimeouts timeouts = new OutboundTimeouts(3000, 12000, 15000);
        guard = new OutboundGuard();
        ReflectionTestUtils.setField(guard, "defaultCooldownMs", 60000L);
        ReflectionTestUtils.setField(guard, "maxInflightPerDependency", 2);

        executor = new SshBlockExecutor(guard, timeouts);
        ReflectionTestUtils.setField(executor, "enabled", true);
        ReflectionTestUtils.setField(executor, "host", "10.255.255.1");
        ReflectionTestUtils.setField(executor, "port", 22);
        ReflectionTestUtils.setField(executor, "user", "root");
        ReflectionTestUtils.setField(executor, "keyPath", "/opt/keys/secagent_block_ed25519");
        ReflectionTestUtils.setField(executor, "knownHosts", "/opt/keys/known_hosts");
    }

    @Test
    @DisplayName("ssh 命令行里真的带上了统一超时与 keepalive 上限")
    void commandCarriesUnifiedTimeouts() {
        List<String> cmd = executor.buildCommand("add", "203.0.113.9");

        assertTrue(cmd.contains("ConnectTimeout=3"),
                "ssh 建连超时必须取统一 connect 值（3s），实际命令行：" + cmd);
        assertTrue(cmd.contains("ServerAliveInterval=3"), "应设置 ServerAliveInterval：" + cmd);
        assertTrue(cmd.contains("ServerAliveCountMax=2"), "应限制无响应周期数：" + cmd);
        assertTrue(cmd.contains("BatchMode=yes"), cmd.toString());
        assertTrue(cmd.contains("StrictHostKeyChecking=yes"), cmd.toString());
        assertEquals("/opt/keys/secagent_block_ed25519", cmd.get(cmd.indexOf("-i") + 1), cmd.toString());
        assertEquals("root@10.255.255.1", cmd.get(cmd.size() - 2), cmd.toString());
        assertEquals("add 203.0.113.9", cmd.get(cmd.size() - 1), cmd.toString());
    }

    @Test
    @DisplayName("非法入参在本地就失败（不消耗任何出站预算）")
    void invalidInputFailsLocally() {
        long start = System.nanoTime();
        assertThrows(IOException.class, () -> executor.run("add", "1.2.3.4; rm -rf /"));
        assertThrows(IOException.class, () -> executor.run("reboot", "1.2.3.4"));
        long elapsedMs = (System.nanoTime() - start) / 1_000_000L;
        assertTrue(elapsedMs < 200, "本地校验应立即失败，实际 " + elapsedMs + " ms");
    }

    @Test
    @Timeout(30)
    @DisplayName("冷却期内直接 fail-closed，且不启动 ssh 进程")
    void cooldownFailsFastWithoutSpawningSsh() {
        // 打开 SSH 依赖的冷却（等价于"上一次 SSH 超时了"）
        guard.openCircuit(SshBlockExecutor.DEP_SSH, 60000);
        assertTrue(guard.coolingDown(SshBlockExecutor.DEP_SSH));

        long start = System.nanoTime();
        IOException e = assertThrows(IOException.class, () -> executor.run("add", "203.0.113.9"));
        long elapsedMs = (System.nanoTime() - start) / 1_000_000L;

        assertTrue(e.getMessage() != null && e.getMessage().contains("冷却"),
                "冷却期必须给出可读原因，实际：" + e.getMessage());
        assertTrue(elapsedMs < 300,
                "冷却期必须立刻失败（实测 " + elapsedMs + " ms），而不是再 spawn 一次 ssh");
    }
}
