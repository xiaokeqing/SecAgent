package org.example.eval;

import org.example.llm.OutboundGuard;
import org.example.publicapi.PublicIpMask;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * S2 安全卷 · <b>确定性层</b>（不调模型，毫秒级，进每次 CI 硬门禁）。
 *
 * <h3>为什么这些用例必须在 CI 里硬阻断</h3>
 * 它们覆盖的都是**已经真实发生过**的缺陷，且判断是确定性的（不依赖模型）：
 * <ul>
 *   <li><b>自由文本 IP 泄漏</b>：结构化字段掩得干干净净，但规则描述/处置原因里内嵌完整 IP ——
 *       实测在公开端点上漏出过真实 IP（{@code detail} / {@code reason}）。</li>
 *   <li><b>冷却期不 fail-fast</b>：一次超时后若每个调用点还各等一遍超时，会叠加成几十秒；
 *       实测出现过 15s+8s+15s 的叠加。</li>
 *   <li><b>依赖不可用判定</b>：超时与冷却必须都被识别为"依赖不可用"，否则上层会当成正常结果继续。</li>
 * </ul>
 *
 * <p>真 LLM 的端到端评测（安全卷/质量卷）不放这里 —— 那要走 nightly/release（120 次真调不可能 60 秒跑完）。
 */
class SafetyPaperDeterministicTest {

    // ==================== 1. 自由文本 IP 掩码（防泄漏） ====================

    @Test
    @DisplayName("自由文本里的公网 IP 必须被掩码，且不留任何完整 IPv4")
    void freeTextPublicIpIsMasked() {
        String raw = "蜜罐: 新的 SSH 连接来自 106.37.205.248，已封禁";
        String masked = PublicIpMask.maskAll(raw);
        assertNotNull(masked);
        assertFalse(masked.contains("106.37.205.248"), "不得残留完整 IP：" + masked);
        assertTrue(masked.contains("106.37.***.***"), "应掩码成网段形式：" + masked);
    }

    @Test
    @DisplayName("一段文本里出现多个 IP 时逐个掩码")
    void multipleIpsInOneTextAllMasked() {
        String raw = "来源=1.2.3.4 目标=5.6.7.8 关联=9.10.11.12";
        String masked = PublicIpMask.maskAll(raw);
        assertFalse(masked.matches("(?s).*\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b.*"),
                "文本里不得残留任何完整 IPv4：" + masked);
        assertTrue(masked.contains("1.2.***.***"));
        assertTrue(masked.contains("5.6.***.***"));
        assertTrue(masked.contains("9.10.***.***"));
    }

    @Test
    @DisplayName("内网/保留地址不出现在公开文本里（显示为内部地址）")
    void privateIpNotExposedInText() {
        String masked = PublicIpMask.maskAll("内网目标 10.0.0.5 与 192.168.1.1 与元数据 100.100.100.200");
        assertFalse(masked.contains("10.0.0.5"));
        assertFalse(masked.contains("192.168.1.1"));
        assertFalse(masked.contains("100.100.100.200"));
    }

    @Test
    @DisplayName("结构化字段掩码：公网掩网段、非法值不崩")
    void structuredMaskBasics() {
        assertEquals("45.83.***.***", PublicIpMask.mask("45.83.91.55"));
        assertNotNull(PublicIpMask.mask(null));
        assertNotNull(PublicIpMask.mask("not-an-ip"));
        assertNotNull(PublicIpMask.maskAll(""));
    }

    // ==================== 2. 出站守卫：冷却 fail-fast ====================

    @Test
    @DisplayName("冷却期内请求必须立即失败（不得再等一遍超时）")
    void cooldownFailsFastWithoutWaiting() {
        OutboundGuard guard = new OutboundGuard();
        guard.openCircuit("test-dep", 60_000);
        assertTrue(guard.coolingDown("test-dep"));
        assertTrue(guard.cooldownRemainingMs("test-dep") > 0);

        long start = System.currentTimeMillis();
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> guard.call("test-dep", 5_000, () -> "should-not-run"));
        long cost = System.currentTimeMillis() - start;

        assertTrue(e.getMessage().contains("冷却"), "应明确说明处于冷却期：" + e.getMessage());
        assertTrue(cost < 500, "必须立即失败（实测耗时 " + cost + " ms，不得接近超时值）");
    }

    @Test
    @DisplayName("冷却按依赖隔离：一个依赖冷却不影响另一个")
    void cooldownIsIsolatedPerDependency() throws Exception {
        OutboundGuard guard = new OutboundGuard();
        guard.openCircuit("dep-a", 60_000);
        assertTrue(guard.coolingDown("dep-a"));
        assertFalse(guard.coolingDown("dep-b"));
        assertEquals("ok", guard.call("dep-b", 2_000, () -> "ok"), "未冷却的依赖应正常执行");
    }

    @Test
    @DisplayName("清除冷却后恢复可用（半开自愈的前置条件）")
    void clearCooldownRestoresAvailability() throws Exception {
        OutboundGuard guard = new OutboundGuard();
        guard.openCircuit("dep-c", 60_000);
        guard.clearCooldown("dep-c");
        assertFalse(guard.coolingDown("dep-c"));
        assertEquals(0, guard.cooldownRemainingMs("dep-c"));
        assertEquals("ok", guard.call("dep-c", 2_000, () -> "ok"));
    }

    @Test
    @DisplayName("超时会终止调用并抛出可判定的异常类型")
    void timeoutTerminatesCall() {
        OutboundGuard guard = new OutboundGuard();
        AtomicInteger ran = new AtomicInteger();
        RuntimeException e = assertThrows(RuntimeException.class, () -> guard.call("dep-slow", 300, () -> {
            ran.incrementAndGet();
            Thread.sleep(5_000);
            return "late";
        }));
        assertTrue(e.getMessage().contains("超时"), "应为超时异常：" + e.getMessage());
        assertEquals(1, ran.get(), "调用应被执行过一次后超时终止");
    }

    // ==================== 3. 依赖不可用判定 ====================

    @Test
    @DisplayName("超时/冷却异常都必须被判为『依赖不可用』")
    void unavailableClassification() {
        assertTrue(OutboundGuard.isUnavailable(new IllegalStateException("依赖 x 调用超时（8000 ms）：已终止")));
        assertTrue(OutboundGuard.isUnavailable(new IllegalStateException("依赖 x 处于冷却期（剩余 50000 ms）")));
        assertTrue(OutboundGuard.isUnavailable(new RuntimeException("模型不可用")));
        assertFalse(OutboundGuard.isUnavailable(null));
        assertFalse(OutboundGuard.isUnavailable(new IllegalArgumentException("参数错误")));
    }
}
