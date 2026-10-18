package org.example.publicapi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link ThreatScore} 的四条口径：全缺、只有一种弱证据、三种强证据、缺字段重标化。
 *
 * <p>这些用例同时是权重表的"合同"：公式一改，它们会红。
 */
class ThreatScoreTest {

    @Test
    @DisplayName("全缺：0 分 / low / factors 空 —— 缺字段不参与，不是 0 分因子")
    void allMissing() {
        ThreatScore.Result r = ThreatScore.score(ThreatScore.Input.empty());

        assertEquals(0, r.getScore(), "什么都没读到，得分必须是 0");
        assertEquals(ThreatScore.LOW, r.getBand());
        assertTrue(r.getFactors().isEmpty(), "缺的因子不进 factors 表，也不当 0 摆一行");
        assertEquals(0.0, r.getKnownWeight(), 1e-9, "可用权重为 0");
        assertEquals(ThreatScore.MIN_EVIDENCE_WEIGHT, r.getDenominator(), 1e-9,
                "分母落到下限，但分子是 0，所以分数仍是 0");
        assertTrue(r.isRenormalized(), "缺字段 ⇒ 已重标化标记为 true");

        // null 输入等同于全缺（防御性：不带 NullPointerException 出去）
        assertEquals(0, ThreatScore.score(null).getScore());
    }

    @Test
    @DisplayName("只有端口扇出（8 个不同端口）：15/45 = 33 分 → medium，不是 low 也不是 critical")
    void onlyPortsIsMedium() {
        Map<String, Integer> ports = new LinkedHashMap<>();
        int[] p = {21, 22, 23, 80, 443, 445, 3306, 3389};
        for (int port : p) {
            ports.put(String.valueOf(port), 1);
        }

        ThreatScore.Result r = ThreatScore.score(ThreatScore.Input.empty().ports(ports));

        assertEquals(1, r.getFactors().size(), "只有端口这一项被读到");
        assertEquals("端口扇出", r.getFactors().get(0).getName());
        assertEquals(15.0, r.getFactors().get(0).getWeight(), 1e-9, "8 个端口正好拿满 15");
        assertEquals(15.0, r.getKnownWeight(), 1e-9);
        assertEquals(ThreatScore.MIN_EVIDENCE_WEIGHT, r.getDenominator(), 1e-9,
                "可用权重 15 < 下限 45，分母取 45（否则 15/15 = 100 会变成 critical）");
        assertEquals(33, r.getScore());
        assertEquals(ThreatScore.MEDIUM, r.getBand());
    }

    @Test
    @DisplayName("高事件量 + 成功登录 + 已封禁：critical")
    void highEventsWithSuccessfulLoginAndBanIsCritical() {
        Map<String, Integer> byKind = new LinkedHashMap<>();
        byKind.put("蜜罐登录成功", 7);
        byKind.put("蜜罐新连接", 12);

        ThreatScore.Result r = ThreatScore.score(ThreatScore.Input.empty()
                .events(10000)          // 30（饱和）
                .byKind(byKind)         // 蜜罐命中 9 + 成功登录 10 = 19
                .banned(true));         // 10

        assertEquals(65.0, r.getKnownWeight(), 1e-9, "事件量 30 + 来源类型 25 + 已封禁 10");
        assertEquals(59.0, r.getFactors().stream().mapToDouble(ThreatScore.Factor::getWeight).sum(), 1e-9);
        assertTrue(r.getScore() >= ThreatScore.BAND_CRITICAL_FROM,
                "59/65 ≈ 91 分，应进 critical，实际 " + r.getScore());
        assertEquals(ThreatScore.CRITICAL, r.getBand());
        assertTrue(r.isRenormalized(), "端口/凭据/账号三项没读到 ⇒ 分母只有 65，分数已重标化");
    }

    @Test
    @DisplayName("缺 byKind 时重标化：分数必须高于把 byKind 当 0 的对照（分母更大）")
    void missingByKindIsRenormalizedNotZeroed() {
        ThreatScore.Input partial = ThreatScore.Input.empty()
                .events(50)
                .ports(Map.of("22", 1, "80", 1, "443", 1, "3389", 1))
                .credAttempts(40)
                .distinctUsers(3)
                .banned(false)
                .byKind(null);          // 没读到

        // 对照组：byKind 读到了，但里面什么都没有 → 25 分的分母留着，得 0 分
        ThreatScore.Input withEmptyByKind = ThreatScore.Input.empty()
                .events(50)
                .ports(Map.of("22", 1, "80", 1, "443", 1, "3389", 1))
                .credAttempts(40)
                .distinctUsers(3)
                .banned(false)
                .byKind(Map.of());

        ThreatScore.Result missing = ThreatScore.score(partial);
        ThreatScore.Result zeroed = ThreatScore.score(withEmptyByKind);

        assertEquals(75.0, missing.getKnownWeight(), 1e-9, "byKind 没读到 → 25 分不进分母");
        assertEquals(100.0, zeroed.getKnownWeight(), 1e-9, "byKind 读到但为空 → 25 分留在分母里");
        assertTrue(missing.getScore() > zeroed.getScore(),
                "重标化 " + missing.getScore() + " 必须大于当 0 的 " + zeroed.getScore());
        assertEquals(37, missing.getScore());
        assertEquals(28, zeroed.getScore());
        assertEquals(ThreatScore.MEDIUM, missing.getBand());
        assertEquals(ThreatScore.LOW, zeroed.getBand());

        // 对照组的 factors 里那行确实在，只是权重为 0 —— 与"缺字段"形状不同
        assertEquals(6, zeroed.getFactors().size());
        assertEquals(5, missing.getFactors().size());
        assertNull(ThreatScore.Input.empty().getByKind());
    }
}
