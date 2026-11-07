package org.example.metrics;

import org.example.core.model.SecurityAlert;
import org.example.response.BlockRecord;
import org.example.response.ResponseAudit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.example.metrics.MetricsTestFixtures.FMT;
import static org.example.metrics.MetricsTestFixtures.NOW;
import static org.example.metrics.MetricsTestFixtures.activeBlock;
import static org.example.metrics.MetricsTestFixtures.auditOf;
import static org.example.metrics.MetricsTestFixtures.blockAudit;
import static org.example.metrics.MetricsTestFixtures.list;
import static org.example.metrics.MetricsTestFixtures.map;
import static org.example.metrics.MetricsTestFixtures.metric;
import static org.example.metrics.MetricsTestFixtures.service;
import static org.example.metrics.MetricsTestFixtures.unblockedBlock;
import static org.example.metrics.MetricsTestFixtures.wazuhAlert;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * 时效指标口径单测：不启 Spring、不碰磁盘、时钟钉死。
 */
class MetricsSummaryServiceTest {

    @Test
    @DisplayName("样本 < 3：available=false + reason=样本不足，不返回 0 分钟")
    void unavailableWhenFewerThanThreeSamples() {
        List<SecurityAlert> alerts = List.of(
                wazuhAlert("a1", "198.51.100.1", NOW.minusHours(2)),
                wazuhAlert("a2", "198.51.100.2", NOW.minusHours(2)));
        List<BlockRecord> blocks = List.of(
                unblockedBlock("198.51.100.1", NOW.minusHours(1), NOW.minusMinutes(10),
                        NOW.minusMinutes(10), "手动"),
                unblockedBlock("198.51.100.2", NOW.minusHours(1), NOW.minusMinutes(10),
                        NOW.minusMinutes(10), "手动"));

        Map<String, Object> data = service("REAL", alerts, "REAL", List.of(), blocks).summary(24);

        Map<String, Object> mttd = metric(data, "mttd");
        assertEquals(false, mttd.get("available"));
        assertEquals("样本不足", mttd.get("reason"));
        assertEquals(2, mttd.get("samples"));
        assertFalse(mttd.containsKey("medianMinutes"), "样本不足时不能编造 0 时延");

        Map<String, Object> mttr = metric(data, "mttr");
        assertEquals(false, mttr.get("available"));
        assertEquals("样本不足", mttr.get("reason"));
        assertEquals(2, mttr.get("samples"));

        assertEquals(2, map(data, "samples").get("alerts"));
        assertEquals(2, map(data, "samples").get("blocks"));
        assertEquals(2, map(data, "samples").get("mttdPairs"));
        assertEquals(2, map(data, "samples").get("mttrPairs"));
    }

    @Test
    @DisplayName("偶数个样本：中位数取中间两个的平均（10/20/30/40 → 25.0）")
    void medianAveragesMiddleTwoForEvenSampleCount() {
        int[] delays = {10, 20, 30, 40};
        List<SecurityAlert> alerts = new ArrayList<>();
        List<BlockRecord> blocks = new ArrayList<>();
        for (int i = 0; i < delays.length; i++) {
            String ip = "198.51.100." + (10 + i);
            LocalDateTime alertAt = NOW.minusHours(2);
            alerts.add(wazuhAlert("a" + i, ip, alertAt));
            // 未解除：只参与 MTTD，不污染 MTTR
            blocks.add(activeBlock(ip, alertAt.plusMinutes(delays[i]), "自动"));
        }

        Map<String, Object> data = service("REAL", alerts, "REAL", List.of(), blocks).summary(24);

        Map<String, Object> mttd = metric(data, "mttd");
        assertEquals(true, mttd.get("available"));
        assertEquals(25.0, mttd.get("medianMinutes"));
        assertEquals(4, mttd.get("samples"));
        assertEquals("minutes", mttd.get("unit"));

        List<Map<String, Object>> worst = list(data, "worst");
        assertEquals(3, worst.size(), "worst 固定最多 3 条，按分钟降序");
        assertEquals(40.0, worst.get(0).get("minutes"));
        assertEquals("MTTD", worst.get(0).get("metric"));
        assertEquals(30.0, worst.get(1).get("minutes"));
        assertEquals(20.0, worst.get(2).get("minutes"));
    }

    @Test
    @DisplayName("窗口过滤：窗口外的告警与封禁都不进样本")
    void windowFiltersOutOldSamples() {
        // A：告警 -90min（1h 窗口外），封禁 -80min（1h 窗口外）
        // B：告警 -30min，封禁 -10min → 1h 窗口内
        List<SecurityAlert> alerts = List.of(
                wazuhAlert("a1", "198.51.100.1", NOW.minusMinutes(90)),
                wazuhAlert("a2", "198.51.100.2", NOW.minusMinutes(30)));
        List<BlockRecord> blocks = List.of(
                unblockedBlock("198.51.100.1", NOW.minusMinutes(80), NOW.minusMinutes(40),
                        NOW.minusMinutes(40), "手动"),
                unblockedBlock("198.51.100.2", NOW.minusMinutes(10), NOW.plusMinutes(30),
                        NOW.plusMinutes(30), "手动"));

        MetricsSummaryService svc = service("REAL", alerts, "REAL", List.of(), blocks);

        Map<String, Object> oneHour = svc.summary(1);
        assertEquals(1, map(oneHour, "samples").get("alerts"));
        assertEquals(1, map(oneHour, "samples").get("blocks"));
        assertEquals(1, map(oneHour, "samples").get("mttdPairs"));
        assertEquals(1, metric(oneHour, "mttd").get("samples"));
        assertEquals(FMT.format(NOW.minusHours(1)), map(oneHour, "window").get("start"));
        assertEquals(FMT.format(NOW), map(oneHour, "window").get("end"));

        Map<String, Object> twoHours = svc.summary(2);
        assertEquals(2, map(twoHours, "samples").get("alerts"));
        assertEquals(2, map(twoHours, "samples").get("blocks"));
        assertEquals(2, map(twoHours, "samples").get("mttdPairs"));
        assertEquals(2, map(twoHours, "window").get("hours"));
    }

    @Test
    @DisplayName("MTTR：只算已解除；恢复时间取 unblockedAt/expiresAt 较早者；负时延丢弃")
    void mttrUsesRecoveryTimeAndSkipsNegative() {
        LocalDateTime created = NOW.minusHours(3);
        List<BlockRecord> blocks = List.of(
                // A：到期自动解封，调度器晚 5 分钟才写 unblockedAt → 取 expiresAt = 60 分钟
                unblockedBlock("198.51.100.1", created, NOW.minusHours(2), NOW.minusMinutes(115), "自动"),
                // B：只有 expiresAt → 60 分钟
                unblockedBlock("198.51.100.2", created, NOW.minusHours(2), null, "自动"),
                // C：人工提前解封 → 取 unblockedAt = 90 分钟
                unblockedBlock("198.51.100.3", created, NOW.minusHours(1), NOW.minusMinutes(90), "手动"),
                // D：仍在封禁中 → 不进分母
                activeBlock("198.51.100.4", created, "自动"),
                // E：恢复时间早于创建（时钟偏移/历史数据）→ 丢弃
                unblockedBlock("198.51.100.5", created, NOW.minusHours(2), NOW.minusHours(4), "手动"),
                // F：已解除但两个恢复时间都缺失 → 计入 dropped
                unblockedBlock("198.51.100.6", created, null, null, "手动"));

        Map<String, Object> data = service("REAL", List.of(), "REAL", List.of(), blocks).summary(24);

        Map<String, Object> mttr = metric(data, "mttr");
        assertEquals(true, mttr.get("available"));
        assertEquals(60.0, mttr.get("medianMinutes"));
        assertEquals(3, mttr.get("samples"), "A/B/C 三条，D 未解除、E 负时延、F 缺恢复时间都不进样本");

        Map<String, Object> dropped = map(data, "dropped");
        assertEquals(1, dropped.get("negativeMttr"));
        assertEquals(1, dropped.get("missingRecoveryTime"));
        assertEquals(6, map(data, "samples").get("blocks"));
        assertEquals(0, map(data, "samples").get("mttdPairs"));
    }

    @Test
    @DisplayName("数据源非 REAL：内置样本整体剔除，mode=MOCK 且样本为 0")
    void mockModeIsFailClosed() {
        List<SecurityAlert> fakeAlerts = List.of(
                wazuhAlert("m1", "203.0.113.10", NOW.minusMinutes(50)),
                wazuhAlert("m2", "203.0.113.11", NOW.minusMinutes(40)));
        List<BlockRecord> fakeBlocks = List.of(
                unblockedBlock("203.0.113.10", NOW.minusMinutes(30), NOW.minusMinutes(20),
                        NOW.minusMinutes(20), "自动"));

        Map<String, Object> data = service("MOCK", fakeAlerts, "OFF", List.of(), fakeBlocks).summary(24);

        assertEquals("MOCK", data.get("mode"));
        assertEquals("MOCK", data.get("wazuhMode"));
        assertEquals("OFF", data.get("suricataMode"));
        assertEquals(0, map(data, "samples").get("alerts"));
        assertEquals(0, map(data, "samples").get("mttdPairs"));
        assertEquals(0, metric(data, "mttd").get("samples"));
        assertEquals("样本不足", metric(data, "mttd").get("reason"));
        // MTTD 被剔除，但本机 BlockRecord 是本地事实，MTTR 仍可算（这里 1 条 → 样本不足，worst 里保留 10 分钟）
        assertEquals(1, map(data, "samples").get("mttrPairs"));
        assertEquals(1, list(data, "worst").size());
        assertEquals("MTTR", list(data, "worst").get(0).get("metric"));
        assertEquals(10.0, list(data, "worst").get(0).get("minutes"));
    }

    @Test
    @DisplayName("MTTD 回退到审计留痕：封禁记录被清理后仍可配对，与 createdAt 取较早者")
    void mttdFallsBackToAuditTrail() {
        List<SecurityAlert> alerts = List.of(
                wazuhAlert("a1", "198.51.100.1", NOW.minusHours(2)),
                wazuhAlert("a2", "198.51.100.2", NOW.minusHours(2)),
                wazuhAlert("a3", "198.51.100.3", NOW.minusHours(2)));
        // IP1 同时有封禁记录（8 分钟）与留痕（5 分钟）→ 取较早的 5 分钟
        List<BlockRecord> blocks = List.of(activeBlock("198.51.100.1", NOW.minusMinutes(112), "自动"));
        // IP2/IP3 已无封禁记录，只剩审计留痕
        List<ResponseAudit> audits = List.of(
                blockAudit("198.51.100.1", NOW.minusMinutes(115)),
                blockAudit("198.51.100.2", NOW.minusMinutes(115)),
                blockAudit("198.51.100.3", NOW.minusMinutes(115)));

        Map<String, Object> data = service("REAL", alerts, "REAL", List.of(), blocks, auditOf(audits))
                .summary(24);

        Map<String, Object> mttd = metric(data, "mttd");
        assertEquals(true, mttd.get("available"));
        assertEquals(5.0, mttd.get("medianMinutes"));
        assertEquals(3, mttd.get("samples"));
        assertEquals(1, map(data, "samples").get("blocks"));
        assertEquals(0, map(data, "dropped").get("unparseableAuditTimes"));
    }

    @Test
    @DisplayName("hours 越界收敛到 1..168，而不是抛 400")
    void hoursIsClamped() {
        MetricsSummaryService svc = service("REAL", List.of(), "REAL", List.of(), List.of());

        assertEquals(1, map(svc.summary(0), "window").get("hours"));
        assertEquals(1, map(svc.summary(-5), "window").get("hours"));
        assertEquals(168, map(svc.summary(999), "window").get("hours"));
        assertEquals(6, map(svc.summary(6), "window").get("hours"));
        assertEquals(24, map(svc.summary(24), "window").get("hours"));
    }

    @Test
    @DisplayName("median：奇数取正中，偶数取中间两个平均")
    void medianMath() {
        assertEquals(20.0, MetricsSummaryService.median(new double[]{10, 20, 100}));
        assertEquals(25.0, MetricsSummaryService.median(new double[]{10, 20, 30, 40}));
        assertEquals(5.0, MetricsSummaryService.median(new double[]{5}));
        assertEquals(0.5, MetricsSummaryService.median(new double[]{0, 1}));
    }
}
