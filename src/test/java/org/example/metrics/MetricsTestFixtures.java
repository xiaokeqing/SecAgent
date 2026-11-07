package org.example.metrics;

import org.example.core.model.ActiveResponseResult;
import org.example.core.model.AlertSource;
import org.example.core.model.RawLogLine;
import org.example.core.model.SecurityAlert;
import org.example.integration.SuricataGateway;
import org.example.integration.WazuhGateway;
import org.example.integration.suricata.FlowEvent;
import org.example.integration.suricata.Ja3Count;
import org.example.integration.suricata.PortCount;
import org.example.integration.suricata.SniCount;
import org.example.response.AuditService;
import org.example.response.BlockRecord;
import org.example.response.BlockRecordStore;
import org.example.response.ResponseAudit;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 时效指标单测公共夹具：固定时钟 + 网关桩 + 内存封禁记录。
 *
 * <p>为什么不落盘：{@link BlockRecordStore} 的 register/markUnblocked 都会写
 * data/blocked-ips.json，而这里只验证统计口径 —— 用子类覆盖 {@code listAll()}
 * 直接喂内存记录，既不起 Spring、也不碰磁盘，测试可重复且无副作用。
 */
final class MetricsTestFixtures {

    static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    /** 固定"现在"：2026-11-07 12:00:00 UTC */
    static final LocalDateTime NOW = LocalDateTime.of(2026, 11, 7, 12, 0, 0);

    private MetricsTestFixtures() {
    }

    static Clock fixedClock() {
        return Clock.fixed(NOW.toInstant(ZoneOffset.UTC), ZoneOffset.UTC);
    }

    static SecurityAlert alert(String id, String ip, LocalDateTime at, AlertSource source) {
        SecurityAlert a = new SecurityAlert();
        a.setId(id);
        a.setSrcIp(ip);
        a.setOccurredAt(FMT.format(at));
        a.setSource(source);
        return a;
    }

    static SecurityAlert wazuhAlert(String id, String ip, LocalDateTime at) {
        return alert(id, ip, at, AlertSource.WAZUH);
    }

    /** 生效中（未解除）的封禁记录 */
    static BlockRecord activeBlock(String ip, LocalDateTime createdAt, String source) {
        return block(ip, createdAt, source, createdAt.plusHours(1), null, false);
    }

    /** 已解除的封禁记录；unblockedAt 为 null 时表示"靠 expiresAt 到期解封" */
    static BlockRecord unblockedBlock(String ip, LocalDateTime createdAt, LocalDateTime expiresAt,
                                      LocalDateTime unblockedAt, String source) {
        return block(ip, createdAt, source, expiresAt, unblockedAt, true);
    }

    private static BlockRecord block(String ip, LocalDateTime createdAt, String source,
                                     LocalDateTime expiresAt, LocalDateTime unblockedAt, boolean unblocked) {
        BlockRecord r = new BlockRecord();
        r.setId("BLK-" + ip + "-" + createdAt);
        r.setIp(ip);
        r.setSource(source);
        r.setActor("tester");
        r.setCreatedAt(createdAt == null ? null : FMT.format(createdAt));
        r.setExpiresAt(expiresAt == null ? null : FMT.format(expiresAt));
        r.setUnblocked(unblocked);
        if (unblockedAt != null) {
            r.setUnblockedAt(FMT.format(unblockedAt));
        }
        return r;
    }

    static MetricsSummaryService service(String wazuhMode, List<SecurityAlert> wazuhAlerts,
                                         String suricataMode, List<SecurityAlert> suricataAlerts,
                                         List<BlockRecord> blocks) {
        return service(wazuhMode, wazuhAlerts, suricataMode, suricataAlerts, blocks, new AuditService());
    }

    static MetricsSummaryService service(String wazuhMode, List<SecurityAlert> wazuhAlerts,
                                         String suricataMode, List<SecurityAlert> suricataAlerts,
                                         List<BlockRecord> blocks, AuditService auditService) {
        MetricsSummaryService svc = new MetricsSummaryService(
                new StubWazuh(wazuhMode, wazuhAlerts),
                new StubSuricata(suricataMode, suricataAlerts),
                new FixedStore(blocks),
                auditService);
        svc.setClock(fixedClock());
        return svc;
    }

    /** 一条成功执行的 block-ip 审计留痕 */
    static ResponseAudit blockAudit(String ip, LocalDateTime at) {
        ResponseAudit a = ResponseAudit.of("tester", "block-ip", ip, "单测", "low", "REAL", true, "");
        a.setId("AUD-" + ip + "-" + at);
        a.setTime(FMT.format(at));
        return a;
    }

    /** 审计服务桩：只覆盖 list()，不读不写 audit 文件 */
    static AuditService auditOf(List<ResponseAudit> records) {
        return new StubAudit(records);
    }

    private static final class StubAudit extends AuditService {
        private final List<ResponseAudit> records;

        StubAudit(List<ResponseAudit> records) {
            this.records = records == null ? List.of() : new ArrayList<>(records);
        }

        @Override
        public List<ResponseAudit> list(String action, Boolean success) {
            List<ResponseAudit> out = new ArrayList<>();
            for (ResponseAudit r : records) {
                if (action != null && !action.isEmpty() && !action.equals(r.getAction())) {
                    continue;
                }
                if (success != null && success != r.isSuccess()) {
                    continue;
                }
                out.add(r);
            }
            return out;
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> metric(Map<String, Object> data, String name) {
        return (Map<String, Object>) data.get(name);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> map(Map<String, Object> data, String name) {
        return (Map<String, Object>) data.get(name);
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> list(Map<String, Object> data, String name) {
        return (List<Map<String, Object>>) data.get(name);
    }

    /** 内存版封禁记录存储：只覆盖 listAll()，不初始化文件、不写盘 */
    private static final class FixedStore extends BlockRecordStore {
        private final List<BlockRecord> records;

        FixedStore(List<BlockRecord> records) {
            this.records = records == null ? List.of() : new ArrayList<>(records);
        }

        @Override
        public List<BlockRecord> listAll() {
            return records;
        }
    }

    /** Wazuh 网关桩：只有 mode 与 recentAlerts 参与时效统计 */
    static final class StubWazuh implements WazuhGateway {
        private final String mode;
        private final List<SecurityAlert> alerts;

        StubWazuh(String mode, List<SecurityAlert> alerts) {
            this.mode = mode;
            this.alerts = alerts == null ? List.of() : alerts;
        }

        @Override
        public boolean isAvailable() {
            return "REAL".equals(mode);
        }

        @Override
        public String mode() {
            return mode;
        }

        @Override
        public List<SecurityAlert> recentAlerts(int limit) {
            return alerts;
        }

        @Override
        public Map<String, Object> summary24h() {
            return Map.of();
        }

        @Override
        public Map<String, Object> honeypotSummary(int size) {
            return Map.of();
        }

        @Override
        public List<RawLogLine> forensicLogs(String query, int limit) {
            return List.of();
        }

        @Override
        public ActiveResponseResult runActiveResponse(String command, Map<String, Object> arguments) {
            return ActiveResponseResult.mock(command, "", "stub", "AUD-STUB");
        }
    }

    /** Suricata 网关桩：默认没有任何告警 */
    static final class StubSuricata implements SuricataGateway {
        private final String mode;
        private final List<SecurityAlert> alerts;

        StubSuricata(String mode, List<SecurityAlert> alerts) {
            this.mode = mode;
            this.alerts = alerts == null ? List.of() : alerts;
        }

        @Override
        public boolean isAvailable() {
            return "REAL".equals(mode);
        }

        @Override
        public String mode() {
            return mode;
        }

        @Override
        public List<SecurityAlert> recentNetworkAlerts(int limit) {
            return alerts;
        }

        @Override
        public List<FlowEvent> connectionsByIp(String ip, int limit) {
            return List.of();
        }

        @Override
        public List<PortCount> topDestPorts(int minutes, int limit) {
            return List.of();
        }

        @Override
        public List<SniCount> topSni(int minutes, int limit) {
            return List.of();
        }

        @Override
        public List<Ja3Count> ja3Stats(int minutes, int limit) {
            return List.of();
        }
    }
}
