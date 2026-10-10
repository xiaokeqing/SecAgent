package org.example.response;

import org.example.core.model.ActiveResponseResult;
import org.example.integration.WazuhGateway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 封禁到期自动解封调度器。
 *
 * <p>按 {@code response.unblock.interval-ms}（默认 60s）周期扫描 {@link BlockRecordStore} 中
 * 已到期（expiresAt &lt;= now）且未解封的封禁记录，调用 Wazuh {@code firewall-unblock} 解封；
 * 无真实 Wazuh 时 MOCK 自动成功。解封后：
 * <ol>
 *   <li>把记录标记 unblocked=true / unblockedAt / unblockMode 并写回；</li>
 *   <li>写一条审计（action=unblock-ip，actor=scheduler）；</li>
 *   <li>INFO 日志打印自动解封证据。</li>
 * </ol>
 * 开关 {@code response.unblock.enabled=false} 时不扫描。
 */
@Component
public class UnblockScheduler {

    private static final Logger logger = LoggerFactory.getLogger(UnblockScheduler.class);

    private final BlockRecordStore blockRecordStore;
    private final AuditService auditService;
    private final ObjectProvider<WazuhGateway> wazuhGatewayProvider;

    @Value("${response.unblock.enabled:true}")
    private boolean enabled;

    public UnblockScheduler(BlockRecordStore blockRecordStore,
                            AuditService auditService,
                            ObjectProvider<WazuhGateway> wazuhGatewayProvider) {
        this.blockRecordStore = blockRecordStore;
        this.auditService = auditService;
        this.wazuhGatewayProvider = wazuhGatewayProvider;
    }

    /** 网关是否可用：存在 Bean 且 isAvailable() 为真（与 ResponseActionService 同一判据） */
    private WazuhGateway readyGateway() {
        try {
            WazuhGateway gw = wazuhGatewayProvider.getIfAvailable();
            return (gw != null && gw.isAvailable()) ? gw : null;
        } catch (Exception e) {
            return null;
        }
    }

    @Scheduled(fixedDelayString = "${response.unblock.interval-ms:60000}",
            initialDelayString = "${response.unblock.initial-delay-ms:10000}")
    public void sweep() {
        if (!enabled) {
            return;
        }
        List<BlockRecord> due = blockRecordStore.findDueForUnblock();
        if (due.isEmpty()) {
            return;
        }
        logger.info("自动解封调度：发现 {} 条到期封禁记录待处理", due.size());
        for (BlockRecord r : due) {
            unblockOne(r);
        }
    }

    private void unblockOne(BlockRecord r) {
        ActiveResponseResult result;
        WazuhGateway gw = readyGateway();
        if (gw != null) {
            Map<String, Object> args = new HashMap<>();
            args.put("ip", r.getIp());
            try {
                result = gw.runActiveResponse("firewall-unblock", args);
            } catch (Exception e) {
                result = ActiveResponseResult.failed("firewall-unblock", r.getIp(), "Wazuh 解封下发异常: " + e.getMessage());
            }
        } else {
            result = ActiveResponseResult.mock("firewall-unblock", r.getIp(),
                    "已解封 " + r.getIp() + "（MOCK 模拟，未连接真实 Wazuh）",
                    "AUD-" + java.util.UUID.randomUUID().toString().substring(0, 8));
        }

        if (result.isSuccess()) {
            blockRecordStore.markUnblocked(r.getId(), result.getMode());
            auditService.append(ResponseAudit.of("scheduler", "unblock-ip", r.getIp(),
                    "封禁到期自动解封", "LOW", result.getMode(), true,
                    "到期时间=" + r.getExpiresAt() + "; 封禁时长=" + r.getDurationMinutes()
                            + "min; 来源=" + r.getSource() + "; 原审计=" + r.getAuditId()));
            logger.info("已自动解封 IP {}（到期时间 {}，封禁时长 {}min，来源 {}）",
                    r.getIp(), r.getExpiresAt(), r.getDurationMinutes(), r.getSource());
        } else {
            // 解封失败不标记，下一轮调度重试
            auditService.append(ResponseAudit.of("scheduler", "unblock-ip", r.getIp(),
                    "到期解封执行失败", "LOW", result.getMode(), false,
                    "到期时间=" + r.getExpiresAt() + "; " + result.getMessage()));
            logger.warn("自动解封失败 IP {}（到期时间 {}）：{}", r.getIp(), r.getExpiresAt(), result.getMessage());
        }
    }
}
