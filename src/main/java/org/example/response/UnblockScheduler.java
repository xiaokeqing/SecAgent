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
 * 已到期（expiresAt &lt;= now）且未解封的封禁记录，<b>优先走与封禁相同的 SSH 直连通道</b>
 * （ipset 原生 timeout 到期其实会自动消失，但回退到 iptables 逐条规则的后端不会，
 * 所以这里不能省：记录、审计、真实的规则清理三件事都要做）；
 * SSH 不可用时降级 Wazuh {@code firewall-unblock}，再没有就 MOCK 自动成功。解封后：
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

    /**
     * SSH 直连执行器（解封也必须走这条）。
     *
     * <p>为什么必须加：封禁已经改成走 SSH + ipset，而旧版解封只走 Wazuh AR。
     * 两条路不一致的后果是<b>封得住、解不掉</b> —— 记录按到期时间标记成已解封，
     * ipset 集合里的条目却一直留着，IP 被永久封死，且日志上看起来一切正常。
     * 解封路径必须跟封禁路径成对，这里的顺序与 {@link ResponseActionService} 保持一致。
     */
    private final ObjectProvider<org.example.integration.wazuh.SshBlockExecutor> sshBlockProvider;

    /** 通知门面（解封属于低等级事件，夜间会被静默）——可缺失，缺失时行为与改造前一致 */
    private final ObjectProvider<org.example.notify.SecurityEventNotifier> notifierProvider;

    @Value("${response.unblock.enabled:true}")
    private boolean enabled;

    /** 便捷构造器：**仅供单测**直接 new 使用（通知为空）。Spring 不要用它。 */
    public UnblockScheduler(BlockRecordStore blockRecordStore,
                            AuditService auditService,
                            ObjectProvider<WazuhGateway> wazuhGatewayProvider) {
        this(blockRecordStore, auditService, wazuhGatewayProvider, null, null);
    }

    /**
     * 生产用构造器（Spring 用这一个）。
     *
     * <p>【2026-10-13 生产事故】与 {@code ResponseActionService} 同一类问题：多构造器 + 都没标注
     * → 启动 {@code No default constructor found}。由 {@code SpringBeanConstructorTest} 门禁揪出。
     */
    @org.springframework.beans.factory.annotation.Autowired
    public UnblockScheduler(BlockRecordStore blockRecordStore,
                            AuditService auditService,
                            ObjectProvider<WazuhGateway> wazuhGatewayProvider,
                            ObjectProvider<org.example.integration.wazuh.SshBlockExecutor> sshBlockProvider,
                            ObjectProvider<org.example.notify.SecurityEventNotifier> notifierProvider) {
        this.blockRecordStore = blockRecordStore;
        this.auditService = auditService;
        this.wazuhGatewayProvider = wazuhGatewayProvider;
        this.sshBlockProvider = sshBlockProvider;
        this.notifierProvider = notifierProvider;
    }

    /** 取 SSH 执行器（可能不存在/未启用），异常一律当"不存在"处理 */
    private org.example.integration.wazuh.SshBlockExecutor ssh() {
        if (sshBlockProvider == null) {
            return null;
        }
        try {
            return sshBlockProvider.getIfAvailable();
        } catch (Exception e) {
            return null;
        }
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
        ActiveResponseResult result = null;
        String command = "firewall-unblock";

        // ① 首选与封禁同一条路：SSH 直连（ipset del / iptables -D），失败再降级
        org.example.integration.wazuh.SshBlockExecutor ssh = ssh();
        if (ssh != null && ssh.isEnabled()) {
            command = "ipset-unblock";
            try {
                String out = ssh.unblock(r.getIp());
                result = ActiveResponseResult.real("ipset-unblock", r.getIp(),
                        "已解封 " + r.getIp() + "（后端=" + BlockCommands.parseBackend(out) + "）：" + out,
                        "AUD-" + java.util.UUID.randomUUID().toString().substring(0, 8));
            } catch (Exception e) {
                // 不直接把失败定案：Wazuh 通道可能仍然可用（双通道部署）
                logger.warn("SSH 解封失败，尝试降级 Wazuh：ip={} err={}", r.getIp(), e.getMessage());
            }
        }

        // ② 降级：Wazuh AR
        if (result == null) {
            WazuhGateway gw = readyGateway();
            if (gw != null) {
                Map<String, Object> args = new HashMap<>();
                args.put("ip", r.getIp());
                try {
                    result = gw.runActiveResponse("firewall-unblock", args);
                } catch (Exception e) {
                    result = ActiveResponseResult.failed("firewall-unblock", r.getIp(), "Wazuh 解封下发异常: " + e.getMessage());
                }
            }
        }

        // ③ 都没有真实通道：MOCK（演示环境仍要跑出"到期自动解封"闭环）
        if (result == null) {
            result = ActiveResponseResult.mock("firewall-unblock", r.getIp(),
                    "已解封 " + r.getIp() + "（MOCK 模拟，未连接真实 Wazuh）",
                    "AUD-" + java.util.UUID.randomUUID().toString().substring(0, 8));
        }

        if (result.isSuccess()) {
            blockRecordStore.markUnblocked(r.getId(), result.getMode());
            auditService.append(ResponseAudit.of("scheduler", "unblock-ip", r.getIp(),
                    "封禁到期自动解封", "LOW", result.getMode(), true,
                    "cmd=" + command + "; 到期时间=" + r.getExpiresAt() + "; 封禁时长=" + r.getDurationMinutes()
                            + "min; 来源=" + r.getSource() + "; 原审计=" + r.getAuditId()));
            logger.info("已自动解封 IP {}（到期时间 {}，封禁时长 {}min，来源 {}）",
                    r.getIp(), r.getExpiresAt(), r.getDurationMinutes(), r.getSource());
            notifyUnblock(r.getIp(), result.getMode());
        } else {
            // 解封失败不标记，下一轮调度重试
            auditService.append(ResponseAudit.of("scheduler", "unblock-ip", r.getIp(),
                    "到期解封执行失败", "LOW", result.getMode(), false,
                    "到期时间=" + r.getExpiresAt() + "; " + result.getMessage()));
            logger.warn("自动解封失败 IP {}（到期时间 {}）：{}", r.getIp(), r.getExpiresAt(), result.getMessage());
        }
    }

    /** ② 解封通知：低等级（夜间静默会压制它——这是刻意的，解封不是呼救） */
    private void notifyUnblock(String ip, String mode) {
        if (notifierProvider == null) {
            return;
        }
        try {
            org.example.notify.SecurityEventNotifier n = notifierProvider.getIfAvailable();
            if (n != null) {
                n.unblockIp(ip, mode, "scheduler");
            }
        } catch (Exception e) {
            logger.warn("解封通知失败（不影响解封结果）：{}", e.getMessage());
        }
    }
}
