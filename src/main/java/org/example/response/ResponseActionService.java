package org.example.response;

import org.example.core.model.ActiveResponseResult;
import org.example.security.ResponseGuard;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * 处置动作执行服务（SecAgent 自己的"手"的编排层）。
 *
 * <p>架构原则：研判、风险分级、护栏都在本服务内；Wazuh 只是"真实执行封禁的手"。
 * 没有 Wazuh 可用时，一律走 MOCK 模拟，保证闭环可演示。
 *
 * <p>每一个动作执行前都会先过 {@link ResponseGuard} 护栏（封IP）或基本入参校验（锁账号/杀进程），
 * 被拦截的动作不真正下发，但同样写审计留痕。
 */
@Service
public class ResponseActionService {

    private static final Logger logger = LoggerFactory.getLogger(ResponseActionService.class);

    private final ResponseGuard responseGuard;
    private final AuditService auditService;
    private final BlockRecordStore blockRecordStore;

    /** Wazuh 网关可能没有实现 Bean，缺失时自动降级 MOCK */
    private final ObjectProvider<org.example.integration.WazuhGateway> wazuhGatewayProvider;

    public ResponseActionService(ResponseGuard responseGuard,
                                 AuditService auditService,
                                 BlockRecordStore blockRecordStore,
                                 ObjectProvider<org.example.integration.WazuhGateway> wazuhGatewayProvider) {
        this.responseGuard = responseGuard;
        this.auditService = auditService;
        this.blockRecordStore = blockRecordStore;
        this.wazuhGatewayProvider = wazuhGatewayProvider;
    }

    /**
     * 处置通道是否可用。
     *
     * <h3>这里修的是一个"判据过时"的 bug</h3>
     * 原来的实现是 {@code gw.isAvailable()} —— 它的语义是
     * "Wazuh 管理 API 连上了吗"。但处置现在**已经不走 Wazuh API 了**
     * （AR 投递链路在这套环境里走不通，改用 SSH 直连）。
     * 于是出现一个很隐蔽的情况：
     * <b>链路明明是通的、脚本手工执行能封，但业务代码判断"不可用"，
     * 直接走了 MOCK 分支</b> —— 表现就是 "已封禁 …（MOCK 模拟）"。
     * <p>
     * 这类 bug 的特点是：<b>判据和实际执行方式脱节了</b>。
     * 改了一半（执行方式换了）没改另一半（可用性判据），
     * 两边就不一致了。所以这里改成问网关一个专门的问题：
     * "你能不能真的执行处置动作"，而不是复用一个语义不同的方法。
     */
    private boolean wazuhReady() {
        try {
            org.example.integration.WazuhGateway gw = wazuhGatewayProvider.getIfAvailable();
            if (gw == null) {
                return false;
            }
            if (gw instanceof org.example.integration.wazuh.WazuhService) {
                return ((org.example.integration.wazuh.WazuhService) gw).isResponseCapable();
            }
            return gw.isAvailable();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 封禁来源 IP（默认来源"手动"）。
     * 先过护栏；护栏拒绝则返回 BLOCKED 并写审计。通过后：网关可用→REAL 下发 firewall-drop，否则 MOCK。
     * 真正执行成功后追加一条带到期时间的封禁记录，供到期自动解封。
     */
    public ActiveResponseResult blockIp(String ip, Integer durationMinutes, String reason, String actor) {
        return blockIp(ip, durationMinutes, reason, actor, "手动");
    }

    /**
     * 封禁来源 IP（显式指定执行来源 source：手动 / 审批 / 智能体）。
     * 护栏与高危审批逻辑保持不变；仅在成功执行（非 BLOCKED）后追加封禁记录。
     */
    public ActiveResponseResult blockIp(String ip, Integer durationMinutes, String reason, String actor, String source) {
        String guardReason = responseGuard.validateBlock(ip, durationMinutes);
        if (guardReason != null) {
            ResponseAudit audit = ResponseAudit.of(actor, "block-ip", ip == null ? "" : ip.trim(),
                    guardReason, "LOW", "BLOCKED", false, "封禁被护栏拦截");
            auditService.append(audit);
            logger.warn("封IP被护栏拦截 target={} reason={}", ip, guardReason);
            return ActiveResponseResult.blocked("firewall-drop", ip == null ? "" : ip.trim(), guardReason);
        }
        String target = ip.trim();
        int duration = durationMinutes == null ? responseGuard.getDefaultDurationMinutes() : durationMinutes;

        ActiveResponseResult result;
        if (wazuhReady()) {
            Map<String, Object> args = new HashMap<>();
            args.put("ip", target);
            args.put("duration", duration);
            try {
                result = wazuhGatewayProvider.getIfAvailable().runActiveResponse("firewall-drop", args);
                if (result.getAuditId() == null) {
                    result.setAuditId(nextAuditId());
                }
            } catch (Exception e) {
                result = ActiveResponseResult.failed("firewall-drop", target, "Wazuh 下发异常: " + e.getMessage());
            }
        } else {
            result = ActiveResponseResult.mock("firewall-drop", target,
                    "已封禁 " + target + " 共 " + duration + " 分钟（MOCK 模拟，未连接真实 Wazuh）", nextAuditId());
        }

        String risk = duration > 120 ? "HIGH" : "LOW";
        ResponseAudit audit = ResponseAudit.of(actor, "block-ip", target, reason, risk,
                result.getMode(), result.isSuccess(), "duration=" + duration + "min; " + result.getMessage());
        auditService.append(audit);
        result.setAuditId(audit.getId());

        // 成功执行（REAL/MOCK，非拦截）才登记带到期时间的封禁记录，供到期自动解封；
        // 被护栏拦截或下发失败不登记。
        if (result.isSuccess() && result.getMode() != null && !"BLOCKED".equals(result.getMode())) {
            blockRecordStore.register(target, duration, source, actor, result.getAuditId(), result.getMode());
        }
        return result;
    }

    /**
     * 锁定账号（高危）。基本校验后映射 Wazuh win-disable-account；无网关则 MOCK。
     */
    public ActiveResponseResult lockAccount(String account, String host, String reason, String actor) {
        if (account == null || account.trim().isEmpty()) {
            String r = "锁定账号名为空";
            auditService.append(ResponseAudit.of(actor, "lock-account", "", r, "HIGH", "BLOCKED", false, r));
            return ActiveResponseResult.blocked("win-disable-account", "", r);
        }
        String target = account.trim();
        ActiveResponseResult result;
        if (wazuhReady()) {
            Map<String, Object> args = new HashMap<>();
            args.put("username", target);
            if (host != null) args.put("host", host);
            try {
                result = wazuhGatewayProvider.getIfAvailable().runActiveResponse("win-disable-account", args);
            } catch (Exception e) {
                result = ActiveResponseResult.failed("win-disable-account", target, "Wazuh 下发异常: " + e.getMessage());
            }
        } else {
            result = ActiveResponseResult.mock("win-disable-account", target,
                    "已锁定账号 " + target + (host == null ? "" : "@" + host) + "（MOCK 模拟）", nextAuditId());
        }
        ResponseAudit audit = ResponseAudit.of(actor, "lock-account", target, reason, "HIGH",
                result.getMode(), result.isSuccess(), result.getMessage());
        auditService.append(audit);
        result.setAuditId(audit.getId());
        return result;
    }

    /**
     * 结束恶意进程（高危）。映射 Wazuh kill-process；无网关则 MOCK。
     */
    public ActiveResponseResult killProcess(String pid, String processName, String host, String reason, String actor) {
        if ((pid == null || pid.trim().isEmpty()) && (processName == null || processName.trim().isEmpty())) {
            String r = "进程 PID 与进程名均为空";
            auditService.append(ResponseAudit.of(actor, "kill-process", "", r, "HIGH", "BLOCKED", false, r));
            return ActiveResponseResult.blocked("kill-process", "", r);
        }
        String target = (pid != null && !pid.trim().isEmpty()) ? pid.trim() : processName.trim();
        ActiveResponseResult result;
        if (wazuhReady()) {
            Map<String, Object> args = new HashMap<>();
            if (pid != null) args.put("pid", pid.trim());
            if (processName != null) args.put("process", processName.trim());
            if (host != null) args.put("host", host);
            try {
                result = wazuhGatewayProvider.getIfAvailable().runActiveResponse("kill-process", args);
            } catch (Exception e) {
                result = ActiveResponseResult.failed("kill-process", target, "Wazuh 下发异常: " + e.getMessage());
            }
        } else {
            result = ActiveResponseResult.mock("kill-process", target,
                    "已结束进程 " + target + (host == null ? "" : "@" + host) + "（MOCK 模拟）", nextAuditId());
        }
        ResponseAudit audit = ResponseAudit.of(actor, "kill-process", target, reason, "HIGH",
                result.getMode(), result.isSuccess(), result.getMessage());
        auditService.append(audit);
        result.setAuditId(audit.getId());
        return result;
    }

    private String nextAuditId() {
        return "AUD-" + java.util.UUID.randomUUID().toString().substring(0, 8);
    }
}
