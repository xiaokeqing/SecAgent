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

    /**
     * SSH 直连封禁执行器（处置的首选路径）。
     *
     * <p>这里**直接注入执行器本身**，而不是通过网关问"你能不能执行" ——
     * 原因是我先前那版用 {@code gw instanceof WazuhService} 来判断，
     * 结果一直走 MOCK 分支。问题是：<b>Spring 可能用代理包装 Bean，
     * 此时 instanceof 会返回 false</b>，于是判断悄悄失效、又退回 MOCK，
     * 而表面看不出任何异常。
     * <p>
     * 直接注入依赖对象、按类型检查，绕开代理对 instanceof 的影响。
     * 用 ObjectProvider 是为了在没配置时也能正常启动（缺失即降级）。
     */
    private final ObjectProvider<org.example.integration.wazuh.SshBlockExecutor> sshBlockProvider;

    /**
     * 通知门面（② 自动封禁成功/失败）。
     *
     * <p>用 {@code ObjectProvider} 而不是直接注入：通知是旁路能力，
     * 它在裁剪构建/单测里可能整个不存在，缺失时必须<b>照旧完成处置</b>
     * —— 不允许"因为通知组件不在，封禁就不做了"。
     */
    private final ObjectProvider<org.example.notify.SecurityEventNotifier> notifierProvider;

    /** 便捷构造器：**仅供单测**直接 new 使用（通知为空）。Spring 不要用它。 */
    public ResponseActionService(ResponseGuard responseGuard,
                                 AuditService auditService,
                                 BlockRecordStore blockRecordStore,
                                 ObjectProvider<org.example.integration.WazuhGateway> wazuhGatewayProvider,
                                 ObjectProvider<org.example.integration.wazuh.SshBlockExecutor> sshBlockProvider) {
        this(responseGuard, auditService, blockRecordStore, wazuhGatewayProvider, sshBlockProvider, null);
    }

    /**
     * 生产用构造器（Spring 用这一个）。
     *
     * <p>【2026-10-13 生产事故教训】这个类当时有<b>两个</b>构造器、且都没标注：
     * Spring 4.3+ 只在"类里唯一构造器"时才自动注入，多构造器必须显式指定，
     * 否则启动即 {@code No default constructor found} 崩溃（线上 11:35 起崩溃循环）。
     * 而当时 CI 是绿的 —— 单测直接 new 对象、从不加载 Spring 上下文。
     * 因此：① 这里显式 {@code @Autowired}；② 另加 {@code SpringBeanConstructorTest} 作为门禁，
     * 反射扫描所有 Spring 组件，凡是"多构造器但没有恰好一个 @Autowired"就直接测试失败。
     */
    @org.springframework.beans.factory.annotation.Autowired
    public ResponseActionService(ResponseGuard responseGuard,
                                 AuditService auditService,
                                 BlockRecordStore blockRecordStore,
                                 ObjectProvider<org.example.integration.WazuhGateway> wazuhGatewayProvider,
                                 ObjectProvider<org.example.integration.wazuh.SshBlockExecutor> sshBlockProvider,
                                 ObjectProvider<org.example.notify.SecurityEventNotifier> notifierProvider) {
        this.responseGuard = responseGuard;
        this.auditService = auditService;
        this.blockRecordStore = blockRecordStore;
        this.wazuhGatewayProvider = wazuhGatewayProvider;
        this.sshBlockProvider = sshBlockProvider;
        this.notifierProvider = notifierProvider;
    }

    /** 通知门面（可能不存在）；任何异常都不影响处置链路 */
    private org.example.notify.SecurityEventNotifier notifier() {
        if (notifierProvider == null) {
            return null;
        }
        try {
            return notifierProvider.getIfAvailable();
        } catch (Exception e) {
            logger.warn("取通知门面失败（不影响处置）：{}", e.getMessage());
            return null;
        }
    }

    /**
     * 处置通道是否可用。
     *
     * <h3>这里修的是一个"判据过时"的 bug</h3>
     * 原来的实现是 {@code gw.isAvailable()} —— 语义是
     * "Wazuh 管理 API 连上了吗"。但处置现在**已经不走 Wazuh API 了**
     * （AR 投递链路不通，改用 SSH 直连）。
     * 于是出现很隐蔽的情况：
     * <b>链路明明是通的、脚本手工执行能封，业务代码却判断"不可用"，
     * 直接走 MOCK 分支</b> —— 表现就是 "已封禁 …（MOCK 模拟）"。
     * <p>
     * 教训：改执行路径时，必须同时检查
     * "有哪些地方在判断这条路可不可用"，否则两边不一致，
     * 而且表现是【成功 + 假数据】，最难发现。
     */
    private boolean wazuhReady() {
        try {
            // 1) 首选：SSH 直连可用就能处置（不依赖 Wazuh API）
            org.example.integration.wazuh.SshBlockExecutor ssh = sshBlockProvider.getIfAvailable();
            logger.info("处置通道判定: sshBean={} enabled={}",
                    ssh != null, ssh == null ? "n/a" : ssh.isEnabled());
            if (ssh != null && ssh.isEnabled()) {
                return true;
            }
            // 2) 退回：Wazuh API 通道
            org.example.integration.WazuhGateway gw = wazuhGatewayProvider.getIfAvailable();
            return gw != null && gw.isAvailable();
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

        // ② 自动封禁通知：成功与失败都通知（失败等级更高，见 NotifyEvent.defaultSeverity）。
        // 刻意放在"审计与登记之后"：通知是最后一步，它慢了/挂了都不该改变处置结果。
        notifyBlock(target, result, reason, actor, duration);
        return result;
    }

    /** 封禁结果 → 通知（封禁被护栏拦截属于"没执行"，不通知，避免噪声） */
    private void notifyBlock(String target, ActiveResponseResult result, String reason,
                             String actor, int durationMinutes) {
        org.example.notify.SecurityEventNotifier notifier = notifier();
        if (notifier == null) {
            return;
        }
        try {
            if ("BLOCKED".equals(result.getMode())) {
                logger.info("封禁被护栏拦截（{}），不触发通知（未执行的动作不是「处置结果」）", target);
                return;
            }
            notifier.blockIp(target, result.isSuccess(), result.getMode(),
                    reason == null ? result.getMessage() : reason, actor, durationMinutes);
        } catch (Exception e) {
            logger.warn("封禁通知失败（不影响处置结果）：{}", e.getMessage());
        }
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
