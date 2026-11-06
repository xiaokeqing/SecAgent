package org.example.response;

import org.example.core.model.ActiveResponseResult;
import org.example.security.ResponseGuard;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 处置动作执行服务（SecAgent 自己的"手"的编排层）。
 *
 * <p>架构原则：研判、风险分级、护栏都在本服务内；执行器（SSH 直连脚本 / Wazuh）
 * 只是"真实执行封禁的手"。
 *
 * <p>每一个动作执行前都会先过 {@link ResponseGuard} 护栏（封 IP）或基本入参校验，
 * 被拦截的动作不真正下发，但同样写审计留痕。
 *
 * <h3>封禁链路（本次升级后的顺序）</h3>
 * <ol>
 *   <li><b>分级 TTL</b>：{@link BlockPolicy} 按攻击类型/显式时长定下封多久（不再写死 60 分钟）</li>
 *   <li><b>护栏</b>：白名单/本机公网 IP/健康检查源/上限，一律先在 {@link ResponseGuard} 判；
 *       策略算出的长时长走"策略上限"，人工指定走"人工上限"</li>
 *   <li><b>dry-run</b>：只算出并记录"本应执行的命令"，<b>不碰执行器、不登记封禁记录</b></li>
 *   <li><b>SSH 集合式封禁</b>（ipset 优先、无 ipset 回退 iptables，回退点在服务端）</li>
 *   <li><b>降级</b>：SSH 失败 → Wazuh AR（若可用）→ 仍失败则如实返回 failed</li>
 * </ol>
 * 任何一步失败都<b>不抛异常</b>：处置接口被调用方包在告警流水线里，
 * 抛出去会打断整条告警处理；失败要变成"带审计的失败结果"而不是异常。
 */
@Service
public class ResponseActionService {

    private static final Logger logger = LoggerFactory.getLogger(ResponseActionService.class);

    /** 全局演练开关：打开后所有封禁只算命令不下发（与单次 dryRun 是"或"关系） */
    @org.springframework.beans.factory.annotation.Value("${response.dry-run:false}")
    private boolean dryRunEnabled;

    private final ResponseGuard responseGuard;
    private final AuditService auditService;
    private final BlockRecordStore blockRecordStore;
    private final BlockPolicy blockPolicy;

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

    /** 便捷构造器：**仅供单测**直接 new 使用（通知为空，策略用默认档位）。Spring 不要用它。 */
    public ResponseActionService(ResponseGuard responseGuard,
                                 AuditService auditService,
                                 BlockRecordStore blockRecordStore,
                                 ObjectProvider<org.example.integration.WazuhGateway> wazuhGatewayProvider,
                                 ObjectProvider<org.example.integration.wazuh.SshBlockExecutor> sshBlockProvider) {
        this(responseGuard, auditService, blockRecordStore, wazuhGatewayProvider, sshBlockProvider, null, new BlockPolicy());
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
                                 ObjectProvider<org.example.notify.SecurityEventNotifier> notifierProvider,
                                 BlockPolicy blockPolicy) {
        this.responseGuard = responseGuard;
        this.auditService = auditService;
        this.blockRecordStore = blockRecordStore;
        this.wazuhGatewayProvider = wazuhGatewayProvider;
        this.sshBlockProvider = sshBlockProvider;
        this.notifierProvider = notifierProvider;
        this.blockPolicy = blockPolicy == null ? new BlockPolicy() : blockPolicy;
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

    /** 取 SSH 执行器（可能不存在/未启用），异常一律当"不存在"处理 */
    private org.example.integration.wazuh.SshBlockExecutor ssh() {
        if (sshBlockProvider == null) {
            return null;
        }
        try {
            return sshBlockProvider.getIfAvailable();
        } catch (Exception e) {
            logger.warn("取 SSH 封禁执行器失败（降级）：{}", e.getMessage());
            return null;
        }
    }

    private boolean sshReady() {
        org.example.integration.wazuh.SshBlockExecutor ssh = ssh();
        return ssh != null && ssh.isEnabled();
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
            if (sshReady()) {
                return true;
            }
            // 2) 退回：Wazuh API 通道
            org.example.integration.WazuhGateway gw = wazuhGatewayProvider == null
                    ? null : wazuhGatewayProvider.getIfAvailable();
            return gw != null && gw.isAvailable();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 封禁来源 IP（默认来源"手动"）。
     */
    public ActiveResponseResult blockIp(String ip, Integer durationMinutes, String reason, String actor) {
        return blockIp(ip, durationMinutes, reason, actor, "手动");
    }

    /**
     * 封禁来源 IP（显式指定执行来源 source：手动 / 审批 / 智能体）。
     *
     * <p>保留这个签名是刻意的：审批服务与智能体工具都按它调用，
     * 单测也用匿名子类覆写它来验证"只执行一次"。新增能力一律通过
     * {@link #blockIp(BlockRequest)} 扩展，不动这条缝。
     */
    public ActiveResponseResult blockIp(String ip, Integer durationMinutes, String reason, String actor, String source) {
        return blockIp(BlockRequest.of(ip, durationMinutes, reason, actor, source));
    }

    /**
     * 封禁来源 IP（完整参数：风险提示 + dry-run）。
     *
     * <p>顺序见类注释。失败<b>不抛异常</b>，一律转成 failed 结果 + 审计。
     */
    public ActiveResponseResult blockIp(BlockRequest req) {
        if (req == null) {
            req = new BlockRequest();
        }
        String actor = req.getActor() == null || req.getActor().isBlank() ? "system" : req.getActor();
        String source = req.getSource() == null || req.getSource().isBlank() ? "手动" : req.getSource();
        String rawIp = req.getIp();
        boolean dryRun = req.isDryRun() || dryRunEnabled;

        // ① 分级 TTL：显式时长 > 攻击类型 > 风险等级兜底 > 默认
        BlockPolicy.Decision decision = blockPolicy.decide(req.getDurationMinutes(), req.getReason(), req.getRiskLevel());
        int duration = decision.getMinutes();
        int cap = decision.isPolicyDerived()
                ? responseGuard.getPolicyMaxDurationMinutes()
                : responseGuard.getMaxDurationMinutes();
        boolean clamped = duration > cap;
        if (clamped) {
            // 策略配得比上限还大时在这里截断，而不是让护栏直接拒绝 ——
            // 拒绝会让这次攻击完全得不到处置，截断至少保住了"封住"这个目标
            logger.warn("封禁时长 {}min 超过{}上限 {}min，已截断",
                    duration, decision.isPolicyDerived() ? "策略" : "人工", cap);
            duration = cap;
        }

        // ② 护栏（新路径同样必须过；policyDerived 决定用哪档上限）
        String guardReason = responseGuard.validateBlock(rawIp, duration, decision.isPolicyDerived());
        if (guardReason != null) {
            ResponseAudit audit = ResponseAudit.of(actor, "block-ip", rawIp == null ? "" : rawIp.trim(),
                    guardReason, riskOf(duration), "BLOCKED", false,
                    "封禁被护栏拦截（type=" + decision.getThreatClass().getToken() + "）");
            auditService.append(audit);
            logger.warn("封IP被护栏拦截 target={} reason={}", rawIp, guardReason);
            return ActiveResponseResult.blocked("ipset-block", rawIp == null ? "" : rawIp.trim(), guardReason);
        }
        String target = rawIp.trim();
        int ttl = BlockPolicy.toTimeoutSeconds(duration);
        String slug = BlockCommands.reasonSlug(decision.getThreatClass().getToken());

        // ③ dry-run：算出命令就返回，绝不调用执行器
        if (dryRun) {
            String planned = BlockCommands.plan(target, ttl, slug);
            String detail = baseDetail(duration, ttl, decision, clamped)
                    + "; backend=DRY_RUN; 未下发; plan={" + planned.replace('\n', '|') + "}";
            ResponseAudit audit = ResponseAudit.of(actor, "block-ip", target, req.getReason(),
                    riskOf(duration), "DRY_RUN", true, detail);
            auditService.append(audit);
            logger.info("封禁 dry-run（未下发）：target={} duration={}min plan={}", target, duration, planned);
            return ActiveResponseResult.dryRun("ipset-block", target,
                    "DRY_RUN（演练，未下发）：本应执行\n" + planned, audit.getId());
        }

        // ④ 真实下发：SSH 集合式 → Wazuh 降级
        ActiveResponseResult result;
        String backend;
        String command = BlockCommands.forcedCommand(target, ttl, slug);
        org.example.integration.wazuh.SshBlockExecutor ssh = ssh();
        boolean sshUsable = ssh != null && ssh.isEnabled();
        if (sshUsable) {
            try {
                String out = ssh.block(target, ttl, slug);
                backend = BlockCommands.parseBackend(out);
                result = ActiveResponseResult.real("ipset-block", target,
                        "已封禁 " + target + " 共 " + duration + " 分钟（后端=" + backend
                                + "，ttl=" + ttl + "s）：" + out, nextAuditId());
            } catch (Exception e) {
                logger.warn("SSH 集合式封禁失败，尝试降级 Wazuh：target={} err={}", target, e.getMessage());
                backend = "SSH-FAILED";
                result = degradeToWazuh(target, duration, "SSH 失败: " + e.getMessage());
                if (result != null) {
                    backend = "WAZUH";
                } else {
                    result = ActiveResponseResult.failed("ipset-block", target,
                            "封禁下发失败（SSH: " + e.getMessage() + "；Wazuh 不可用或同样失败）");
                }
            }
        } else if (wazuhReady()) {
            backend = "WAZUH";
            ActiveResponseResult w = degradeToWazuh(target, duration, "SSH 未启用");
            if (w != null) {
                result = w;
            } else {
                backend = "MOCK";
                result = mockResult(target, duration);
            }
        } else {
            backend = "MOCK";
            result = mockResult(target, duration);
        }

        // ⑤ 审计 + 登记 + 通知
        String detail = baseDetail(duration, ttl, decision, clamped)
                + "; backend=" + backend + "; cmd=" + command + "; " + result.getMessage();
        ResponseAudit audit = ResponseAudit.of(actor, "block-ip", target, req.getReason(),
                riskOf(duration), result.getMode(), result.isSuccess(), detail);
        auditService.append(audit);
        result.setAuditId(audit.getId());

        // 只有真正生效（REAL/MOCK/wazuh，且非拦截、非演练）才登记到期记录。
        // MOCK 也登记是历史约定：演示环境里仍要能看到"到期自动解封"闭环。
        if (result.isSuccess()
                && !"BLOCKED".equals(result.getMode())
                && !"DRY_RUN".equals(result.getMode())) {
            try {
                blockRecordStore.register(target, duration, source, actor, result.getAuditId(),
                        result.getMode(), decision.getThreatClass().getToken(),
                        decision.isPolicyDerived(), backend, command);
            } catch (Exception e) {
                // 登记失败不能反过来把一次已经成功的封禁报成失败
                logger.error("封禁记录登记失败（封禁已生效）：target={} err={}", target, e.getMessage());
            }
        }

        notifyBlock(target, result, req.getReason(), actor, duration);
        return result;
    }

    /** 降级到 Wazuh AR；不可用或失败返回 null（让调用方决定最终结果） */
    private ActiveResponseResult degradeToWazuh(String target, int duration, String why) {
        try {
            org.example.integration.WazuhGateway gw = wazuhGatewayProvider == null
                    ? null : wazuhGatewayProvider.getIfAvailable();
            if (gw == null || !gw.isAvailable()) {
                return null;
            }
            Map<String, Object> args = new HashMap<>();
            args.put("ip", target);
            args.put("duration", duration);
            ActiveResponseResult r = gw.runActiveResponse("firewall-drop", args);
            if (r == null) {
                return null;
            }
            if (r.getAuditId() == null) {
                r.setAuditId(nextAuditId());
            }
            r.setMessage((r.getMessage() == null ? "" : r.getMessage()) + "（降级路径：" + why + "）");
            return r;
        } catch (Exception e) {
            logger.warn("降级 Wazuh 也失败：{}", e.getMessage());
            return null;
        }
    }

    private ActiveResponseResult mockResult(String target, int duration) {
        return ActiveResponseResult.mock("ipset-block", target,
                "已封禁 " + target + " 共 " + duration + " 分钟（MOCK 模拟，未连接真实执行通道）", nextAuditId());
    }

    private static String baseDetail(int duration, int ttl, BlockPolicy.Decision d, boolean clamped) {
        return "duration=" + duration + "min; class=" + d.getThreatClass().getToken()
                + "; policy=" + (d.isPolicyDerived() ? "auto" : "explicit")
                + "（" + d.getBasis() + "）; ttl=" + ttl + "s" + (clamped ? "; clamped=true" : "");
    }

    private static String riskOf(int durationMinutes) {
        return durationMinutes > 120 ? "HIGH" : "LOW";
    }

    /**
     * 解封单个 IP（手动/回滚）。
     *
     * <p>解封<b>不套用封禁白名单</b>：白名单是"不该封"，不是"不该解"。
     * 反过来说，如果历史上误封了白名单里的地址，套用白名单会让它永远解不掉。
     */
    public ActiveResponseResult unblockIp(String ip, String actor, String source) {
        String a = actor == null || actor.isBlank() ? "system" : actor;
        if (!BlockCommands.isIpLiteral(ip)) {
            String r = "非法 IP 地址: " + ip;
            auditService.append(ResponseAudit.of(a, "unblock-ip", ip == null ? "" : ip,
                    r, "LOW", "BLOCKED", false, "解封被入参校验拦截"));
            return ActiveResponseResult.blocked("ipset-unblock", ip == null ? "" : ip, r);
        }
        String target = ip.trim();
        ActiveResponseResult result;
        String backend;
        try {
            org.example.integration.wazuh.SshBlockExecutor ssh = ssh();
            if (ssh != null && ssh.isEnabled()) {
                String out = ssh.unblock(target);
                backend = BlockCommands.parseBackend(out);
                result = ActiveResponseResult.real("ipset-unblock", target,
                        "已解封 " + target + "（后端=" + backend + "）：" + out, nextAuditId());
            } else if (wazuhReady()) {
                backend = "WAZUH";
                Map<String, Object> args = new HashMap<>();
                args.put("ip", target);
                ActiveResponseResult r = wazuhGatewayProvider.getIfAvailable()
                        .runActiveResponse("firewall-unblock", args);
                result = r == null ? ActiveResponseResult.failed("ipset-unblock", target, "Wazuh 返回空结果") : r;
            } else {
                backend = "MOCK";
                result = ActiveResponseResult.mock("ipset-unblock", target,
                        "已解封 " + target + "（MOCK 模拟，未连接真实执行通道）", nextAuditId());
            }
        } catch (Exception e) {
            backend = "FAILED";
            result = ActiveResponseResult.failed("ipset-unblock", target, "解封下发失败: " + e.getMessage());
        }

        ResponseAudit audit = ResponseAudit.of(a, "unblock-ip", target,
                "手动解封（来源=" + (source == null ? "手动" : source) + "）", "LOW",
                result.getMode(), result.isSuccess(),
                "backend=" + backend + "; " + result.getMessage());
        auditService.append(audit);
        result.setAuditId(audit.getId());

        if (result.isSuccess()) {
            try {
                blockRecordStore.markUnblockedByIp(target, result.getMode());
            } catch (Exception e) {
                logger.error("标记解封记录失败：target={} err={}", target, e.getMessage());
            }
        }
        return result;
    }

    /**
     * 回滚（误封止血）：清空本次运行加入的封禁条目。
     *
     * @param flushAll true = 一次性清空服务端两个集合（v4/v6）+ 回退规则；
     *                 false = 逐条解封当前"生效中"的记录
     * @return 结构化结果（mode/removed/failed/message），供控制器直接返回
     */
    public Map<String, Object> rollback(boolean flushAll, String actor) {
        String a = actor == null || actor.isBlank() ? "system" : actor;
        Set<String> ips = new LinkedHashSet<>();
        for (BlockRecord r : blockRecordStore.listActive()) {
            if (r.getIp() != null && !r.getIp().isBlank()) {
                ips.add(r.getIp());
            }
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("flushAll", flushAll);
        out.put("targets", new ArrayList<>(ips));

        if (!flushAll && ips.isEmpty()) {
            out.put("success", true);
            out.put("removed", 0);
            out.put("message", "当前没有生效中的封禁记录，无需回滚");
            return out;
        }

        int removed = 0;
        List<String> failed = new ArrayList<>();
        String mode;
        String command;
        org.example.integration.wazuh.SshBlockExecutor ssh = ssh();
        try {
            if (ssh != null && ssh.isEnabled()) {
                mode = "REAL";
                if (flushAll) {
                    command = "flush";
                    String resp = ssh.flush();
                    out.put("response", resp);
                    for (String ip : ips) {
                        blockRecordStore.markUnblockedByIp(ip, "REAL");
                        removed++;
                    }
                } else {
                    command = "unblock <ip> ×" + ips.size();
                    for (String ip : ips) {
                        try {
                            ssh.unblock(ip);
                            blockRecordStore.markUnblockedByIp(ip, "REAL");
                            removed++;
                        } catch (Exception e) {
                            failed.add(ip + ": " + e.getMessage());
                        }
                    }
                }
            } else if (wazuhReady()) {
                mode = "REAL";
                command = "firewall-unblock <ip> ×" + ips.size();
                for (String ip : ips) {
                    try {
                        Map<String, Object> args = new HashMap<>();
                        args.put("ip", ip);
                        wazuhGatewayProvider.getIfAvailable().runActiveResponse("firewall-unblock", args);
                        blockRecordStore.markUnblockedByIp(ip, "REAL");
                        removed++;
                    } catch (Exception e) {
                        failed.add(ip + ": " + e.getMessage());
                    }
                }
            } else {
                // 无执行通道时仍标记记录：与调度器 MOCK 口径一致，避免记录永远挂着
                mode = "MOCK";
                command = "MOCK rollback ×" + ips.size();
                for (String ip : ips) {
                    blockRecordStore.markUnblockedByIp(ip, "MOCK");
                    removed++;
                }
            }
        } catch (Exception e) {
            mode = "REAL";
            command = flushAll ? "flush" : "unblock <ip>";
            failed.add("整体失败: " + e.getMessage());
        }

        boolean ok = failed.isEmpty();
        auditService.append(ResponseAudit.of(a, flushAll ? "rollback-all" : "rollback-ip",
                flushAll ? "*" : String.join(",", ips), "手动回滚封禁（误封止血）", "HIGH",
                mode, ok, "cmd=" + command + "; 解除=" + removed + "; 失败=" + failed));

        out.put("success", ok);
        out.put("mode", mode);
        out.put("removed", removed);
        out.put("failed", failed.size());
        out.put("failedTargets", failed);
        out.put("command", command);
        out.put("message", ok
                ? "已回滚 " + removed + " 条封禁（" + mode + "）"
                : "回滚部分失败：成功 " + removed + "，失败 " + failed.size());
        logger.info("封禁回滚完成：flushAll={} mode={} removed={} failed={}", flushAll, mode, removed, failed.size());
        return out;
    }

    /** 封禁结果 → 通知（拦截/演练属于"没执行"，不通知，避免噪声） */
    private void notifyBlock(String target, ActiveResponseResult result, String reason,
                             String actor, int durationMinutes) {
        org.example.notify.SecurityEventNotifier notifier = notifier();
        if (notifier == null) {
            return;
        }
        try {
            if ("BLOCKED".equals(result.getMode()) || "DRY_RUN".equals(result.getMode())) {
                logger.info("封禁未真正执行（mode={}，{}），不触发通知",
                        result.getMode(), target);
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
