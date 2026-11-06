package org.example.response;

import jakarta.servlet.http.HttpServletRequest;
import org.example.core.model.ActiveResponseResult;
import org.example.core.model.SecurityAlert;
import org.example.security.ResponseGuard;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.time.LocalDateTime;

/**
 * 处置中心接口（仅管理员，由 RbacInterceptor 强制）。
 * 提供：自动策略开关读写、处置建议、封IP/锁账号/杀进程、待审批审批、审计留痕查询。
 */
@RestController
@RequestMapping("/api/response")
public class ResponseController {

    private static final Logger logger = LoggerFactory.getLogger(ResponseController.class);

    private final ResponseActionService actionService;
    private final ApprovalService approvalService;
    private final AuditService auditService;
    private final BlockRecordStore blockRecordStore;
    private final ResponseGuard responseGuard;
    private final ObjectProvider<org.example.integration.WazuhGateway> wazuhGatewayProvider;

    /**
     * 分级 TTL 策略。
     *
     * <p>控制器需要它<b>只为两件事</b>：① 在转审批之前就定出"到底封多久"
     * （审批卡片必须显示真实时长，否则管理员批的是一个数、执行的是另一个数）；
     * ② 需求里"高危 = 超长封禁"的判据要基于最终时长，而不是请求里有没有填 durationMinutes。
     * 真正的时长决策仍然只在服务层做一次（{@code BlockPolicy.decide} 是纯函数，重复调用结果一致）。
     */
    private final BlockPolicy blockPolicy;

    /** 超长封禁（分钟）即视为高危，需人工确认 */
    private static final int LONG_BLOCK_MINUTES = 120;

    // ===== 自动策略开关（启动时取自 yml，运行时可改） =====
    // 加 volatile：状态在 policyLock 里改，读它的请求线程（getPolicy/block/lock/kill）
    // 大多不持锁 —— 不加会出现"改了策略但下一个请求还按旧策略走"的可见性问题。
    @Value("${response.auto-block-enabled:true}")
    private volatile boolean autoBlockEnabled;
    @Value("${response.auto-lock-account:false}")
    private volatile boolean autoLockAccount;
    @Value("${response.auto-kill-process:false}")
    private volatile boolean autoKillProcess;
    @Value("${response.high-risk-require-approval:true}")
    private volatile boolean highRiskRequireApproval;

    /**
     * 全局演练开关（只读，来自 yml）。
     *
     * <p>加它是因为"演练模式"必须能被运维<b>紧急打开</b>而不改代码；
     * 单次请求上的 {@code dryRun} 字段则给测试/演示用。两者的关系是"或"，
     * 由服务层的 {@code dryRun || dryRunEnabled} 统一裁决，避免两个地方各判一套。
     */
    @Value("${response.dry-run:false}")
    private boolean dryRunEnabled;

    /**
     * 策略锁：<b>只保护四个开关的内存更新</b>。
     *
     * <p>原来 {@code putPolicy} 是 {@code synchronized} 方法，临界区里包含
     * {@code auditService.append()}（整份审计文件序列化 + 落盘）。
     * 结果是一次"改策略"会阻塞本控制器所有同步方法（包括封 IP/杀进程的入口）。
     * 现在锁内只做内存写入，审计落盘在锁外。
     */
    private final Object policyLock = new Object();

    public ResponseController(ResponseActionService actionService,
                              ApprovalService approvalService,
                              AuditService auditService,
                              BlockRecordStore blockRecordStore,
                              ResponseGuard responseGuard,
                              ObjectProvider<org.example.integration.WazuhGateway> wazuhGatewayProvider,
                              BlockPolicy blockPolicy) {
        this.actionService = actionService;
        this.approvalService = approvalService;
        this.auditService = auditService;
        this.blockRecordStore = blockRecordStore;
        this.responseGuard = responseGuard;
        this.wazuhGatewayProvider = wazuhGatewayProvider;
        this.blockPolicy = blockPolicy == null ? new BlockPolicy() : blockPolicy;
    }

    private static Map<String, Object> ok(Object data, String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", 200);
        body.put("message", message == null ? "success" : message);
        body.put("data", data);
        return body;
    }

    private static String actor(HttpServletRequest req) {
        Object u = req.getAttribute("secagent.user");
        return u == null ? "system" : String.valueOf(u);
    }

    // ===== 自动策略 =====

    @GetMapping("/policy")
    public Map<String, Object> getPolicy() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("autoBlockEnabled", autoBlockEnabled);
        p.put("autoLockAccount", autoLockAccount);
        p.put("autoKillProcess", autoKillProcess);
        p.put("highRiskRequireApproval", highRiskRequireApproval);
        p.put("defaultDurationMinutes", responseGuard.getDefaultDurationMinutes());
        p.put("maxDurationMinutes", responseGuard.getMaxDurationMinutes());
        p.put("policyMaxDurationMinutes", responseGuard.getPolicyMaxDurationMinutes());
        p.put("dryRun", dryRunEnabled);
        // 把分级 TTL 档位暴露给前端：运维要能一眼看到"扫描 30min / 爆破 1d / 利用 7d"，
        // 否则封了 7 天会被当成 bug 来报
        Map<String, Object> ttl = new LinkedHashMap<>();
        for (BlockPolicy.ThreatClass tc : BlockPolicy.ThreatClass.values()) {
            Map<String, Object> one = new LinkedHashMap<>();
            one.put("label", tc.getLabel());
            one.put("minutes", blockPolicy.minutesFor(tc));
            ttl.put(tc.getToken(), one);
        }
        p.put("ttl", ttl);
        return ok(p, "success");
    }

    @PutMapping("/policy")
    public Map<String, Object> putPolicy(@RequestBody(required = false) Map<String, Object> body,
                                         HttpServletRequest req) {
        String snapshot;
        synchronized (policyLock) {
            // 锁内只改内存（纳秒级）；审计落盘在锁外做
            if (body != null) {
                if (body.get("autoBlockEnabled") != null) autoBlockEnabled = Boolean.parseBoolean(String.valueOf(body.get("autoBlockEnabled")));
                if (body.get("autoLockAccount") != null) autoLockAccount = Boolean.parseBoolean(String.valueOf(body.get("autoLockAccount")));
                if (body.get("autoKillProcess") != null) autoKillProcess = Boolean.parseBoolean(String.valueOf(body.get("autoKillProcess")));
                if (body.get("highRiskRequireApproval") != null) highRiskRequireApproval = Boolean.parseBoolean(String.valueOf(body.get("highRiskRequireApproval")));
            }
            snapshot = "block=" + autoBlockEnabled + ";lock=" + autoLockAccount
                    + ";kill=" + autoKillProcess + ";requireApproval=" + highRiskRequireApproval;
        }
        auditService.append(ResponseAudit.of(actor(req), "policy-update", "-",
                "更新自动处置策略", "LOW", "MOCK", true, snapshot));
        return getPolicy();
    }

    // ===== 处置建议 =====

    @GetMapping("/suggestions")
    public Map<String, Object> suggestions() {
        List<Map<String, Object>> list = new ArrayList<>();
        org.example.integration.WazuhGateway gw = null;
        try {
            gw = wazuhGatewayProvider.getIfAvailable();
        } catch (Exception ignore) {
        }
        boolean real = gw != null && gw.isAvailable();

        if (real) {
            List<SecurityAlert> alerts = gw.recentAlerts(10);
            for (SecurityAlert a : alerts) {
                Map<String, Object> s = new LinkedHashMap<>();
                s.put("alertId", a.getId());
                s.put("ruleName", a.getRuleName());
                s.put("title", a.getTitle());
                s.put("srcIp", a.getSrcIp());
                s.put("severity", a.getSeverity() == null ? "MEDIUM" : a.getSeverity().name());
                s.put("recommendAction", "block-ip");
                s.put("target", a.getSrcIp());
                s.put("riskLevel", a.getSeverity() != null && a.getSeverity().getRank() >= 3 ? "HIGH" : "LOW");
                s.put("reason", "针对 " + a.getTitle() + " 的来源 IP 建议封禁");
                list.add(s);
            }
        }
        if (list.isEmpty()) {
            // 内置兜底建议（无 Wazuh 时也能演示）
            list.add(suggestion("sug-brute", "SSH 暴力破解", "block-ip", "203.0.113.24",
                    "HIGH", "检测到 SSH 密码爆破 50+ 次失败，建议封禁来源 IP 60 分钟"));
            list.add(suggestion("sug-sql", "SQL 注入尝试", "block-ip", "198.51.100.7",
                    "HIGH", "WAF 拦截到 UNION SELECT 注入载荷，建议封禁来源 IP"));
            list.add(suggestion("sug-webshell", "Webshell 上传成功", "kill-process", "4821",
                    "HIGH", "检测到一句话后门被执行，建议结束可疑进程（高危，需人工确认）"));
            list.add(suggestion("sug-account", "异常账号登录", "lock-account", "guest",
                    "HIGH", "检测到外部 IP 登录普通账号 guest，建议锁定该账号（高危，需人工确认）"));
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("mode", real ? "REAL" : "MOCK");
        data.put("items", list);
        return ok(data, "success");
    }

    private static Map<String, Object> suggestion(String id, String rule, String action, String target,
                                                 String risk, String reason) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("alertId", id);
        s.put("ruleName", rule);
        s.put("title", rule);
        s.put("srcIp", action.equals("block-ip") ? target : "");
        s.put("severity", risk.equals("HIGH") ? "HIGH" : "MEDIUM");
        s.put("recommendAction", action);
        s.put("target", target);
        s.put("riskLevel", risk);
        s.put("reason", reason);
        return s;
    }

    // ===== 执行 / 转审批 =====

    /**
     * 封禁来源 IP。
     *
     * <p>请求体可带：ip / durationMinutes / reason / riskLevel / dryRun。
     * {@code durationMinutes} 省略时<b>不再默认 60 分钟</b>，而是交给
     * {@link BlockPolicy} 按攻击类型定档（扫描 30min、爆破 24h、利用 7d）。
     */
    @PostMapping("/block")
    public Map<String, Object> block(@RequestBody Map<String, Object> body, HttpServletRequest req) {
        String actor = actor(req);
        String ip = str(body.get("ip"));
        Integer duration = body.get("durationMinutes") == null ? null
                : (intVal(body.get("durationMinutes")));
        String reason = str(body.get("reason"));
        if (reason == null) reason = "手动封IP";
        String riskHint = str(body.get("riskLevel"));
        boolean dryRun = Boolean.parseBoolean(String.valueOf(body.get("dryRun")));

        if (!autoBlockEnabled) {
            ActiveResponseResult blocked = ActiveResponseResult.blocked("ipset-block", ip == null ? "" : ip,
                    "封IP自动处置策略已关闭，请先在策略面板开启");
            auditService.append(ResponseAudit.of(actor, "block-ip", ip == null ? "" : ip,
                    blocked.getMessage(), "LOW", "BLOCKED", false, "策略关闭"));
            return ok(wrap(blocked, false, false), "封IP被策略关闭拦截");
        }

        // 先过护栏：被拦立刻返回原因，不进入审批。
        // 用"策略派生"口径预判（与下面最终下发的时长档位一致），避免预判和实际执行用两套上限
        BlockPolicy.Decision decision = blockPolicy.decide(duration, reason, riskHint);
        String guardReason = responseGuard.validateBlock(ip, decision.getMinutes(),
                decision.isPolicyDerived());
        if (guardReason != null) {
            // 交给服务层统一写"被护栏拦截"的审计并返回标准结果（不要在这里重复造审计）
            ActiveResponseResult blocked = actionService.blockIp(
                    request(ip, duration, reason, actor, riskHint, dryRun));
            return ok(wrap(blocked, false, false), "已被护栏拦截");
        }

        int dur = decision.getMinutes();
        String risk = dur > LONG_BLOCK_MINUTES ? "HIGH" : "LOW";
        boolean needApproval = "HIGH".equals(risk) && highRiskRequireApproval && !dryRun;
        if (needApproval) {
            Map<String, Object> params = new LinkedHashMap<>();
            params.put("ip", ip);
            params.put("durationMinutes", dur);
            // 这两个标记是给审批回放用的：策略派生的时长必须回放"派生"语义，
            // 否则 7 天的利用类封禁在审批通过后会被人工上限截成 1 天
            params.put("policyDerived", decision.isPolicyDerived());
            params.put("dryRun", dryRun);
            ApprovalService.Order order = approvalService.create("block-ip", ip, reason, risk, params, actor);
            return ok(wrap(null, true, true, order), "超长封禁为高危，已转人工审批");
        }
        ActiveResponseResult r = actionService.blockIp(
                request(ip, duration, reason, actor, riskHint, dryRun));
        String msg = dryRun ? "演练完成（未真正下发）" : "执行完成";
        return ok(wrap(r, false, true, null), msg);
    }

    /** 组装封禁请求（把 riskLevel 提示与 dryRun 一起带下去，服务层只做一次决策） */
    private static BlockRequest request(String ip, Integer duration, String reason, String actor,
                                        String riskHint, boolean dryRun) {
        BlockRequest r = new BlockRequest();
        r.setIp(ip);
        r.setDurationMinutes(duration);
        r.setReason(reason);
        r.setActor(actor);
        r.setSource("手动");
        r.setRiskLevel(riskHint);
        r.setDryRun(dryRun);
        return r;
    }

    // ===== 解封 / 回滚（误封止血） =====

    /**
     * 手动解封单个 IP（不经过审批：解封是"减少伤害"方向的动作，卡它只会延长误封）。
     */
    @PostMapping("/unblock")
    public Map<String, Object> unblock(@RequestBody Map<String, Object> body, HttpServletRequest req) {
        String ip = str(body.get("ip"));
        ActiveResponseResult r = actionService.unblockIp(ip, actor(req), "手动");
        return ok(wrap(r, false, true), r.isSuccess() ? "已解封" : "解封失败");
    }

    /**
     * 一键回滚封禁。
     *
     * <p>请求体 {@code {"flush": true}} = 清空服务端 secagent_block / secagent_block6 两个集合
     * （以及无 ipset 时的回退规则）；{@code false} 或不填 = 只逐条解封当前生效中的记录。
     * flush 更快（一条命令），逐条更保守（不会误伤不属于本次会话的条目）。
     */
    @PostMapping("/rollback")
    public Map<String, Object> rollback(@RequestBody(required = false) Map<String, Object> body,
                                        HttpServletRequest req) {
        boolean flush = body != null && Boolean.parseBoolean(String.valueOf(body.get("flush")));
        Map<String, Object> r = actionService.rollback(flush, actor(req));
        boolean okFlag = Boolean.TRUE.equals(r.get("success"));
        return ok(r, okFlag ? String.valueOf(r.get("message")) : "回滚部分失败，详见 failedTargets");
    }

    @PostMapping("/lock")
    public Map<String, Object> lock(@RequestBody Map<String, Object> body, HttpServletRequest req) {
        String actor = actor(req);
        String account = str(body.get("account"));
        String host = str(body.get("host"));
        String reason = str(body.get("reason"));
        if (reason == null) reason = "手动锁定账号";

        if (!autoLockAccount) {
            ActiveResponseResult blocked = ActiveResponseResult.blocked("win-disable-account", account == null ? "" : account,
                    "锁账号策略已关闭（高危动作默认关闭）");
            auditService.append(ResponseAudit.of(actor, "lock-account", account == null ? "" : account,
                    blocked.getMessage(), "HIGH", "BLOCKED", false, "策略关闭"));
            return ok(wrap(blocked, false, false), "锁账号已被策略关闭");
        }
        boolean needApproval = highRiskRequireApproval;
        if (needApproval) {
            Map<String, Object> params = new LinkedHashMap<>();
            params.put("account", account);
            params.put("host", host);
            ApprovalService.Order order = approvalService.create("lock-account", account, reason, "HIGH", params, actor);
            return ok(wrap(null, true, true, order), "锁账号为高危，已转人工审批");
        }
        ActiveResponseResult r = actionService.lockAccount(account, host, reason, actor);
        return ok(wrap(r, false, true, null), "执行完成");
    }

    @PostMapping("/kill")
    public Map<String, Object> kill(@RequestBody Map<String, Object> body, HttpServletRequest req) {
        String actor = actor(req);
        String pid = str(body.get("pid"));
        String process = str(body.get("process"));
        String host = str(body.get("host"));
        String reason = str(body.get("reason"));
        if (reason == null) reason = "手动结束进程";
        String target = (pid != null && !pid.isEmpty()) ? pid : process;

        if (!autoKillProcess) {
            ActiveResponseResult blocked = ActiveResponseResult.blocked("kill-process", target == null ? "" : target,
                    "杀进程策略已关闭（高危动作默认关闭）");
            auditService.append(ResponseAudit.of(actor, "kill-process", target == null ? "" : target,
                    blocked.getMessage(), "HIGH", "BLOCKED", false, "策略关闭"));
            return ok(wrap(blocked, false, false), "杀进程已被策略关闭");
        }
        boolean needApproval = highRiskRequireApproval;
        if (needApproval) {
            Map<String, Object> params = new LinkedHashMap<>();
            params.put("pid", pid);
            params.put("process", process);
            params.put("host", host);
            ApprovalService.Order order = approvalService.create("kill-process", target, reason, "HIGH", params, actor);
            return ok(wrap(null, true, true, order), "杀进程为高危，已转人工审批");
        }
        ActiveResponseResult r = actionService.killProcess(pid, process, host, reason, actor);
        return ok(wrap(r, false, true, null), "执行完成");
    }

    // ===== 审批 =====

    @GetMapping("/approvals")
    public Map<String, Object> approvals() {
        return ok(approvalService.listPending(), "success");
    }

    @PostMapping("/approve/{id}")
    public Map<String, Object> approve(@PathVariable String id, HttpServletRequest req) {
        Map<String, Object> r = approvalService.approve(id, actor(req));
        return ok(r, (Boolean) r.getOrDefault("success", false) ? "已批准并执行" : "处理失败");
    }

    @PostMapping("/reject/{id}")
    public Map<String, Object> reject(@PathVariable String id, HttpServletRequest req) {
        Map<String, Object> r = approvalService.reject(id, actor(req));
        return ok(r, (Boolean) r.getOrDefault("success", false) ? "已驳回" : "处理失败");
    }

    // ===== 审计 =====

    @GetMapping("/audit")
    public Map<String, Object> audit(@RequestParam(required = false) String action,
                                     @RequestParam(required = false) String success) {
        Boolean succ = null;
        if (success != null && !success.isEmpty()) {
            succ = Boolean.parseBoolean(success);
        }
        return ok(auditService.list(action, succ), "success");
    }

    // ===== 封禁中列表（含到期自动解封） =====

    @GetMapping("/blocks")
    public Map<String, Object> blocks() {
        LocalDateTime now = LocalDateTime.now();
        List<Map<String, Object>> out = new ArrayList<>();
        for (BlockRecord r : blockRecordStore.listAll()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", r.getId());
            m.put("ip", r.getIp());
            m.put("durationMinutes", r.getDurationMinutes());
            m.put("source", r.getSource());
            m.put("actor", r.getActor());
            m.put("auditId", r.getAuditId());
            m.put("createdAt", r.getCreatedAt());
            m.put("expiresAt", r.getExpiresAt());
            m.put("unblocked", r.isUnblocked());
            m.put("unblockedAt", r.getUnblockedAt());
            m.put("unblockMode", r.getUnblockMode());
            // 新增三列是为了排障：封了多久的、按哪档定的、走的是 ipset 还是 iptables 回退
            m.put("threatClass", r.getThreatClass());
            m.put("policyDerived", r.isPolicyDerived());
            m.put("backend", r.getBackend());
            m.put("status", r.isUnblocked() ? "UNBLOCKED" : "BLOCKED");
            // 距到期分钟数（已解封记 0；时间解析失败记 -1）
            long remainingMinutes = -1;
            if (!r.isUnblocked()) {
                try {
                    long mins = java.time.Duration.between(now,
                            LocalDateTime.parse(r.getExpiresAt(), BlockRecordStore.FMT)).toMinutes();
                    remainingMinutes = Math.max(0, mins);
                } catch (Exception ignore) {
                }
            } else {
                remainingMinutes = 0;
            }
            m.put("remainingMinutes", remainingMinutes);
            out.add(m);
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("items", out);
        data.put("now", now.format(BlockRecordStore.FMT));
        return ok(data, "success");
    }

    // ===== 工具 =====

    private static Map<String, Object> wrap(ActiveResponseResult result, boolean needApproval,
                                            boolean executed, ApprovalService.Order order) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("needApproval", needApproval);
        m.put("executed", executed);
        m.put("result", result);
        if (order != null) m.put("approval", order);
        return m;
    }

    private static Map<String, Object> wrap(ActiveResponseResult result, boolean needApproval, boolean executed) {
        return wrap(result, needApproval, executed, null);
    }

    private static String str(Object o) {
        return o == null ? null : String.valueOf(o).trim().isEmpty() ? null : String.valueOf(o).trim();
    }

    private static int intVal(Object o) {
        if (o instanceof Number) return ((Number) o).intValue();
        return Integer.parseInt(String.valueOf(o));
    }
}
