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
                              ObjectProvider<org.example.integration.WazuhGateway> wazuhGatewayProvider) {
        this.actionService = actionService;
        this.approvalService = approvalService;
        this.auditService = auditService;
        this.blockRecordStore = blockRecordStore;
        this.responseGuard = responseGuard;
        this.wazuhGatewayProvider = wazuhGatewayProvider;
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

    @PostMapping("/block")
    public Map<String, Object> block(@RequestBody Map<String, Object> body, HttpServletRequest req) {
        String actor = actor(req);
        String ip = str(body.get("ip"));
        Integer duration = body.get("durationMinutes") == null ? null
                : (intVal(body.get("durationMinutes")));
        String reason = str(body.get("reason"));
        if (reason == null) reason = "手动封IP";

        if (!autoBlockEnabled) {
            ActiveResponseResult blocked = ActiveResponseResult.blocked("firewall-drop", ip == null ? "" : ip,
                    "封IP自动处置策略已关闭，请先在策略面板开启");
            auditService.append(ResponseAudit.of(actor, "block-ip", ip == null ? "" : ip,
                    blocked.getMessage(), "LOW", "BLOCKED", false, "策略关闭"));
            return ok(wrap(blocked, false, false), "封IP被策略关闭拦截");
        }

        // 先过护栏：被拦立刻返回原因，不进入审批
        String guardReason = responseGuard.validateBlock(ip, duration);
        if (guardReason != null) {
            ActiveResponseResult blocked = actionService.blockIp(ip, duration, reason, actor);
            return ok(wrap(blocked, false, false), "已被护栏拦截");
        }

        int dur = duration == null ? responseGuard.getDefaultDurationMinutes() : duration;
        String risk = dur > LONG_BLOCK_MINUTES ? "HIGH" : "LOW";
        boolean needApproval = "HIGH".equals(risk) && highRiskRequireApproval;
        if (needApproval) {
            Map<String, Object> params = new LinkedHashMap<>();
            params.put("ip", ip);
            params.put("durationMinutes", dur);
            ApprovalService.Order order = approvalService.create("block-ip", ip, reason, risk, params, actor);
            return ok(wrap(null, true, true, order), "超长封禁为高危，已转人工审批");
        }
        ActiveResponseResult r = actionService.blockIp(ip, dur, reason, actor);
        return ok(wrap(r, false, true, null), "执行完成");
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
