package org.example.response;

import lombok.Data;
import org.example.core.model.ActiveResponseResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 人在回路审批服务。
 * 高危动作（锁账号 / 杀进程 / 超长封禁）先在这里生成"待审批单"，
 * 管理员点击批准后才真正调 {@link ResponseActionService} 执行；驳回则不执行。
 * 审批通过/驳回都写审计。
 */
@Service
public class ApprovalService {

    private static final Logger logger = LoggerFactory.getLogger(ApprovalService.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final ResponseActionService actionService;
    private final AuditService auditService;

    /** 审批单：id -> Order */
    private final Map<String, Order> orders = new ConcurrentHashMap<>();

    public ApprovalService(ResponseActionService actionService, AuditService auditService) {
        this.actionService = actionService;
        this.auditService = auditService;
    }

    /** 创建待审批单 */
    public Order create(String action, String target, String reason, String riskLevel,
                        Map<String, Object> params, String requestedBy) {
        Order o = new Order();
        o.setId("APR-" + UUID.randomUUID().toString().substring(0, 8));
        o.setAction(action);
        o.setTarget(target);
        o.setReason(reason);
        o.setRiskLevel(riskLevel);
        o.setParams(params == null ? new LinkedHashMap<>() : new LinkedHashMap<>(params));
        o.setRequestedBy(requestedBy);
        o.setCreatedAt(LocalDateTime.now().format(FMT));
        o.setStatus("PENDING");
        orders.put(o.getId(), o);
        logger.info("生成待审批单 {}：{} -> {}（{}）", o.getId(), action, target, reason);
        return o;
    }

    /** 待审批列表（仅 PENDING，最新在前） */
    public List<Order> listPending() {
        List<Order> out = new ArrayList<>();
        for (Order o : orders.values()) {
            if ("PENDING".equals(o.getStatus())) {
                out.add(o);
            }
        }
        out.sort((a, b) -> b.getCreatedAt().compareTo(a.getCreatedAt()));
        return out;
    }

    /**
     * 批准：真正执行对应动作，返回执行结果。
     *
     * <h3>锁的范围（C3 重构点）</h3>
     * 原来是 {@code synchronized} 方法 —— 临界区里包含
     * {@code auditService.append()}（整份审计文件落盘）与
     * {@code dispatch()}（可能真的走 SSH，最长十几秒）。
     * 于是"批准一张单"会把整个审批服务锁住，其它审批/驳回全部排队等待，
     * 长尾表现为"审批面板点了没反应"。
     * <p>
     * 现在只把"检查状态 + 置为 APPROVED"放进该单据自己的锁里（纯内存、纳秒级），
     * 审计落盘与真实执行都在锁外。并发点两次"批准"仍然只有一个能成功
     * （状态机在锁内完成 CAS），不会重复下发处置动作。
     */
    public Map<String, Object> approve(String id, String actor) {
        Order o = orders.get(id);
        Map<String, Object> resp = new LinkedHashMap<>();
        if (o == null) {
            resp.put("success", false);
            resp.put("message", "审批单不存在: " + id);
            return resp;
        }
        synchronized (o) {
            if (!"PENDING".equals(o.getStatus())) {
                resp.put("success", false);
                resp.put("message", "审批单已处理，状态: " + o.getStatus());
                return resp;
            }
            // 只改内存：抢到 PENDING → APPROVED 的那个线程才继续往下做 I/O 与执行
            o.setStatus("APPROVED");
            o.setDecidedBy(actor);
            o.setDecidedAt(LocalDateTime.now().format(FMT));
        }

        // ==== 以下都在锁外：审计落盘 + 真实执行（SSH 可能耗时）====
        auditService.append(ResponseAudit.of(actor, "approve", o.getTarget(),
                "管理员批准处置：" + o.getReason(), o.getRiskLevel(), "MOCK", true,
                "审批单 " + o.getId()));

        ActiveResponseResult result = dispatch(o);
        o.setExecutedMode(result.getMode());
        o.setExecutedSuccess(result.isSuccess());
        o.setResultMessage(result.getMessage());
        resp.put("success", true);
        resp.put("message", "已批准并执行");
        resp.put("order", o);
        resp.put("result", result);
        return resp;
    }

    /**
     * 驳回：不执行。
     *
     * <p>与 {@link #approve} 同因同治：锁内只做状态 CAS，审计落盘在锁外。
     */
    public Map<String, Object> reject(String id, String actor) {
        Order o = orders.get(id);
        Map<String, Object> resp = new LinkedHashMap<>();
        if (o == null) {
            resp.put("success", false);
            resp.put("message", "审批单不存在: " + id);
            return resp;
        }
        synchronized (o) {
            if (!"PENDING".equals(o.getStatus())) {
                resp.put("success", false);
                resp.put("message", "审批单已处理，状态: " + o.getStatus());
                return resp;
            }
            o.setStatus("REJECTED");
            o.setDecidedBy(actor);
            o.setDecidedAt(LocalDateTime.now().format(FMT));
        }
        auditService.append(ResponseAudit.of(actor, "reject", o.getTarget(),
                "管理员驳回处置：" + o.getReason(), o.getRiskLevel(), "BLOCKED", false,
                "审批单 " + o.getId()));
        resp.put("success", true);
        resp.put("message", "已驳回，不执行");
        resp.put("order", o);
        return resp;
    }

    private ActiveResponseResult dispatch(Order o) {
        Map<String, Object> p = o.getParams() == null ? new LinkedHashMap<>() : o.getParams();
        switch (o.getAction()) {
            case "block-ip": {
                String ip = str(p.get("ip"));
                Integer dur = p.get("durationMinutes") == null ? null
                        : (p.get("durationMinutes") instanceof Number ? ((Number) p.get("durationMinutes")).intValue()
                        : Integer.parseInt(String.valueOf(p.get("durationMinutes"))));
                return actionService.blockIp(ip, dur, o.getReason(), o.getDecidedBy(), "审批");
            }
            case "lock-account":
                return actionService.lockAccount(str(p.get("account")), str(p.get("host")),
                        o.getReason(), o.getDecidedBy());
            case "kill-process":
                return actionService.killProcess(str(p.get("pid")), str(p.get("process")),
                        str(p.get("host")), o.getReason(), o.getDecidedBy());
            default:
                return ActiveResponseResult.failed(o.getAction(), o.getTarget(), "未知动作类型");
        }
    }

    private static String str(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    /** 审批单 */
    @Data
    public static class Order {
        private String id;
        private String action;
        private String target;
        private String reason;
        private String riskLevel;
        private Map<String, Object> params;
        private String requestedBy;
        private String createdAt;
        /**
         * PENDING / APPROVED / REJECTED。
         *
         * <p>加 {@code volatile}：状态在"该单据自己的锁"里改，而
         * {@link #listPending()} 与控制器是在锁外读它的 —— 不加就会出现
         * "刚批准的单还挂在待审批列表里"这种可见性问题。
         */
        private volatile String status;
        private String decidedBy;
        private String decidedAt;
        private String executedMode;
        private boolean executedSuccess;
        private String resultMessage;
    }
}
