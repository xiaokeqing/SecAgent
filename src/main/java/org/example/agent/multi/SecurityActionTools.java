package org.example.agent.multi;

import org.example.core.model.ActiveResponseResult;
import org.example.response.ResponseActionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * 处置执行工具（供 RESPONDER 处置执行员智能体调用）。
 *
 * <p>这是"人在回路分级自动处置"在智能体侧的入口：智能体哪怕被诱导发起
 * 封禁/锁账号/杀进程，工具内部也一律走 {@link ResponseActionService}——
 * 即执行前强制 ResponseGuard 白名单护栏（环回/私网/非法 IP/超长时长拦截）、
 * 高危动作转人工审批（批准才执行）、全部动作写审计留痕。
 * 所以"处置必须过护栏+审批+审计"不是靠提示词约束，而是代码强制。</p>
 */
@Component
public class SecurityActionTools {

    private static final Logger logger = LoggerFactory.getLogger(SecurityActionTools.class);

    /** 智能体侧默认执行人标识（真实动作仍以审计中的请求人/审批人为准） */
    private static final String ACTOR = "responder-agent";

    @Autowired
    private ResponseActionService responseActionService;

    /**
     * 封禁来源 IP。
     * 执行前强制护栏校验：保留/环回/组播地址、内网白名单(10/8、172.16/12、192.168/16)一律拦截；
     * 超长封禁转人工审批，批准后才执行；全部动作写审计。
     */
    @Tool(description = "封禁来源IP（处置动作）：自动过安全护栏校验，非法/内网/环回IP会被拦截，超长封禁转人工审批，全部留痕审计。返回执行结果与审计ID。")
    public String blockIp(
            @ToolParam(description = "要封禁的IPv4地址，如 203.0.113.24") String ip,
            @ToolParam(description = "封禁时长（分钟），不传用默认值；超过上限(如120分钟)视为高危转人工审批") Integer durationMinutes,
            @ToolParam(description = "封禁原因说明") String reason) {
        logger.info("[SecurityActionTools] 处置智能体请求封禁 IP={} duration={} reason={}", ip, durationMinutes, reason);
        ActiveResponseResult r = responseActionService.blockIp(ip, durationMinutes, reason, ACTOR, "智能体");
        return formatResult("封禁IP", r);
    }

    /**
     * 锁定账号。
     * 高危动作，默认需人工审批；策略关闭时直接拦截；全部动作写审计。
     */
    @Tool(description = "锁定账号（高危处置动作）：默认转人工审批，批准才执行；策略关闭时直接拦截；全部留痕审计。返回执行结果与审计ID。")
    public String lockAccount(
            @ToolParam(description = "要锁定的账号名，如 guest") String account,
            @ToolParam(description = "账号所在主机，如 web-01") String host,
            @ToolParam(description = "锁定原因说明") String reason) {
        logger.info("[SecurityActionTools] 处置智能体请求锁定账号 account={} host={} reason={}", account, host, reason);
        ActiveResponseResult r = responseActionService.lockAccount(account, host, reason, ACTOR);
        return formatResult("锁定账号", r);
    }

    /**
     * 结束进程。
     * 高危动作，默认需人工审批；策略关闭时直接拦截；全部动作写审计。
     */
    @Tool(description = "结束可疑进程（高危处置动作）：默认转人工审批，批准才执行；策略关闭时直接拦截；全部留痕审计。返回执行结果与审计ID。")
    public String killProcess(
            @ToolParam(description = "进程PID，如 4821") String pid,
            @ToolParam(description = "进程名，如 php-fpm") String processName,
            @ToolParam(description = "进程所在主机，如 web-01") String host,
            @ToolParam(description = "处置原因说明") String reason) {
        logger.info("[SecurityActionTools] 处置智能体请求结束进程 pid={} name={} host={} reason={}", pid, processName, host, reason);
        ActiveResponseResult r = responseActionService.killProcess(pid, processName, host, reason, ACTOR);
        return formatResult("结束进程", r);
    }

    private String formatResult(String actionName, ActiveResponseResult r) {
        StringBuilder sb = new StringBuilder();
        sb.append("【").append(actionName).append("】结果：").append(r.isSuccess() ? "成功" : "未执行").append("\n");
        sb.append("目标：").append(r.getTarget()).append("\n");
        sb.append("模式：").append(r.getMode())
                .append(r.getMode() != null && "MOCK".equals(r.getMode()) ? "（内置模拟，未连接真实Wazuh）" : "").append("\n");
        sb.append("说明：").append(r.getMessage());
        if (r.getAuditId() != null) {
            sb.append("\n审计ID：").append(r.getAuditId());
        }
        return sb.toString();
    }
}
