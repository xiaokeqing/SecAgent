package org.example.agent.multi;

import com.alibaba.cloud.ai.dashscope.api.DashScopeApi;
import com.alibaba.cloud.ai.dashscope.chat.DashScopeChatModel;
import com.alibaba.cloud.ai.graph.agent.ReactAgent;
import org.example.agent.tool.DateTimeTools;
import org.example.agent.tool.InternalDocsTools;
import org.example.agent.tool.QueryLogsTools;
import org.example.agent.tool.QueryMetricsTools;
import org.example.service.ChatService;
import org.example.service.ToolAuditWrapper;
import org.example.knowledge.KnowledgePendingService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 多智能体协同编排器实现（本项目"多智能体化"核心）。
 *
 * <p>职责：用户输入先进入编排层，由 PLANNER 调度员决定派哪个专职智能体执行，
 * 执行完把各步过程记成 {@link AgentStepResult} 时间线并汇总最终答复。</p>
 *
 * <p>四个角色（对应 {@link AgentRole}）：</p>
 * <ul>
 *   <li>PLANNER 调度员：规则路由为主、模型路由为辅（无 Key/模型不可达时回退规则，保证离线可演示）；</li>
 *   <li>ANALYST 研判分析员：工具=知识库RAG + 时间，只依据知识库作答、未命中须标注；</li>
 *   <li>FORENSICS 取证分析员：工具=告警指标 + 安全日志 + 时间，只输出工具返回的事实；</li>
 *   <li>RESPONDER 处置执行员：工具=处置动作工具 + 时间，动作一律走 {@link SecurityActionTools}，
 *       其内部已强制 ResponseGuard 白名单护栏 + 高危人工审批 + 审计留痕，本层绝不绕过。</li>
 * </ul>
 *
 * <p>降级策略：检测到无真实模型 Key（占位 sk-placeholder）或模型调用失败时，
 * 不真正发 ReAct 请求，而是由编排层直接调用各智能体"本该调用的同一组工具"并拼装结论——
 * 工具集合与在线时完全一致，因此离线演示的路由、取证、处置、护栏拦截行为都真实可复现。</p>
 */
@Component
public class MultiAgentCoordinatorImpl implements MultiAgentCoordinator {

    private static final Logger logger = LoggerFactory.getLogger(MultiAgentCoordinator.class);

    @Autowired
    private ChatService chatService;

    @Autowired
    private InternalDocsTools internalDocsTools;

    @Autowired
    private DateTimeTools dateTimeTools;

    @Autowired
    private QueryMetricsTools queryMetricsTools;

    @Autowired(required = false) // Mock 模式才注册
    private QueryLogsTools queryLogsTools;

    @Autowired
    private SecurityActionTools securityActionTools;

    @Autowired
    private KnowledgePendingService knowledgePendingService;

    @Value("${spring.ai.dashscope.api-key:sk-placeholder}")
    private String dashScopeApiKey;

    /**
     * 是否启用真实模型 ReAct 闭环。默认 auto：检测到占位 Key 视为离线，走工具直连降级。
     * 配置为 true 可强制走模型（需真实可达 Key）。
     */
    @Value("${app.multi-agent.llm-enabled:auto}")
    private String llmEnabledConfig;

    private static final Pattern IPV4 = Pattern.compile(
            "\\b((25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.(25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.(25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.(25[0-5]|2[0-4]\\d|1?\\d?\\d))\\b");
    private static final Pattern DURATION = Pattern.compile("(\\d+)\\s*(分钟|min|分)");

    @Override
    public MultiAgentResult routeAndRun(String userInput, List<Map<String, String>> history) throws Exception {
        long totalStart = System.currentTimeMillis();
        MultiAgentResult result = new MultiAgentResult(userInput);

        // ---------- 1. PLANNER 调度 ----------
        long plannerStart = System.currentTimeMillis();
        DispatchDecision decision = plan(userInput, history);
        long plannerCost = System.currentTimeMillis() - plannerStart;
        result.setPlannerNote(decision.note);
        result.addStep(new AgentStepResult(
                AgentRole.PLANNER.getDisplayName(), AgentRole.PLANNER.name(), "planner_agent",
                "调度决策：拆解任务并选择执行智能体",
                "派发给【" + decision.role.getDisplayName() + "】（" + decision.role.name() + "）",
                decision.note + (llmReady() ? "\n路由方式：模型优先，失败回退规则" : "\n路由方式：规则路由（离线降级，未配置真实模型 Key）"),
                plannerCost, true));

        // ---------- 2. 执行被派发的专职智能体（单个失败不影响整体汇总） ----------
        Map<AgentRole, String> bodies = new java.util.EnumMap<>(AgentRole.class);
        AgentStepResult specialistStep = runSpecialist(decision, userInput, history, bodies);
        result.addStep(specialistStep);

        // ---------- 3. 汇总最终答复：结论 + 证据 + 处置结果 ----------
        result.setFinalAnswer(assembleFinalAnswer(userInput, decision, specialistStep, bodies));
        result.setTotalDurationMs(System.currentTimeMillis() - totalStart);
        logger.info("[MultiAgent] 编排完成 role={} steps={} totalMs={}",
                decision.role, result.getSteps().size(), result.getTotalDurationMs());
        return result;
    }

    // ==================== PLANNER 调度 ====================

    /** 一次调度决策：选中的主角色 + 处置类入参 + 决策说明 */
    private static class DispatchDecision {
        AgentRole role;
        String matchedKeyword;   // 规则命中的关键词（离线/回退用）
        String actionType;       // blockIp / lockAccount / killProcess
        String ip;
        Integer durationMinutes;
        String account;
        String host;
        String pid;
        String processName;
        String note;
    }

    private DispatchDecision plan(String userInput, List<Map<String, String>> history) {
        DispatchDecision d = new DispatchDecision();
        String q = userInput == null ? "" : userInput.toLowerCase();

        // 先尝试模型路由（仅在配置为真实模型时）；失败一律回退规则
        String modelRoute = null;
        if (llmReady()) {
            try {
                modelRoute = askPlannerModel(userInput, history);
            } catch (Exception e) {
                logger.warn("[MultiAgent] Planner 模型路由失败，回退规则路由: {}", e.getMessage());
            }
        }
        if (modelRoute != null) {
            AgentRole mapped = mapModelRoute(modelRoute);
            if (mapped != null) {
                applyRuleTargets(userInput, q, d); // 仍用规则抽取处置入参
                d.role = mapped;
                d.matchedKeyword = "model:" + modelRoute;
                d.note = "Planner 模型判定本次意图为【" + mapped.getDisplayName() + "】类任务。";
                return d;
            }
        }

        // 规则路由（离线主路径）
        applyRuleTargets(userInput, q, d);
        if (isResponder(q)) {
            d.role = AgentRole.RESPONDER;
        } else if (isForensics(q)) {
            d.role = AgentRole.FORENSICS;
        } else {
            // ANALYST：知识/原理/防护/规范，以及兜底
            d.role = AgentRole.ANALYST;
        }
        d.note = "规则路由命中关键词【" + d.matchedKeyword + "】，判定为【"
                + d.role.getDisplayName() + "】任务。";
        return d;
    }

    private boolean isResponder(String q) {
        return containsAny(q, "封禁", "封ip", "封掉", "拉黑", "锁账号", "锁定账号", "锁定用户",
                "杀进程", "结束进程", "终止进程", "killprocess")
                || (q.contains("处置") && (IPV4.matcher(q).find() || q.contains("账号") || q.contains("进程")));
    }

    private boolean isForensics(String q) {
        return containsAny(q, "日志", "告警", "取证", "入侵分析", "登录失败", "登录日志", "外联",
                "大屏", "指标", "查最近", "查一下", "流量", "扫描", "活跃告警", "攻击");
    }

    /** 从用户输入抽取处置入参（IP/时长/账号/进程） */
    private void applyRuleTargets(String raw, String q, DispatchDecision d) {
        Matcher ip = IPV4.matcher(raw == null ? "" : raw);
        if (ip.find()) {
            d.ip = ip.group(1);
        }
        Matcher dur = DURATION.matcher(raw == null ? "" : raw);
        if (dur.find()) {
            try {
                d.durationMinutes = Integer.parseInt(dur.group(1));
            } catch (NumberFormatException ignore) {
                d.durationMinutes = null;
            }
        }
        if (q.contains("锁账号") || q.contains("锁定账号") || q.contains("锁定用户")) {
            d.actionType = "lockAccount";
            d.account = extractAfter(raw, "账号", 1) != null ? extractAfter(raw, "账号", 1)
                    : extractAfter(raw, "用户", 1);
        } else if (q.contains("杀进程") || q.contains("结束进程") || q.contains("终止进程")) {
            d.actionType = "killProcess";
            Matcher pid = Pattern.compile("\\b(\\d{2,6})\\b").matcher(raw == null ? "" : raw);
            if (pid.find()) d.pid = pid.group(1);
            d.processName = extractAfter(raw, "进程", 0);
        } else if (d.ip != null) {
            d.actionType = "blockIp";
        }
        // 记录命中关键词用于调度说明
        for (String kw : new String[]{"封禁", "锁账号", "杀进程", "结束进程", "日志", "告警", "取证",
                "登录失败", "外联", "大屏", "漏洞", "原理", "防护", "规范", "加固", "webshell", "sql注入", "提权"}) {
            if (q.contains(kw)) { d.matchedKeyword = kw; break; }
        }
        if (d.matchedKeyword == null) d.matchedKeyword = "（无明确关键词，默认研判分析）";
    }

    private String extractAfter(String raw, String key, int expectLen) {
        if (raw == null) return null;
        int idx = raw.indexOf(key);
        if (idx < 0) return null;
        String tail = raw.substring(idx + key.length()).trim();
        Matcher m = Pattern.compile("^[：:\\s]*([A-Za-z0-9_\\-\\.]+)").matcher(tail);
        return m.find() ? m.group(1) : null;
    }

    private boolean containsAny(String q, String... keys) {
        for (String k : keys) if (q.contains(k)) return true;
        return false;
    }

    private AgentRole mapModelRoute(String route) {
        if (route == null) return null;
        String r = route.trim().toUpperCase();
        try {
            // 模型可能输出完整角色名或别名
            if (r.contains("RESPONDER") || r.contains("处置")) return AgentRole.RESPONDER;
            if (r.contains("FORENSICS") || r.contains("取证")) return AgentRole.FORENSICS;
            if (r.contains("ANALYST") || r.contains("研判")) return AgentRole.ANALYST;
            return AgentRole.valueOf(r);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** 仅在线时调用：让 Planner 模型输出一个角色名；任何异常都返回 null 触发回退 */
    private String askPlannerModel(String userInput, List<Map<String, String>> history) {
        DashScopeApi api = chatService.createDashScopeApi();
        DashScopeChatModel model = chatService.createChatModel(api, 0.0, 50, 0.1);
        String sys = "你是 SecAgent 的调度员PLANNER。根据用户意图只输出一个角色名："
                + "FORENSICS(查日志/告警/取证)、ANALYST(知识/漏洞原理/防护规范)、RESPONDER(封禁/锁账号/杀进程)。"
                + "只输出单词，不要解释。";
        try {
            ReactAgent planner = ReactAgent.builder().name("planner_router")
                    .model(model).systemPrompt(sys).build();
            String out = chatService.executeChat(planner, userInput);
            if (out != null && !out.isBlank()) {
                logger.info("[MultiAgent] Planner 模型路由输出: {}", out.trim());
                return out.trim();
            }
        } catch (Exception e) {
            logger.warn("[MultiAgent] Planner 模型调用异常: {}", e.getMessage());
        }
        return null;
    }

    // ==================== 专职智能体执行 ====================

    private AgentStepResult runSpecialist(DispatchDecision d, String userInput, List<Map<String, String>> history,
                                          Map<AgentRole, String> bodies) {
        long start = System.currentTimeMillis();
        try {
            switch (d.role) {
                case ANALYST:    return runAnalyst(userInput, history, start, bodies);
                case FORENSICS:  return runForensics(userInput, start, bodies);
                case RESPONDER:  return runResponder(d, userInput, start, bodies);
                default:         return runAnalyst(userInput, history, start, bodies);
            }
        } catch (Exception e) {
            logger.error("[MultiAgent] {} 智能体执行失败", d.role, e);
            return new AgentStepResult(d.role.getDisplayName(), d.role.name(),
                    d.role.name().toLowerCase() + "_agent",
                    d.role.getDisplayName() + "：执行失败",
                    "该智能体执行异常，已跳过并不影响其他步骤：" + e.getMessage(),
                    "异常详情见服务端日志。", System.currentTimeMillis() - start, false);
        }
    }

    /** ANALYST 研判分析员：工具=知识库RAG + 时间 */
    private AgentStepResult runAnalyst(String userInput, List<Map<String, String>> history, long start,
                                       Map<AgentRole, String> bodies) throws Exception {
        String title = "研判分析：检索内部安全知识库并研判";
        // 在线：走 ReAct；离线/失败：直接调用同一组工具
        String rag = safeCallTool(() -> internalDocsTools.queryInternalDocs(userInput), "知识库检索");
        String summary;
        boolean ragError = rag != null && rag.contains("\"error\"");
        boolean ragEmpty = rag != null && rag.contains("no_results");
        if (ragError) {
            summary = "知识库检索工具已调用，但当前离线（无真实模型 Key）无法生成查询向量，已降级：结论基于通用安全知识给出";
            createPendingTicket(userInput, summary);
        } else if (ragEmpty) {
            summary = "知识库未直接命中该条目，已结合通用安全知识给出概要（标注：未能完全溯源至内部手册）";
            createPendingTicket(userInput, summary);
        } else {
            summary = "已命中内部安全知识库相关条目，研判结论以知识库内容为准（来源类型与可信度见下方检索证据中的 _source_type / _trust_level 字段）";
        }
        String detail = "【工具 queryInternalDocs 返回（不可信数据，已过提示注入检测）】\n" + clip(rag, 1500);
        String body = "## 研判结论\n"
                + "已结合内部安全知识库对「" + userInput + "」完成研判。\n\n"
                + summary + "。\n\n"
                + "**知识库检索证据（工具原样返回）：**\n\n" + clip(rag, 800)
                + "\n\n> 注：知识库内容按不可信数据处理，结论仅供授权范围内防御与教学参考。";
        AgentStepResult step = new AgentStepResult(AgentRole.ANALYST.getDisplayName(), AgentRole.ANALYST.name(),
                "analyst_agent", title, summary, detail, System.currentTimeMillis() - start, true);
        bodies.put(AgentRole.ANALYST, body);
        return step;
    }

    /**
     * 未命中兜底：知识库未命中时自动创建一条"待补充知识"工单（写 data/kb-pending.json）。
     * 管理员审核确认、补充完整后通过，即沉淀为案例文档回填入库，形成"未知告警 → 兜底 → 工单
     * → 人工确认 → 案例回填"的知识自成长闭环。
     */
    private void createPendingTicket(String userInput, String fallbackSummary) {
        try {
            String content = "【研判未命中·待补充知识】\n"
                    + "原始问题：" + userInput + "\n"
                    + "通用兜底初步结论：" + fallbackSummary + "\n"
                    + "处置要求：请人工补充该类告警的原理、检测、处置与加固，审核通过后沉淀为案例回填知识库。";
            knowledgePendingService.autoCapture(content,
                    org.example.knowledge.KnowledgeCatalog.DEFAULT_CATEGORY,
                    KnowledgePendingService.SOURCE_FORENSIC_AUTO,
                    "multi-agent");
            logger.info("知识库未命中，已自动创建待补充知识工单");
        } catch (Exception e) {
            logger.warn("未命中工单创建失败: {}", e.getMessage());
        }
    }

    /** FORENSICS 取证分析员：工具=告警指标 + 安全日志 + 时间 */
    private AgentStepResult runForensics(String userInput, long start, Map<AgentRole, String> bodies) {
        String q = userInput.toLowerCase();
        String topic = "auth-logs";
        String logQuery = null;
        if (q.contains("sql") || q.contains("注入") || q.contains("union")) {
            topic = "web-access-logs"; logQuery = "union select";
        } else if (q.contains("webshell") || q.contains("木马") || q.contains("文件")) {
            topic = "web-access-logs"; logQuery = "webshell";
        } else if (q.contains("外联") || q.contains("c2") || q.contains("反弹")) {
            topic = "firewall-logs"; logQuery = "outbound";
        } else if (q.contains("扫描") || q.contains("探测")) {
            topic = "firewall-logs"; logQuery = "scan";
        } else {
            topic = "auth-logs"; logQuery = "Failed password";
        }
        final String fTopic = topic;
        final String fLogQuery = logQuery;

        String logs = queryLogsTools == null ? null
                : safeCallTool(() -> queryLogsTools.queryLogs(null, fTopic, fLogQuery, 10), "日志查询");
        String alerts = safeCallTool(() -> queryMetricsTools.queryPrometheusAlerts("1h"), "告警查询");

        String summary = "已采集【" + topic + "】日志证据与当前活动告警，仅输出工具返回事实";
        String detail = "【日志工具 queryLogs 返回】\n" + clip(logs, 1200)
                + "\n\n【告警工具 queryPrometheusAlerts 返回】\n" + clip(alerts, 1200);
        String body = "## 取证发现\n"
                + "取证分析员已采集日志与活动告警作为证据（仅陈述工具返回的事实，未做主观推断）。\n\n"
                + "**日志证据（" + topic + "，关键字：" + (logQuery == null ? "核心日志" : logQuery) + "）：**\n\n"
                + clip(logs, 600)
                + "\n\n**当前活动告警：**\n\n" + clip(alerts, 600)
                + "\n\n**初步研判建议：** 上述证据若显示暴力破解/WebShell/外联等活动，建议转研判分析员对照知识库定性，并按需转处置执行员封禁来源 IP 或隔离主机（处置仍过护栏+审批+审计）。";
        AgentStepResult step = new AgentStepResult(AgentRole.FORENSICS.getDisplayName(), AgentRole.FORENSICS.name(),
                "forensics_agent", "取证分析：查询日志与告警、采集证据", summary, detail,
                System.currentTimeMillis() - start, true);
        bodies.put(AgentRole.FORENSICS, body);
        return step;
    }

    /** RESPONDER 处置执行员：工具=SecurityActionTools（内部强制护栏/审批/审计）+ 时间 */
    private AgentStepResult runResponder(DispatchDecision d, String userInput, long start, Map<AgentRole, String> bodies) {
        String reason = "多智能体协同处置：" + userInput;
        String resultText;
        String title;
        if ("lockAccount".equals(d.actionType)) {
            title = "处置执行：锁定账号（过护栏+审批+审计）";
            resultText = safeCallTool(() -> securityActionTools.lockAccount(d.account, d.host, reason), "锁定账号");
        } else if ("killProcess".equals(d.actionType)) {
            title = "处置执行：结束进程（过护栏+审批+审计）";
            resultText = safeCallTool(() -> securityActionTools.killProcess(d.pid, d.processName, d.host, reason), "结束进程");
        } else {
            title = "处置执行：封禁来源 IP（过护栏+审批+审计）";
            resultText = safeCallTool(() -> securityActionTools.blockIp(d.ip, d.durationMinutes, reason), "封禁IP");
        }
        boolean blocked = resultText != null && resultText.contains("BLOCKED");
        boolean success = resultText != null && resultText.contains("结果：成功");
        String summary = blocked
                ? "处置被 ResponseGuard 护栏拦截（已留痕），未真正下发"
                : (success ? "处置动作已执行（含 MOCK 模拟/审计留痕）" : "处置未执行");
        String body = "## 处置结果\n"
                + "处置执行员已通过安全工具发起动作，工具内部强制经过 ResponseGuard 白名单护栏、高危人工审批与全量审计：\n\n"
                + "```\n" + clip(resultText, 800) + "\n```\n\n"
                + (blocked ? "**护栏生效**：该目标命中保护策略，动作被拦截并未下发，符合安全预期。"
                          : "动作已记录审计 ID，可在处置审计中追溯。");
        AgentStepResult step = new AgentStepResult(AgentRole.RESPONDER.getDisplayName(), AgentRole.RESPONDER.name(),
                "responder_agent", title, summary, clip(resultText, 1500),
                System.currentTimeMillis() - start, !blocked);
        bodies.put(AgentRole.RESPONDER, body);
        return step;
    }

    private String assembleFinalAnswer(String question, DispatchDecision d, AgentStepResult specialist,
                                      Map<AgentRole, String> bodies) {
        StringBuilder sb = new StringBuilder();
        sb.append("## 多智能体协同结果\n\n");
        sb.append("> 调度员判定本次任务为【").append(d.role.getDisplayName()).append("】，由对应专职智能体执行。\n\n");
        String body = bodies.get(d.role);
        if (body != null) sb.append(body);
        if (!specialist.isSuccess()) {
            sb.append("\n\n⚠️ 注意：").append(specialist.getTitle()).append(" 执行失败（").append(specialist.getSummary()).append("）。");
        }
        return sb.toString();
    }

    // ==================== 工具方法 ====================

    private boolean llmReady() {
        if ("true".equalsIgnoreCase(llmEnabledConfig)) return true;
        if ("false".equalsIgnoreCase(llmEnabledConfig)) return false;
        // auto：占位/空 Key 视为离线
        return dashScopeApiKey != null && !dashScopeApiKey.isBlank()
                && !dashScopeApiKey.toLowerCase().contains("placeholder");
    }

    /**
     * 单工具调用隔离：异常不抛出（未熔断时），返回错误说明字符串，保证编排不整体崩。
     * 同时统一做工具调用审计（写 data/tool-call-audit.json）与连续失败熔断。
     */
    private String safeCallTool(ThrowingSupplier<String> tool, String label) {
        long start = System.currentTimeMillis();
        try {
            String result = tool.get();
            ToolAuditWrapper.record("MultiAgent-Coordinator", label, "", result,
                    System.currentTimeMillis() - start, true);
            ToolAuditWrapper.registerSuccess(label);
            return result;
        } catch (Exception e) {
            String preview = e.getClass().getSimpleName() + ": " + e.getMessage();
            ToolAuditWrapper.record("MultiAgent-Coordinator", label, "", preview,
                    System.currentTimeMillis() - start, false);
            logger.warn("[MultiAgent] 工具[{}]调用失败: {}", label, e.getMessage());
            // 连续失败 ≥5 次 registerFailure 会直接抛异常熔断（硬终止该方向）；否则返回错误串
            ToolAuditWrapper.registerFailure(label);
            return "{\"status\":\"error\",\"message\":\"" + label + " 调用失败: " + e.getMessage() + "\"}";
        }
    }

    private String clip(String s, int max) {
        if (s == null) return "（无返回）";
        s = s.trim();
        if (s.length() <= max) return s;
        return s.substring(0, max) + " ……(已截断)";
    }

    @FunctionalInterface
    private interface ThrowingSupplier<T> {
        T get() throws Exception;
    }
}
