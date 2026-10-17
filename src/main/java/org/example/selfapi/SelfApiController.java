package org.example.selfapi;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.agent.multi.MultiAgentResult;
import org.example.service.ModelQuotaService;
import org.example.service.OrchestrationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * 自用面端点：{@code /api/user/**}（需要请求头 {@code X-User-Token}）。
 *
 * <h3>它的三条边界（写在类注释里，因为它们是"不该被顺手改掉"的东西）</h3>
 * <ol>
 *   <li><b>代码路径与公开面完全隔离</b>：本包不得反向引用公开面包的
 *       任何代码 —— 连只读的也一样（包名只出现在 {@code SelfApiIsolationTest} 的禁引清单里）。
 *       知识检索因此自建 {@link SelfKbService}，
 *       可见性口径仍复用 {@code org.example.knowledge} 包那份唯一定义。
 *       这条由 {@code SelfApiIsolationTest} 在构建期强制。</li>
 *   <li><b>不新增认证体系</b>：身份只来自 {@link UserTokenService} 对 {@code X-User-Token} 的校验结果——
 *       本类<b>不解析</b>令牌、不接触明文（拦截器已经判完并把结果写进请求属性）。
 *       这样"令牌处理"只有一个地方，审计"永不记令牌"也只需要在一个地方证明。</li>
 *   <li><b>不另写编排</b>：复用 {@link OrchestrationService#run(String, List, long)}，
 *       与 {@code /api/chat} / {@code /api/public/ask} 同一条链路。复制一份编排的代价
 *       不是"多几行"，而是"两份会慢慢不一致"（本项目已有前车之鉴）。</li>
 * </ol>
 *
 * <h3>与公开面的差别（这正是"登录后自用"的意义）</h3>
 * <ul>
 *   <li>额度：走<b>第四本账</b>（{@code app.quota.self-daily-soft-limit}=500/日，<b>只提醒不硬停</b>）；</li>
 *   <li>窗口：带 <b>3~5 轮</b>对话记忆（公开面没有，那是成本护栏的一部分）；</li>
 *   <li>入口：4000 字符 / 60 s（公开面 1200 字符 / 25 s）；</li>
 *   <li>内容：<b>不</b>套用公开面的输出脱敏（站主看自己系统的数据不需要被掩码）——
 *       但仍会走既有输出护栏 {@code OutputGuardService}（凭据/私钥不外泄），
 *       这两件事不是一回事，别混。</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/user")
public class SelfApiController {

    private static final Logger logger = LoggerFactory.getLogger(SelfApiController.class);

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /** 请求属性名：由拦截器写入的鉴权失败原因（控制器据此如实回 401/429） */
    static final String ATTR_FAIL_REASON = "secagent.self.failReason";
    static final String ATTR_FAIL_MESSAGE = "secagent.self.failMessage";
    static final String ATTR_FAIL_STATUS = "secagent.self.failStatus";
    static final String ATTR_FAIL_RETRY_AFTER = "secagent.self.failRetryAfter";
    /** 鉴权通过标记：由 {@code SelfTokenInterceptor} 在放行时写入 */
    static final String ATTR_SELF_OK = SelfTokenInterceptor.ATTR_SELF_OK;

    @Autowired
    private UserTokenService userTokenService;

    @Autowired
    private SelfPoolPolicy policy;

    @Autowired
    private UserConversationStore conversationStore;

    @Autowired
    private OrchestrationService orchestrationService;

    /** 自用面的知识片段检索（只读；可见性复用 {@link PublicKbVisibility} 口径） */
    @Autowired(required = false)
    private SelfKbService kbService;

    /** 配额服务（可为空：裁剪部署 / 单测）。配额闸门本身在模型出口，这里只做可见性披露 */
    @Autowired(required = false)
    private ModelQuotaService quotaService;

    /**
     * 登录探针：{@code GET /api/user/status}。
     *
     * <p>它是前端唯一的"确认令牌有效"手段。鉴权由拦截器完成；本方法只做两件事：
     * 回显自用池额度状态、回显窗口口径。失败路径由拦截器直接写响应（不进入本方法）。
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> status(HttpServletRequest req, HttpServletResponse res) {
        ResponseEntity<Map<String, Object>> failed = authFailure(req, res);
        if (failed != null) {
            return failed;
        }
        Map<String, Object> data = new LinkedHashMap<>();
        // 【字段名：两个都给，别让前端或自检脚本去猜】
        //   loggedIn      —— 站主口径点名的字段（"200 且 loggedIn:true"）
        //   authenticated —— 自述更准确：这个端点回答的是"令牌是否通过校验"，
        //                    而服务端**没有**会话可"登录"（无状态，见 logout 的注释）
        // 只给一个都会造成误读：只用 loggedIn 会被读成"服务端有会话"；
        // 只用 authenticated 会让站主按自己写的自检脚本查不到字段。
        data.put("loggedIn", true);
        data.put("authenticated", true);
        data.put("pool", SelfPoolPolicy.POOL);
        data.put("generatedAt", LocalDateTime.now().format(FMT));
        data.put("quota", policy.quotaSnapshot());
        Map<String, Object> conv = new LinkedHashMap<>();
        conv.put("maxRounds", conversationStore.effectiveMaxRounds());
        conv.put("ttlMinutes", conversationStore.ttlMinutes());
        data.put("conversation", conv);
        data.put("limits", Map.of(
                "maxBodyChars", policy.maxBodyChars(),
                "deadlineMs", policy.deadlineMs(),
                "maxTokens", policy.maxTokens()));
        data.put("note", "自用模式：额度为软上限（只提醒不硬停）；本响应不下发、不记录任何令牌内容。");
        return ok(data, res);
    }

    /**
     * 自用提问：{@code POST /api/user/ask}。
     *
     * <p>请求体：{@code {"question":"…","conversationId":"…"}}（{@code q} 亦可）。
     * 响应：{@code {code,message,data:{answer,conversationId,round,maxRounds,quota,state,generated,…}}}。
     *
     * <h3>为什么失败时也返回 200 + 明确的 state</h3>
     * 与公开面同一纪律：模型不可用是<b>一个状态</b>，不是一次"看起来像成功"的模板回答。
     * 前端据 {@code state} / {@code generated} 决定怎么显示，后端绝不拿模板冒充模型输出。
     */
    @PostMapping("/ask")
    public ResponseEntity<Map<String, Object>> ask(@RequestBody(required = false) Map<String, Object> body,
                                                   HttpServletRequest req, HttpServletResponse res) {
        ResponseEntity<Map<String, Object>> failed = authFailure(req, res);
        if (failed != null) {
            return failed;
        }

        String ip = SelfClientIp.resolve(req);
        String question = extract(body, "question");
        if (question.isEmpty()) {
            question = extract(body, "q");
        }
        String conversationId = extract(body, "conversationId");
        if (conversationId.isEmpty()) {
            conversationId = "xk-" + UUID.randomUUID().toString().substring(0, 12);
        }

        Map<String, Object> data = baseEnvelope(ip, conversationId);

        // ---------- 入口长度闸（站主口径 4000 字符）----------
        if (question.isBlank()) {
            return badRequest(res, data, "INPUT_EMPTY", "请先输入一个问题。");
        }
        if (question.length() > policy.maxBodyChars()) {
            return badRequest(res, data, "BODY_TOO_LARGE",
                    "问题过长（上限 " + policy.maxBodyChars() + " 字符）。");
        }

        // 自用身份标注：必须在调用编排【之前】设置。
        // 配额分派（ModelQuotaGate）与 RESPONDER 分流都读它；不清掉会让下一个请求被当成自用请求。
        SelfIdentity.markSelfRequest();
        try {
            List<Map<String, String>> history = conversationStore.history(conversationId);
            data.put("historyRounds", history.size() / 2);

            // ---------- 公开知识库前置检索（可失败：失败如实标注，不静默）----------
            List<Map<String, Object>> citations = List.of();
            boolean retrievalFailed = false;
            if (kbService != null) {
                try {
                    citations = kbService.search(question);
                } catch (RuntimeException e) {
                    retrievalFailed = true;
                    logger.warn("自用问答前置检索不可用：{}", e.getMessage());
                }
            } else {
                retrievalFailed = true;
            }
            data.put("citations", citations);

            // ---------- 编排（与 /api/chat 同一条链路）----------
            String answer = null;
            MultiAgentResult result = null;
            boolean modelFailed = false;
            try {
                result = orchestrationService.run(question, history, policy.deadlineMs());
                answer = result == null ? null : result.getFinalAnswer();
            } catch (OrchestrationService.OrchestrationTimeoutException e) {
                modelFailed = true;
                logger.warn("自用问答总预算用尽（{} ms）：{}", policy.deadlineMs(), e.getMessage());
                data.put("failureReason", "总预算用尽（" + policy.deadlineMs() + " ms）");
            } catch (Exception e) {
                modelFailed = true;
                // 不回传内部异常细节（可能含地址/堆栈）；日志里也不含令牌
                logger.warn("自用问答编排失败：{}", e.getMessage());
                data.put("failureReason", "编排链路不可用");
            }

            int round = conversationStore.rounds(conversationId);

            if (answer == null || answer.isBlank()) {
                data.put("answer", notGeneratedText(policy.deadlineMs()));
                data.put("state", modelFailed ? "model-failed" : "not-generated");
                data.put("generated", false);
                data.put("round", round);
                data.put("note", "自用模式：本次没有产生结论（模型或链路不可用），**没有**用模板冒充模型输出。");
                userTokenService.auditAsk(ip, conversationId, round, selfUsed(), "model-failed", "fail",
                        modelFailed ? "MODEL_UNAVAILABLE" : "NOT_GENERATED");
                return ok(data, res);
            }

            // 记入窗口（一问一答算一轮；超上限逐出最旧）
            round = conversationStore.append(conversationId, question, answer);

            data.put("answer", withCitations(answer, citations));
            // 机读 state 从正文的 `> state=` 行提取（正文才是唯一真相）；提取不到才回退 model。
            // 不这么改，链路修好了接口里也永远是 state=model（V6 评测 stateConsistency 0/6 就是这么来的）。
            // 注意：自用包**不得依赖**公开面包（SelfApiIsolationTest 锁着），故本地实现最小判定。
            String answerState = extractStateFromAnswer(answer, "model");
            data.put("state", answerState);
            data.put("generated", true);
            data.put("round", round);
            data.put("citationsInAnswer", !citations.isEmpty());
            data.put("note", "自用模式：回答由多智能体编排链路产出；"
                    + "额度为软上限（达到 500 次/日只提醒、不停）。");
            if (retrievalFailed) {
                data.put("retrievalNote", "前置知识库检索不可用，本次引用片段为空（状态如实标注，不用别的内容顶替）。");
            }
            userTokenService.auditAsk(ip, conversationId, round, selfUsed(), answerState, "ok", null);
            return ok(data, res);
        } finally {
            // 两层清理之一：Tomcat 线程这一侧（池线程那侧由 OrchestrationService 负责）
            SelfIdentity.end();
        }
    }

    /**
     * 退出登录：{@code POST /api/user/logout}。
     *
     * <p><b>服务端没有可销的会话</b>：令牌存在站主浏览器的 localStorage 里，服务端只做无状态校验。
     * 所以这个端点的作用是把这件事<b>说清楚</b>（前端据此清 localStorage），
     * 而不是假装服务端"注销"了什么。
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(HttpServletRequest req, HttpServletResponse res) {
        ResponseEntity<Map<String, Object>> failed = authFailure(req, res);
        if (failed != null) {
            return failed;
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("loggedOut", true);
        data.put("generatedAt", LocalDateTime.now().format(FMT));
        data.put("note", "服务端不持有自用会话：请在浏览器清除 localStorage['xk-user-token'] 即完成退出。"
                + "（服务端无状态，因此这里没有「服务端注销」这回事——不假装有。）");
        return ok(data, res);
    }

    // ==================== 组装 ====================

    /**
     * 鉴权兜底：只有<b>拦截器明确标记通过</b>的请求才允许继续；其余一律拒绝。
     *
     * <h3>为什么判据是"必须有一个通过标记"，而不是"没有失败标记"</h3>
     * 正常情况下鉴权在 {@link SelfTokenInterceptor} 完成，未通过的请求根本进不到这里 ——
     * 所以本方法的失败分支平时<b>不会被走到</b>，它挡的是"哪天有人把 {@code /api/user/**}
     * 从拦截器路径里删掉"这类改动。
     *
     * <p>如果用"没有失败标记 ⇒ 放行"，那种改动会让自用面直接变成<b>匿名可访问</b>，
     * 而这里不会报任何错 —— 正是要防的失败模式。所以反过来：
     * <b>没有通过标记就不放行</b>（fail-closed），失败标记只用来决定"如实回哪一个原因"。
     */
    private ResponseEntity<Map<String, Object>> authFailure(HttpServletRequest req, HttpServletResponse res) {
        boolean passed = Boolean.TRUE.equals(req.getAttribute(ATTR_SELF_OK));
        Object attr = req.getAttribute(ATTR_FAIL_STATUS);
        if (passed && attr == null) {
            return null;
        }
        // 没有通过标记（拦截器被绕过）时，按"未配置/未授权"这一最保守的原因拒绝，
        // 不编造具体原因（编造会让排障时以为是令牌问题，而实际是路由配置问题）
        int status = attr instanceof Integer i ? i : 401;
        String reason = attr == null ? "UNAUTHORIZED" : String.valueOf(req.getAttribute(ATTR_FAIL_REASON));
        String message = attr == null
                ? "未授权访问：自用面请求未经过鉴权（拦截器未标记通过）"
                : String.valueOf(req.getAttribute(ATTR_FAIL_MESSAGE));
        Object retry = req.getAttribute(ATTR_FAIL_RETRY_AFTER);
        res.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        boolean hasRetry = retry instanceof Integer r && r > 0;
        if (hasRetry) {
            res.setHeader(HttpHeaders.RETRY_AFTER, String.valueOf(retry));
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", status);
        body.put("message", message);
        body.put("reason", reason);
        if (hasRetry) {
            // 与 SelfTokenInterceptor 同一口径：头 + 体都给（跨域下浏览器读头需要
            // Access-Control-Expose-Headers，见 WebMvcConfig.EXPOSED_HEADERS）。
            body.put("retryAfter", retry);
        }
        return ResponseEntity.status(status).body(body);
    }

    private Map<String, Object> baseEnvelope(String ipMaskedSource, String conversationId) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("generatedAt", LocalDateTime.now().format(FMT));
        m.put("pool", SelfPoolPolicy.POOL);
        m.put("conversationId", conversationId);
        m.put("maxRounds", conversationStore.effectiveMaxRounds());
        m.put("maxBodyChars", policy.maxBodyChars());
        m.put("deadlineMs", policy.deadlineMs());
        // 与公开面同一纪律：**不**回显调用者地址（即使是站主自己，也没有理由出现在响应里）
        m.put("clientIpMasked", UserTokenService.maskIp(ipMaskedSource));
        m.put("quota", policy.quotaSnapshot());
        // 自用面允许完整链路（含只读工具）；处置类仍由编排层既有身份规则约束。
        // TODO(SELF-READONLY-TOOLS)：若将来要"自用池只许只读工具"，在 MultiAgentCoordinatorImpl
        //   的 RESPONDER 分叉处加第三条分支，而不是在各个工具类里逐个加判断（见设计文档 §4.3）。
        m.put("toolExecutionAllowed", true);
        return m;
    }

    private int selfUsed() {
        ModelQuotaService q = quotaService;
        return q == null ? -1 : q.getSelfUsedToday();
    }

    private ResponseEntity<Map<String, Object>> ok(Map<String, Object> data, HttpServletResponse res) {
        res.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", 200);
        body.put("message", "success");
        body.put("data", data);
        return ResponseEntity.ok(body);
    }

    private ResponseEntity<Map<String, Object>> badRequest(HttpServletResponse res, Map<String, Object> data,
                                                           String reason, String message) {
        res.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", 400);
        body.put("message", message);
        body.put("reason", reason);
        body.put("data", data);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    /** 请求体取字符串（非字符串按字面量处理；缺省为空串） */
    private static String extract(Map<String, Object> body, String key) {
        if (body == null) {
            return "";
        }
        Object v = body.get(key);
        return v == null ? "" : String.valueOf(v).trim();
    }

    /**
     * 把命中的知识片段直出到正文里（与公开面 F5 方案 B 同一思路）。
     *
     * <h3>为什么把引用拼进正文，而不是只放在 citations 字段里</h3>
     * 只看字段的话，页面上会出现"依据不足、不做定性"的一屏字，而其实命中了 3 条引用 ——
     * 使用者会以为系统什么也没查到。命中的片段直出，口径才与数据一致。
     *
     * <p>与公开面的差别只在文案（这里服务的是站主，不需要"公开演示只基于公开知识库"这类句子），
     * <b>字段集合与可见性口径完全一致</b>（都来自 {@code PublicKbVisibility} 的判定）。
     *
     * <p><b>注意</b>：这里的拼接只用于<b>这一次响应</b>；写进对话窗口的是模型原始回答
     * （见 {@code conversationStore.append}）—— 否则引用块会一轮一轮堆进上下文，
     * 窗口的 token 成本会被引用块吃掉。
     */
    /** 正文里的机读状态行：`> state=xxx`（与公开面同一形状，但这里不引用公开包） */
    private static final java.util.regex.Pattern STATE_LINE =
            java.util.regex.Pattern.compile("(?m)^>\\s*state=([a-z][a-z-]*)");

    /** 合法状态集（与契约一致；未知状态一律回退 fallback，不把脏值透出去） */
    private static final java.util.Set<String> KNOWN_STATES = java.util.Set.of(
            "model", "rule-based", "input-insufficient", "no-retrieval", "retrieval-failed",
            "model-failed", "injection-blocked", "no-live-data", "no-kb-basis");

    /**
     * 从回答正文提取机读 state。
     *
     * <p>为什么本地实现而不复用公开面包里的同名方法：{@code SelfApiIsolationTest}
     * 明令自用包不得依赖公开面包（两条面共用代码会让边界说不清）。
     */
    private static String extractStateFromAnswer(String answer, String fallback) {
        if (answer == null || answer.isEmpty()) {
            return fallback;
        }
        java.util.regex.Matcher m = STATE_LINE.matcher(answer);
        if (m.find()) {
            String s = m.group(1);
            if (KNOWN_STATES.contains(s)) {
                return s;
            }
        }
        return fallback;
    }

    private String withCitations(String answer, List<Map<String, Object>> citations) {
        if (citations == null || citations.isEmpty()) {
            return answer;
        }
        return answer + "\n\n---\n\n" + SelfKbService.renderCitationBlock(citations);
    }

    /** "未生成"时的正文：说明原因，不含任何看似结论的内容 */
    private String notGeneratedText(long deadlineMs) {
        return "## 本次没有生成结论\n\n"
                + "> state=model-failed\n\n"
                + "原因：模型不可用，或编排链路在 " + deadlineMs + " ms 预算内没有返回。\n\n"
                + "按本项目的 fail-closed 原则，**没有产出就是没有产出**，不退回模板拼装来假装回答过了。\n\n"
                + "（自用池额度与本次失败无关：自用额度是软上限，达到上限也不会停。）";
    }
}
