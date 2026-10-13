package org.example.notify;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 通知中枢的管理面：④ 看门狗回滚触发点 + 只读状态。
 *
 * <h3>为什么需要它（看门狗在容器外面）</h3>
 * {@code srv1-health-watchdog.sh} 跑在宿主机上，它做的"回滚"是本系统最重的一次动作
 * （把生产版本换掉），也是最该被手机看到的一次。但脚本在容器外，
 * 拿不到 {@link NotificationService} 这个 Bean —— 所以给它一个本地 HTTP 入口，
 * 让"回滚已发生"这件事走与其它三类事件<b>同一条通道、同一套降噪与审计</b>。
 *
 * <h3>为什么走 HTTP 而不是 CLI 调用这个方法</h3>
 * 试过把它做成"脚本调 CLI"：容器镜像里<b>没有 python3</b>,而 bash 脚本也发不了
 * HTTPS，结果是这条链路根本没通（而"没通"在脚本里表现为静默跳过，没人会发现）。
 * 宿主机上则有 curl，且应用本来就监听 127.0.0.1:9900 —— 复用现成通路最省事，
 * 也最容易验证。
 *
 * <h3>鉴权：不在白名单里，必须带 API Token</h3>
 * 路径 {@code /api/notify/**} 不在 {@code app.auth.white-list} 里，
 * 因此 {@code ApiTokenInterceptor} 要求 {@code X-API-Token}（等于 {@code SECAGENT_API_TOKEN}）。
 * 这一步不能省：若做成免鉴权，任何人只要能连到 9900（或经隧道绕进来）就能伪造"系统降级"、
 * "看门狗已回滚"这类高危通知 —— <b>通知通道的输入端必须和业务写接口同级</b>。
 *
 * <h3>响应如实</h3>
 * 端点回话里带 {@code outcome}（SENT / SUPPRESSED / NOT_CONFIGURED / FAILED），
 * 脚本据此写日志。这样"手机没响"时，看门狗日志里能直接看到是被降噪压了、
 * 还是通知压根没配。
 */
@RestController
@RequestMapping("/api/notify")
public class NotifyController {

    private static final Logger logger = LoggerFactory.getLogger(NotifyController.class);

    private final SecurityEventNotifier notifier;
    private final NotificationService notificationService;
    private final NotificationAudit audit;

    public NotifyController(SecurityEventNotifier notifier,
                            NotificationService notificationService,
                            NotificationAudit audit) {
        this.notifier = notifier;
        this.notificationService = notificationService;
        this.audit = audit;
    }

    /**
     * ④ 看门狗回滚触发点。
     *
     * <p>请求体（全部可选）：
     * <pre>
     * {"commitFrom":"<回滚前提交>","commitTo":"<last-known-good 提交>",
     *  "reason":"连续 3 次不健康","actor":"watchdog"}
     * </pre>
     *
     * <p>回滚脚本用 curl 调用（见 RUNBOOK §19）：
     * <pre>
     * curl -sS -X POST http://127.0.0.1:9900/api/notify/watchdog-rollback \
     *   -H "X-API-Token: $SECAGENT_API_TOKEN" -H 'Content-Type: application/json' \
     *   -d '{"commitFrom":"'"$CUR_COMMIT"'","commitTo":"'"$LKG_COMMIT"'","reason":"'"$REASON"'"}'
     * </pre>
     */
    @PostMapping("/watchdog-rollback")
    public ResponseEntity<Map<String, Object>> watchdogRollback(
            @RequestBody(required = false) Map<String, Object> body,
            HttpServletRequest req) {
        String from = str(body, "commitFrom", "unknown");
        String to = str(body, "commitTo", "unknown");
        String reason = str(body, "reason", "未提供原因");
        String actor = str(body, "actor", "watchdog");

        boolean configuredBefore = notificationService.configured();
        notifier.watchdogRollback(from, to, reason, actor);

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("eventType", NotifyEvent.Type.WATCHDOG_ROLLBACK.name());
        data.put("severity", NotifyEvent.defaultSeverity(NotifyEvent.Type.WATCHDOG_ROLLBACK).name());
        data.put("commitFrom", from);
        data.put("commitTo", to);
        data.put("notifyConfigured", configuredBefore);
        // 如实回话：脚本据此在日志里写明"通知没配"或"被降噪压制"，而不是只看 HTTP 200
        data.put("outcome", configuredBefore ? "SUBMITTED" : "NOT_CONFIGURED");
        data.put("auditOutcomes", audit == null ? Map.of() : audit.countsByOutcome());
        data.put("note", configuredBefore
                ? "已提交通知中枢，实际发送结果见 data/notify-audit.jsonl"
                : "通知未配置（NOTIFY_WEBHOOK_URL 为空）：本次只写审计与日志，未推送任何消息");

        if (!configuredBefore) {
            logger.warn("看门狗回滚事件到达，但通知未配置（{} 为空）：未推送（如实降级）",
                    "NOTIFY_WEBHOOK_URL");
        } else {
            logger.warn("看门狗回滚事件已受理：{} → {}（原因={}，来源={}，ip={}）",
                    from, to, reason, actor, req == null ? "?" : req.getRemoteAddr());
        }
        return ResponseEntity.ok(envelope(data));
    }

    /** 只读状态：当前生效配置 + 最近审计计数（排障用；不含 webhook 地址内容） */
    @GetMapping("/state")
    public ResponseEntity<Map<String, Object>> state() {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("config", notificationService.configSummary());
        data.put("transport", Map.of(
                "dependency", NotificationService.DEP_WEBHOOK,
                "note", "出站复用统一超时矩阵 + OutboundGuard；生效值见启动自检日志 OUTBOUND-TIMEOUTS-SELFCHECK"));
        data.put("notifier", notifier == null ? Map.of() : notifier.stateSummary());
        data.put("auditOutcomes", audit == null ? Map.of() : audit.countsByOutcome());
        data.put("recent", audit == null ? java.util.List.of() : audit.recent(20));
        return ResponseEntity.ok(envelope(data));
    }

    /** 未配置时回 200 但明确写 outcome：**不能用 4xx/5xx 让脚本误以为"回滚失败"** */
    private static Map<String, Object> envelope(Map<String, Object> data) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", 200);
        body.put("message", "success");
        body.put("data", data);
        return body;
    }

    private static String str(Map<String, Object> body, String key, String dflt) {
        if (body == null) {
            return dflt;
        }
        Object v = body.get(key);
        if (v == null) {
            return dflt;
        }
        String s = String.valueOf(v).trim();
        return s.isEmpty() ? dflt : s;
    }

    /** 保留：便于将来用 GET 做"回调 url 探活"（当前不用，避免多一个入口） */
    @GetMapping("/ping")
    public ResponseEntity<Map<String, Object>> ping() {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("configured", notificationService.configured());
        data.put("minSeverity", notificationService.minSeverity().name());
        return ResponseEntity.status(HttpStatus.OK).body(envelope(data));
    }
}
