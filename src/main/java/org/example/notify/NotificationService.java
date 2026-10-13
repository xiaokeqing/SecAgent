package org.example.notify;

import org.example.core.model.AlertSeverity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PreDestroy;

import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 通知中枢：把四类安全事件推到手机，并做分级与降噪。
 *
 * <h3>它解决的问题</h3>
 * "检测到了"和"人知道了"是两件事。这个项目有告警大屏、有处置护栏、有看门狗自动回滚，
 * 但人不在电脑前的时候，这些能力等于不存在 —— 而真实攻击多数发生在没人看屏的时候。
 *
 * <h3>通道：通用 Webhook，不写死任何一家</h3>
 * Telegram Bot / 飞书 / 钉钉 / 企业微信 / Bark / 自建 n8n 的共同点只有
 * "HTTP POST 一个 JSON"，差异全在载荷形状。所以这里只做一件事：
 * 把 {@code {{变量}}} 渲染进一个可配置的模板（见 {@link NotificationTemplate}），
 * POST 到可配置地址。{@code NOTIFY_WEBHOOK_URL} 留空 = 功能关闭，
 * 且启动自检必须显式打印"通知未配置"（见 {@code OutboundSelfCheck}）—— 不许静默。
 *
 * <h3>降噪三条规则（顺序即优先级）</h3>
 * <ol>
 *   <li><b>等级门槛</b>：{@code NOTIFY_MIN_SEVERITY}（默认 HIGH）以下的直接不发；</li>
 *   <li><b>夜间静默</b>：{@code NOTIFY_NIGHT_QUIET=22:00-07:00}，
 *       只压制 INFO/MEDIUM —— <b>HIGH/CRITICAL 照发</b>。
 *       夜里把高危也压住，等于把"这个功能别用"写进配置；</li>
 *   <li><b>冷却 + 同 IP 合并</b>：同一 {@code dedupKey} 在 {@code NOTIFY_COOLDOWN_SECONDS}
 *       内不重复发；同一 IP 的事件在 {@code NOTIFY_SAME_IP_MERGE} 窗口内合并成一条
 *       "聚合 N 次"。合并刻意做成"<b>等一等再发</b>"（延迟 flush），
 *       否则"每来一条就发一条聚合通知"根本不是合并，只是把刷屏换了个标题。</li>
 * </ol>
 *
 * <h3>失败处理</h3>
 * 有限次重试（{@code NOTIFY_MAX_ATTEMPTS}，指数退避），
 * 每一次"想通知 / 被压制 / 发失败"都写 {@link NotificationAudit}。
 * 全程 <b>不向上抛异常</b>：通知是旁路能力，它挂了不能让告警研判或处置失败 ——
 * 但"没通知出去"必须留下痕迹，不能静默。
 */
@Service
public class NotificationService {

    private static final Logger logger = LoggerFactory.getLogger(NotificationService.class);

    /** 出站依赖标识：冷却/在飞上限按它隔离（与启动自检里的名字对齐） */
    public static final String DEP_WEBHOOK = "notify-webhook";

    /** 发送结果 */
    public enum Outcome {
        /** 已发出（对端 2xx） */
        SENT,
        /** 被降噪规则压制（等级/夜间/冷却），没有出网 */
        SUPPRESSED,
        /** 已并入同 IP 聚合窗口，稍后合并发出 */
        MERGED,
        /** 没配 NOTIFY_WEBHOOK_URL —— 功能关闭（如实降级，不假装成功） */
        NOT_CONFIGURED,
        /** 重试用尽仍失败 */
        FAILED,
        /** 模板写错 / 载荷渲染失败（属于配置错误，不是网络问题） */
        INVALID
    }

    /** 一次发送的结果：成功与否 + 对端状态码 + 可读原因 */
    public record Delivery(boolean success, int httpCode, String message) {
        public static Delivery ok(int code) {
            return new Delivery(true, code, "HTTP " + code);
        }

        public static Delivery fail(int code, String message) {
            return new Delivery(false, code, message);
        }
    }

    /**
     * 发送通道。抽成接口只有一个目的：<b>让降噪/重试/降级逻辑可被确定性地测</b> ——
     * 不需要真起一个 HTTP 服务、也不需要等真实的网络超时。
     */
    public interface Transport {
        /**
         * @param requestUrl 本次目标地址（由 {@link #resolveWebhookUrl} 从事件推出来）
         * @param jsonBody   已经渲染好的 JSON 字符串
         */
        Delivery post(String requestUrl, String jsonBody);

        /**
         * 单次调用的生效预算（毫秒）；未知返回 0。
         *
         * <p>只用于"把实际生效值打出来"（启动自检 / {@link #describe()}）：
         * 报"配置里写的数"会骗人 —— 配置改了但客户端没拿到的情况真的发生过。
         */
        default long timeoutMs() {
            return 0;
        }
    }

    // ==================== 配置（全部走 .env，未配置 = 关闭但显式打印） ====================

    /** 留空 = 关闭。这是唯一的"总开关"，不存在第二个开关与它冲突 */
    @Value("${app.notify.webhook-url:}")
    private String webhookUrl;

    /** 可换 Telegram / 飞书格式；留空用通用 {"text":"{{title}}\n{{body}}"} */
    @Value("${app.notify.webhook-template:}")
    private String webhookTemplate;

    /** 最低通知等级（默认 HIGH：CRITICAL/HIGH 才推） */
    @Value("${app.notify.min-severity:HIGH}")
    private String minSeverityRaw;

    /** 同类事件冷却（秒） */
    @Value("${app.notify.cooldown-seconds:300}")
    private long cooldownSeconds;

    /** 夜间静默窗口，形如 22:00-07:00；留空 = 不静默 */
    @Value("${app.notify.night-quiet:22:00-07:00}")
    private String nightQuiet;

    /** 同 IP 合并窗口（秒）；0 = 关闭合并 */
    @Value("${app.notify.same-ip-merge-seconds:600}")
    private long sameIpMergeSeconds;

    /** 发送失败的最大尝试次数 */
    @Value("${app.notify.max-attempts:3}")
    private int maxAttempts;

    /** 重试退避基数（毫秒），第 n 次重试等 base * 2^(n-1) */
    @Value("${app.notify.retry-backoff-ms:500}")
    private long retryBackoffMs;

    /** 同 IP 合并窗口到期后延迟多久发出（毫秒）：给"后续同类事件"留一点汇合时间 */
    @Value("${app.notify.merge-flush-delay-ms:1000}")
    private long mergeFlushDelayMs;

    /** 出站超时（毫秒）：与统一出站预算同源，单测里可缩短 */
    @Value("${app.notify.timeout-ms:10000}")
    private long timeoutMs;

    private final Transport transport;
    private final NotificationAudit audit;

    /** 冷却表：dedupKey -> 上次真正发出的时刻（毫秒） */
    private final Map<String, Long> lastSentAt = new ConcurrentHashMap<>();

    /**
     * 聚合中的条目：合并键 -> 待发内容。
     *
     * <p>{@code sent} 标记"这个窗口里已经发出过一条了"，随后的同类事件不再二次发送，
     * 只在计数上叠加 —— 否则每次 flush 都会再发一条"聚合 N 次"，仍然是一次风暴。
     */
    private final Map<String, PendingMerge> pending = new ConcurrentHashMap<>();

    private final ScheduledExecutorService timer =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "notify-flush");
                t.setDaemon(true);
                return t;
            });

    /** 时钟：单测里替换成可控时钟，避免"睡 300 秒"这种根本跑不了的测试 */
    private java.util.function.Supplier<LocalDateTime> clock = LocalDateTime::now;

    /** 真实毫秒时钟（冷却用）。与 {@link #clock} 分开：一个要能被测试拨动，一个要单调 */
    private java.util.function.Supplier<Long> millis = System::currentTimeMillis;

    private volatile boolean closed = false;

    public NotificationService(Transport transport, NotificationAudit audit) {
        this.transport = transport;
        this.audit = audit;
    }

    // ==================== 对外入口 ====================

    /**
     * 推一条事件。四类触发事件都走这里。
     *
     * <p>返回结果而不是 void：调用方（例如看门狗端点）需要知道"到底发出去了没有"
     * 才能如实回话。全流程不抛异常。
     */
    public Outcome send(NotifyEvent event) {
        if (event == null) {
            return Outcome.INVALID;
        }
        try {
            if (!configured()) {
                // 未配置：明确记一条 NOT_CONFIGURED，并打 WARN —— 不许静默当成功
                logger.warn("通知未配置（{} 为空）：事件[{}] {} 未推送（如实降级，不假装成功）",
                        "NOTIFY_WEBHOOK_URL", event.type(), event.title());
                record(event, NotificationAudit.OUTCOME_NOT_CONFIGURED, "NOTIFY_WEBHOOK_URL 未配置", 0);
                return Outcome.NOT_CONFIGURED;
            }
            if (belowThreshold(event)) {
                record(event, NotificationAudit.OUTCOME_SUPPRESSED,
                        "等级 " + event.severity() + " 低于门槛 " + minSeverity().name(), 0);
                return Outcome.SUPPRESSED;
            }
            if (inNightQuiet(event)) {
                record(event, NotificationAudit.OUTCOME_SUPPRESSED,
                        "夜间静默 " + nightQuiet + " 压制 " + event.severity(), 0);
                return Outcome.SUPPRESSED;
            }
            if (coolingDown(event)) {
                record(event, NotificationAudit.OUTCOME_SUPPRESSED,
                        "冷却期内（同类事件 " + cooldownSeconds + "s 内只发一次，key=" + event.dedupKey() + "）", 0);
                return Outcome.SUPPRESSED;
            }
            if (shouldMerge(event)) {
                return merge(event);
            }
            return deliverNow(event, 1);
        } catch (Exception e) {
            // 旁路能力绝不影响主流程：这里连"未知异常"都不许穿出去
            logger.error("通知处理异常（已吞掉，不影响主流程）：{}", e.toString());
            try {
                record(event, NotificationAudit.OUTCOME_FAILED, "通知处理异常：" + e.getMessage(), 0);
            } catch (Exception ignored) {
                // 审计也失败就只剩日志了
            }
            return Outcome.FAILED;
        }
    }

    /** 立即把待合并的事件发出去（单测与关停时用；正常由定时器触发） */
    public int flushPending() {
        int n = 0;
        for (Map.Entry<String, PendingMerge> e : new ArrayList<>(pending.entrySet())) {
            if (flushOne(e.getKey(), e.getValue())) {
                n++;
            }
        }
        return n;
    }

    // ==================== 降噪规则 ====================

    /**
     * 同 IP 合并：只有"带 IP"的事件参与。
     *
     * <p>为什么按 IP 而不是"按类型 + IP"：同一个攻击源在几分钟里往往同时刷
     * 端口扫描、暴力破解、Web 探测 —— 对手机来说那是<b>一件事</b>（"这个 IP 在打我们"）。
     * 分类型合并等于让人在同一分钟里收到三条，降噪就白做了。
     */
    private boolean shouldMerge(NotifyEvent event) {
        return sameIpMergeSeconds > 0 && event.hasIp();
    }

    private Outcome merge(NotifyEvent event) {
        String key = "ip:" + event.targetIp();
        PendingMerge pm = pending.computeIfAbsent(key, k -> new PendingMerge(event));
        pm.mergeCount.incrementAndGet();
        pm.lastType = event.type();
        pm.lastSeverity = event.severity();
        pm.lastTitle = event.title();
        pm.lastBody = event.body();
        pm.lastActor = event.actor();

        if (pm.sent) {
            // 本窗口已发过一条：只累加计数，不再发第二条（否则"合并"变成"换标题刷屏"）
            record(event, NotificationAudit.OUTCOME_MERGED,
                    "并入已发出的聚合窗口（累计 " + pm.mergeCount.get() + " 次，不再重复推送）", 0);
            scheduleFlush(key, pm);
            return Outcome.MERGED;
        }
        record(event, NotificationAudit.OUTCOME_MERGED,
                "进入同 IP 聚合窗口 " + sameIpMergeSeconds + "s（累计 " + pm.mergeCount.get() + " 次）", 0);
        scheduleFlush(key, pm);
        return Outcome.MERGED;
    }

    private void scheduleFlush(String key, PendingMerge pm) {
        long delay = Math.max(0, mergeFlushDelayMs);
        try {
            if (pm.scheduled) {
                return;
            }
            pm.scheduled = true;
            timer.schedule(() -> {
                try {
                    flushOne(key, pm);
                } catch (Exception e) {
                    logger.warn("聚合通知发出失败（已记审计）：{}", e.getMessage());
                }
            }, delay, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            // 定时器不可用（关停中）：退化为同步发出，至少不丢这一条
            logger.warn("聚合定时器不可用，改为立即发出：{}", e.getMessage());
            flushOne(key, pm);
        }
    }

    /**
     * 把某条聚合记录发出去。返回 true 表示这次确实发了。
     *
     * <h3>为什么一个聚合窗口只发一条（而不是"计数涨了就再发一条"）</h3>
     * 朴素实现是"每次 flush 都发当前计数"，于是同一窗口里发出
     * "聚合 3 次"→"聚合 8 次"→"聚合 15 次" —— 手机上照样刷屏，
     * 只是把标题从"告警"换成了"聚合告警"。降噪的目标是<b>一个窗口一条</b>：
     * 窗口结束前继续上涨的部分，由下一个窗口的聚合来体现。
     */
    private boolean flushOne(String key, PendingMerge pm) {
        if (pm.sent) {
            // 本窗口已经通知过：只保留计数，不再发第二条
            return false;
        }
        int count = pm.mergeCount.get();
        if (count <= 0) {
            pending.remove(key);
            return false;
        }
        pm.notifiedCount = count;
        NotifyEvent agg = NotifyEvent.of(
                pm.lastType,
                pm.lastSeverity,
                "聚合 " + count + " 次 · " + pm.firstTitle,
                "同一来源 " + pm.firstIp + " 在 " + sameIpMergeSeconds + "s 内触发 " + count + " 次："
                        + "首次=" + pm.firstTitle
                        + "；最近=" + pm.lastTitle
                        + (pm.lastBody.isBlank() ? "" : "；最近详情=" + pm.lastBody),
                "ip-merge:" + pm.firstIp,
                pm.firstIp,
                pm.lastActor);
        Outcome o = deliverNow(agg, count);
        if (o == Outcome.SENT) {
            pm.sent = true;
            // 合并窗口内的冷却键按 IP 记，避免"合并通知 + 单条通知"两条都发
            lastSentAt.put(agg.dedupKey(), millis.get());
            return true;
        }
        // 没发成功：允许下一次 flush 再试（否则这条聚合会被静默丢掉）
        pm.notifiedCount = 0;
        return false;
    }

    private boolean belowThreshold(NotifyEvent event) {
        return rank(event.severity()) < rank(minSeverity());
    }

    private static int rank(AlertSeverity s) {
        return s == null ? 0 : s.getRank();
    }

    /**
     * 解析最低等级配置。
     *
     * <p>刻意<b>只认枚举名</b>（INFO/LOW/MEDIUM/HIGH/CRITICAL），不认中文与数字：
     * {@link AlertSeverity#parse(Object)} 是"宽松解析"，它会把写错的
     * {@code NOTIFY_MIN_SEVERITY=highh} 兜底成 MEDIUM —— 于是配置写错的表现是
     * "夜里被中危刷屏"，而不是报错。这里宁可当成 HIGH 并打 WARN。
     */
    public AlertSeverity minSeverity() {
        if (minSeverityRaw == null || minSeverityRaw.isBlank()) {
            return AlertSeverity.HIGH;
        }
        String up = minSeverityRaw.trim().toUpperCase();
        for (AlertSeverity s : AlertSeverity.values()) {
            if (s.name().equals(up)) {
                return s;
            }
        }
        logger.warn("NOTIFY_MIN_SEVERITY=[{}] 不认识，按 HIGH 处理（宁可少发，也不放宽）", minSeverityRaw);
        return AlertSeverity.HIGH;
    }

    /**
     * 夜间静默判定，支持跨零点（22:00-07:00）。
     *
     * <p>只压制 INFO/MEDIUM —— 呼救（HIGH/CRITICAL）与时间无关。
     */
    public boolean inNightQuiet(NotifyEvent event) {
        if (event == null || rank(event.severity()) >= rank(AlertSeverity.HIGH)) {
            return false;
        }
        if (nightQuiet == null || nightQuiet.isBlank() || !nightQuiet.contains("-")) {
            return false;
        }
        String[] parts = nightQuiet.split("-", 2);
        LocalTime from = parseTime(parts[0]);
        LocalTime to = parseTime(parts[1]);
        if (from == null || to == null) {
            return false;
        }
        LocalTime now = clock.get().toLocalTime();
        if (from.equals(to)) {
            return false;
        }
        if (from.isBefore(to)) {
            return !now.isBefore(from) && now.isBefore(to);
        }
        // 跨零点：now >= from 或 now < to
        return !now.isBefore(from) || now.isBefore(to);
    }

    private static LocalTime parseTime(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        try {
            if (t.length() == 4 && t.charAt(2) == ':') {
                t = "0" + t;
            }
            return LocalTime.parse(t.length() == 5 ? t : t + ":00");
        } catch (Exception e) {
            return null;
        }
    }

    private boolean coolingDown(NotifyEvent event) {
        if (cooldownSeconds <= 0) {
            return false;
        }
        Long last = lastSentAt.get(event.dedupKey());
        if (last == null) {
            return false;
        }
        return (millis.get() - last) < cooldownSeconds * 1000L;
    }

    // ==================== 发送（重试 + 审计） ====================

    private Outcome deliverNow(NotifyEvent event, int mergeCount) {
        // 同 IP 合并时，冷却键也要占上：否则窗口结束后单条事件又会各发一遍
        lastSentAt.put(event.dedupKey(), millis.get());
        if (event.hasIp()) {
            lastSentAt.put("ip-merge:" + event.targetIp(), millis.get());
        }

        String template = webhookTemplate;
        String body;
        try {
            body = NotificationTemplate.render(template, event.variables(mergeCount));
        } catch (IllegalArgumentException e) {
            // 模板写错属于配置错误：必须显式记，而且不能悄悄用默认模板发出去
            logger.error("通知模板渲染失败（未发送）：{}", e.getMessage());
            record(event, NotificationAudit.OUTCOME_FAILED, "模板渲染失败：" + e.getMessage(), 0);
            return Outcome.INVALID;
        }

        String url = resolveWebhookUrl(event);
        int attempts = Math.max(1, maxAttempts);
        String lastError = "";
        for (int i = 1; i <= attempts; i++) {
            Delivery d;
            try {
                d = transport.post(url, body);
            } catch (Exception e) {
                d = Delivery.fail(-1, e.getClass().getSimpleName() + ": " + e.getMessage());
            }
            if (d != null && d.success()) {
                logger.info("通知已发出：{}（{}，第 {} 次尝试，聚合 {} 次）",
                        event.title(), d.message(), i, mergeCount);
                record(event, NotificationAudit.OUTCOME_SENT,
                        "第 " + i + " 次尝试成功（" + d.message() + "，聚合 " + mergeCount + " 次）", i);
                return Outcome.SENT;
            }
            lastError = (d == null) ? "传送器返回 null" : d.message();
            logger.warn("通知发送失败（第 {}/{} 次）：{}", i, attempts, lastError);
            if (i < attempts) {
                sleep(backoffMs(i));
            }
        }

        logger.error("通知发送失败（已重试 {} 次），按如实降级处理：{}", attempts, lastError);
        record(event, NotificationAudit.OUTCOME_FAILED, "重试 " + attempts + " 次仍失败：" + lastError, attempts);
        reportNotifyFailure(event, lastError, attempts);
        return Outcome.FAILED;
    }

    /** 第 i 次失败后等待多久（指数退避，封顶 8s） */
    private long backoffMs(int i) {
        long base = Math.max(0, retryBackoffMs);
        return Math.min(8000L, base * (1L << Math.min(6, Math.max(0, i - 1))));
    }

    private void sleep(long ms) {
        if (ms <= 0) {
            return;
        }
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * 通知发不出去这件事本身要再通知一次 —— <b>但不能无限递归</b>。
     *
     * <p>用独立的事件类型 {@code NOTIFY_FAILED} 且<b>不再重试</b>（只试一次），
     * 这样"webhook 挂了"不会变成自我放大的循环。若这一条也发不出去，就只剩审计与日志。
     */
    private void reportNotifyFailure(NotifyEvent failed, String error, int attempts) {
        if (failed.type() == NotifyEvent.Type.NOTIFY_FAILED) {
            return;
        }
        try {
            String body = NotificationTemplate.render(webhookTemplate,
                    Map.of("title", "通知通道异常", "body",
                            "上一条通知发送失败（重试 " + attempts + " 次）：" + error
                                    + "；原事件=" + failed.type() + " " + failed.title(),
                            "severity", "HIGH", "severityLabel", "高危",
                            "type", "NOTIFY_FAILED", "typeLabel", "通知发送失败",
                            "ip", "", "actor", "system", "time", clock.get().toString(), "count", "1"));
            Delivery d = transport.post(resolveWebhookUrl(failed), body);
            logger.warn("通知通道异常告警本身的结果：{}", d == null ? "null" : d.message());
        } catch (Exception e) {
            logger.error("通知通道异常告警也失败了：{}", e.getMessage());
        }
    }

    // ==================== 配置读取（自检/文档共用） ====================

    /**
     * 目标地址推导：支持"一个 URL 多个事件类型各走不同机器人"。
     *
     * <p>写法：{@code https://hook/a|WATCHDOG_ROLLBACK=https://hook/b}
     * —— 竖线分隔多个候选，带 {@code TYPE=} 前缀的只对该类型生效。
     * 没有类型前缀的第一段作为默认地址。
     * <p>为什么值得支持：看门狗回滚与高危告警的受众往往不是同一群人
     * （一个给运维、一个给安全），而为了这个去写两套通知代码不值。
     */
    public String resolveWebhookUrl(NotifyEvent event) {
        String configured = webhookUrl == null ? "" : webhookUrl.trim();
        if (configured.isEmpty()) {
            return "";
        }
        String[] parts = configured.split("\\|");
        String fallback = "";
        for (String raw : parts) {
            String p = raw.trim();
            if (p.isEmpty()) {
                continue;
            }
            int eq = p.indexOf('=');
            if (eq > 0 && !p.substring(0, eq).contains("/")) {
                String typeName = p.substring(0, eq).trim().toUpperCase();
                String url = p.substring(eq + 1).trim();
                if (event != null && event.type() != null && event.type().name().equals(typeName)) {
                    return url;
                }
            } else if (fallback.isEmpty()) {
                fallback = p;
            }
        }
        return fallback;
    }

    /** 是否已配置（未配置 = 功能关闭，但必须显式可见） */
    public boolean configured() {
        return webhookUrl != null && !webhookUrl.isBlank();
    }

    /** 供启动自检渲染的一行描述（未配置时显式写未配置，不留空） */
    public String describe() {
        if (!configured()) {
            return "NOT-CONFIGURED(通知未配置: NOTIFY_WEBHOOK_URL 为空)";
        }
        long effectiveTimeout = (transport == null) ? 0 : transport.timeoutMs();
        return "configured(minSeverity=" + minSeverity().name()
                + ",cooldown=" + cooldownSeconds + "s"
                + ",nightQuiet=" + (nightQuiet == null || nightQuiet.isBlank() ? "NONE" : nightQuiet)
                + ",sameIpMerge=" + sameIpMergeSeconds + "s"
                + ",maxAttempts=" + Math.max(1, maxAttempts)
                + ",callTimeout=" + (effectiveTimeout > 0 ? effectiveTimeout + "ms" : "MISSING(传送器未报)")
                + ",auditFile=" + (audit == null ? "?" : audit.auditFilePath()) + ")";
    }

    public long cooldownSeconds() {
        return cooldownSeconds;
    }

    public long sameIpMergeSeconds() {
        return sameIpMergeSeconds;
    }

    public int maxAttempts() {
        return Math.max(1, maxAttempts);
    }

    public String webhookTemplateOrDefault() {
        return (webhookTemplate == null || webhookTemplate.isBlank())
                ? NotificationTemplate.DEFAULT_TEMPLATE : webhookTemplate;
    }

    /** 单测用：替换时钟 */
    void setClock(java.util.function.Supplier<LocalDateTime> clock, java.util.function.Supplier<Long> millis) {
        this.clock = clock;
        this.millis = millis;
    }

    /** 单测/调试用：当前聚合待发条数 */
    int pendingMerges() {
        return pending.size();
    }

    private void record(NotifyEvent event, String outcome, String reason, int attempts) {
        if (audit != null) {
            audit.record(event, outcome, reason, attempts);
        }
    }

    @PreDestroy
    public void shutdown() {
        closed = true;
        try {
            flushPending();
        } catch (Exception e) {
            logger.warn("关停时刷新待发通知失败：{}", e.getMessage());
        }
        timer.shutdownNow();
    }

    /** 关停标记（供测试断言不会再调度） */
    boolean isClosed() {
        return closed;
    }

    /** 一次聚合窗口内的状态 */
    private static final class PendingMerge {
        final String firstIp;
        final String firstTitle;
        final AtomicInteger mergeCount = new AtomicInteger(0);
        volatile boolean sent = false;
        volatile boolean scheduled = false;
        volatile int notifiedCount = 0;
        volatile NotifyEvent.Type lastType;
        volatile AlertSeverity lastSeverity;
        volatile String lastTitle = "";
        volatile String lastBody = "";
        volatile String lastActor = "unknown";

        PendingMerge(NotifyEvent e) {
            this.firstIp = e.targetIp();
            this.firstTitle = e.title();
            this.lastType = e.type();
            this.lastSeverity = e.severity();
        }
    }

    /** 便于日志/接口展示的配置摘要 */
    public Map<String, Object> configSummary() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("configured", configured());
        m.put("minSeverity", minSeverity().name());
        m.put("cooldownSeconds", cooldownSeconds);
        m.put("nightQuiet", nightQuiet);
        m.put("sameIpMergeSeconds", sameIpMergeSeconds);
        m.put("maxAttempts", maxAttempts());
        m.put("auditFile", audit == null ? "" : audit.auditFilePath());
        m.put("pendingMerges", pending.size());
        List<String> urls = new ArrayList<>();
        String configuredUrls = webhookUrl == null ? "" : webhookUrl.trim();
        if (!configuredUrls.isEmpty()) {
            for (String s : configuredUrls.split("\\|")) {
                // 地址本身可能含令牌（很多 IM 机器人把 token 写在 URL 里）——
                // 这里只报"配了几条"，不回显内容
                if (!s.isBlank()) {
                    urls.add("(hidden)");
                }
            }
        }
        m.put("webhookRoutes", urls.size());
        return m;
    }
}
