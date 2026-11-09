package org.example.response;

import org.example.core.model.AlertSeverity;
import org.example.core.model.SecurityAlert;
import org.example.publicapi.PublicAlertSource;
import org.example.security.ResponseGuard;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 自动处置调度器：把"看板上恒为 0 的自动封禁"真正接起来。
 *
 * <h3>它修的是什么</h3>
 * 在此之前整条链路只有"手"没有"眼"：{@link ResponseActionService} 能封、护栏也在，
 * 但<b>没有任何调度器在看完告警之后去调它</b>。所以审计文件里 98 条记录全是
 * {@code mode=BLOCKED}、其中 69 条 {@code target=""} 的垃圾（来自"从聊天文本里抽 IP"
 * 的那条路径，抽不到就留一条空目标拦截），而真正下发的自动封禁一条都没有。
 * 这不是"封禁能力坏了"，是"没人触发"。
 *
 * <h3>执行顺序（与 ResponseActionService 的分工）</h3>
 * <ol>
 *   <li>读最近 5 分钟告警（{@link PublicAlertSource#readAlerts()}，REAL 才返回数据）</li>
 *   <li>按 {@code srcIp} 聚合 HIGH+CRITICAL 的命中次数；按阈值挑出候选 IP</li>
 *   <li>冷却检查：已封禁中 / 10 分钟内刚处置过 → 跳过</li>
 *   <li><b>先自己过一遍 {@link ResponseGuard}</b>：空 IP / 非法 IP / 白名单 / 健康检查源命中
 *       → 只 log.info + 记一条决策，<b>不写 BLOCKED 审计</b>。
 *       这一步是刻意重复的 —— {@code blockIp} 内部也会过护栏，但那会在
 *       {@code data/response-audit.json} 里再刷一条 "封禁目标 IP 为空"，
 *       正是这次要止住的垃圾来源。</li>
 *   <li>dry-run（默认 true）：只打日志 + 写 {@code action=block-ip-dryrun} 的自定义审计；</li>
 *   <li>否则调 {@link ResponseActionService#blockIp(String, Integer, String, String, String)}，
 *       actor={@code auto-responder}、source={@code 自动处置}。</li>
 * </ol>
 *
 * <h3>为什么默认关闭、且默认 dry-run</h3>
 * 自动封禁是"会改防火墙"的动作，误封的代价（把自己的健康检查探针封掉 → 服务被判死）
 * 远大于晚封几分钟。所以 Bean 本身由 {@code app.response.auto.enabled}
 * （默认 false）控制是否创建；即使创建了，{@code dry-run} 默认 true 也只记录不下发。
 * 上线顺序是：先 dry-run 观察一轮决策，再切真封。
 *
 * <h3>为什么"异常不许炸调度"</h3>
 * {@code @Scheduled} 的 fixedDelay 任务一旦抛异常，Spring 只会打日志，
 * 下一次仍会跑 —— 但这一轮里其它候选 IP 会被一起放弃，且观测队列看不到原因。
 * 因此对外入口 {@link #tick()} 兜住全部异常，单个 IP 的下发异常也只影响它自己。
 */
@Component
@ConditionalOnProperty(name = "app.response.auto.enabled", havingValue = "true", matchIfMissing = false)
public class AutoResponder {

    private static final Logger log = LoggerFactory.getLogger(AutoResponder.class);

    static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /** 统计窗口：最近多少分钟的告警参与聚合 */
    static final int WINDOW_MINUTES = 5;

    /** 进程内冷却：同一 IP 处置后多少分钟内不再重复处置（防抖动） */
    static final int COOLDOWN_MINUTES = 10;

    /** 决策环形队列容量（内存，不落盘） */
    static final int MAX_WINDOWS = 50;

    /** /state 返回的决策条数上限 */
    static final int STATE_WINDOWS = 10;

    /** 自动处置的执行人/来源，审计里靠它和"手动"区分 */
    static final String ACTOR = "auto-responder";
    static final String SOURCE = "自动处置";

    private final PublicAlertSource alertSource;
    private final ResponseActionService actionService;
    private final ResponseGuard guard;
    private final AuditService auditService;
    private final BlockRecordStore blockRecordStore;

    /** 可替换时钟：单测用它把"冷却 10 分钟"变成确定性的断言，而不是 Thread.sleep */
    private Clock clock = Clock.systemDefaultZone();

    /** 演练开关：默认 true（只记录、不下发） */
    @Value("${app.response.auto.dry-run:true}")
    private boolean dryRun = true;

    /** 同一 IP 5 分钟内 HIGH+CRITICAL 命中次数之和达到该值 → 封 */
    @Value("${app.response.auto.min-high:30}")
    private int minHigh = 30;

    /** 同一 IP 5 分钟内 CRITICAL 命中次数达到该值 → 封（独立于 min-high 的更严格路径） */
    @Value("${app.response.auto.min-critical:3}")
    private int minCritical = 3;

    /** 自动封禁时长（分钟） */
    @Value("${app.response.auto.duration-minutes:60}")
    private int durationMinutes = 60;

    /** 最近决策（环形，最多 {@link #MAX_WINDOWS} 条） */
    private final Deque<Map<String, Object>> decisions = new ArrayDeque<>();
    private final Object decisionsLock = new Object();

    /** 进程内冷却表：IP → 最近一次处置时间 */
    private final Map<String, LocalDateTime> cooldown = new HashMap<>();
    private final Object cooldownLock = new Object();

    private boolean durationClampWarned;

    @Autowired
    public AutoResponder(PublicAlertSource alertSource,
                         ResponseActionService actionService,
                         ResponseGuard guard,
                         AuditService auditService,
                         BlockRecordStore blockRecordStore) {
        this.alertSource = alertSource;
        this.actionService = actionService;
        this.guard = guard;
        this.auditService = auditService;
        this.blockRecordStore = blockRecordStore;
    }

    /**
     * 定时入口：每 60 秒一轮、启动后 45 秒开始。
     *
     * <p>包住全部异常是刻意的：失败的一轮只该是"这轮没封成"，
     * 不该让调度线程把堆栈刷进日志之后仍然每轮重复同样的失败。
     */
    @Scheduled(fixedDelay = 60000, initialDelay = 45000)
    public void tick() {
        try {
            runOnce();
        } catch (Exception e) {
            log.error("[AutoResponder] 本轮自动处置异常（下一轮照常）：{}", e.getMessage(), e);
        }
    }

    /**
     * 执行一轮判定。单测直接调它，不需要等 45 秒的 initialDelay。
     *
     * <p>本方法内部只兜"单个 IP 的下发异常"；数据源/聚合层异常由 {@link #tick()} 兜。
     */
    public void runOnce() {
        List<SecurityAlert> alerts;
        try {
            alerts = alertSource == null ? List.of() : alertSource.readAlerts();
        } catch (Exception e) {
            log.warn("[AutoResponder] 读取告警失败，本轮跳过：{}", e.getMessage());
            return;
        }
        if (alerts == null || alerts.isEmpty()) {
            log.debug("[AutoResponder] 最近 {} 分钟没有可用告警，本轮空跑", WINDOW_MINUTES);
            return;
        }

        LocalDateTime now = LocalDateTime.now(clock);
        LocalDateTime from = now.minusMinutes(WINDOW_MINUTES);

        Map<String, Counts> counts = new HashMap<>();
        for (SecurityAlert a : alerts) {
            if (a == null) {
                continue;
            }
            String ip = a.getSrcIp() == null ? "" : a.getSrcIp().trim();
            if (ip.isEmpty()) {
                continue;
            }
            LocalDateTime at = parseAlertTime(a.getOccurredAt());
            if (at == null) {
                continue;
            }
            // 未来时间只容忍一个窗口的时钟偏差：上游（Wazuh indexer）与本机时区/时钟
            // 不一致时，把"刚发生"的告警丢掉会让自动封禁永远等不到热点。
            if (at.isBefore(from) || at.isAfter(now.plusMinutes(WINDOW_MINUTES))) {
                continue;
            }
            // 【count 是命中次数，不是重复行数】Wazuh 会把同一规则在同一时间窗内的多次
            // 命中折叠进一条告警的 count；只数"行数"会把 100 次爆破记成 1 次，阈值永远打不穿。
            int weight = Math.max(1, a.getCount());
            Counts c = counts.computeIfAbsent(ip, k -> new Counts());
            if (a.getSeverity() == AlertSeverity.CRITICAL) {
                c.critical += weight;
                c.high += weight; // high 含 critical：min-high 是"HIGH+CRITICAL 总量"
            } else if (a.getSeverity() == AlertSeverity.HIGH) {
                c.high += weight;
            }
        }

        int highThreshold = Math.max(1, minHigh);
        int criticalThreshold = Math.max(1, minCritical);
        List<Map.Entry<String, Counts>> candidates = new ArrayList<>();
        for (Map.Entry<String, Counts> e : counts.entrySet()) {
            Counts c = e.getValue();
            if (c.high >= highThreshold || c.critical >= criticalThreshold) {
                candidates.add(e);
            }
        }
        if (candidates.isEmpty()) {
            log.debug("[AutoResponder] 本轮 {} 个来源 IP 均未达阈值（min-high={} / min-critical={}）",
                    counts.size(), highThreshold, criticalThreshold);
            return;
        }
        // 严重的先处置；同分按 IP 排序只为让日志与单测结果稳定
        candidates.sort(Comparator
                .comparingInt((Map.Entry<String, Counts> e) -> e.getValue().critical).reversed()
                .thenComparing(Comparator.comparingInt(
                        (Map.Entry<String, Counts> e) -> e.getValue().high).reversed())
                .thenComparing(Map.Entry::getKey));

        pruneCooldown(now);
        Set<String> active = activeIps();
        int duration = effectiveDuration();

        for (Map.Entry<String, Counts> e : candidates) {
            String ip = e.getKey();
            Counts c = e.getValue();
            String reason = String.format("自动封禁：5 分钟内 %d 条高危（含 %d 条严重）", c.high, c.critical);

            if (active.contains(ip)) {
                String why = "已封禁中（生效记录里已有该 IP），不重复封";
                log.info("[AutoResponder] 跳过 {}：{}；{}", ip, why, reason);
                record(now, ip, "skip-cooldown", why);
                continue;
            }
            if (inCooldown(ip, now)) {
                String why = "冷却期内（" + COOLDOWN_MINUTES + " 分钟内已处置过），不重复封";
                log.info("[AutoResponder] 跳过 {}：{}；{}", ip, why, reason);
                record(now, ip, "skip-cooldown", why);
                continue;
            }

            // 提前过护栏：blockIp 内部还会再判一次，但那时被拒会写一条 BLOCKED 审计，
            // 正是这次要止住的"空目标垃圾"。这里拒掉的只留日志 + 决策，不留审计。
            String guardReason = guard == null ? null : guard.validateBlock(ip, duration);
            if (guardReason != null) {
                log.info("[AutoResponder] 跳过 {}：{}（命中阈值但护栏拒绝）", ip, guardReason);
                record(now, ip, "skip-guard", guardReason);
                continue;
            }

            markCooldown(ip, now);
            if (dryRun) {
                log.info("[AutoResponder] DRY-RUN 本应封禁 {} {}", ip, reason);
                auditDryRun(ip, reason, c);
                record(now, ip, "dry-run", reason);
                continue;
            }

            try {
                org.example.core.model.ActiveResponseResult result =
                        actionService.blockIp(ip, duration, reason, ACTOR, SOURCE);
                log.info("[AutoResponder] 已下发封禁 {}（{} 分钟，mode={}）：{}", ip, duration,
                        result == null ? "UNKNOWN" : result.getMode(), reason);
                record(now, ip, "block", reason);
            } catch (Exception ex) {
                // 一个 IP 下发异常不能带走本轮其它候选，也不能炸掉调度
                log.warn("[AutoResponder] 封禁下发异常，已跳过该 IP：ip={} err={}", ip, ex.getMessage());
                record(now, ip, "error",
                        ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage());
            }
        }
    }

    /** 观测端点用的状态快照（阈值 + 最近 10 次决策） */
    public Map<String, Object> state() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("enabled", true); // Bean 能存在就说明 app.response.auto.enabled=true
        m.put("dryRun", dryRun);
        m.put("minHigh", minHigh);
        m.put("minCritical", minCritical);
        m.put("durationMinutes", durationMinutes);
        m.put("windows", recentWindows(STATE_WINDOWS));
        return m;
    }

    /** 最近 limit 条决策（时间正序，最新在最后） */
    public List<Map<String, Object>> recentWindows(int limit) {
        if (limit <= 0) {
            return List.of();
        }
        synchronized (decisionsLock) {
            List<Map<String, Object>> all = new ArrayList<>(decisions);
            int from = Math.max(0, all.size() - limit);
            return new ArrayList<>(all.subList(from, all.size()));
        }
    }

    // ---------------------------------------------------------------- 内部

    private void record(LocalDateTime now, String ip, String action, String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("time", now.format(FMT));
        m.put("ip", ip);
        m.put("action", action);
        m.put("reason", reason);
        synchronized (decisionsLock) {
            decisions.addLast(m);
            while (decisions.size() > MAX_WINDOWS) {
                decisions.removeFirst();
            }
        }
    }

    private void auditDryRun(String ip, String reason, Counts c) {
        if (auditService == null) {
            return;
        }
        try {
            auditService.append(ResponseAudit.of(ACTOR, "block-ip-dryrun", ip, reason,
                    "HIGH", "DRY_RUN", true,
                    "自动处置演练：未下发；5 分钟内 HIGH+CRITICAL=" + c.high
                            + "，CRITICAL=" + c.critical
                            + "；阈值 min-high=" + minHigh + " / min-critical=" + minCritical));
        } catch (Exception e) {
            // 审计失败不能改变"这一轮是否该封"的判定
            log.warn("[AutoResponder] 写演练审计失败（不影响决策）：{}", e.getMessage());
        }
    }

    /** 生效中的封禁记录里的 IP（blockActive 的对应物是 BlockRecordStore#listActive） */
    private Set<String> activeIps() {
        Set<String> out = new HashSet<>();
        if (blockRecordStore == null) {
            return out;
        }
        try {
            List<BlockRecord> active = blockRecordStore.listActive();
            if (active != null) {
                for (BlockRecord r : active) {
                    if (r != null && r.getIp() != null) {
                        out.add(r.getIp().trim());
                    }
                }
            }
        } catch (Exception e) {
            // 读不到生效记录只意味着"不知道已封了什么"，仍可继续（护栏兜底），不能因此停摆
            log.warn("[AutoResponder] 读取生效封禁记录失败（继续本轮）：{}", e.getMessage());
        }
        return out;
    }

    /**
     * 实际使用的封禁时长：收敛到 [1, 人工上限]。
     *
     * <p>为什么截断而不等护栏拒绝：这里显式传了时长，{@code blockIp} 会按"人工上限"判，
     * 配置写大了就会每个 IP 每轮都被拒；截断至少保住"封住"这个目标，同时日志留痕。
     */
    private int effectiveDuration() {
        int max = guard == null ? 1440 : guard.getMaxDurationMinutes();
        if (max <= 0) {
            max = 1440;
        }
        int d = Math.max(1, Math.min(durationMinutes, max));
        if (d != durationMinutes && !durationClampWarned) {
            durationClampWarned = true;
            log.warn("[AutoResponder] 配置的封禁时长 {} 分钟超过人工上限 {}，按 {} 分钟执行",
                    durationMinutes, max, d);
        }
        return d;
    }

    private boolean inCooldown(String ip, LocalDateTime now) {
        synchronized (cooldownLock) {
            LocalDateTime at = cooldown.get(ip);
            return at != null && at.plusMinutes(COOLDOWN_MINUTES).isAfter(now);
        }
    }

    private void markCooldown(String ip, LocalDateTime now) {
        synchronized (cooldownLock) {
            cooldown.put(ip, now);
        }
    }

    private void pruneCooldown(LocalDateTime now) {
        synchronized (cooldownLock) {
            cooldown.entrySet().removeIf(e -> !e.getValue().plusMinutes(COOLDOWN_MINUTES).isAfter(now));
        }
    }

    /**
     * 解析告警时间。
     *
     * <p>Wazuh 链路已经统一成 {@code yyyy-MM-dd HH:mm:ss}（见 {@code WazuhTime}），
     * 但这里额外容忍 ISO 偏移量写法：解析失败的告警会被跳过，
     * 如果上游哪天换了时间格式，症状会是"自动封禁永远为 0"——那正是这次要修的 bug，
     * 不能用一个更隐蔽的格式假设把同一个 bug 带回来。
     */
    static LocalDateTime parseAlertTime(String s) {
        if (s == null || s.isBlank()) {
            return null;
        }
        String t = s.trim();
        try {
            return LocalDateTime.parse(t, FMT);
        } catch (Exception ignore) {
            // 继续尝试 ISO 写法
        }
        try {
            return OffsetDateTime.parse(t).atZoneSameInstant(ZoneId.systemDefault()).toLocalDateTime();
        } catch (Exception ignore) {
            // 继续尝试无偏移 ISO
        }
        try {
            return LocalDateTime.parse(t);
        } catch (Exception ignore) {
            return null;
        }
    }

    /** 单个 IP 的窗口计数 */
    static final class Counts {
        int high;
        int critical;
    }
}
