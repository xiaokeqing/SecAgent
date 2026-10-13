package org.example.notify;

import org.example.core.model.AlertSeverity;
import org.example.core.model.SecurityAlert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 领域侧的通知门面：把"发生了什么事"翻译成 {@link NotifyEvent}。
 *
 * <h3>为什么不让各处直接注入 {@link NotificationService}</h3>
 * 一来通知的触发点有四处（告警轮询 / 处置 / 降级 / 看门狗），每处都自己拼标题、
 * 自己定等级、自己想去重键 —— 迟早出现"同一类事在两个地方是两种等级"；
 * 二来这里还要承担两件<b>不该让通用通知服务知道</b>的事：
 * <ul>
 *   <li>告警侧的<b>已通知集合</b>（避免同一条告警每次轮询都推一遍）；</li>
 *   <li>"不要为已经封掉的 IP 再刷通知"这类业务判断。</li>
 * </ul>
 *
 * <p>所有方法都<b>不抛异常</b>：通知是旁路，它出问题不能让研判/处置失败。
 */
public class SecurityEventNotifier {

    private static final Logger logger = LoggerFactory.getLogger(SecurityEventNotifier.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /** 已推送过的告警 id（有界：只留最近这些，防止长期运行吃内存） */
    private static final int SEEN_LIMIT = 2000;

    private final NotificationService notify;

    private final Map<String, Boolean> seenAlertIds = new ConcurrentHashMap<>();

    /** 已封禁的 IP —— 用来跳过"已被处置的源"这类重复告警 */
    private final Set<String> blockedIps = ConcurrentHashMap.newKeySet();

    public SecurityEventNotifier(NotificationService notify) {
        this.notify = notify;
    }

    /**
     * ① 高危告警：把最近一批告警里<b>新出现的 severity >= HIGH</b> 逐条推出去。
     *
     * <p>"新出现"是按告警 id 判定的，而且 id 一旦推过就记住 —— 否则轮询端点每秒都在跑，
     * 同一条高危告警会变成每轮一条推送，手机上就是刷屏。
     *
     * @param alerts  候选告警（调用方负责保证这是真实数据，不含内置样本）
     * @param trigger 触发来源（如 {@code poller} / {@code watchdog}），写进审计
     * @return 本次真正交给通知中枢的条数
     */
    public int highSeverityAlerts(Iterable<SecurityAlert> alerts, String trigger) {
        if (alerts == null || notify == null) {
            return 0;
        }
        int submitted = 0;
        try {
            for (SecurityAlert a : alerts) {
                if (a == null) {
                    continue;
                }
                AlertSeverity sev = a.getSeverity();
                if (sev == null || sev.getRank() < AlertSeverity.HIGH.getRank()) {
                    continue;
                }
                String id = (a.getId() == null || a.getId().isBlank())
                        ? (String.valueOf(a.getRuleName()) + "|" + String.valueOf(a.getOccurredAt()))
                        : a.getId();
                if (seenAlertIds.putIfAbsent(id, Boolean.TRUE) != null) {
                    continue;      // 已经推过
                }
                trimSeen();
                // 已经被封禁的源不再重复推送：处置完还在推，只会训练人忽略通知
                if (a.getSrcIp() != null && blockedIps.contains(a.getSrcIp().trim())) {
                    logger.debug("告警源 {} 已封禁，跳过重复通知（alertId={}）", a.getSrcIp(), id);
                    continue;
                }
                LocalDateTime at = parseTime(a.getOccurredAt());
                NotifyEvent e = NotifyEvent.of(NotifyEvent.Type.HIGH_ALERT, sev,
                        "[" + sev.getLabel() + "] " + safe(a.getTitle()),
                        "规则=" + safe(a.getRuleName())
                                + "；来源=" + safe(a.getSrcIp())
                                + (a.getDstAsset() == null || a.getDstAsset().isBlank() ? "" : "；资产=" + safe(a.getDstAsset()))
                                + "；时间=" + safe(a.getOccurredAt())
                                + "；触发=" + safe(trigger),
                        "alert:" + id, a.getSrcIp(), "system", at);
                notify.send(e);
                submitted++;
            }
        } catch (Exception ex) {
            logger.error("高危告警通知失败（已吞掉，不影响告警接口）：{}", ex.toString());
        }
        return submitted;
    }

    /** ② 自动封禁：成功 / 失败都通知（失败等级更高） */
    public void blockIp(String ip, boolean success, String mode, String reason, String actor, int durationMinutes) {
        if (notify == null) {
            return;
        }
        try {
            if (success && ip != null) {
                blockedIps.add(ip.trim());
            }
            NotifyEvent.Type type = success ? NotifyEvent.Type.BLOCK_IP : NotifyEvent.Type.BLOCK_FAILED;
            String title = success
                    ? "自动封禁成功：" + safe(ip)
                    : "自动封禁失败：" + safe(ip);
            String body = "模式=" + safe(mode)
                    + "；时长=" + durationMinutes + "min"
                    + "；原因=" + safe(reason)
                    + "；执行者=" + safe(actor)
                    + "；时间=" + LocalDateTime.now().format(FMT);
            // 去重键刻意不含时间：同一个 IP 反复封禁失败属于"持续故障"，
            // 冷却期（默认 5 分钟）内只该看一次，而不是每个请求推一条
            notify.send(NotifyEvent.of(type, null, title, body,
                    "block:" + (success ? "ok:" : "fail:") + safe(ip), ip, actor));
        } catch (Exception e) {
            logger.error("封禁通知失败（已吞掉）：{}", e.toString());
        }
    }

    /** ② 解封（到期自动解封 / 人工解封）：低等级，夜间会被静默 */
    public void unblockIp(String ip, String mode, String actor) {
        if (notify == null) {
            return;
        }
        try {
            if (ip != null) {
                blockedIps.remove(ip.trim());
            }
            notify.send(NotifyEvent.of(NotifyEvent.Type.UNBLOCK_IP, AlertSeverity.LOW,
                    "已解封：" + safe(ip),
                    "模式=" + safe(mode) + "；时间=" + LocalDateTime.now().format(FMT),
                    "unblock:" + safe(ip), ip, actor));
        } catch (Exception e) {
            logger.error("解封通知失败（已吞掉）：{}", e.toString());
        }
    }

    /**
     * ③ 系统降级 / 恢复。
     *
     * <p>做成成对的通知而不是只报"坏了"：只看得到坏消息的通道，
     * 久了会被当成常态噪声（"反正一直在报警"）。恢复也要说一声。
     */
    public void systemDegraded(boolean degraded, String mode, String detail) {
        if (notify == null) {
            return;
        }
        try {
            if (degraded) {
                notify.send(NotifyEvent.of(NotifyEvent.Type.SYSTEM_DEGRADED, null,
                        "系统降级：数据源不再是 REAL（当前 " + safe(mode) + "）",
                        "详情=" + safe(detail)
                                + "；影响=告警大屏与公网端点会如实显示「数据源不可用」，不以内置样本顶替"
                                + "；时间=" + LocalDateTime.now().format(FMT),
                        "degraded:" + safe(mode), null, "system"));
            } else {
                notify.send(NotifyEvent.of(NotifyEvent.Type.SYSTEM_RECOVERED, null,
                        "系统已恢复：数据源回到 REAL（" + safe(mode) + "）",
                        "详情=" + safe(detail) + "；时间=" + LocalDateTime.now().format(FMT),
                        "recovered:" + safe(mode), null, "system"));
            }
        } catch (Exception e) {
            logger.error("降级通知失败（已吞掉）：{}", e.toString());
        }
    }

    /** ④ 看门狗回滚（由 srv1-health-watchdog.sh 经本地端点触发） */
    public void watchdogRollback(String commitFrom, String commitTo, String reason, String actor) {
        if (notify == null) {
            return;
        }
        try {
            notify.send(NotifyEvent.of(NotifyEvent.Type.WATCHDOG_ROLLBACK, null,
                    "看门狗已回滚：" + safe(shortSha(commitFrom)) + " → " + safe(shortSha(commitTo)),
                    "原因=" + safe(reason)
                            + "；触发者=" + safe(actor)
                            + "；时间=" + LocalDateTime.now().format(FMT),
                    // 回滚是稀有事件，去重键按目标提交：同一目标重复回滚只推一次
                    "rollback:" + safe(commitTo), null, actor));
        } catch (Exception e) {
            logger.error("看门狗回滚通知失败（已吞掉）：{}", e.toString());
        }
    }

    /**
     * ③ 从"数据源模式"推降级事件（供接口轮询这类没有状态机的调用点使用）。
     *
     * <p>它自己记上一次的模式，于是"降级→恢复→再降级"每次都会通知一次；
     * 而持续处于同一状态时不会重复推送（去重键 + 冷却双保险）。
     *
     * @return true 表示模式发生了变化
     */
    private volatile String lastMode = null;

    public boolean observeMode(String mode) {
        String m = (mode == null || mode.isBlank()) ? "UNKNOWN" : mode.trim();
        String prev = lastMode;
        lastMode = m;
        if (prev == null) {
            return false;      // 首次只记录，不通知（启动时的初始值不是"变化"）
        }
        if (prev.equals(m)) {
            return false;
        }
        systemDegraded(!"REAL".equalsIgnoreCase(m), m, "模式由 " + prev + " 变为 " + m);
        return true;
    }

    /** 供接口如实回话：当前已记住多少条已推送告警 / 已封禁 IP */
    public Map<String, Object> stateSummary() {
        return Map.of(
                "seenAlerts", seenAlertIds.size(),
                "blockedIps", blockedIps.size(),
                "lastMode", lastMode == null ? "UNKNOWN" : lastMode);
    }

    /** 单测用：清空"已推送"记忆 */
    void resetSeen() {
        seenAlertIds.clear();
    }

    Set<String> seenIds() {
        return new HashSet<>(seenAlertIds.keySet());
    }

    private void trimSeen() {
        if (seenAlertIds.size() <= SEEN_LIMIT) {
            return;
        }
        // 简单粗暴地砍掉一半：这里不需要精确 LRU，只需要"不无限长"
        int drop = seenAlertIds.size() / 2;
        for (String k : seenAlertIds.keySet()) {
            if (drop-- <= 0) {
                break;
            }
            seenAlertIds.remove(k);
        }
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }

    private static String shortSha(String s) {
        if (s == null || s.isBlank()) {
            return "unknown";
        }
        String t = s.trim();
        return t.length() > 7 ? t.substring(0, 7) : t;
    }

    private static LocalDateTime parseTime(String s) {
        if (s == null || s.isBlank()) {
            return null;
        }
        try {
            return LocalDateTime.parse(s.trim(), FMT);
        } catch (Exception e) {
            return null;
        }
    }
}
