package org.example.notify;

import org.example.core.model.AlertSeverity;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 一条"要推到手机上"的安全事件的规范化形状。
 *
 * <h3>为什么先把它做成一个类，而不是各处直接拼字符串</h3>
 * 通知内容一旦由调用点各自拼装，就会出现两种很难查的问题：
 * <ul>
 *   <li><b>同一件事有好几种写法</b>：告警说"高危告警"，封禁说"封禁失败"，
 *       而它们的等级/去重键/合并 IP 各不相同 —— 降噪规则没法统一施加；</li>
 *   <li><b>等级靠调用点手写</b>：写错不会报错，只会安静地通知错级别
 *       （例如把"自动封禁失败"写成 INFO，于是被夜间静默压制掉）。</li>
 * </ul>
 * 所以这里把"等级"和"事件类型"绑成一张固定表（见 {@link #type()} 与
 * {@link #severity()} 的默认关系），调用点只回答"发生了哪一类事"。
 *
 * <p>{@code dedupKey} 是同类事件的冷却键：同一把钥匙在冷却期内只发一次。
 * 它刻意由调用方给（而不是用标题）：标题里带 IP/时间的话，每次都是新钥匙，
 * 冷却就永远不会命中 —— 那等于没有降噪。
 */
public final class NotifyEvent {

    /** 事件类型：四类触发事件 + 发送失败（失败本身也要如实通知一次） */
    public enum Type {
        /** ① 高危告警（severity >= HIGH） */
        HIGH_ALERT("高危告警"),
        /** ② 自动封禁成功 */
        BLOCK_IP("自动封禁"),
        /** ② 自动封禁失败 —— 失败比成功更需要被看见 */
        BLOCK_FAILED("自动封禁失败"),
        /** ② 解封（到期自动解封 / 人工解封） */
        UNBLOCK_IP("解封"),
        /** ③ 系统降级（WAZUH_MODE != REAL 或 degraded=true） */
        SYSTEM_DEGRADED("系统降级"),
        /** ③ 系统恢复（降级后链路回来了，必须成对地报，否则手机上只会看到"坏了"） */
        SYSTEM_RECOVERED("系统恢复"),
        /** ④ 看门狗回滚（srv1-health-watchdog.sh 触发） */
        WATCHDOG_ROLLBACK("看门狗回滚"),
        /** 通知自身发送失败（有限次重试后仍失败） */
        NOTIFY_FAILED("通知发送失败");

        private final String label;

        Type(String label) {
            this.label = label;
        }

        public String getLabel() {
            return label;
        }
    }

    private final Type type;
    private final AlertSeverity severity;
    private final String title;
    private final String body;
    private final String dedupKey;
    private final String targetIp;
    private final String actor;
    private final LocalDateTime occurredAt;

    private NotifyEvent(Type type, AlertSeverity severity, String title, String body,
                        String dedupKey, String targetIp, String actor, LocalDateTime occurredAt) {
        this.type = type;
        this.severity = severity;
        this.title = title == null ? "" : title;
        this.body = body == null ? "" : body;
        this.dedupKey = (dedupKey == null || dedupKey.isBlank()) ? type.name() : dedupKey;
        this.targetIp = targetIp;
        // actor 留空时写"未知"，不留空 —— 留空在审计里会被读成"没有人触发"
        this.actor = (actor == null || actor.isBlank()) ? "unknown" : actor;
        this.occurredAt = (occurredAt == null) ? LocalDateTime.now() : occurredAt;
    }

    /**
     * 构造一条事件。
     *
     * @param type       四类触发事件之一（等级默认按类型给，见 {@link #defaultSeverity(Type)}）
     * @param severity   显式等级；传 null 时用该类型的默认等级
     * @param dedupKey   同类事件冷却键（建议"类型:目标:原因"这种稳定组合）
     * @param targetIp   关联 IP（用于同 IP 合并）；没有就传 null
     * @param actor      谁触发的（人工账号 / scheduler / watchdog / system）
     */
    public static NotifyEvent of(Type type, AlertSeverity severity, String title, String body,
                                 String dedupKey, String targetIp, String actor) {
        return new NotifyEvent(type, severity == null ? defaultSeverity(type) : severity,
                title, body, dedupKey, targetIp, actor, LocalDateTime.now());
    }

    /** 带发生时间的构造（告警用：告警自己的时间是上游给的，不是"now"） */
    public static NotifyEvent of(Type type, AlertSeverity severity, String title, String body,
                                 String dedupKey, String targetIp, String actor,
                                 LocalDateTime occurredAt) {
        return new NotifyEvent(type, severity == null ? defaultSeverity(type) : severity,
                title, body, dedupKey, targetIp, actor, occurredAt);
    }

    /**
     * 每类事件的默认等级 —— <b>这是"分级"的唯一事实来源</b>。
     *
     * <p>注意两处刻意的选择：
     * <ul>
     *   <li>封禁<b>失败</b>是 CRITICAL（比成功更高）：成功只是"系统按预期工作"，
     *       失败意味着"该拦的没拦住"，属于要立刻看的那种；</li>
     *   <li>系统降级是 HIGH 而不是 CRITICAL：它不直接等于"正在被攻击"，
     *       但已经是"眼睛瞎了"，必须越过夜间静默（夜间静默只压 INFO/MEDIUM）。</li>
     * </ul>
     */
    public static AlertSeverity defaultSeverity(Type type) {
        switch (type) {
            case HIGH_ALERT:
                return AlertSeverity.HIGH;
            case BLOCK_IP:
                return AlertSeverity.HIGH;
            case BLOCK_FAILED:
                return AlertSeverity.CRITICAL;
            case UNBLOCK_IP:
                return AlertSeverity.LOW;
            case SYSTEM_DEGRADED:
                return AlertSeverity.HIGH;
            case SYSTEM_RECOVERED:
                return AlertSeverity.MEDIUM;
            case WATCHDOG_ROLLBACK:
                return AlertSeverity.CRITICAL;
            case NOTIFY_FAILED:
            default:
                return AlertSeverity.HIGH;
        }
    }

    public Type type() {
        return type;
    }

    public AlertSeverity severity() {
        return severity;
    }

    public String title() {
        return title;
    }

    public String body() {
        return body;
    }

    public String dedupKey() {
        return dedupKey;
    }

    public String targetIp() {
        return targetIp;
    }

    public String actor() {
        return actor;
    }

    public LocalDateTime occurredAt() {
        return occurredAt;
    }

    /** 是否属于"同一 IP 合并窗口"的候选：没有 IP 的事件（如系统降级）不参与合并 */
    public boolean hasIp() {
        return targetIp != null && !targetIp.isBlank();
    }

    /**
     * 模板可引用的变量表。
     *
     * <p>刻意只放这些"不会泄露内部数据面"的字段：标题/正文/等级/类型/IP/时间/次数。
     * 模板是运维自己写的，一旦变量里放了内部数据，就等于给了一个"把内网数据推到公网
     * webhook"的口子 —— 而那条链路在手机上，没人会去审它。
     */
    public Map<String, String> variables(int mergeCount) {
        Map<String, String> v = new LinkedHashMap<>();
        v.put("title", title);
        v.put("body", body);
        v.put("severity", severity.name());
        v.put("severityLabel", severity.getLabel());
        v.put("type", type.name());
        v.put("typeLabel", type.getLabel());
        v.put("ip", targetIp == null ? "" : targetIp);
        v.put("actor", actor);
        v.put("time", occurredAt == null ? "" : occurredAt.toString());
        v.put("count", String.valueOf(Math.max(1, mergeCount)));
        return v;
    }

    @Override
    public String toString() {
        return "NotifyEvent{" + type + "/" + severity + " title=" + title
                + " dedupKey=" + dedupKey + " ip=" + targetIp + "}";
    }
}
