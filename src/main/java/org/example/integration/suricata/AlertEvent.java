package org.example.integration.suricata;

import org.example.core.model.SecurityAlert;

import java.time.Instant;

/**
 * event_type=alert 的告警记录。
 *
 * <p>为什么包一层而不是直接往缓冲里放 {@link SecurityAlert}：缓冲需要一个统一的
 * {@link EveEvent} 口径（带 {@link Instant}）才能和其他类型一起按时间窗过滤；
 * 告警本身的展示模型沿用现有 {@code SecurityAlert}，不另造一套字段。
 *
 * @param ts    事件时间
 * @param alert 现有告警模型（与 /api/alerts 用的是同一个类，保证口径一致）
 */
public record AlertEvent(Instant ts, SecurityAlert alert) implements EveEvent {

    @Override
    public String eventType() {
        return "alert";
    }
}
