package org.example.integration.suricata;

import java.time.Instant;

/**
 * eve.json 中一条被收纳的事件（轻量视图，不保留原始 JSON 行）。
 *
 * <p>为什么按 event_type 分成多个记录，而不是一个"大而全"的类：
 * http 有 url、tls 有 sni、flow 有字节数，这些字段互不相干。塞进同一个类只会得到一堆
 * 恒为 null 的字段，查询时也分不清"这条事件没有这个字段"和"这个字段恰好为空"。
 * 分类型之后，反查逻辑只处理自己认识的类型（{@code instanceof}），不会误读别的类型。
 *
 * <p>时间统一用 {@link Instant}：eve.json 的 timestamp 带时区偏移，
 * 而"最近 N 分钟"是绝对时间窗，用字符串比较会在跨时区/跨格式时静默出错。
 */
public interface EveEvent {

    /** 对应 eve.json 的 event_type（alert / flow / netflow / http / dns / tls）。 */
    String eventType();

    /** 事件时间；解析失败时为 null（调用方按"时间未知"处理，不编造当前时间）。 */
    Instant ts();
}
