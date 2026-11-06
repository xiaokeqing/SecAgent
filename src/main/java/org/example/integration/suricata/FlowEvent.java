package org.example.integration.suricata;

import java.time.Instant;

/**
 * event_type=flow / netflow 的连接记录。
 *
 * <p>为什么把 netflow 也收进这个记录：Suricata 7 的 netflow 事件就是"一条连接的五元组 + 流量统计"，
 * 与 flow 事件字段高度重合，反查（按 IP 找连接）时需要两者一起看。用 {@code eventType}
 * 区分来源，避免把两种日志形状硬拆成两套几乎一样的查询代码。
 *
 * <p>字节/包数只认 {@code flow.*}（分 toserver/toclient 两个方向）。netflow 事件只有一个合计值，
 * 把合计塞进 toserver 属于口径造假，这里宁可留 0 —— 缺字段能看出来，"方向搞反的字节数"看不出来。
 *
 * @param eventType      "flow" 或 "netflow"
 * @param ts             eve.json 顶层 timestamp
 * @param srcIp          源 IP
 * @param srcPort        源端口（未知为 0）
 * @param destIp         目的 IP
 * @param destPort       目的端口（未知为 0）
 * @param proto          传输层协议，如 TCP / UDP
 * @param appProto       应用层协议，如 http / tls / dns
 * @param bytesToServer  客户端→服务端字节数
 * @param bytesToClient  服务端→客户端字节数
 * @param pktsToServer   客户端→服务端包数
 * @param pktsToClient   服务端→客户端包数
 * @param flowStart      连接开始时间
 * @param flowEnd        连接结束时间
 */
public record FlowEvent(
        String eventType,
        Instant ts,
        String srcIp,
        int srcPort,
        String destIp,
        int destPort,
        String proto,
        String appProto,
        long bytesToServer,
        long bytesToClient,
        long pktsToServer,
        long pktsToClient,
        Instant flowStart,
        Instant flowEnd
) implements EveEvent {
}
