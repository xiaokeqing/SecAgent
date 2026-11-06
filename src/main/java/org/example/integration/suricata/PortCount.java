package org.example.integration.suricata;

/**
 * 目标端口统计的一行：端口 + 该时间窗内的连接数。
 *
 * <p>用 record 而不是 Map：返回给前端的字段名/类型是稳定的契约，
 * Map 少拼一个键不会编译失败，排障时只能靠肉眼比对。
 */
public record PortCount(int port, long count) {
}
