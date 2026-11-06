package org.example.integration.suricata;

/**
 * JA3 客户端指纹统计的一行：指纹 + 该时间窗内出现的次数。
 *
 * <p>只统计 {@code tls.ja3.hash}，不含 JA3S：两者含义不同，混在一张榜里会让
 * "同一客户端指纹回连多个站点"这类画像被服务端指纹冲散。
 */
public record Ja3Count(String ja3, long count) {
}
