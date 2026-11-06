package org.example.integration.suricata;

/**
 * SNI 统计的一行：域名 + 该时间窗内出现的次数。
 *
 * <p>与 {@link Ja3Count} 分开定义（而不是共用一个 StringCount），
 * 是为了让接口签名自己说清"这一列是域名、那一列是 JA3"，读代码时不用回头查注释。
 */
public record SniCount(String sni, long count) {
}
