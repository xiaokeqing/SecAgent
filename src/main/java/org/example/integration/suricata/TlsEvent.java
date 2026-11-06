package org.example.integration.suricata;

import java.time.Instant;

/**
 * event_type=tls 的 TLS 握手记录（SNI / JA3 / JA3S / 证书指纹）。
 *
 * <p>为什么单独留 ja3 与 ja3s：JA3 是客户端指纹、JA3S 是服务端指纹，两者混用会让
 * "同一套恶意客户端打不同站点"这种画像失效 —— 统计接口里只统计 ja3.hash，ja3s 仅供单条连接查看。
 *
 * @param ts          事件时间
 * @param srcIp       客户端 IP
 * @param destIp      服务端 IP
 * @param destPort    服务端端口
 * @param sni         TLS SNI（明文域名，可能为空）
 * @param version     TLS 版本，如 TLSv1.2 / TLSv1.3
 * @param ja3Hash     客户端 JA3 指纹
 * @param ja3sHash    服务端 JA3S 指纹
 * @param fingerprint 证书指纹（tls.fingerprint，部分版本是数组，取第一条）
 */
public record TlsEvent(
        Instant ts,
        String srcIp,
        String destIp,
        int destPort,
        String sni,
        String version,
        String ja3Hash,
        String ja3sHash,
        String fingerprint
) implements EveEvent {

    @Override
    public String eventType() {
        return "tls";
    }
}
