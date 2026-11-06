package org.example.integration.suricata;

import java.time.Instant;
import java.util.List;

/**
 * event_type=dns 的 DNS 查询记录。
 *
 * <p>answers 保留成可读字符串（"rrname rrtype rdata"）而不是原样嵌套对象：
 * 反查只需要"这个域名解析到了什么"，ttl 之类的字段对安全研判没有增量信息，
 * 保留成结构体只会让 50000 条缓冲多占一倍内存。
 *
 * @param ts     事件时间
 * @param srcIp  查询方 IP
 * @param destIp DNS 服务器 IP
 * @param rrname 被查询的域名
 * @param rrtype 查询类型（A / AAAA / CNAME …）
 * @param rcode  响应码（NOERROR / NXDOMAIN …）
 * @param answers 应答记录，元素形如 "example.com A 93.184.216.34"
 */
public record DnsEvent(
        Instant ts,
        String srcIp,
        String destIp,
        String rrname,
        String rrtype,
        String rcode,
        List<String> answers
) implements EveEvent {

    @Override
    public String eventType() {
        return "dns";
    }
}
