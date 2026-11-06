package org.example.integration.suricata;

import java.time.Instant;

/**
 * event_type=http 的 HTTP 事务记录。
 *
 * <p>只留"反查与统计真的会用"的字段：hostname / url / method / status / UA。
 * 请求头、请求体一概不进内存 —— eve.json 本身可能带认证头，而这块缓冲是为了查询，
 * 不是为了取证；把原文全量留在内存里既费内存又多一份泄露面。
 *
 * @param ts        事件时间
 * @param srcIp     客户端 IP
 * @param destIp    服务端 IP
 * @param hostname  Host 头（可能为空）
 * @param url       请求 URL
 * @param method    HTTP 方法
 * @param status    响应状态码，未知为 0
 * @param userAgent User-Agent（eve.json 里字段名是 http.http_user_agent）
 */
public record HttpEvent(
        Instant ts,
        String srcIp,
        String destIp,
        String hostname,
        String url,
        String method,
        int status,
        String userAgent
) implements EveEvent {

    @Override
    public String eventType() {
        return "http";
    }
}
