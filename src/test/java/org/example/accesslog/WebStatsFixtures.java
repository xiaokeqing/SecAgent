package org.example.accesslog;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;

/**
 * 测试夹具：造"与 {@code AccessLogFilter} 真实输出字段顺序一致"的访问日志行（JSONL）。
 *
 * <p>刻意带上 {@code clientIp}（一个 IP）：公开响应必须<b>一个 IP 都没有</b> ——
 * 有了这个输入，任何"不小心把 clientIp 带出去"的改动都会被正则扫描测试抓住。
 */
public final class WebStatsFixtures {

    private WebStatsFixtures() {
    }

    public static String accessLine(OffsetDateTime ts, String method, String path, int status, String ua) {
        return accessLine(ts, method, path, status, ua, "203.0.113.9");
    }

    public static String accessLine(OffsetDateTime ts, String method, String path, int status, String ua, String clientIp) {
        return "{\"ts\":\"" + ts.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
                + "\",\"method\":\"" + esc(method)
                + "\",\"path\":\"" + esc(path)
                + "\",\"queryKeys\":\"\",\"status\":" + status
                + ",\"clientIp\":\"" + esc(clientIp)
                + "\",\"ua\":\"" + esc(ua)
                + "\",\"ms\":3,\"reqId\":\"fixture-1\"}";
    }

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
