package org.example.mcp;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 只用 JDK 自带 {@link HttpClient} 的只读上游客户端（零新增依赖）。
 *
 * <h3>两条硬边界（在构造函数里就拦，不等到请求时）</h3>
 * <ol>
 *   <li><b>只允许回环地址</b>：{@code 127.0.0.1 / localhost / ::1}。
 *       这个 MCP server 的定位是"让本机的 AI 客户端查询本机的观测数据"，
 *       base URL 一旦能指到别的机器，就等于把只读端点变成了别人的探测入口
 *       （也给"不碰 srv1/srv2"这条线留了口子）。</li>
 *   <li><b>不允许带 query / fragment</b>：路径拼接必须是确定的，防止 {@code ?x=1} 这类尾巴
 *       改写实际请求的端点。</li>
 * </ol>
 *
 * <p>超时默认 5s（{@code XK_MCP_TIMEOUT_MS} 可调）：MCP 客户端对 tools/call 的等待通常也是秒级，
 * 上游卡住时必须**快速失败成 available:false**，而不是把客户端一起挂死。
 */
public final class HttpPlatformClient implements PlatformClient {

    public static final String DEFAULT_BASE_URL = "http://127.0.0.1:9900";
    public static final int DEFAULT_TIMEOUT_MS = 5000;

    private final String baseUrl;
    private final int timeoutMs;
    private final HttpClient http;

    public HttpPlatformClient(String baseUrl, int timeoutMs) {
        this.baseUrl = normalize(baseUrl);
        this.timeoutMs = Math.max(500, timeoutMs);
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(this.timeoutMs))
                // 不跟随重定向：只读端点若返回 302，跟随就可能被引到别处去
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    /** 校验并规范化 base URL；不合法直接抛 {@link IllegalArgumentException}（启动期退出，不在请求期才发现）。 */
    public static String normalize(String raw) {
        String v = raw == null || raw.isBlank() ? DEFAULT_BASE_URL : raw.trim();
        while (v.endsWith("/")) {
            v = v.substring(0, v.length() - 1);
        }
        URI uri;
        try {
            uri = URI.create(v);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("XK_MCP_BASE_URL 不是合法 URL：" + v);
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase();
        if (!"http".equals(scheme) && !"https".equals(scheme)) {
            throw new IllegalArgumentException("XK_MCP_BASE_URL 只支持 http/https，收到：" + v);
        }
        String host = uri.getHost();
        if (host == null || !isLoopback(host)) {
            throw new IllegalArgumentException(
                    "XK_MCP_BASE_URL 只允许回环地址（127.0.0.1 / localhost / ::1），收到：" + host
                            + "。本 MCP server 只读本机观测数据，不连其他机器。");
        }
        if (uri.getQuery() != null || uri.getFragment() != null) {
            throw new IllegalArgumentException("XK_MCP_BASE_URL 不允许带 query / fragment：" + v);
        }
        return v;
    }

    static boolean isLoopback(String host) {
        String h = host.toLowerCase();
        return "127.0.0.1".equals(h) || "localhost".equals(h) || "::1".equals(h) || "[::1]".equals(h);
    }

    @Override
    public String describe() {
        return baseUrl;
    }

    @Override
    public Map<String, Object> get(String path, Map<String, String> query) throws PlatformUnavailableException {
        String url = baseUrl + (path.startsWith("/") ? path : "/" + path) + queryString(query);
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofMillis(timeoutMs))
                .header("Accept", "application/json")
                .GET()
                .build();
        HttpResponse<String> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new PlatformUnavailableException("UPSTREAM_UNAVAILABLE",
                    "连不上 " + baseUrl + "（" + rootMessage(e) + "）；平台没起或端口不通时就是这个结果", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new PlatformUnavailableException("UPSTREAM_INTERRUPTED", "请求被中断：" + url, e);
        }

        String body = response.body() == null ? "" : response.body();
        int status = response.statusCode();
        if (status >= 200 && status < 300) {
            Map<String, Object> parsed;
            try {
                parsed = Json.readObject(body);
            } catch (IOException e) {
                throw new PlatformUnavailableException("UPSTREAM_BAD_JSON",
                        "上游 HTTP " + status + " 但返回不是 JSON 对象：" + head(body));
            }
            return unwrap(parsed, status);
        }

        // 非 2xx：优先用平台自己的错误码/文案（/api/public/ip 的 400 就是 MISSING_Q / INVALID_IP / NOT_PUBLIC_IP）
        String code = "HTTP_" + status;
        String message = head(body);
        try {
            Map<String, Object> err = Json.readObject(body);
            Object c = err.get("code");
            if (c != null && !String.valueOf(c).isBlank()) {
                code = String.valueOf(c);
            }
            Object m = err.get("message");
            if (m == null) {
                m = err.get("error");
            }
            if (m != null) {
                message = String.valueOf(m);
            }
        } catch (IOException ignored) {
            // 错误体不是 JSON 就保留 HTTP 状态码 + 截断后的原文
        }
        throw new PlatformUnavailableException(code, "上游 HTTP " + status + "：" + message);
    }

    /**
     * 拆掉平台公开面的统一外壳 {@code {"code":200,"message":"success","data":{…}}}。
     *
     * <p>三条判定，都是为了"取不到就说取不到"：
     * <ol>
     *   <li>空对象 {@code {}} / 空文本 → {@code UPSTREAM_EMPTY_BODY}。「上游什么都没说」不等于「上游说没有数据」，
     *       否则工具会拿一个空壳冒充"窗口内没有告警"。</li>
     *   <li>外壳 {@code code} 不是 200/0 → 按不可用处理（平台有时用 HTTP 200 + 业务码表达失败）。</li>
     *   <li>外壳里 {@code data} 缺失或不是对象 → {@code UPSTREAM_EMPTY_BODY}。</li>
     * </ol>
     * 没有外壳的响应（例如手工调试的裸 JSON）原样返回，不做多余假设。
     */
    static Map<String, Object> unwrap(Map<String, Object> body, int status) throws PlatformUnavailableException {
        if (body == null || body.isEmpty()) {
            throw new PlatformUnavailableException("UPSTREAM_EMPTY_BODY",
                    "上游 HTTP " + status + " 但响应体是空对象/空文本");
        }
        // 平台外壳的判据：有 code（平台一定带）；或者 message + data 同时在。
        // 只看 data 不够 —— 业务失败时平台会给出 {"code":503,"message":"…"} 而没有 data。
        boolean enveloped = body.containsKey("code")
                || (body.containsKey("message") && body.containsKey("data"));
        if (!enveloped) {
            return body;
        }
        Object code = body.get("code");
        if (code != null) {
            String c = String.valueOf(code).trim();
            if (!c.isEmpty() && !"200".equals(c) && !"0".equals(c)) {
                Object message = body.get("message");
                throw new PlatformUnavailableException("UPSTREAM_" + c,
                        "上游外壳 code=" + c + "："
                                + (message == null || String.valueOf(message).isBlank() ? "（无 message）" : message));
            }
        }
        Object data = body.get("data");
        if (!(data instanceof Map<?, ?> map)) {
            throw new PlatformUnavailableException("UPSTREAM_EMPTY_BODY",
                    "上游外壳里没有 data 对象（data=" + (data == null ? "null" : data.getClass().getSimpleName()) + "）");
        }
        Map<String, Object> out = new LinkedHashMap<>();
        map.forEach((k, v) -> out.put(String.valueOf(k), v));
        if (out.isEmpty()) {
            throw new PlatformUnavailableException("UPSTREAM_EMPTY_BODY", "上游外壳里的 data 是空对象");
        }
        return out;
    }

    private static String queryString(Map<String, String> query) {
        if (query == null || query.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : new LinkedHashMap<>(query).entrySet()) {
            if (e.getKey() == null || e.getValue() == null) {
                continue;
            }
            sb.append(sb.length() == 0 ? '?' : '&')
                    .append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8))
                    .append('=')
                    .append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
        }
        return sb.toString();
    }

    private static String head(String body) {
        if (body == null) {
            return "";
        }
        String v = body.strip();
        return v.length() <= 200 ? v : v.substring(0, 200) + "…";
    }

    private static String rootMessage(Throwable t) {
        Throwable cur = t;
        while (cur.getCause() != null && cur.getCause() != cur) {
            cur = cur.getCause();
        }
        String m = cur.getMessage();
        return m == null ? cur.getClass().getSimpleName() : m;
    }
}
