package org.example.integration.wazuh;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Wazuh API 低层客户端（不做业务研判，只管"通信"）。
 *
 * <p>职责：
 * <ul>
 *   <li>用 Basic 认证（base64(user:pass)）调 GET /security/user/authenticate 换取 JWT，并缓存；</li>
 *   <li>后续请求带 Authorization: Bearer {token}；遇到 401 自动重新登录一次再重试；</li>
 *   <li>GET 拉告警 / 拉取证日志，PUT 下发 active-response；</li>
 *   <li>verify-ssl=false 时信任自签证书（本地测试常见）。</li>
 * </ul>
 *
 * <p>所有连接/超时/HTTP 错误都以 IOException 抛出，由上层 WazuhService 捕获后降级为 MOCK，
 * 保证没有真实 Wazuh 时系统照常启动、大屏用内置样本演示。
 */
public class WazuhClient {

    private static final Logger logger = LoggerFactory.getLogger(WazuhClient.class);
    private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");

    private final String baseUrl;
    private final String authHeader;   // Basic base64(user:pass)
    private final boolean verifySsl;
    private final int timeoutSeconds;
    private final ObjectMapper mapper = new ObjectMapper();

    private final OkHttpClient http;
    private volatile String cachedToken;

    public WazuhClient(String baseUrl, String username, String password,
                       boolean verifySsl, int timeoutSeconds) {
        this.baseUrl = trimTrailingSlash(baseUrl);
        this.authHeader = "Basic " + Base64.getEncoder()
                .encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
        this.verifySsl = verifySsl;
        this.timeoutSeconds = Math.max(timeoutSeconds, 3);
        this.http = buildClient();
    }

    private static String trimTrailingSlash(String s) {
        if (s == null) return "";
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    private OkHttpClient buildClient() {
        OkHttpClient.Builder b = new OkHttpClient.Builder()
                .connectTimeout(Duration.ofSeconds(timeoutSeconds))
                .readTimeout(Duration.ofSeconds(timeoutSeconds))
                .writeTimeout(Duration.ofSeconds(timeoutSeconds));
        if (!verifySsl) {
            try {
                X509TrustManager trustAll = new X509TrustManager() {
                    @Override public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) { }
                    @Override public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) { }
                    @Override public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new java.security.cert.X509Certificate[0];
                    }
                };
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, new TrustManager[]{trustAll}, new java.security.SecureRandom());
                SSLSocketFactory factory = ctx.getSocketFactory();
                b.sslSocketFactory(factory, trustAll);
                b.hostnameVerifier((hostname, session) -> true);
                logger.info("Wazuh 客户端：已关闭 SSL 证书校验（verify-ssl=false）");
            } catch (Exception e) {
                logger.warn("初始化信任所有证书的 SSL 上下文失败，将按默认校验", e);
            }
        }
        return b.build();
    }

    // ==================== 登录与 token 缓存 ====================

    /**
     * 用 Basic 认证换取 JWT。成功后缓存 token。
     * @return JWT 字符串
     * @throws IOException 连接失败/认证失败
     */
    public synchronized String login() throws IOException {
        Request req = new Request.Builder()
                .url(baseUrl + "/security/user/authenticate")
                .header("Authorization", authHeader)
                .get()
                .build();
        try (Response resp = http.newCall(req).execute()) {
            String body = readBody(resp);
            if (resp.code() != 200) {
                throw new IOException("Wazuh 登录失败 HTTP " + resp.code() + ": " + snippet(body));
            }
            JsonNode json = mapper.readTree(body);
            JsonNode tokenNode = json.path("data").path("token");
            if (tokenNode.isMissingNode() || tokenNode.asText().isEmpty()) {
                // 兼容个别版本直接返回 data 为字符串 token
                tokenNode = json.path("data");
            }
            String token = tokenNode.asText();
            if (token == null || token.isEmpty()) {
                throw new IOException("Wazuh 登录响应中未找到 token: " + snippet(body));
            }
            this.cachedToken = token;
            logger.info("Wazuh JWT 登录成功（baseUrl={}）", baseUrl);
            return token;
        }
    }

    private String token() throws IOException {
        if (cachedToken == null) {
            return login();
        }
        return cachedToken;
    }

    /** 启动期探活：尝试一次登录，成功返回 true，任何异常返回 false（不抛出）。 */
    public boolean testConnection() {
        try {
            login();
            return true;
        } catch (Exception e) {
            logger.info("Wazuh 连接测试失败（将降级为 MOCK）：{}", e.getMessage());
            return false;
        }
    }

    // ==================== 通用 GET / PUT ====================

    /**
     * 带 Bearer 的 GET。401 时清掉缓存 token 并重新登录重试一次。
     */
    public JsonNode getJson(String path) throws IOException {
        try {
            return doGet(path, false);
        } catch (UnauthorizedException e) {
            logger.info("Wazuh token 失效（401），重新登录后重试一次");
            this.cachedToken = null;
            return doGet(path, true);
        }
    }

    private JsonNode doGet(String path, boolean retried) throws IOException {
        Request req = new Request.Builder()
                .url(baseUrl + path)
                .header("Authorization", "Bearer " + token())
                .get()
                .build();
        try (Response resp = http.newCall(req).execute()) {
            String body = readBody(resp);
            if (resp.code() == 401 && !retried) {
                throw new UnauthorizedException();
            }
            if (resp.code() < 200 || resp.code() >= 300) {
                throw new IOException("Wazuh GET " + path + " 失败 HTTP " + resp.code() + ": " + snippet(body));
            }
            return mapper.readTree(body);
        }
    }

    /** 带 Bearer 的 PUT（下发 active-response），body 为任意可序列化对象。 */
    public JsonNode putJson(String path, Object bodyObj) throws IOException {
        try {
            return doPut(path, bodyObj, false);
        } catch (UnauthorizedException e) {
            this.cachedToken = null;
            return doPut(path, bodyObj, true);
        }
    }

    private JsonNode doPut(String path, Object bodyObj, boolean retried) throws IOException {
        String json = mapper.writeValueAsString(bodyObj);
        RequestBody reqBody = RequestBody.create(json, JSON);
        Request req = new Request.Builder()
                .url(baseUrl + path)
                .header("Authorization", "Bearer " + token())
                .put(reqBody)
                .build();
        try (Response resp = http.newCall(req).execute()) {
            String body = readBody(resp);
            if (resp.code() == 401 && !retried) {
                throw new UnauthorizedException();
            }
            if (resp.code() < 200 || resp.code() >= 300) {
                throw new IOException("Wazuh PUT " + path + " 失败 HTTP " + resp.code() + ": " + snippet(body));
            }
            return mapper.readTree(body);
        }
    }

    // ==================== 业务接口封装 ====================

    /**
     * 拉取近期告警。Wazuh 4.x 告警接口返回结构可能是
     * {data:{affected_items:[...]}} 或 {data:[...]}，这里两种都兼容。
     */
    public JsonNode fetchAlerts(int limit) throws IOException {
        String path = "/security/alerts?limit=" + Math.max(1, limit) + "&sort=-timestamp";
        return getJson(path);
    }

    /** 拉取 manager 日志（取证用）。 */
    public JsonNode fetchManagerLogs(String query, int limit) throws IOException {
        StringBuilder path = new StringBuilder("/manager/logs?limit=" + Math.max(1, limit));
        if (query != null && !query.isBlank()) {
            // q 参数：Wazuh 日志查询关键字
            path.append("&q=").append(java.net.URLEncoder.encode(query.trim(), StandardCharsets.UTF_8));
        }
        return getJson(path.toString());
    }

    /**
     * 下发 active-response（例如 firewall-drop 封 IP）。
     * Wazuh active-response 请求体：{command, agents:[agentId], arguments:{...}}
     */
    public JsonNode sendActiveResponse(String command, Map<String, Object> arguments) throws IOException {
        Map<String, Object> payload = new ConcurrentHashMap<>();
        payload.put("command", command);
        Object agentId = arguments.get("agentid");
        payload.put("agents", agentId != null
                ? new String[]{String.valueOf(agentId)} : new String[]{"000"});
        Map<String, Object> args = new ConcurrentHashMap<>(arguments);
        args.remove("agentid");
        payload.put("arguments", args);
        return putJson("/active-response", payload);
    }

    // ==================== 工具 ====================

    private String readBody(Response resp) throws IOException {
        ResponseBody rb = resp.body();
        if (rb == null) return "";
        return rb.string();
    }

    private static String snippet(String s) {
        if (s == null) return "";
        s = s.trim();
        return s.length() > 300 ? s.substring(0, 300) + "..." : s;
    }

    private static class UnauthorizedException extends IOException {
    }
}
