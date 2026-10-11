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

    /**
     * Wazuh indexer（OpenSearch）地址与凭据。
     *
     * <h3>为什么需要第二个地址</h3>
     * 告警【不在 Wazuh 管理 API 里】。管理 API（55000）提供的是
     * agents / manager 日志 / active-response 这些运维接口，
     * <b>没有任何查询告警的端点</b> —— 实测 {@code /security/alerts}
     * 返回 404，而这个项目原来的代码正是在调它，
     * 所以"真实告警"从来没取到过，界面上显示的永远是内置样本。
     * <p>
     * 告警实际存在 indexer（OpenSearch，9200）的
     * {@code wazuh-alerts-*} 索引里。要拿真实数据，必须查那里。
     */
    private final String indexerUrl;
    private final String indexerAuthHeader;
    private final OkHttpClient indexerHttp;

    private final OkHttpClient http;
    private volatile String cachedToken;

    public WazuhClient(String baseUrl, String username, String password,
                       boolean verifySsl, int timeoutSeconds) {
        this(baseUrl, username, password, verifySsl, timeoutSeconds, null, null, null);
    }

    /**
     * 完整构造：额外给出 indexer 地址与凭据。
     *
     * @param indexerUrl      形如 https://wazuh-indexer:9200；为 null 表示不接真实告警
     * @param indexerUser     indexer 用户名
     * @param indexerPassword indexer 口令
     */
    public WazuhClient(String baseUrl, String username, String password,
                       boolean verifySsl, int timeoutSeconds,
                       String indexerUrl, String indexerUser, String indexerPassword) {
        this.baseUrl = trimTrailingSlash(baseUrl);
        this.authHeader = "Basic " + Base64.getEncoder()
                .encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
        this.verifySsl = verifySsl;
        this.timeoutSeconds = Math.max(timeoutSeconds, 3);
        this.http = buildClient();

        this.indexerUrl = (indexerUrl == null || indexerUrl.isBlank())
                ? null : trimTrailingSlash(indexerUrl.trim());
        this.indexerAuthHeader = (indexerUser == null)
                ? null
                : "Basic " + Base64.getEncoder()
                        .encodeToString((indexerUser + ":" + (indexerPassword == null ? "" : indexerPassword))
                                .getBytes(StandardCharsets.UTF_8));
        this.indexerHttp = (this.indexerUrl == null) ? null : buildClient();
        if (this.indexerUrl != null) {
            logger.info("Wazuh 告警改用 indexer 查询：{}", this.indexerUrl);
        } else {
            logger.warn("未配置 Wazuh indexer 地址 —— 无法获取真实告警，将使用内置样本");
        }
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

    /**
     * indexer（<b>告警真正的存放处</b>）是否可达且凭据有效。
     *
     * <h3>为什么探测必须包含它</h3>
     * {@link #testConnection()} 只登录管理 API（55000），而告警<b>不在管理 API 里</b>
     * —— 那个查询端点根本不存在。于是会出现这种最坏的情况：
     * 管理 API 通了 → 模式报 REAL，但取告警的链路（独立端口 9200、独立凭据）坏了，
     * 页面就变成"有模式、没数据"，而且看不出来是哪一端的问题。
     * <p>
     * 判据必须覆盖<b>实际用到的那条链路</b>，否则它只是一个安慰性的绿灯。
     *
     * @return true 表示 indexer 可达且鉴权通过；未配置时返回 false
     *         （未配置 indexer 就等于没有真实告警来源，不该报 REAL）
     */
    public boolean indexerReachable() {
        if (indexerUrl == null || indexerHttp == null) {
            logger.info("未配置 Wazuh indexer 地址，真实告警来源不存在");
            return false;
        }
        Request req = new Request.Builder()
                .url(indexerUrl + "/")
                .header("Authorization", indexerAuthHeader != null ? indexerAuthHeader : authHeader)
                .get()
                .build();
        try (Response resp = indexerHttp.newCall(req).execute()) {
            boolean ok = resp.isSuccessful();
            if (!ok) {
                logger.info("Wazuh indexer 探测失败：HTTP {}（{}）", resp.code(), indexerUrl);
            }
            return ok;
        } catch (IOException e) {
            logger.info("Wazuh indexer 探测异常：{}（{}）", e.getMessage(), indexerUrl);
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
     * 拉取近期告警 —— <b>从 indexer（OpenSearch）查，不是从管理 API</b>。
     *
     * <h3>这里修的是一个长期存在的根本性 bug</h3>
     * 原实现调 {@code GET /security/alerts}。<b>这个端点在 Wazuh 里不存在</b>
     * （实测返回 404，管理 API 也没有任何查询告警的端点）。
     * 后果是：连接明明成功（隧道通、JWT 登录成功、mode 显示 REAL），
     * 但每次取告警都抛异常 → 上层 catch 里回退到内置样本 →
     * <b>界面上显示的告警从头到尾都是假的</b>。
     * <p>
     * 而"假数据看起来很像真的"（SSH 暴力破解、SQL 注入、Webshell……），
     * 所以这个 bug 藏了很久才被发现。
     * <p>
     * 告警的真实位置：indexer 的 {@code wazuh-alerts-*} 索引。
     * 返回结构是 OpenSearch 的 <code>{hits:{hits:[{_source:{...}}]}}</code>，
     * 和原来按 Wazuh API 结构解析的代码不兼容 —— 上层 mapRealAlerts
     * 已经相应加了 _source 的处理。
     *
     * @param limit 最多返回多少条
     * @return OpenSearch 的 _search 响应
     * @throws IOException indexer 不可达或未配置
     */
    public JsonNode fetchAlerts(int limit) throws IOException {
        if (indexerUrl == null || indexerHttp == null) {
            throw new IOException("未配置 Wazuh indexer 地址（integration.wazuh.indexer-url）—— "
                    + "告警不在管理 API 里，必须从 indexer 查询");
        }
        int size = Math.max(1, limit);
        // 排序用 @timestamp：Wazuh 写入 indexer 时就是这么命名的
        String path = "/wazuh-alerts-*/_search?size=" + size + "&sort=@timestamp:desc";
        Request req = new Request.Builder()
                .url(indexerUrl + path)
                .header("Authorization", indexerAuthHeader != null ? indexerAuthHeader : authHeader)
                .get()
                .build();
        try (Response resp = indexerHttp.newCall(req).execute()) {
            String body = resp.body() != null ? resp.body().string() : "";
            if (!resp.isSuccessful()) {
                throw new IOException("indexer 查询告警失败 HTTP " + resp.code() + ": " + snippet(body));
            }
            return mapper.readTree(body);
        }
    }

    /**
     * 近 24 小时告警概览：总数 + 按等级分档 + 每小时趋势（一次聚合查询拿全）。
     *
     * <h3>为什么需要它</h3>
     * 告警流取的是"最新 N 条"。网络侧的低危告警一旦刷屏，
     * 严重/高危就被挤到窗口之外 —— 面板上会显示「严重 0 / 高危 0」，
     * 让人以为没出事，实际上只是口径被噪声挤掉了。
     * 时间窗口口径必须由<b>按时间范围聚合</b>来回答，不能靠"取最新几条"推断。
     *
     * @return OpenSearch 的 _search 响应（size=0，只有聚合结果）
     */
    public JsonNode fetchSummary24h() throws IOException {
        if (indexerUrl == null || indexerHttp == null) {
            throw new IOException("未配置 Wazuh indexer 地址（integration.wazuh.indexer-url）");
        }
        String body = "{\"size\":0,"
                + "\"query\":{\"bool\":{\"filter\":[{\"range\":{\"@timestamp\":{\"gte\":\"now-24h\"}}}]}},"
                + "\"aggs\":{"
                + "\"by_level\":{\"terms\":{\"field\":\"rule.level\",\"size\":20}},"
                + "\"by_hour\":{\"date_histogram\":{\"field\":\"@timestamp\",\"fixed_interval\":\"1h\","
                + "\"min_doc_count\":0,\"extended_bounds\":{\"min\":\"now-24h\",\"max\":\"now\"}}}}}";

        Request req = new Request.Builder()
                .url(indexerUrl + "/wazuh-alerts-*/_search")
                .header("Authorization", indexerAuthHeader != null ? indexerAuthHeader : authHeader)
                .post(RequestBody.create(body, JSON))
                .build();
        try (Response resp = indexerHttp.newCall(req).execute()) {
            String respBody = resp.body() != null ? resp.body().string() : "";
            if (!resp.isSuccessful()) {
                throw new IOException("indexer 24h 聚合查询失败 HTTP " + resp.code() + ": " + snippet(respBody));
            }
            return mapper.readTree(respBody);
        }
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
