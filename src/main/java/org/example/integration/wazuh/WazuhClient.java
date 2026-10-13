package org.example.integration.wazuh;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.example.config.OutboundTimeouts;
import org.example.llm.OutboundGuard;
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
import java.util.concurrent.Callable;
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
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * 统一出站超时（connect 3s / read 12s / call 15s）。
     *
     * <p>以前这里只有一个 {@code timeoutSeconds}，三项共用且来源是
     * {@code integration.wazuh.timeout} —— 与 LLM 通道的 15s/8s 各说各话，
     * 外部依赖挂起时会拖住请求线程。现在改成显式声明、可被启动自检核对的值。
     */
    private final OutboundTimeouts timeouts;

    /** 出站守卫（有界等待 + 熔断冷却 + 半开）；为 null 时退化为"仅传输层超时"（单测/旧构造） */
    private final OutboundGuard guard;

    /** 依赖标识：管理 API 与 indexer 分开计冷却，互不拖累 */
    public static final String DEP_API = "wazuh-api";
    public static final String DEP_INDEXER = "wazuh-indexer";

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

    /** 旧构造：三项超时同为 timeoutSeconds（保留兼容，内部走统一默认值语义） */
    public WazuhClient(String baseUrl, String username, String password,
                       boolean verifySsl, int timeoutSeconds) {
        this(baseUrl, username, password, verifySsl,
                new OutboundTimeouts(timeoutSeconds * 1000L, timeoutSeconds * 1000L, timeoutSeconds * 1000L),
                null, null, null, null);
    }

    /**
     * 完整构造（统一超时 + 出站守卫）。
     *
     * @param timeouts        统一出站超时（connect/read/call）
     * @param guard           出站守卫；为 null 表示不启用有界等待与冷却（单测用）
     * @param indexerUrl      形如 https://wazuh-indexer:9200；为 null 表示不接真实告警
     * @param indexerUser     indexer 用户名
     * @param indexerPassword indexer 口令
     */
    public WazuhClient(String baseUrl, String username, String password,
                       boolean verifySsl, OutboundTimeouts timeouts, OutboundGuard guard,
                       String indexerUrl, String indexerUser, String indexerPassword) {
        this.baseUrl = trimTrailingSlash(baseUrl);
        this.authHeader = "Basic " + Base64.getEncoder()
                .encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
        this.verifySsl = verifySsl;
        this.timeouts = (timeouts == null) ? OutboundTimeouts.defaults() : timeouts;
        this.guard = guard;
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
            logger.info("Wazuh 告警改用 indexer 查询：{}（{}）", this.indexerUrl, this.timeouts.describe());
        } else {
            logger.warn("未配置 Wazuh indexer 地址 —— 无法获取真实告警，将使用内置样本");
        }
    }

    /** 统一超时的实际生效值（供启动自检核对） */
    public OutboundTimeouts effectiveTimeouts() {
        return timeouts;
    }

    /** 出站守卫是否接入（false 表示只有传输层超时，没有冷却/半开） */
    public boolean guardEnabled() {
        return guard != null;
    }

    private static String trimTrailingSlash(String s) {
        if (s == null) return "";
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    private OkHttpClient buildClient() {
        // callTimeout 与总预算一致：兜住"读超时之上还有重试/重定向"的情况，
        // 保证单次调用绝不会超过入口预算。
        OkHttpClient.Builder b = new OkHttpClient.Builder()
                .connectTimeout(Duration.ofMillis(timeouts.getConnectTimeoutMs()))
                .readTimeout(Duration.ofMillis(timeouts.getReadTimeoutMs()))
                .writeTimeout(Duration.ofMillis(timeouts.getReadTimeoutMs()))
                .callTimeout(Duration.ofMillis(timeouts.getCallTimeoutMs()));
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

    /**
     * 出站调用的统一收口：<b>传输层超时之上再套一层有界等待 + 熔断冷却</b>。
     *
     * <h3>为什么两层都要</h3>
     * <ul>
     *   <li>OkHttp 的 connect/read/callTimeout 管的是"这一次 HTTP 调用"；</li>
     *   <li>{@link OutboundGuard} 管的是"调用方最多等多久 + 故障后不再反复等"
     *       —— 一次超时后该依赖进入 60s 冷却，期间立即失败，
     *       避免一次请求里每个调用点各等一遍（实测过 15s+15s+15s 叠加）。</li>
     * </ul>
     * 超时/冷却抛出的信息里带"超时/冷却"，{@link OutboundGuard#isUnavailable} 可据此判定，
     * 上层照旧走 fail-closed 降级（MOCK / 数据源不可用），不会静默成功。
     */
    private <T> T bounded(String dependency, Callable<T> call) throws IOException {
        if (guard == null) {
            try {
                return call.call();
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                throw new IOException("出站调用失败（依赖=" + dependency + "）：" + e.getMessage(), e);
            }
        }
        try {
            return guard.call(dependency, timeouts.getCallTimeoutMs(), call);
        } catch (IOException e) {
            // 传输层失败（连不上/读超时/DNS 失败）也要打开冷却：
            // 实测 read timeout(12s) 会先于守卫的 callTimeout(15s) 触发，
            // 若只靠守卫自己的超时来开熔断，60s 冷却就永远不会生效 ——
            // 表现是"依赖已经挂了，每个请求还要各等 12 秒"。
            if (guard != null && isConnectivityFailure(e)) {
                guard.openCircuit(dependency);
                logger.warn("依赖 {} 传输层失败（{}），打开熔断冷却：{}",
                        dependency, e.getClass().getSimpleName(), e.getMessage());
            }
            throw e;
        } catch (RuntimeException e) {
            // 超时/冷却：保留 IllegalStateException 的类型与文案（含"超时/冷却"），
            // 上层与 OutboundGuard.isUnavailable 的判定都依赖这段文案
            throw e;
        } catch (Exception e) {
            throw new IOException("出站调用失败（依赖=" + dependency + "）：" + e.getMessage(), e);
        }
    }

    /**
     * 是否属于"连接层失败"（而不是对端明确回了错误码）。
     *
     * <p>刻意只认这几类：HTTP 4xx/5xx 是"服务在、但拒绝"，不该把依赖整体熔断；
     * 而连不上、读超时、DNS 解析失败意味着"这条链路现在不通"，应当立刻冷却。
     */
    private static boolean isConnectivityFailure(IOException e) {
        if (e instanceof java.net.UnknownHostException
                || e instanceof java.net.SocketException          // 含 ConnectException / NoRouteToHost / reset
                || e instanceof java.io.InterruptedIOException) { // 含 SocketTimeoutException
            return true;
        }
        // OkHttp 在部分路径上会把原因包一层
        Throwable cause = e.getCause();
        return cause instanceof IOException
                && (cause instanceof java.net.UnknownHostException
                    || cause instanceof java.net.SocketException
                    || cause instanceof java.io.InterruptedIOException);
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
        try (Response resp = bounded(DEP_API, () -> http.newCall(req).execute())) {
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
        try (Response resp = bounded(DEP_INDEXER, () -> indexerHttp.newCall(req).execute())) {
            boolean ok = resp.isSuccessful();
            if (!ok) {
                logger.info("Wazuh indexer 探测失败：HTTP {}（{}）", resp.code(), indexerUrl);
            }
            return ok;
        } catch (Exception e) {
            // 探活必须"什么失败都不抛"：除了 IOException，超时/冷却这类
            // 有界等待的结果是 IllegalStateException —— 之前只 catch IOException，
            // 加了 OutboundGuard 之后它就会穿出去，把"探活失败"变成"重新探测异常"。
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
        try (Response resp = bounded(DEP_API, () -> http.newCall(req).execute())) {
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
        try (Response resp = bounded(DEP_API, () -> http.newCall(req).execute())) {
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
        try (Response resp = bounded(DEP_INDEXER, () -> indexerHttp.newCall(req).execute())) {
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
        String body = "{\"size\":0,\"track_total_hits\":true,"
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
        try (Response resp = bounded(DEP_INDEXER, () -> indexerHttp.newCall(req).execute())) {
            String respBody = resp.body() != null ? resp.body().string() : "";
            if (!resp.isSuccessful()) {
                throw new IOException("indexer 24h 聚合查询失败 HTTP " + resp.code() + ": " + snippet(respBody));
            }
            return mapper.readTree(respBody);
        }
    }

    /**
     * 近 24 小时的<b>来源 IP 分布</b>：按 IP 做 terms 聚合 + 带来源 IP 的告警按小时分桶。
     *
     * <h3>为什么是一条独立查询，而不是拿 {@link #fetchAlerts(int)} 回来本地数</h3>
     * 实测 24 小时有 11 万条告警，其中 99% 集中在两三个 IP 上。取"最近 1000 条"再本地统计，
     * 既要把几 MB 原始日志（含 payload 与内网目的地址）搬进应用进程，又会得到
     * "最近几分钟谁在刷"而不是"24 小时全国分布"。这里让 indexer 只回聚合结果：
     * <b>字节数从 MB 级降到 KB 级，且是整窗口的精确计数</b>。
     *
     * <h3>为什么是"两个字段各一条 terms"</h3>
     * 实测同一索引里两类告警的来源字段名不同：
     * 主机侧/蜜罐写 {@code data.srcip}，Suricata（经 Wazuh agent 进来）写 {@code data.src_ip}。
     * 只查一个字段会丢掉一大半来源（实测 host-side 24h 只有约 700 条，
     * 而 suricata 侧有 10 万+ 条）—— 这种"少了一半还不报错"是最难发现的错。
     * 字段名由配置给出（{@code app.geoip.src-ip-fields}），不写死在代码里。
     *
     * <p>{@code src_present} 这个 filter 聚合负责回答"窗口内有多少条告警真的带来源 IP" ——
     * 公开端点要用它如实标注"分母是多少"，否则读者会以为地图覆盖了全部 11 万条告警。
     * 趋势也取自它（而不是取全部告警），这样趋势与地图是同一批数据。
     *
     * @param topN     每个字段取多少个 IP（terms 的 size）；超出的长尾由 sum_other_doc_count 如实暴露
     * @param srcFields 来源 IP 的字段名（至少一个）
     */
    public JsonNode fetchGeoAggregates24h(int topN, java.util.List<String> srcFields) throws IOException {
        if (indexerUrl == null || indexerHttp == null) {
            throw new IOException("未配置 Wazuh indexer 地址（integration.wazuh.indexer-url）");
        }
        int size = Math.max(1, Math.min(topN, 5000));
        // 查询体用 Jackson 构造，不拼字符串：字段名来自配置，拼字符串时一个引号就能把整个查询变成语法错误
        java.util.List<Object> should = new java.util.ArrayList<>();
        for (String f : srcFields) {
            should.add(java.util.Map.of("exists", java.util.Map.of("field", f)));
        }
        java.util.Map<String, Object> aggs = new java.util.LinkedHashMap<>();
        int i = 0;
        for (String f : srcFields) {
            aggs.put("by_ip_" + (i++), java.util.Map.of("terms",
                    java.util.Map.of("field", f, "size", size)));
        }
        aggs.put("src_present", java.util.Map.of(
                "filter", java.util.Map.of("bool", java.util.Map.of("should", should, "minimum_should_match", 1)),
                "aggs", java.util.Map.of("by_hour", java.util.Map.of("date_histogram", java.util.Map.of(
                        "field", "@timestamp",
                        "fixed_interval", "1h",
                        "min_doc_count", 0,
                        "extended_bounds", java.util.Map.of("min", "now-24h", "max", "now"))))));

        java.util.Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("size", 0);
        body.put("track_total_hits", true);
        body.put("query", java.util.Map.of("bool", java.util.Map.of("filter",
                java.util.List.of(java.util.Map.of("range",
                        java.util.Map.of("@timestamp", java.util.Map.of("gte", "now-24h")))))));
        body.put("aggs", aggs);

        Request req = new Request.Builder()
                .url(indexerUrl + "/wazuh-alerts-*/_search")
                .header("Authorization", indexerAuthHeader != null ? indexerAuthHeader : authHeader)
                .post(RequestBody.create(mapper.writeValueAsString(body), JSON))
                .build();
        try (Response resp = bounded(DEP_INDEXER, () -> indexerHttp.newCall(req).execute())) {
            String respBody = resp.body() != null ? resp.body().string() : "";
            if (!resp.isSuccessful()) {
                throw new IOException("indexer 来源分布查询失败 HTTP " + resp.code() + ": " + snippet(respBody));
            }
            return mapper.readTree(respBody);
        }
    }

    /**
     * 通用只读 indexer 查询（蜜罐战报等公开只读端点用）。     *
     * <p>刻意只接受<b>查询体</b>、只走 {@code _search}：不给调用方留写操作的口子，
     * 也避免有人顺手把删改请求传进来。
     *
     * @param indexPattern 索引模式，如 {@code wazuh-alerts-*}
     * @param bodyJson     OpenSearch 查询体
     */
    public JsonNode search(String indexPattern, String bodyJson) throws IOException {
        if (indexerUrl == null || indexerHttp == null) {
            throw new IOException("未配置 Wazuh indexer 地址");
        }
        Request req = new Request.Builder()
                .url(indexerUrl + "/" + indexPattern + "/_search")
                .header("Authorization", indexerAuthHeader != null ? indexerAuthHeader : authHeader)
                .post(RequestBody.create(bodyJson, JSON))
                .build();
        try (Response resp = bounded(DEP_INDEXER, () -> indexerHttp.newCall(req).execute())) {
            String respBody = resp.body() != null ? resp.body().string() : "";
            if (!resp.isSuccessful()) {
                throw new IOException("indexer 查询失败 HTTP " + resp.code() + ": " + snippet(respBody));
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
