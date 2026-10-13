package org.example.accesslog;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;

/**
 * <b>应用侧访问日志</b>：把每一个到达应用的请求写一行 JSONL 到 {@code data/access.jsonl}。
 *
 * <h3>为什么要加它（RUNBOOK §21.2 第 1 条的直接收口）</h3>
 * 之前实测过：{@code /wp-login.php}、{@code /.env}、{@code /../../etc/passwd}
 * 这类 <b>URL 级扫描</b>在应用里"一行都不记"（Spring 不记未匹配路由），
 * 返回 404 且日志无痕 —— 于是 srv1 上的 fail2ban 与 Wazuh 对这类攻击<b>完全瞎</b>。
 * 主机侧补不出来（信息在应用里），只能在应用侧补。
 *
 * <h3>字段是<b>白名单</b>（不加字段是纪律，不是偷懒）</h3>
 * 每行恰好这些键，顺序固定（fail2ban 的正则依赖这个顺序）：
 * <pre>
 * ts        请求开始时间（ISO-8601 带时区）
 * method    HTTP 方法（截断 16 字符）
 * path      <b>只有 path，没有查询串</b>（截断 512 字符；控制字符被替换成空格）
 * queryKeys <b>只有查询键名</b>（逗号分隔，最多 8 个，每个 ≤32 字符）—— 永不落查询值
 * status    响应状态码
 * clientIp  优先 CF-Connecting-IP（必须是合法 IP 字面量），否则 remoteAddr
 * ua        User-Agent（截断 200 字符）
 * ms        处理耗时（毫秒）
 * reqId     本次请求的关联 id（进程内唯一，仅存于本日志）
 * </pre>
 * <b>刻意不记</b>：请求体、查询串原文、Cookie、Authorization、Referer、
 * 响应体、任何 header 全集。理由：这个文件会长期驻留、会被 fail2ban/Wazuh
 * 反复读取、出事时还可能被人打包带走排障 —— 里面出现凭据或用户数据就是二次泄露。
 * 想验证这一条，看 {@code AccessLogFilterTest}（body/query 原文都有哨兵值断言）。
 *
 * <h3>为什么是 Filter，而且是最外层（{@link Ordered#HIGHEST_PRECEDENCE}）</h3>
 * <ol>
 *   <li>Filter 才能看到<b>所有</b>请求：包括没匹配任何 Controller 的 404
 *       （拦截器只在匹配到 handler 之后才跑，未匹配路由时它根本不执行）。</li>
 *   <li>必须在最外层：{@code PublicEtagFilter} 会在链尾把 200 改写成 304。
 *       我们在里面的话会把 304 记成 200；在最外层才能记到<b>最终</b>状态码。</li>
 * </ol>
 *
 * <h3>对现有语义零影响</h3>
 * 本类只读 request/response，<b>不写任何 header、不改状态码、不碰 body、
 * 不包装 request/response</b>；写盘在独立线程（见 {@link AccessLogWriter}）。
 * 也就是说：公开面的字段白名单 / 掩码 / CORS / 限流 / ETag 语义一个都没动。
 *
 * <h3>关掉它</h3>
 * {@code app.accesslog.enabled=false}（环境变量 {@code APP_ACCESSLOG_ENABLED=false}）。
 * 关闭时启动日志里仍会打印一行 {@code ACCESSLOG-...} 自检，
 * 明写 {@code DISABLED} —— 不静默（照 §23 的教训）。
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class AccessLogFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(AccessLogFilter.class);

    /** UA 截断长度（字符） */
    static final int UA_MAX_CHARS = 200;
    /** path 截断长度（字符）——Tomcat 的请求行上限是 8KB，这里再收一次口 */
    static final int PATH_MAX_CHARS = 512;
    /** method 截断长度 */
    static final int METHOD_MAX_CHARS = 16;
    /** IP 字段截断长度 */
    static final int IP_MAX_CHARS = 64;
    /** 每个请求最多记几个查询键名 */
    static final int MAX_QUERY_KEYS = 8;
    /** 单个查询键名截断长度 */
    static final int QUERY_KEY_MAX_CHARS = 32;

    private static final DateTimeFormatter ISO = DateTimeFormatter.ISO_OFFSET_DATE_TIME;
    /** 降级 WARN 的节流间隔：日志起不来时不要每条请求打一行 */
    private static final long DEGRADED_WARN_INTERVAL_MS = 300_000L;

    @Value("${app.accesslog.enabled:true}")
    private boolean enabled = true;

    @Value("${app.accesslog.dir:data}")
    private String dir = "data";

    @Value("${app.accesslog.retain-days:7}")
    private int retainDays = 7;

    @Value("${app.accesslog.max-file-mb:64}")
    private int maxFileMb = 64;

    @Value("${app.accesslog.skip-paths:/api/health}")
    private String skipPaths = "/api/health";

    /**
     * 公开聚合端点 {@code /api/public/webstats} 的数据面（可选 Bean）。
     *
     * <p>为什么把它挂在<b>写线程</b>上：请求线程只做一次 {@code offer}（RUNBOOK §23），
     * 聚合计数是写线程"顺手"做的事；公开端点只读内存，从不读文件。
     * 这个 Bean 缺席（老部署/单测直接 new Filter）时访问日志照常工作。
     */
    @Autowired(required = false)
    private WebStatsService webStatsService;

    private final ObjectMapper mapper = new ObjectMapper();
    private final AtomicLong reqIdSeq = new AtomicLong();
    private final List<String> skipPrefixes = new ArrayList<>();
    private final Set<String> skipExact = new LinkedHashSet<>();

    private volatile AccessLogWriter writer;
    private volatile String degradedReason = "";
    private volatile long lastDegradedWarnAt;

    @PostConstruct
    void init() {
        initAccessLog();
    }

    /**
     * 解析配置并启动写线程。抽成独立方法是为了单测能直接调用
     * （不需要起 Spring 上下文 —— 本项目所有单测都不加载上下文）。
     */
    void initAccessLog() {
        parseSkipPaths(skipPaths);
        if (!enabled) {
            writer = null;
            logger.info("ACCESSLOG DISABLED: app.accesslog.enabled=false（不写访问日志，"
                    + "URL 级扫描在应用侧与主机侧都不可见）");
            return;
        }
        long maxBytes = Math.max(1, maxFileMb) * 1024L * 1024L;
        // 【顺序不可换】先让聚合器记下"回填读到哪一位"，再启动写线程：
        // 回填只读 [0, 当时的长度)，写线程从那个长度往后实时计 —— 同一行不会被数两遍。
        WebStatsService stats = webStatsService;
        if (stats != null) {
            stats.beginBackfill(Path.of(dir));
        }
        AccessLogWriter w = new AccessLogWriter(Path.of(dir), retainDays, maxBytes, this::onLinePersisted);
        try {
            w.start();
            writer = w;
            logger.info("ACCESSLOG ENABLED: file={} retainDays={} maxFileMB={} skipPaths={} queueCapacity={}",
                    w.activeFilePath(), retainDays, maxFileMb, skipPaths, w.queueCapacity());
        } catch (IOException e) {
            // 启动期 StorageGuard 已经会因为 data 不可写而拒绝启动；这里是第二道，
            // 属于"真出事了也不静默"：打 WARN，并且让后续请求继续走
            // offer() -> 丢弃 + 节流 WARN 的路径（日志里持续可见，不是假装成功）。
            writer = null;
            degradedReason = e.getClass().getSimpleName() + ": " + e.getMessage();
            lastDegradedWarnAt = System.currentTimeMillis();
            logger.warn("ACCESSLOG DEGRADED: 访问日志无法启动（目录 {} 不可写？），"
                    + "URL 级扫描将不可见；请求本身不受影响。原因: {}", dir, degradedReason);
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        AccessLogWriter w = writer;
        if (w == null) {
            if (enabled) {
                warnDegradedThrottled();
            }
            chain.doFilter(request, response);
            return;
        }
        if (shouldSkip(request)) {
            chain.doFilter(request, response);
            return;
        }

        long startNanos = System.nanoTime();
        Throwable error = null;
        try {
            chain.doFilter(request, response);
        } catch (Throwable t) {
            // 异常继续往上抛（绝不改变行为），只是为了记一个更接近事实的状态码
            error = t;
            throw t;
        } finally {
            try {
                int status = response.getStatus();
                if (error != null && status < 500) {
                    // 容器会把未捕获异常映射成 500（本项目里几乎都由
                    // GlobalExceptionHandler 兜住；这一支是兜底），如实记 500
                    status = 500;
                }
                long ms = (System.nanoTime() - startNanos) / 1_000_000L;
                w.offer(serialize(request, status, ms));
            } catch (Throwable t) {
                // "记一行日志"绝不能把请求搞坏：这里的失败只打 debug（写线程侧还有 WARN 兜底）
                logger.debug("访问日志组装失败（本条丢弃，请求不受影响）: {}", t.toString());
            }
        }
    }

    /** 组装一行 JSON。可见性：包内可见，供单测直接断言字段集合。 */
    Map<String, Object> buildRow(String ts, String method, String path, String queryKeys,
                                 int status, String clientIp, String ua, long ms, String reqId) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ts", ts);
        row.put("method", method);
        row.put("path", path);
        row.put("queryKeys", queryKeys);
        row.put("status", status);
        row.put("clientIp", clientIp);
        row.put("ua", ua);
        row.put("ms", ms);
        row.put("reqId", reqId);
        return row;
    }

    private String serialize(HttpServletRequest request, int status, long ms) throws Exception {
        Map<String, Object> row = buildRow(
                // 截断到毫秒：ISO_OFFSET_DATE_TIME 默认会带上 9 位纳秒，
                // 而 fail2ban 的日期模板（Python strptime 的 %f）只认 1-6 位小数 ——
                // 9 位会让它解析失败并退化成"用当前时间"，findtime 的窗口不再精确。
                OffsetDateTime.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS).format(ISO),
                sanitize(request.getMethod(), METHOD_MAX_CHARS),
                sanitize(request.getRequestURI(), PATH_MAX_CHARS),
                queryKeys(request.getQueryString()),
                status,
                resolveClientIp(request.getHeader("CF-Connecting-IP"), request.getRemoteAddr()),
                sanitize(request.getHeader("User-Agent"), UA_MAX_CHARS),
                ms,
                nextReqId());
        return mapper.writeValueAsString(row);
    }

    /**
     * 取调用方 IP：优先 {@code CF-Connecting-IP}，否则 {@code remoteAddr}。
     *
     * <p>与 {@code PublicApiController#clientIp} 的口径一致，但多了一道
     * <b>必须是合法 IP 字面量</b>的校验：
     * <ul>
     *   <li>这个值会<b>落盘</b>并被 fail2ban 拿去封禁，不能接受任意字符串
     *       （否则日志里会出现 attacker 自己编的"IP"，还能变成日志注入）；</li>
     *   <li>刻意<b>不回退到 X-Forwarded-For</b>：在云隧道场景下它是
     *       CF 追加的链，取谁都能被讨论；只认一个明确来源更容易审计。</li>
     *   <li>校验用纯字符串判断（不调 {@code InetAddress.getByName}）——
     *       后者的入参会触发 DNS 解析，等于让请求方控制我们的出站查询。</li>
     * </ul>
     */
    static String resolveClientIp(String cfHeader, String remoteAddr) {
        String cf = sanitize(cfHeader, IP_MAX_CHARS);
        if (isIpLiteral(cf)) {
            return cf;
        }
        String remote = sanitize(remoteAddr, IP_MAX_CHARS);
        return remote.isEmpty() ? "unknown" : remote;
    }

    static boolean isIpLiteral(String s) {
        if (s == null || s.isEmpty() || s.length() > IP_MAX_CHARS) {
            return false;
        }
        if (s.indexOf(':') >= 0) {
            // IPv6（含 IPv4-mapped ::ffff:1.2.3.4）：只放行十六进制与冒号、点
            if (!s.matches("[0-9A-Fa-f:.]+") || s.contains(":::")) {
                return false;
            }
            int colons = 0;
            for (int i = 0; i < s.length(); i++) {
                if (s.charAt(i) == ':') {
                    colons++;
                }
            }
            return colons >= 2;
        }
        String[] parts = s.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String p : parts) {
            if (p.isEmpty() || p.length() > 3) {
                return false;
            }
            for (int i = 0; i < p.length(); i++) {
                if (!Character.isDigit(p.charAt(i))) {
                    return false;
                }
            }
            if (Integer.parseInt(p) > 255) {
                return false;
            }
        }
        return true;
    }

    /**
     * 查询串 → <b>只保留键名</b>（去重、最多 {@link #MAX_QUERY_KEYS} 个）。
     *
     * <p>为什么连键名都记：{@code ?id=}、{@code ?cmd=}、{@code ?file=} 这种
     * "参数名爆破"是有情报价值的，而值才是敏感的部分。
     * <b>值一律丢弃 —— 查询串原文永远不落盘</b>（有单测用哨兵值钉住这一点）。
     */
    static String queryKeys(String query) {
        if (query == null || query.isBlank()) {
            return "";
        }
        LinkedHashSet<String> keys = new LinkedHashSet<>();
        for (String pair : query.split("&")) {
            if (keys.size() >= MAX_QUERY_KEYS) {
                break;
            }
            String key = pair;
            int eq = pair.indexOf('=');
            if (eq >= 0) {
                key = pair.substring(0, eq);
            }
            key = sanitize(key, QUERY_KEY_MAX_CHARS);
            if (!key.isEmpty()) {
                keys.add(key);
            }
        }
        return String.join(",", keys);
    }

    /**
     * 控制字符替换成空格后截断。
     *
     * <p>JSON 序列化本身会转义换行（JSONL 的一行一条因此不会被破坏），
     * 但日志文件还会被 fail2ban / Wazuh 的<b>行式</b>规则读，
     * 并且可能被 {@code tail} 到终端 —— 让 header 里的控制字符"原样落地"
     * 是标准的日志注入面，这里直接替换掉。
     */
    static String sanitize(String raw, int maxChars) {
        if (raw == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(Math.min(raw.length(), maxChars));
        for (int i = 0; i < raw.length() && sb.length() < maxChars; i++) {
            char c = raw.charAt(i);
            sb.append(c < 0x20 || c == 0x7F ? ' ' : c);
        }
        return sb.toString().trim();
    }

    private String nextReqId() {
        return Long.toHexString(System.currentTimeMillis()) + "-"
                + Long.toHexString(reqIdSeq.incrementAndGet()) + "-"
                + Integer.toHexString(ThreadLocalRandom.current().nextInt() & 0xFFFF);
    }

    /**
     * 跳过清单：逗号分隔；以 {@code *} 结尾的按前缀匹配，其余精确匹配。
     * 默认跳过 {@code /api/health}（容器 healthcheck 每 30 秒一次，
     * 一天 2880 行纯噪声，会把真信号淹掉）。
     */
    void parseSkipPaths(String raw) {
        skipExact.clear();
        skipPrefixes.clear();
        if (raw == null || raw.isBlank()) {
            return;
        }
        for (String item : raw.split(",")) {
            String s = item.trim();
            if (s.isEmpty()) {
                continue;
            }
            if (s.endsWith("*")) {
                skipPrefixes.add(s.substring(0, s.length() - 1));
            } else {
                skipExact.add(s);
            }
        }
    }

    boolean shouldSkip(HttpServletRequest request) {
        String uri = request.getRequestURI();
        if (uri == null) {
            return false;
        }
        for (String prefix : skipPrefixes) {
            if (uri.startsWith(prefix)) {
                return true;
            }
        }
        return skipExact.contains(uri);
    }

    /**
     * 写线程落盘每一行时回调：顺手喂给公开聚合端点（{@code /api/public/webstats}）的数据面。
     *
     * <p>只做一次方法调用 + 计数，<b>不读文件、不阻塞</b>；Bean 缺席时为 no-op。
     */
    private void onLinePersisted(String line) {
        WebStatsService stats = webStatsService;
        if (stats != null) {
            stats.acceptLine(line);
        }
    }

    private void warnDegradedThrottled() {
        long now = System.currentTimeMillis();
        if (now - lastDegradedWarnAt >= DEGRADED_WARN_INTERVAL_MS) {
            lastDegradedWarnAt = now;
            logger.warn("ACCESSLOG DEGRADED（仍未恢复）: {} —— URL 级扫描当前不可见",
                    degradedReason.isEmpty() ? "访问日志未启动" : degradedReason);
        }
    }

    @PreDestroy
    void shutdown() {
        AccessLogWriter w = writer;
        if (w != null) {
            w.close();
            logger.info("ACCESSLOG 关闭，统计: {}", w.stats());
        }
    }

    // ==================== 供单测/自检使用 ====================

    /** 启动自检与单测用：当前生效的写入器（未启用时为 null） */
    AccessLogWriter writerForTest() {
        return writer;
    }

    String degradedReason() {
        return degradedReason;
    }
}
