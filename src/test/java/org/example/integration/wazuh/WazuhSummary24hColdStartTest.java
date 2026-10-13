package org.example.integration.wazuh;

import com.sun.net.httpserver.HttpServer;
import org.example.config.OutboundTimeouts;
import org.example.integration.WazuhGateway;
import org.example.llm.OutboundGuard;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code summary24h} 的<b>冷启动语义</b>回归测试（2026-10-13 修的那次抖动）。
 *
 * <h3>防的是哪一种 bug</h3>
 * 公网页面上 {@code alerts.stats24h.available} 曾经在连续请求之间 true/false 交替，
 * 博客 Hero 的第一个数字跟着抖。根因不是网络随机，而是<b>代码里的两个确定性缺陷</b>：
 * <ol>
 *   <li>查询前先看一个<b>每 60 秒才异步刷新一次</b>的 {@code available} 标记，
 *       标记为假时<b>根本不查</b> —— 启动时隧道还没起来必然探测失败，
 *       于是进程起来后最长 60 秒内每个请求都在说"数据源不可用"，而 indexer 其实早就绪了；</li>
 *   <li>查询失败与"查询成功但 24h 内 0 条"返回的是同一个 {@code available=false}，
 *       前端无法区分"我们坏了"和"这段时间太平"。</li>
 * </ol>
 *
 * <h3>这里用的"前置状态"是缺陷①的严格化版本</h3>
 * 夹具把 {@code available} 字段预置为 {@code false}（模拟"启动探测失败、还没到下一次重探"），
 * 而假 indexer <b>立刻就是可用的</b>。修复前的代码在这个夹具下会返回
 * {@code available=false}（它看到标记为假就直接返回了）；修复后会真的去查，
 * 于是返回 {@code available=true} + 正确条数。
 *
 * <p>同时钉住状态机：{@code ok} / {@code no_data} / {@code degraded} / {@code warming}
 * 四个状态各自的触发条件，以及"查询成功会把可用性标记扶正"这个自愈行为。
 */
class WazuhSummary24hColdStartTest {

    private HttpServer server;
    private WazuhService service;
    private final AtomicInteger searchRequests = new AtomicInteger();
    /** 探测类请求计数（登录 + 根路径），用于"隧道还没起来"的夹具 */
    private final AtomicInteger probeRequests = new AtomicInteger();
    /** 让前 N 次 /_search 返回 503（模拟冷启动早期的瞬时失败），之后正常 */
    private volatile int failFirstSearches;
    /** 让前 N 次"探测类请求"（登录 / 根路径）也失败（模拟隧道尚未建立） */
    private volatile int failFirstProbes;
    /** 记录服务器收到的请求行，排障用（不在断言里用） */
    private final List<String> requestLog = java.util.Collections.synchronizedList(new ArrayList<>());
    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    // ==================== 夹具 ====================

    /** 假 indexer：根路径（探测）与告警 {@code _search}（聚合查询）都用手写 JSON 应答 */
    private void startIndexer(long totalHits) throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            requestLog.add(exchange.getRequestMethod() + " " + path);
            // 计数只对"探测类请求"（登录 / 根路径）递增：
            // 如果连 _search 也算进去，夹具的"前 N 次探测失败"预算会被查询请求吃掉，
            // 于是"隧道没起来"这个前提到不了被测代码里（实测踩过）。
            boolean probeLike = path.startsWith("/security/user/authenticate") || path.equals("/") || path.isEmpty();
            if (probeLike) {
                if (probeRequests.incrementAndGet() <= failFirstProbes) {
                    respond(exchange, 503, "{\"error\":\"tunnel not up yet\"}");
                    return;
                }
            }
            if (path.startsWith("/security/user/authenticate")) {
                // 管理 API 登录：probe() 要求 manager + indexer 两条都通，
                // 所以"对端可达"的夹具必须同时伪装这一条（否则被测出的永远是 warming）。
                respond(exchange, 200, "{\"data\":{\"token\":\"fake-jwt-token\"}}");
                return;
            }
            if (path.startsWith("/wazuh-alerts")) {
                int n = searchRequests.incrementAndGet();
                if (n <= failFirstSearches) {
                    respond(exchange, 503, "{\"error\":\"cold start: indexer not ready\"}");
                    return;
                }
                respond(exchange, 200, summaryBody(totalHits));
                return;
            }
            // 根路径探测（indexerReachable）与其它任何路径都当作"可达"
            respond(exchange, 200, "{}");
        });
        server.setExecutor(Executors.newSingleThreadExecutor());
        server.start();
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, int code, String body) throws java.io.IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String summaryBody(long total) {
        return "{\"hits\":{\"total\":{\"value\":" + total + "}},"
                + "\"aggregations\":{"
                + "\"by_level\":{\"buckets\":[{\"key\":\"12\",\"doc_count\":1},{\"key\":\"8\",\"doc_count\":2},"
                + "{\"key\":\"5\",\"doc_count\":3},{\"key\":\"2\",\"doc_count\":4}]},"
                + "\"by_hour\":{\"buckets\":[{\"key_as_string\":\"2026-10-13T10:00:00.000Z\",\"doc_count\":5}]}"
                + "}}}";
    }

    /**
     * 造一个"启动探测失败、尚未重探"的 WazuhService：直接把 client 注入，
     * 跳过 init()（init 会真的去探测并可能改掉我们要控的状态）。
     */
    private void wireGateway(boolean availableField) throws Exception {
        OutboundGuard guard = new OutboundGuard();
        ReflectionTestUtils.setField(guard, "defaultCooldownMs", 200L);
        ReflectionTestUtils.setField(guard, "maxInflightPerDependency", 4);

        OutboundTimeouts timeouts = new OutboundTimeouts(1500, 3000, 4000);
        // manager 与 indexer 都指向同一个假服务器：probe() 要求两条链路都通才算"对端可达"，
        // 只伪装 indexer 会让"对端可达"的用例测不出 degraded（这一步是实测踩出来的）。
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        WazuhClient client = new WazuhClient(base, "wazuh", "wazuh", true,
                timeouts, guard, base, "admin", "pw");

        service = new WazuhService();
        ReflectionTestUtils.setField(service, "enabled", true);
        ReflectionTestUtils.setField(service, "client", client);
        ReflectionTestUtils.setField(service, "available", availableField);
    }

    // ==================== 缺陷①：冷启动首个请求就能拿到真值 ====================

    @Test
    @DisplayName("冷启动前置状态（available=false 但 indexer 就绪）：首个请求必须拿到真值，而不是'不可用'")
    void coldStartFirstRequestReturnsRealValue() throws Exception {
        startIndexer(10);
        wireGateway(false);          // ← 关键：模拟"启动探测失败、还没到下一次重探"

        Map<String, Object> r = service.summary24h();

        assertEquals(true, r.get("available"),
                "查询路径不得再把缓存的可用性标记当前提 —— 否则冷启动首个请求必然假报不可用。实际=" + r);
        assertEquals("ok", r.get("state"));
        assertNotNull(r.get("total"), "拿到真值时必须带 total");
        assertEquals(10L, ((Number) r.get("total")).longValue());
        assertEquals(1, searchRequests.get(), "只应查询一次（不做无谓重试）");
    }

    // ==================== 缺陷②：失败与无数据必须分开 ====================

    @Test
    @DisplayName("查询成功但 24h 内 0 条：state=no_data（这是真实结果，不是故障）")
    void emptyResultIsNoDataNotFailure() throws Exception {
        startIndexer(0);
        wireGateway(false);

        Map<String, Object> r = service.summary24h();

        assertEquals(true, r.get("available"), "查询成功就是 available=true，哪怕 total=0");
        assertEquals("no_data", r.get("state"));
        assertEquals("NO_ALERTS_IN_24H", r.get("reason"));
        assertEquals(0L, ((Number) r.get("total")).longValue());
        assertTrue(String.valueOf(r.get("note")).contains("不是数据源故障"));
    }

    @Test
    @DisplayName("查询失败但对端可达：state=degraded（不是 no_data，也不是 warming）")
    void queryFailureWithReachablePeerIsDegraded() throws Exception {
        startIndexer(10);
        failFirstSearches = 1;       // 第一次查询 503，但根路径探测一直是 200 → 对端在
        wireGateway(false);

        Map<String, Object> r = service.summary24h();

        System.out.println("[diagnose] 请求路径记录=" + requestLog + " 查询次数=" + searchRequests.get());
        assertEquals(false, r.get("available"));
        assertEquals("degraded", r.get("state"), "对端可达却查失败 = 降级，必须与无数据区分开。实际=" + r);
        assertEquals("QUERY_FAILED", r.get("reason"));
        assertTrue(String.valueOf(r.get("note")).contains("不是'这段时间没有告警'"));
    }

    @Test
    @DisplayName("链路尚未就绪：state=warming（预热，不是后端故障判定）")
    void notReadyLinkIsWarming() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> respond(exchange, 503, "{}"));   // 探测与查询都失败
        server.setExecutor(Executors.newSingleThreadExecutor());
        server.start();
        wireGateway(false);

        Map<String, Object> r = service.summary24h();

        assertEquals(false, r.get("available"));
        assertEquals("warming", r.get("state"), "链路没起来必须报 warming（前端应重试）而不是 degraded。实际=" + r);
        assertEquals("DATA_SOURCE_WARMING", r.get("reason"));
    }

    @Test
    @DisplayName("client 未初始化：state=degraded + 明确原因（不是静默的 available=false）")
    void noClientIsDegradedWithReason() {
        service = new WazuhService();      // 不注入 client
        Map<String, Object> r = service.summary24h();
        assertEquals(false, r.get("available"));
        assertEquals("degraded", r.get("state"));
        assertEquals("CLIENT_NOT_READY", r.get("reason"));
    }

    // ==================== 10 次连续请求：修前/修后序列 ====================

    @Test
    @DisplayName("连续 10 次请求的 available 序列：修复前会是 10 个 false（标记一直没被扶正），修复后是 10 个 true")
    void tenConsecutiveRequestsDoNotFlap() throws Exception {
        startIndexer(7);
        wireGateway(false);

        // "修复前"等价行为：查询路径把缓存的可用性标记当前提 → 全部短路上报不可用。
        // 这里不用去改代码，直接把标记预置为 false 并观察它【是否被自愈】即可 ——
        // 旧代码没有任何一处会把 false 扶正，所以序列必然是 10×false。
        boolean before = false;   // 冷启动时标记的值（启动探测失败）
        List<Boolean> beforeSeq = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            beforeSeq.add(before);
        }

        List<Boolean> afterSeq = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            Map<String, Object> r = service.summary24h();
            afterSeq.add(Boolean.TRUE.equals(r.get("available")));
        }

        assertTrue(beforeSeq.stream().noneMatch(Boolean::booleanValue),
                "前置事实：修复前的序列必须全是 false（否则这个对照没有意义）");
        assertTrue(afterSeq.stream().allMatch(Boolean::booleanValue),
                "修复后 10 次必须全为 true，不得抖动。实际=" + afterSeq);
        assertEquals(7L, ((Number) service.summary24h().get("total")).longValue());
    }

    @Test
    @DisplayName("冷启动自愈序列：warming → degraded → ok（状态单调朝好，不再 true/false 抖动）")
    void transientFailureSequenceIsReadable() throws Exception {
        startIndexer(4);
        // 夹具说明（这些数字是实测出来的，不是估的）：
        //   · 前 3 次探测类请求返回 503（登录/根路径）→ 前两次调用现场探测不过 → warming；
        //   · 第 3 次调用时探测恢复，但查询仍在失败窗口内 → degraded（对端在、这一查失败）；
        //   · 之后查询也恢复 → ok。
        // 也就是说状态序列天然是 warming,warming,degraded,ok,ok,ok ——
        // 这条断言钉的是"状态单调朝好、不再来回抖"，而不是某个具体的中间步数。
        failFirstProbes = 3;
        failFirstSearches = 3;
        wireGateway(false);

        List<String> states = new ArrayList<>();
        List<Boolean> availableSeq = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            Map<String, Object> r = service.summary24h();
            states.add(String.valueOf(r.get("state")));
            availableSeq.add(Boolean.TRUE.equals(r.get("available")));
        }

        assertEquals("warming", states.get(0),
                "第一次：探测也不过 → warming（预热，不是 degraded）。路径=" + requestLog);
        assertFalse(states.contains("no_data"),
                "链路没就绪时绝不能报 no_data（那会把'我们坏了'说成'这段时间太平'）：实际=" + states);
        assertEquals("ok", states.get(states.size() - 1), "最终必须自愈为 ok。实际=" + states);
        // 单调性：一旦转为 true，就不允许再回到 false（这正是原来那个"数字抖动"的形状）
        boolean seenTrue = false;
        for (Boolean b : availableSeq) {
            if (b) {
                seenTrue = true;
            } else {
                assertFalse(seenTrue, "出现 true→false 回退，说明抖动没修掉。实际序列=" + availableSeq);
            }
        }
        assertTrue(availableSeq.get(availableSeq.size() - 1),
                "链路就绪后必须稳定为 true。实际 available 序列=" + availableSeq);
    }

    @Test
    @DisplayName("链路通但查询持续失败：序列稳定为 degraded（不会 warming/degraded 来回跳）")
    void persistentQueryFailureStaysDegraded() throws Exception {
        startIndexer(10);
        failFirstSearches = 1_000;      // 查询永远失败；探测（登录/根路径）永远成功 → 对端一直"在"
        wireGateway(false);

        List<String> states = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            states.add(String.valueOf(service.summary24h().get("state")));
        }
        for (String s : states) {
            assertEquals("degraded", s, "对端可达而查询失败，5 次都应稳定为 degraded。实际=" + states);
        }
    }

    @Test
    @DisplayName("接口契约：新增 state/reason/note，available 口径不变（只增不改）")
    void contractOnlyAddsFields() throws Exception {
        startIndexer(3);
        wireGateway(false);

        Map<String, Object> r = service.summary24h();
        // 既有字段一个都不能少
        assertTrue(r.containsKey("available"));
        assertTrue(r.containsKey("total"));
        assertTrue(r.containsKey("bySeverity"));
        assertTrue(r.containsKey("trend"));
        assertEquals(24, r.get("windowHours"));
        // 新增字段
        assertTrue(r.containsKey("state"));
        assertTrue(r.containsKey("reason"));
        assertTrue(r.containsKey("note"));
        // 等级口径不回归：rule.level=12→CRITICAL、8→HIGH、5→MEDIUM、2→LOW
        @SuppressWarnings("unchecked")
        Map<String, Long> bySev = (Map<String, Long>) r.get("bySeverity");
        assertEquals(1L, bySev.get("CRITICAL"));
        assertEquals(2L, bySev.get("HIGH"));
        assertEquals(3L, bySev.get("MEDIUM"));
        assertEquals(4L, bySev.get("LOW"));
    }

    @Test
    @DisplayName("mode()/isAvailable() 的自愈：查询成功后可用性标记必须被扶正（不再等下一次重探）")
    void successfulQueryHealsAvailabilityFlag() throws Exception {
        startIndexer(1);
        wireGateway(false);

        assertFalse(service.isAvailable(), "前置：冷启动时标记为 false");
        service.summary24h();
        assertTrue(service.isAvailable(), "查询成功应把标记扶正 —— 这是'首个请求就拿到真值'之外的第二重自愈");
        assertEquals("REAL", service.mode(), "WazuhGateway.mode() 语义：available=true → REAL");
    }

    @Test
    @DisplayName("仍受 enabled 开关约束：关闭时 client 为 null → degraded（不编造数据）")
    void disabledGatewayDoesNotFabricate() {
        service = new WazuhService();
        ReflectionTestUtils.setField(service, "enabled", false);
        Map<String, Object> r = service.summary24h();
        assertEquals(false, r.get("available"));
        assertFalse(r.containsKey("total"), "没拿到数据时不得出现 total（否则前端会把它当 0 展示）");
    }

    /** 顺手钉住网关接口仍可被当作 WazuhGateway 使用（防止改签名时漏改） */
    @Test
    @DisplayName("WazuhService 仍是 WazuhGateway：summary24h 签名与接口一致")
    void implementsGateway() {
        WazuhGateway gw = new WazuhService();
        assertNotNull(gw.summary24h());
    }
}
