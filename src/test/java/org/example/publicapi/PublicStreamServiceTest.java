package org.example.publicapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.core.model.AlertSeverity;
import org.example.core.model.AlertType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyEmitter;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 实时推送器的<b>协议与生命周期</b>测试。
 *
 * <h3>防的是什么</h3>
 * <ol>
 *   <li>帧格式漂移：EventSource 对格式极其挑剔，少一个空格、少一个空行，前端就"一个事件都不来"，
 *       而且浏览器控制台不会报错（静默失败）；</li>
 *   <li>连接泄漏：断开的 emitter 留注册表里，每来一个访客涨一个，跑到 OOM 才被发现；</li>
 *   <li>重复推送：按"最大时间戳"取增量时，同一秒的多条聚合会被漏掉或无限重推。</li>
 * </ol>
 *
 * <p>这里不用 Sleep 等 15 秒：时钟与调度器都由构造器注入，
 * 直接把时间快进到心跳点，断言既快又稳定。
 */
class PublicStreamServiceTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ZoneId ZONE = ZoneId.of("Asia/Shanghai");

    /** 可变时钟：tick() 判定"到点了吗"全看它 */
    private static final class MutableClock extends Clock {
        private volatile Instant now;

        private MutableClock(Instant start) {
            this.now = start;
        }

        @Override
        public ZoneId getZone() {
            return ZONE;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }

        void advance(Duration d) {
            now = now.plus(d);
        }
    }

    /** 可控数据源：不连 Wazuh，只返回测试指定的聚合结果 */
    private static final class StubSource extends PublicAlertSource {
        private String mode = "REAL";
        private boolean realData = true;
        private int windowMinutes = 5;
        private List<Map<String, Object>> items = new ArrayList<>();
        private RuntimeException failure;

        @Override
        public String mode() {
            return mode;
        }

        @Override
        public boolean realData() {
            return realData;
        }

        @Override
        public int aggregationWindowMinutes() {
            return windowMinutes;
        }

        @Override
        public List<Map<String, Object>> aggregated() {
            if (failure != null) {
                throw failure;
            }
            return items;
        }
    }

    /**
     * 捕获帧内容的 emitter。
     *
     * <p>只覆盖 send(SseEventBuilder)：服务端就是把整帧文本交给这个重载的，
     * 于是断言可以精确到"event: hello\ndata: ...\n\n"的每一个字节。
     */
    private static final class RecordingEmitter extends SseEmitter {
        private final List<String> frames = new ArrayList<>();
        private Runnable completion;
        private Consumer<Throwable> error;
        private Runnable timeout;
        private boolean failSends;
        private boolean completed;

        private RecordingEmitter() {
            super(0L);
        }

        @Override
        public synchronized void send(SseEventBuilder builder) throws IOException {
            if (failSends) {
                throw new IOException("客户端已断开（broken pipe）");
            }
            for (ResponseBodyEmitter.DataWithMediaType data : builder.build()) {
                Object payload = data.getData();
                frames.add(payload instanceof byte[] bytes
                        ? new String(bytes, StandardCharsets.UTF_8)
                        : String.valueOf(payload));
            }
        }

        @Override
        public void onCompletion(Runnable callback) {
            this.completion = callback;
            super.onCompletion(callback);
        }

        @Override
        public void onError(Consumer<Throwable> callback) {
            this.error = callback;
            super.onError(callback);
        }

        @Override
        public void onTimeout(Runnable callback) {
            this.timeout = callback;
            super.onTimeout(callback);
        }

        @Override
        public void complete() {
            this.completed = true;
        }
    }

    private static PublicStreamService service(PublicAlertSource source, Clock clock, int maxClients) {
        return new PublicStreamService(source, PublicIpPolicy.masking(), clock,
                Executors.newSingleThreadScheduledExecutor(), 1000, 15000, 15000, maxClients);
    }

    private static MutableClock clock() {
        return new MutableClock(Instant.parse("2026-11-07T04:00:00Z"));
    }

    private static Map<String, Object> alert(String aggId, String endTime, String srcIp, AlertType type,
                                             String rule, AlertSeverity severity, int count) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("aggId", aggId);
        m.put("endTime", endTime);
        m.put("startTime", endTime);
        m.put("srcIp", srcIp);
        m.put("type", type);
        m.put("severity", severity);
        m.put("ruleName", rule);
        m.put("count", count);
        return m;
    }

    private static JsonNode dataOf(String frame) throws Exception {
        int start = frame.indexOf("data: ") + "data: ".length();
        int end = frame.lastIndexOf("\n\n");
        return JSON.readTree(frame.substring(start, end));
    }

    private static long countPrefix(List<String> frames, String prefix) {
        return frames.stream().filter(f -> f.startsWith(prefix)).count();
    }

    // ==================== ① hello 帧 ====================

    @Test
    @DisplayName("【核心】首帧原文：event: hello + data 三字段 + 空行结尾（EventSource 只认这个格式）")
    void helloFrameIsExact() {
        PublicStreamService service = service(new StubSource(), clock(), 10);
        RecordingEmitter emitter = new RecordingEmitter();
        service.attach(emitter);

        assertEquals(1, emitter.frames.size(), "建连后应立刻下发且只下发一帧 hello");
        assertEquals("event: hello\n"
                        + "data: {\"generatedAt\":\"2026-11-07 12:00:00\",\"mode\":\"REAL\",\"windowMinutes\":5}\n\n",
                emitter.frames.get(0),
                "hello 帧必须逐字节可控（冒号后有空格、结尾两个换行）");
        assertEquals(1, service.onlineCount(), "连接必须注册进注册表");
    }

    @Test
    @DisplayName("hello 的 mode：REAL 但最近取数失败 → PARTIAL；非 REAL → MOCK")
    void helloModeReflectsDataSource() {
        StubSource partial = new StubSource();
        partial.realData = false;
        PublicStreamService s1 = service(partial, clock(), 10);
        RecordingEmitter e1 = new RecordingEmitter();
        s1.attach(e1);
        assertTrue(e1.frames.get(0).contains("\"mode\":\"PARTIAL\""), "链路是 REAL 但取数失败，必须自报 PARTIAL");

        StubSource mock = new StubSource();
        mock.mode = "MOCK";
        PublicStreamService s2 = service(mock, clock(), 10);
        RecordingEmitter e2 = new RecordingEmitter();
        s2.attach(e2);
        assertTrue(e2.frames.get(0).contains("\"mode\":\"MOCK\""), "非 REAL 一律 MOCK，不假装有数据");
    }

    // ==================== ② alert 帧 ====================

    @Test
    @DisplayName("【核心】alert 帧六字段与 /api/public/alerts 的 list[] 同名同义，src 已脱敏")
    void alertFrameCarriesContractFields() throws Exception {
        StubSource source = new StubSource();
        source.items = List.of(alert("agg-1", "2026-11-07 11:59:30", "203.0.113.7",
                AlertType.BRUTE_FORCE, "sshd：疑似暴力破解", AlertSeverity.HIGH, 3));
        PublicStreamService service = service(source, clock(), 10);
        RecordingEmitter emitter = new RecordingEmitter();
        service.attach(emitter);

        service.tick();

        long alerts = countPrefix(emitter.frames, "event: alert");
        assertEquals(1, alerts, "一条新增聚合应推一帧 alert");
        String frame = emitter.frames.stream()
                .filter(f -> f.startsWith("event: alert"))
                .findFirst()
                .orElseThrow();
        assertTrue(frame.endsWith("\n\n"), "SSE 帧必须以空行结束");

        JsonNode data = dataOf(frame);
        assertEquals("2026-11-07 11:59:30", data.get("time").asText(), "time ← endTime");
        assertEquals("203.0.***.***", data.get("src").asText(), "公网默认脱敏，src 不能是原 IP");
        assertEquals("BRUTE_FORCE", data.get("kind").asText(), "kind ← 告警类型枚举名");
        assertEquals("sshd：疑似暴力破解", data.get("rule").asText(), "rule ← ruleName");
        assertEquals("HIGH", data.get("sev").asText(), "sev ← 严重度枚举名");
        assertEquals(3, data.get("count").asInt(), "count 是聚合条数");
        assertEquals(6, data.size(), "对外只暴露六个字段，防止把内部字段带出去");
    }

    @Test
    @DisplayName("单次最多推 20 条，剩余的下一轮继续（不丢事件、不无限攒）")
    void batchIsCappedAtTwenty() {
        StubSource source = new StubSource();
        List<Map<String, Object>> items = new ArrayList<>();
        for (int i = 0; i < 25; i++) {
            items.add(alert("agg-" + i, String.format("2026-11-07 11:59:%02d", i), "198.51.100." + i,
                    AlertType.SCAN, "扫描", AlertSeverity.MEDIUM, 1));
        }
        source.items = items;
        PublicStreamService service = service(source, clock(), 10);
        RecordingEmitter emitter = new RecordingEmitter();
        service.attach(emitter);

        service.tick();
        assertEquals(20, countPrefix(emitter.frames, "event: alert"), "第一批只推 20 条");

        service.tick();
        assertEquals(25, countPrefix(emitter.frames, "event: alert"), "剩余 5 条在下一批补齐");
        assertEquals(0, service.pendingCount(), "推完队列必须清空");
    }

    @Test
    @DisplayName("同一批数据重复 tick 不会重推（水位按 endTime + aggId）")
    void watermarkPreventsDuplicates() {
        StubSource source = new StubSource();
        source.items = List.of(alert("agg-1", "2026-11-07 11:59:30", "203.0.113.7",
                AlertType.BRUTE_FORCE, "暴力破解", AlertSeverity.HIGH, 1));
        PublicStreamService service = service(source, clock(), 10);
        RecordingEmitter emitter = new RecordingEmitter();
        service.attach(emitter);

        service.tick();
        service.tick();

        assertEquals(1, countPrefix(emitter.frames, "event: alert"), "同一条聚合只能推一次");
    }

    @Test
    @DisplayName("同一秒内的两条不同聚合都要推（只比时间戳会漏掉后一条）")
    void sameSecondDifferentAggregatesBothPushed() {
        StubSource source = new StubSource();
        source.items = List.of(
                alert("agg-1", "2026-11-07 11:59:30", "203.0.113.7", AlertType.BRUTE_FORCE,
                        "暴力破解", AlertSeverity.HIGH, 1),
                alert("agg-2", "2026-11-07 11:59:30", "198.51.100.9", AlertType.SCAN,
                        "端口扫描", AlertSeverity.MEDIUM, 2));
        PublicStreamService service = service(source, clock(), 10);
        RecordingEmitter emitter = new RecordingEmitter();
        service.attach(emitter);

        service.tick();

        assertEquals(2, countPrefix(emitter.frames, "event: alert"), "同一秒的第二个 aggId 不能被水位吞掉");
    }

    // ==================== ③ 心跳 / 生命周期 ====================

    @Test
    @DisplayName("【核心】心跳 15 秒一次，且帧就是 : ping 注释行；中间不刷屏")
    void heartbeatIsPingEveryFifteenSeconds() {
        PublicStreamService service = service(new StubSource(), clock(), 10);
        RecordingEmitter emitter = new RecordingEmitter();
        service.attach(emitter);

        service.tick(); // 首次 tick 立即发一次心跳（建连时前端已经等了，不该再等 15 秒）
        assertEquals(1, countPrefix(emitter.frames, ": ping\n\n"));

        assertTrue(emitter.frames.contains(": ping\n\n"), "心跳必须是 : ping\\n\\n 注释行");
        assertFalse(emitter.frames.stream().anyMatch(f -> f.startsWith("event: ping")),
                "心跳不能做成 event 帧，否则前端会收到一个业务事件");
    }

    @Test
    @DisplayName("心跳按注入的时钟判定 15 秒：5 秒不重发，15 秒才再发")
    void heartbeatRespectsClock() {
        MutableClock clock = clock();
        PublicStreamService service = service(new StubSource(), clock, 10);
        RecordingEmitter emitter = new RecordingEmitter();
        service.attach(emitter);

        service.tick(); // t=0 → ping
        assertEquals(1, countPrefix(emitter.frames, ": ping\n\n"));

        clock.advance(Duration.ofSeconds(5));
        service.tick();
        assertEquals(1, countPrefix(emitter.frames, ": ping\n\n"), "5 秒未到心跳点，不能重发");

        clock.advance(Duration.ofSeconds(10));
        service.tick();
        assertEquals(2, countPrefix(emitter.frames, ": ping\n\n"), "满 15 秒必须再发一次心跳");
    }

    @Test
    @DisplayName("【核心】onCompletion / onError 回调必须把 emitter 移出注册表（防泄漏）")
    void disconnectCallbacksRemoveEmitter() {
        PublicStreamService service = service(new StubSource(), clock(), 10);

        RecordingEmitter normal = new RecordingEmitter();
        service.attach(normal);
        assertNotNull(normal.completion, "必须注册 onCompletion");
        normal.completion.run();
        assertEquals(0, service.onlineCount(), "正常断开（浏览器关页）后注册表必须归零");

        RecordingEmitter broken = new RecordingEmitter();
        service.attach(broken);
        assertNotNull(broken.error, "必须注册 onError");
        broken.error.accept(new IOException("connection reset"));
        assertEquals(0, service.onlineCount(), "异常断开同样必须归零");
    }

    @Test
    @DisplayName("写失败（对端已断）立即摘除并 complete，不能让死连接一直留在注册表")
    void sendFailureRemovesEmitter() {
        PublicStreamService service = service(new StubSource(), clock(), 10);
        RecordingEmitter emitter = new RecordingEmitter();
        service.attach(emitter);

        emitter.failSends = true;
        service.tick(); // 这一轮心跳写入失败

        assertEquals(0, service.onlineCount(), "写失败的连接必须移除");
        assertTrue(emitter.completed, "移除后要 complete()，释放容器侧资源");
    }

    @Test
    @DisplayName("数据源异常不退出、不影响心跳：hello 已发，连接继续活")
    void sourceFailureDegradesGracefully() {
        StubSource source = new StubSource();
        source.failure = new IllegalStateException("indexer timeout");
        PublicStreamService service = service(source, clock(), 10);
        RecordingEmitter emitter = new RecordingEmitter();
        service.attach(emitter);

        service.tick();

        assertEquals(1, service.onlineCount(), "取数失败不能把连接踢掉");
        assertTrue(emitter.frames.contains(": ping\n\n"), "取数失败也要照常发心跳");
    }

    @Test
    @DisplayName("在线连接达到上限时 subscribe 返回 null（由控制器回 503，不做无界堆积）")
    void maxClientsIsEnforced() {
        PublicStreamService service = service(new StubSource(), clock(), 1);
        assertNotNull(service.subscribe(), "第一个连接应成功");
        assertNull(service.subscribe(), "超过上限必须拒绝，而不是无限接受");
        assertEquals(1, service.onlineCount());
    }

    @Test
    @DisplayName("stop() 关闭全部连接并清空注册表（应用下线不留悬挂连接）")
    void stopClosesEverything() {
        PublicStreamService service = service(new StubSource(), clock(), 10);
        RecordingEmitter emitter = new RecordingEmitter();
        service.attach(emitter);

        service.stop();

        assertEquals(0, service.onlineCount());
        assertTrue(emitter.completed);
    }
}
