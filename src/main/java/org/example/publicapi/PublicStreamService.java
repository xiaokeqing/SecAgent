package org.example.publicapi;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyEmitter;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * 作战室实时攻击流的 <b>SSE 推送器</b>（{@code /api/public/stream} 的实现）。
 *
 * <h3>为什么单独一个类，而不是塞进公开面的 god controller</h3>
 * <ul>
 *   <li>那个控制器已经两千多行，且所有方法都是"一次请求 → 一份 JSON 信封"的短生命周期；
 *       SSE 是长连接 + 自己的调度线程 + 注册表，生命周期与 REST 完全不同，混在一起最容易
 *       在 {@code onCompletion} 漏掉清理。</li>
 *   <li>SSE <b>不走</b> {@code {code,message,data}} 信封：EventSource 只认 {@code event:} /
 *       {@code data:} 行，包一层信封反而让前端无法复用 {@code /api/public/alerts} 的渲染逻辑。</li>
 * </ul>
 *
 * <h3>数据源：复用 {@link PublicAlertSource}，不新建外部连接</h3>
 * 公网面所有告警都从这一个入口取（内部是 Wazuh indexer 的最近 200 条），
 * 实时流若另开一条 Suricata eve.json 通道，会出现两份口径不一致的告警，
 * 甚至把服务机上读不到 eve.json 时降级出来的<b>内置样本</b>当成真实攻击推出去。
 * 所以这里只调 {@code aggregated()}，并且它本身已经做了 fail-closed（非 REAL 返回空）。
 *
 * <h3>为什么自己拼帧</h3>
 * {@code SseEmitter.event()} 输出的是 {@code event:hello}/{@code data:...}（冒号后没有空格），
 * 而验收与前端约定的是 {@code event: hello} + {@code data: {...}}。为了逐字节可控（也为了
 * {@code : ping} 这种注释行），这里把整帧文本交给 {@code send(SseEventBuilder)} 原样写出。
 *
 * <h3>线程模型</h3>
 * 请求线程只做"注册 + 发 hello"两件事，<b>绝不 sleep</b>；心跳与增量推送全部由
 * 注入的 {@link ScheduledExecutorService}（生产上 1 个线程）驱动。
 * 单客户端写失败（浏览器关页/网络断）时立即移出注册表并静默 complete，
 * 不让死连接一直占着注册表。
 */
@Component
public class PublicStreamService {

    private static final Logger logger = LoggerFactory.getLogger(PublicStreamService.class);

    /** 与公开面同一口径，前端可直接展示 */
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /** 心跳注释行：15 秒一次，防止 Cloudflare/nginx 把空闲连接当死连接掐掉 */
    static final String HEARTBEAT_FRAME = ": ping\n\n";

    /** 单次推送批量上限（新增事件多时先推 20 条，剩余的下一轮继续） */
    static final int BATCH_LIMIT = 20;

    /** 待发队列上限：客户端极慢或长期没人消费时防止内存无限涨 */
    static final int MAX_PENDING = 200;

    private static final ObjectMapper JSON = new ObjectMapper();

    private final PublicAlertSource source;
    private final PublicIpPolicy ipPolicy;
    private final Clock clock;
    private final ScheduledExecutorService scheduler;

    private final long tickMs;
    private final long heartbeatMs;
    private final long pollMs;
    private final int maxClients;

    /**
     * 在线连接注册表。
     *
     * <p>用 {@link CopyOnWriteArrayList}：遍历（每轮扇出）远多于增删（只在建连/断连时），
     * 读时不需要加锁，也不会因为某个客户端断开而让别的连接拿到 {@code ConcurrentModificationException}。
     */
    private final CopyOnWriteArrayList<SseEmitter> emitters = new CopyOnWriteArrayList<>();

    /** 推送状态互斥：调度线程与单测里的手动 tick() 都走这把锁，保证水位只前进不后退 */
    private final Object lock = new Object();

    /** 已推送到的最大 {@code endTime}（字符串可直接比较：yyyy-MM-dd HH:mm:ss 字典序 = 时间序） */
    private String watermarkEndTime = "";

    /** 水位那一秒内已经推过的 aggId（同一秒可能有多条聚合，只比时间会漏） */
    private final Set<String> watermarkIds = new HashSet<>();

    /** 已拉取但还没推出去的聚合项（旧 → 新） */
    private final ArrayDeque<Map<String, Object>> pending = new ArrayDeque<>();

    /** 与 pending 对应的去重键（防止同一轮里重复入队） */
    private final Set<String> pendingKeys = new HashSet<>();

    private long lastPollMillis = -1L;
    private long lastPingMillis = -1L;

    /** 调度是否已启动（单测直接 new 时不会启动） */
    private boolean running;

    /**
     * 构造器注入：数据源、IP 口径、时钟、调度器都由 Spring 给；
     * 单测可以传固定时钟与可控调度器，不必起整个应用上下文。
     */
    public PublicStreamService(PublicAlertSource source,
                               PublicIpPolicy ipPolicy,
                               Clock clock,
                               @Qualifier("publicStreamScheduler") ScheduledExecutorService scheduler,
                               @Value("${app.public-api.stream.tick-ms:1000}") long tickMs,
                               @Value("${app.public-api.stream.heartbeat-ms:15000}") long heartbeatMs,
                               @Value("${app.public-api.stream.poll-ms:15000}") long pollMs,
                               @Value("${app.public-api.stream.max-clients:200}") int maxClients) {
        this.source = source;
        this.ipPolicy = ipPolicy;
        this.clock = clock;
        this.scheduler = scheduler;
        this.tickMs = Math.max(200L, tickMs);
        this.heartbeatMs = Math.max(1000L, heartbeatMs);
        this.pollMs = Math.max(1000L, pollMs);
        this.maxClients = Math.max(1, maxClients);
    }

    // ==================== 建连 / 断连 ====================

    /**
     * 新建一条 SSE 连接并立即下发 hello 帧。
     *
     * @return 已注册的 emitter；在线连接达到上限时返回 {@code null}
     *         （由控制器回 503 + Retry-After，而不是把已建好的长连接静默掐掉）
     */
    public SseEmitter subscribe() {
        synchronized (lock) {
            if (emitters.size() >= maxClients) {
                logger.warn("SSE 在线连接已达上限 {}，拒绝新连接", maxClients);
                return null;
            }
            // 0 = 不主动超时：断线由容器发现（下一次心跳写失败），浏览器自己负责重连。
            // 不设 5 分钟是为了避免"刚订上就被服务端 complete、前端不停重连"的抖动。
            SseEmitter emitter = new SseEmitter(0L);
            attach(emitter);
            return emitter;
        }
    }

    /**
     * 注册连接、挂断连回调、发 hello。
     *
     * <p>包级可见是为了单测能传一个"捕获帧内容"的 {@link SseEmitter} 子类，
     * 无需真的跑 MVC 异步链路。
     */
    SseEmitter attach(SseEmitter emitter) {
        emitter.onCompletion(() -> remove(emitter, "onCompletion"));
        emitter.onError(e -> remove(emitter, "onError:" + e));
        emitter.onTimeout(() -> {
            remove(emitter, "onTimeout");
            safeComplete(emitter);
        });
        emitters.add(emitter);
        send(emitter, helloFrame());
        logger.debug("SSE 连接建立，当前在线 {}", emitters.size());
        return emitter;
    }

    /** 从注册表移除；重复调用无副作用（onCompletion 与写失败两条路都会走到） */
    private void remove(SseEmitter emitter, String reason) {
        if (emitters.remove(emitter)) {
            logger.debug("SSE 连接移除（{}），当前在线 {}", reason, emitters.size());
        }
    }

    // ==================== 调度 ====================

    /**
     * 应用就绪后再启动调度：单测 {@code new PublicStreamService(...)} 不会自己跑起来，
     * 只能手动调 {@link #tick()}，这样断言才可重复。
     */
    @EventListener(ApplicationReadyEvent.class)
    public void start() {
        synchronized (lock) {
            if (running) {
                return;
            }
            running = true;
        }
        scheduler.scheduleAtFixedRate(this::safeTick, tickMs, tickMs, TimeUnit.MILLISECONDS);
        logger.info("作战室实时推送已启动：tick={}ms，取数={}ms，心跳={}ms，连接上限={}",
                tickMs, pollMs, heartbeatMs, maxClients);
    }

    @PreDestroy
    public void stop() {
        synchronized (lock) {
            running = false;
        }
        scheduler.shutdownNow();
        for (SseEmitter emitter : emitters) {
            safeComplete(emitter);
        }
        emitters.clear();
    }

    /** 调度线程里包一层：任何异常都不该把 ScheduledExecutorService 的周期任务干掉 */
    private void safeTick() {
        try {
            tick();
        } catch (Throwable t) {
            logger.warn("SSE 推送调度异常（继续下一轮）：{}", t.toString());
        }
    }

    /**
     * 一轮推送：按到点情况取增量、发告警、发心跳。
     *
     * <p>包级可见，单测直接调用（配固定 {@link Clock} 即可精确断言"15 秒才发一次"）。
     */
    void tick() {
        synchronized (lock) {
            long now = clock.millis();
            if (lastPollMillis < 0 || now - lastPollMillis >= pollMs) {
                lastPollMillis = now;
                collectNewAlerts();
            }
            drainPending();
            if (lastPingMillis < 0 || now - lastPingMillis >= heartbeatMs) {
                lastPingMillis = now;
                broadcast(HEARTBEAT_FRAME);
            }
        }
    }

    // ==================== 增量取数 ====================

    /**
     * 从 {@link PublicAlertSource#aggregated()} 里挑出"比水位新"的聚合项放进待发队列。
     *
     * <p>水位规则：先比 {@code endTime}，<b>同一秒</b>再比 aggId 集合。
     * 只比时间会在"同一秒两条不同来源"时漏推；只比 aggId 则永远推不完历史数据。
     */
    private void collectNewAlerts() {
        List<Map<String, Object>> latest;
        try {
            latest = source.aggregated();
        } catch (Exception e) {
            // 取不到不是致命错误：hello 已经发过，连接继续靠心跳活着，前端自己降级
            logger.warn("实时推送取告警失败（本轮只发心跳，前端自行降级）：{}", e.getMessage());
            return;
        }
        if (latest == null || latest.isEmpty()) {
            return;
        }
        List<Map<String, Object>> sorted = new ArrayList<>(latest);
        sorted.sort(OLDEST_FIRST);

        for (Map<String, Object> item : sorted) {
            if (item == null) {
                continue;
            }
            String time = text(item.get("endTime"));
            if (time.isEmpty()) {
                continue;
            }
            String id = itemKey(item);
            if (time.compareTo(watermarkEndTime) < 0) {
                continue; // 比水位旧：不补历史（实时流只承诺"从现在起"）
            }
            if (time.equals(watermarkEndTime) && watermarkIds.contains(id)) {
                continue; // 同一秒已经推过
            }
            String key = time + "|" + id;
            if (!pendingKeys.add(key)) {
                continue; // 已在待发队列里，避免重复入队
            }
            pending.addLast(item);
            advanceWatermark(time, id);
            drainOverflow();
        }
    }

    /** 待发队列超限时丢最旧的：宁可缺一条，也不能让慢客户端把进程内存撑爆 */
    private void drainOverflow() {
        while (pending.size() > MAX_PENDING) {
            Map<String, Object> dropped = pending.removeFirst();
            pendingKeys.remove(pendingKey(dropped));
            logger.warn("SSE 待发队列超过 {} 条，丢弃最旧一条", MAX_PENDING);
        }
    }

    private void advanceWatermark(String time, String id) {
        int cmp = time.compareTo(watermarkEndTime);
        if (cmp > 0) {
            watermarkEndTime = time;
            watermarkIds.clear();
        }
        if (cmp >= 0) {
            watermarkIds.add(id);
        }
    }

    /** 每轮最多推 {@link #BATCH_LIMIT} 条，剩下的留在队列里下一轮继续 */
    private void drainPending() {
        int sent = 0;
        while (sent < BATCH_LIMIT && !pending.isEmpty()) {
            Map<String, Object> item = pending.pollFirst();
            pendingKeys.remove(pendingKey(item));
            broadcast(alertFrame(toStreamItem(item)));
            sent++;
        }
    }

    // ==================== 帧格式 ====================

    /** 首帧：告诉前端"现在是几点的数据、数据源什么模式、窗口多大" */
    String helloFrame() {
        Map<String, Object> data = new LinkedHashMap<>();
        // 与 REST 端点同格式，前端不用为 SSE 再写一个时间解析
        data.put("generatedAt", LocalDateTime.now(clock).format(FMT));
        data.put("mode", mode());
        data.put("windowMinutes", windowMinutes());
        return "event: hello\ndata: " + json(data) + "\n\n";
    }

    /** 单条告警帧；字段名与 {@code /api/public/alerts?w=5} 的 {@code list[]} 对齐 */
    static String alertFrame(Map<String, Object> streamItem) {
        return "event: alert\ndata: " + json(streamItem) + "\n\n";
    }

    /**
     * 聚合项 → 实时帧载荷（七字段）。
     *
     * <p>只做"改名 + 脱敏"，不改语义：{@code time} 取 endTime（聚合窗口结束时间），
     * {@code count} 是这簇事件条数；{@code kind}/{@code sev} 用枚举名，和列表页一致。
     * {@code cc} 是来源国家二字码，与 {@code /api/public/alerts} 的 {@code list[].cc}
     * 共用 {@code PublicAlertSource#countryCode}，取不到为 {@code null}。
     */
    Map<String, Object> toStreamItem(Map<String, Object> agg) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("time", text(agg.get("endTime")));
        item.put("src", ipPolicy.display(text(agg.get("srcIp"))));
        item.put("kind", enumName(agg.get("type")));
        item.put("rule", text(agg.get("ruleName")));
        item.put("sev", enumName(agg.get("severity")));
        item.put("count", count(agg.get("count")));
        // 来源国家码：与 REST 列表同一个解析入口（srcGeo 首段优先，缺了才查离线库），null=取不到。
        item.put("cc", source.countryCode(agg));
        return item;
    }

    /** REAL=真数据；PARTIAL=链路 REAL 但最近一次取数失败；MOCK=没有真实数据源（含 OFF） */
    String mode() {
        try {
            String m = source.mode();
            if (!"REAL".equalsIgnoreCase(m)) {
                return "MOCK";
            }
            return source.realData() ? "REAL" : "PARTIAL";
        } catch (Exception e) {
            return "MOCK";
        }
    }

    int windowMinutes() {
        try {
            return Math.max(1, source.aggregationWindowMinutes());
        } catch (Exception e) {
            return 5;
        }
    }

    // ==================== 扇出 ====================

    /** 写所有在线连接；写失败的连接立刻摘掉（这就是"断开检测"） */
    private void broadcast(String frame) {
        for (SseEmitter emitter : emitters) {
            if (!send(emitter, frame)) {
                remove(emitter, "send-failed");
                safeComplete(emitter);
            }
        }
    }

    private boolean send(SseEmitter emitter, String frame) {
        try {
            emitter.send(rawFrame(frame));
            return true;
        } catch (Exception e) {
            // 典型：浏览器关页后 Tomcat 抛 IOException，或上一轮已 complete 抛 IllegalStateException
            logger.debug("SSE 写入失败，摘除连接：{}", e.toString());
            return false;
        }
    }

    /**
     * 把"拼好的原文"原样写进 SseEmitter。
     *
     * <p>{@code SseEmitter.send(Object)} 会自动包一层 {@code data:} 前缀，
     * 所以这里实现一个只提供 {@code build()} 的 {@link SseEmitter.SseEventBuilder}，
     * 让 Spring 直接写出这一帧。
     *
     * <p><b>为什么载荷是 String 且显式给 text/event-stream</b>：最初这里用
     * {@code byte[] + null} 媒体类型，单测（standalone MockMvc，默认转换器链）是通的，
     * 但真实容器里应用自定义的转换器顺序把 Jackson 排在前面，
     * {@code canWrite(byte[].class, null)} 为 true ⇒ 字节被序列化成 base64 字符串再加引号，
     * 浏览器收到的根本不是 SSE 帧（curl 实测可见 {@code "ZXZlbnQ6..."}）。
     * 换成 String + 明确媒体类型后由 StringHttpMessageConverter 原样写出，
     * 与 MockMvc、真实 Tomcat 两条链路口径一致。
     */
    private static SseEmitter.SseEventBuilder rawFrame(String frame) {
        return new SseEmitter.SseEventBuilder() {
            @Override
            public Set<ResponseBodyEmitter.DataWithMediaType> build() {
                return Collections.singleton(
                        new ResponseBodyEmitter.DataWithMediaType(frame, MediaType.TEXT_EVENT_STREAM));
            }

            @Override
            public SseEmitter.SseEventBuilder id(String id) {
                throw new UnsupportedOperationException("SSE 原样帧不支持增量构建");
            }

            @Override
            public SseEmitter.SseEventBuilder name(String name) {
                throw new UnsupportedOperationException("SSE 原样帧不支持增量构建");
            }

            @Override
            public SseEmitter.SseEventBuilder reconnectTime(long reconnectTime) {
                throw new UnsupportedOperationException("SSE 原样帧不支持增量构建");
            }

            @Override
            public SseEmitter.SseEventBuilder comment(String comment) {
                throw new UnsupportedOperationException("SSE 原样帧不支持增量构建");
            }

            @Override
            public SseEmitter.SseEventBuilder data(Object object) {
                throw new UnsupportedOperationException("SSE 原样帧不支持增量构建");
            }

            @Override
            public SseEmitter.SseEventBuilder data(Object object, MediaType mediaType) {
                throw new UnsupportedOperationException("SSE 原样帧不支持增量构建");
            }
        };
    }

    private static void safeComplete(SseEmitter emitter) {
        try {
            emitter.complete();
        } catch (Exception e) {
            // 已抛过错的连接再 complete 也可能抛：这里必须吞掉，否则调度线程会被一条死连接带崩
            logger.debug("SSE complete 忽略异常：{}", e.toString());
        }
    }

    // ==================== 小工具 ====================

    private static final Comparator<Map<String, Object>> OLDEST_FIRST =
            Comparator.comparing((Map<String, Object> m) -> text(m.get("endTime")))
                    .thenComparing(PublicStreamService::itemKey);

    private static String pendingKey(Map<String, Object> item) {
        return text(item.get("endTime")) + "|" + itemKey(item);
    }

    /** 聚合项的稳定标识：优先 aggId，缺失时退化成"时间+来源+类型+规则" */
    private static String itemKey(Map<String, Object> item) {
        String aggId = text(item.get("aggId"));
        if (!aggId.isEmpty()) {
            return aggId;
        }
        return text(item.get("endTime")) + "|" + text(item.get("srcIp")) + "|"
                + text(item.get("type")) + "|" + text(item.get("ruleName"));
    }

    private static String text(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private static String enumName(Object value) {
        if (value instanceof Enum<?> e) {
            return e.name();
        }
        return text(value);
    }

    private static int count(Object value) {
        if (value instanceof Number n) {
            return n.intValue();
        }
        try {
            return Integer.parseInt(text(value));
        } catch (Exception e) {
            return 1;
        }
    }

    private static String json(Object value) {
        try {
            return JSON.writeValueAsString(value);
        } catch (Exception e) {
            // 帧里只有字符串/数字，理论上不会失败；真失败也发一个空对象，让前端自己降级
            logger.warn("SSE 帧 JSON 序列化失败：{}", e.getMessage());
            return "{}";
        }
    }

    /** 供测试与监控：当前在线连接数 */
    int onlineCount() {
        return emitters.size();
    }

    /** 保留给排查：pending 队列长度（不参与对外契约） */
    int pendingCount() {
        synchronized (lock) {
            return pending.size();
        }
    }

    /** 供测试断言"水印是否只前进"（不参与对外契约） */
    String watermark() {
        synchronized (lock) {
            return watermarkEndTime;
        }
    }

    /** 测试辅助：清空调度状态，避免多个用例共用一个服务时互相污染 */
    void resetForTest() {
        synchronized (lock) {
            watermarkEndTime = "";
            watermarkIds.clear();
            pending.clear();
            pendingKeys.clear();
            lastPollMillis = -1L;
            lastPingMillis = -1L;
        }
    }
}
