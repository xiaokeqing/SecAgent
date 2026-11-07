package org.example.integration.suricata;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.example.core.model.SecurityAlert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Suricata 事件的最近窗口缓存 + 反查。
 *
 * <h3>为什么按类型各放一个环形缓冲</h3>
 * <p>eve.json 里 flow 的条数远多于 alert/tls（每个连接一条 flow，而 tls 只覆盖加密流量），
 * 如果混在一条缓冲里，高流量的 flow 会把同窗口内的 alert 和 tls 全挤出去，
 * 于是"最近 N 分钟的 SNI 分布"在繁忙网络上永远为空。分桶后各类型各占自己的容量，
 * 总量仍有上界（5 类 × capacity），不会因分桶变成无界。
 *
 * <h3>为什么查询都在快照上做</h3>
 * <p>反查是 O(窗口内条数) 的线性扫描：窗口通常只有几分钟、几万条，一次就是几毫秒；
 * 相比维护增量索引（端口→连接、IP→连接），省掉了一整套"索引与淘汰如何保持一致"的正确性负担。
 * 快照在锁内复制，查询期间写入不会看到半更新的数组。
 *
 * <p>所有查询在无数据、参数非法、无时间戳时返回空列表，绝不抛异常：
 * 这是给 HTTP 层用的，查不到就是查不到，不该变成 500。
 */
public final class SuricataEventStore {

    private static final Logger logger = LoggerFactory.getLogger(SuricataEventStore.class);

    /**
     * 快照序列化器：record 直接用 Jackson，Instant 要 JavaTimeModule（默认 ObjectMapper
     * 不认 java.time，且会把 Instant 写成时间戳 —— 关掉时间戳，快照文件才可读/可 grep）。
     * 配置完成后 ObjectMapper 是线程安全的，静态共用一个即可。
     */
    private static final ObjectMapper SNAPSHOT_MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    private final int capacity;
    private final BoundedRingBuffer<FlowEvent> flows;
    private final BoundedRingBuffer<HttpEvent> httpEvents;
    private final BoundedRingBuffer<DnsEvent> dnsEvents;
    private final BoundedRingBuffer<TlsEvent> tlsEvents;
    private final BoundedRingBuffer<AlertEvent> alertEvents;

    public SuricataEventStore(int capacity) {
        this.capacity = capacity;
        this.flows = new BoundedRingBuffer<>(capacity);
        this.httpEvents = new BoundedRingBuffer<>(capacity);
        this.dnsEvents = new BoundedRingBuffer<>(capacity);
        this.tlsEvents = new BoundedRingBuffer<>(capacity);
        this.alertEvents = new BoundedRingBuffer<>(capacity);
    }

    public int capacity() {
        return capacity;
    }

    /** 按运行时类型分发到对应桶；不认识的类型静默忽略。 */
    public void add(EveEvent event) {
        if (event == null) {
            return;
        }
        if (event instanceof FlowEvent f) {
            flows.add(f);
        } else if (event instanceof HttpEvent h) {
            httpEvents.add(h);
        } else if (event instanceof DnsEvent d) {
            dnsEvents.add(d);
        } else if (event instanceof TlsEvent t) {
            tlsEvents.add(t);
        } else if (event instanceof AlertEvent a) {
            alertEvents.add(a);
        }
    }

    /** 一次取走全部类型的快照，供"按需导出"这类只遍历一次的调用方少拿几次锁。 */
    public List<EveEvent> allSnapshot() {
        List<EveEvent> all = new ArrayList<>();
        all.addAll(flows.snapshot());
        all.addAll(httpEvents.snapshot());
        all.addAll(dnsEvents.snapshot());
        all.addAll(tlsEvents.snapshot());
        all.addAll(alertEvents.snapshot());
        return all;
    }

    public int flowCount() {
        return flows.size();
    }

    public int tlsCount() {
        return tlsEvents.size();
    }

    public long totalIngested() {
        return flows.totalAdded() + httpEvents.totalAdded() + dnsEvents.totalAdded()
                + tlsEvents.totalAdded() + alertEvents.totalAdded();
    }

    public List<SecurityAlert> recentAlerts(int limit) {
        if (limit <= 0) {
            return List.of();
        }
        List<AlertEvent> snapshot = alertEvents.snapshot();
        List<SecurityAlert> out = new ArrayList<>(Math.min(limit, snapshot.size()));
        for (int i = snapshot.size() - 1; i >= 0 && out.size() < limit; i--) {
            out.add(snapshot.get(i).alert());
        }
        return out;
    }

    /**
     * 该 IP 作为源或目标的最近连接（新 → 旧）。
     *
     * <p>两个方向都算"与该 IP 有关"：只查源地址会漏掉"谁在连我"（入站），
     * 只查目标地址会漏掉"我在连谁"（出站），而排障几乎总是问"这台机器跟谁通过话"。
     */
    public List<FlowEvent> connectionsByIp(String ip, int limit) {
        if (ip == null || ip.isBlank() || limit <= 0) {
            return List.of();
        }
        String needle = ip.trim();
        List<FlowEvent> snapshot = flows.snapshot();
        List<FlowEvent> out = new ArrayList<>(Math.min(limit, snapshot.size()));
        for (int i = snapshot.size() - 1; i >= 0 && out.size() < limit; i--) {
            FlowEvent f = snapshot.get(i);
            if (needle.equals(f.srcIp()) || needle.equals(f.destIp())) {
                out.add(f);
            }
        }
        return out;
    }

    /** 最近 minutes 分钟内被访问最多的目标端口。 */
    public List<PortCount> topDestPorts(int minutes, int limit) {
        List<FlowEvent> window = windowed(flows.snapshot(), minutes, FlowEvent::ts);
        return topCounts(window, limit, FlowEvent::destPort, p -> p > 0, PortCount::new);
    }

    /** 最近 minutes 分钟内出现最多的 TLS SNI。 */
    public List<SniCount> topSni(int minutes, int limit) {
        List<TlsEvent> window = windowed(tlsEvents.snapshot(), minutes, TlsEvent::ts);
        return topCounts(window, limit, TlsEvent::sni, s -> !s.isBlank(), SniCount::new);
    }

    /** 最近 minutes 分钟内出现最多的客户端 JA3 指纹。 */
    public List<Ja3Count> ja3Stats(int minutes, int limit) {
        List<TlsEvent> window = windowed(tlsEvents.snapshot(), minutes, TlsEvent::ts);
        return topCounts(window, limit, TlsEvent::ja3Hash, s -> !s.isBlank(), Ja3Count::new);
    }

    // ==================== 内部实现 ====================

    /**
     * 取时间窗内的元素。
     *
     * <p>时间戳为空的事件不计入时间窗统计：它可能发生在窗口内也可能在三个月前，
     * 挪进"最近 5 分钟"就是编造；宁可少一条，也不让榜单的时间口径变得不可信。
     */
    private static <T> List<T> windowed(List<T> snapshot, int minutes, Function<T, Instant> tsOf) {
        if (minutes <= 0 || snapshot.isEmpty()) {
            return List.of();
        }
        Instant from = Instant.now().minus(Duration.ofMinutes(minutes));
        List<T> out = new ArrayList<>();
        for (T item : snapshot) {
            Instant ts = tsOf.apply(item);
            if (ts != null && !ts.isBefore(from)) {
                out.add(item);
            }
        }
        return out;
    }

    /**
     * 计数按次数降序、同次数按键升序（TreeMap 的天然顺序）后截断。
     *
     * <p>同次数时若用 HashMap 的遍历顺序，两次相同的请求可能给出不同的排序，
     * 前端列表会莫名跳动；固定次键排序让结果可复现。
     */
    private static <T, K, R> List<R> topCounts(List<T> items, int limit,
                                                Function<T, K> keyOf,
                                                java.util.function.Predicate<K> valid,
                                                java.util.function.BiFunction<K, Long, R> factory) {
        if (limit <= 0 || items.isEmpty()) {
            return List.of();
        }
        Map<K, Long> counts = new HashMap<>();
        for (T item : items) {
            K key = keyOf.apply(item);
            if (key != null && valid.test(key)) {
                counts.merge(key, 1L, Long::sum);
            }
        }
        List<Map.Entry<K, Long>> entries = new ArrayList<>(counts.entrySet());
        entries.sort(Comparator.<Map.Entry<K, Long>>comparingLong(Map.Entry::getValue).reversed()
                .thenComparing(e -> String.valueOf(e.getKey())));
        List<R> out = new ArrayList<>(Math.min(limit, entries.size()));
        for (Map.Entry<K, Long> e : entries) {
            if (out.size() >= limit) {
                break;
            }
            out.add(factory.apply(e.getKey(), e.getValue()));
        }
        return Collections.unmodifiableList(out);
    }

    // ==================== 快照落盘（重启不空） ====================

    /**
     * 把五个桶的当前内容写成快照文件，返回写入条数。
     *
     * <p>行格式：{@code 类型<TAB>JSON}。类型标签按桶归属取（而不是 {@code eventType()}），
     * 因为 flow 桶同时装着 "flow" 与 "netflow" 两种事件，回载时只认得同一个类。
     *
     * <p>先写同目录 .tmp 再原子替换：进程写到一半被杀，上一次的完整快照仍然可用。
     */
    public int saveSnapshot(Path path) throws IOException {
        List<EveEvent> events = allSnapshot();
        Path absolute = path.toAbsolutePath();
        Path parent = absolute.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Path tmp = absolute.resolveSibling(absolute.getFileName() + ".tmp");
        try (BufferedWriter writer = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
            for (EveEvent event : events) {
                writer.write(typeTag(event));
                writer.write('\t');
                writer.write(SNAPSHOT_MAPPER.writeValueAsString(event));
                writer.write('\n');
            }
        }
        try {
            Files.move(tmp, absolute, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            // 容器 overlay / 某些网络盘不支持原子 rename，退化为普通替换。
            Files.move(tmp, absolute, StandardCopyOption.REPLACE_EXISTING);
        }
        return events.size();
    }

    /**
     * 回载快照到本 store，返回成功读入的条数；文件不存在返回 0（首次启动的正常路径）。
     *
     * <p>单行坏了只跳过这一行：上次落盘可能正好被杀在最后一行中间，截断的末行不该让
     * 整份快照作废；未知类型标签同理（旧版本写的标签）。两条路径都只 WARN。
     */
    public int loadSnapshot(Path path) throws IOException {
        if (path == null || !Files.isRegularFile(path)) {
            return 0;
        }
        int loaded = 0;
        int skipped = 0;
        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }
                int tab = line.indexOf('\t');
                if (tab <= 0 || tab == line.length() - 1) {
                    skipped++;
                    continue;
                }
                EveEvent event = decode(line.substring(0, tab), line.substring(tab + 1));
                if (event == null) {
                    skipped++;
                    continue;
                }
                add(event);
                loaded++;
            }
        }
        if (skipped > 0) {
            logger.warn("Suricata 缓冲快照有 {} 行无法解析，已跳过：{}", skipped, path);
        }
        return loaded;
    }

    /** 快照行的类型标签：按桶归属取名，netflow 与 flow 同桶同标签。 */
    private static String typeTag(EveEvent event) {
        if (event instanceof FlowEvent) {
            return "flow";
        }
        if (event instanceof HttpEvent) {
            return "http";
        }
        if (event instanceof DnsEvent) {
            return "dns";
        }
        if (event instanceof TlsEvent) {
            return "tls";
        }
        if (event instanceof AlertEvent) {
            return "alert";
        }
        return "unknown";
    }

    private static EveEvent decode(String type, String json) {
        try {
            return switch (type) {
                case "flow" -> SNAPSHOT_MAPPER.readValue(json, FlowEvent.class);
                case "http" -> SNAPSHOT_MAPPER.readValue(json, HttpEvent.class);
                case "dns" -> SNAPSHOT_MAPPER.readValue(json, DnsEvent.class);
                case "tls" -> SNAPSHOT_MAPPER.readValue(json, TlsEvent.class);
                case "alert" -> SNAPSHOT_MAPPER.readValue(json, AlertEvent.class);
                default -> null;
            };
        } catch (IOException e) {
            logger.warn("Suricata 缓冲快照行反序列化失败（type={}）：{}", type, e.toString());
            return null;
        }
    }
}
