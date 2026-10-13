package org.example.accesslog;

import java.time.Clock;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 公开聚合端点的<b>内存滑动窗口聚合器</b>（写线程顺手累加，请求路径零 I/O）。
 *
 * <h3>为什么是内存聚合器，而不是"请求时读 access.jsonl"</h3>
 * RUNBOOK §23 的教训是"请求路径上做 I/O = 整站 502"；再加上访问日志是<b>内部数据面</b>
 * （含 IP），公开端点不该去读它。所以：由 {@link AccessLogWriter} 的写线程在落盘同一行时
 * 顺手喂这里，公开端点只读内存里的计数。
 *
 * <h3>固定内存上限（口径④，测试钉住常量）</h3>
 * <pre>
 * 24h 窗口：288 个 5 分钟桶          （24×60/5）
 * 每桶：requests + 5 个状态类 + 9 个路径类别 + 最多 24 个 UA 槽
 * 7 天：  7 个"天"聚合（每天 24 个整点计数）→ 7×24 = 168 格热力图
 * 全局 UA 命名上限：128 个（超出的只计数、不命名）
 * </pre>
 * 数字全部是常量，攻击者刷任何形态的 UA/路径都不可能让内存增长：
 * 路径维度是固定枚举（见 {@link WebStatsCategory}），UA 维度是"每桶 24 槽"的有界映射。
 * 最坏情况 ≈ 288×24 = 6912 条 UA 记录（约 1MB 量级），与请求数无关。
 *
 * <h3>确定性与线程安全</h3>
 * <ul>
 *   <li>输出排序全部确定（计数降序 → 名称升序；天/小时按时间升序），
 *       同一批输入永远得到同一段 JSON —— 这是 ETag/304 能生效的前提。</li>
 *   <li>{@link #record} 会被<b>写线程</b>与<b>回填线程</b>同时调用，{@link #snapshot} 会被请求线程调用，
 *       三者用同一把锁串行化。快照是"复制 + 排序"，不返回内部可变结构。</li>
 * </ul>
 *
 * <h3>窗口的时间口径</h3>
 * 时间来自日志行的 {@code ts}（ISO-8601 <b>带偏移量</b>）：
 * <ul>
 *   <li>24h 窗口/5 分钟桶按<b>瞬时</b>对齐（与服务器时区无关，跨时区迁移不会错位）；</li>
 *   <li>天/小时（byDay、heatmap）按日志行<b>自己带的偏移量</b>取本地日期与整点 ——
 *       与写日志那一侧的口径一致，迁移时区后历史数据仍落在它当时的日历格子里。</li>
 * </ul>
 * 代价是窗口按 5 分钟桶对齐（最老的 ≤5 分钟落在窗口外），文档与 {@code note} 里如实写明。
 */
public final class WebStatsAggregator {

    /** 24h 窗口 */
    public static final int WINDOW_SECONDS = 24 * 3600;
    /** 5 分钟桶（口径④建议值） */
    public static final int BUCKET_SECONDS = 300;
    /** 288 个桶覆盖 24 小时 */
    public static final int BUCKET_COUNT = WINDOW_SECONDS / BUCKET_SECONDS;
    /** 按天/热力图保留 7 天 */
    public static final int DAYS = 7;
    public static final int HOURS_PER_DAY = 24;
    /** 热力图总格数（7×24） */
    public static final int HOUR_CELLS = DAYS * HOURS_PER_DAY;
    /** 每个 5 分钟桶最多命名几个 UA（超出的只计数、不命名） */
    public static final int UA_SLOTS_PER_BUCKET = 24;
    /** 合并后最多命名几个不同 UA（超过门槛也不再加名字） */
    public static final int GLOBAL_UA_SLOTS = 128;
    /** 状态类个数：2xx / 3xx / 4xx / 5xx / other */
    public static final int STATUS_CLASSES = 5;

    private static final int CATEGORY_COUNT = WebStatsCategory.ALL.size();

    private final Object lock = new Object();
    private final Clock clock;
    private final int uaMaxChars;
    private final int uaSlotsPerBucket;
    private final int globalUaSlots;
    private final Bucket[] buckets = new Bucket[BUCKET_COUNT];
    private final Map<LocalDate, DayAgg> daily = new LinkedHashMap<>();

    private long droppedOutOfWindow;
    private long staleSlotSkips;

    /** 入榜门槛（口径⑤⑥：类别计数 ≥minCount 才入榜） */
    public record Thresholds(int minCount, int topCategories, int topUas) {

        public static Thresholds defaults() {
            return new Thresholds(5, 10, 5);
        }

        public Thresholds normalized() {
            return new Thresholds(Math.max(1, minCount), Math.max(1, topCategories), Math.max(0, topUas));
        }
    }

    /** 状态类计数（只到"类"，口径⑥：不给具体码） */
    public record StatusClass(long c2xx, long c3xx, long c4xx, long c5xx, long other) {

        public static final StatusClass EMPTY = new StatusClass(0L, 0L, 0L, 0L, 0L);

        public long total() {
            return c2xx + c3xx + c4xx + c5xx + other;
        }
    }

    /** 类别计数（category 是 {@link WebStatsCategory#wireName()}） */
    public record CategoryCount(String category, long count) {
    }

    /** UA 计数（ua 已清洗/截断/去 IP） */
    public record UaCount(String ua, long count) {
    }

    /** 一天的汇总（date = 日志行自己的本地日期） */
    public record DayStat(String date, long requests, StatusClass statusClass) {
    }

    /** 热力图一格（date + 本地整点） */
    public record HourStat(String date, int hour, long requests) {
    }

    /** 一次快照（**不可变**：调用方只读） */
    public record Snapshot(long requests,
                           StatusClass statusClass,
                           List<CategoryCount> topCategories,
                           List<UaCount> topUas,
                           List<DayStat> byDay,
                           List<HourStat> heatmap,
                           long uaOverflowRows,
                           long uaKeysDropped,
                           long droppedOutOfWindow,
                           long staleSlotSkips) {

        public static Snapshot empty() {
            return new Snapshot(0L, StatusClass.EMPTY, List.of(), List.of(), List.of(), List.of(),
                    0L, 0L, 0L, 0L);
        }
    }

    public WebStatsAggregator() {
        this(Clock.systemDefaultZone(), ZoneId.systemDefault(), 60, UA_SLOTS_PER_BUCKET, GLOBAL_UA_SLOTS);
    }

    /**
     * @param uaMaxChars        UA 截断长度（口径：60 字符）
     * @param uaSlotsPerBucket  每个 5 分钟桶最多命名几个 UA（内存上限的一部分）
     * @param globalUaSlots     合并后最多命名几个 UA（内存上限的一部分）
     */
    public WebStatsAggregator(Clock clock, ZoneId zone, int uaMaxChars,
                              int uaSlotsPerBucket, int globalUaSlots) {
        this.clock = clock == null ? Clock.systemDefaultZone() : clock;
        this.uaMaxChars = Math.max(8, uaMaxChars);
        this.uaSlotsPerBucket = Math.max(1, uaSlotsPerBucket);
        this.globalUaSlots = Math.max(1, globalUaSlots);
        for (int i = 0; i < buckets.length; i++) {
            buckets[i] = new Bucket();
        }
    }

    /** 写线程/回填线程的唯一入口：一行访问日志 → 计数（O(1)，无 I/O） */
    public void record(OffsetDateTime ts, int status, String path, String ua) {
        if (ts == null) {
            synchronized (lock) {
                droppedOutOfWindow++;
            }
            return;
        }
        LocalDate date = ts.toLocalDate();
        LocalDate today = LocalDate.now(clock);
        if (date.toEpochDay() < today.toEpochDay() - (DAYS - 1L)) {
            // 7 天窗口外的历史行：只计数、不占内存（回填读到了 7 天前的轮转文件时走这条）
            synchronized (lock) {
                droppedOutOfWindow++;
            }
            return;
        }

        long epoch = ts.toEpochSecond();
        long start = Math.floorDiv(epoch, BUCKET_SECONDS) * BUCKET_SECONDS;
        int slot = (int) Math.floorMod(start / BUCKET_SECONDS, (long) BUCKET_COUNT);
        int statusClass = statusClassIndex(status);
        int category = WebStatsCategory.classify(path, status).ordinal();
        String uaKey = sanitizeUa(ua);
        int hour = Math.max(0, Math.min(HOURS_PER_DAY - 1, ts.getHour()));

        synchronized (lock) {
            Bucket b = buckets[slot];
            if (b.startSecond < start) {
                b.reset(start);
            }
            // 环槽复用必须"只许往新的方向走"：回填是按文件逐行读的（活动文件今天、轮转文件更早），
            // 一条 24h/48h 前的记录会与某个"还活着的"桶撞在同一个下标上。若直接重置，
            // 就会把窗口内的新数据抹掉 —— 而这个错误不会报错，只会让最近 24 小时少了几个桶。
            // 撞槽的旧记录必然 <=now-24h（两个起点相差 24h 的整数倍），本来就在窗口外，跳过它即可；
            // 但按天/热力图（7 天口径）仍要照常累加，所以下面不是 return。
            boolean inBucket = b.startSecond == start;
            if (inBucket) {
                b.requests++;
                b.statusClass[statusClass]++;
                b.categories[category]++;
                if (!uaKey.isEmpty()) {
                    Long cur = b.uas.get(uaKey);
                    if (cur != null) {
                        b.uas.put(uaKey, cur + 1L);
                    } else if (b.uas.size() < uaSlotsPerBucket) {
                        b.uas.put(uaKey, 1L);
                    } else {
                        b.uaOverflow++;
                    }
                }
            } else {
                staleSlotSkips++;
            }

            DayAgg day = daily.get(date);
            if (day == null) {
                if (daily.size() >= DAYS + 2) {
                    removeOldestDay();
                }
                day = new DayAgg();
                daily.put(date, day);
            }
            day.requests++;
            day.statusClass[statusClass]++;
            day.hours[hour]++;
        }
    }

    /**
     * 生成快照（纯内存复制 + 排序；不做任何 I/O）。
     *
     * @param now        "现在"（窗口右端；由调用方传入，便于测试固定时间）
     * @param thresholds 入榜门槛与榜长（null → 默认 5 / 10 / 5）
     */
    public Snapshot snapshot(OffsetDateTime now, Thresholds thresholds) {
        OffsetDateTime at = now == null ? OffsetDateTime.now(clock) : now;
        Thresholds t = (thresholds == null ? Thresholds.defaults() : thresholds).normalized();
        long nowEpoch = at.toEpochSecond();
        // 窗口 = "最近 288 个 5 分钟桶"：桶起点严格晚于 now-24h。
        // 为什么不是 >=：288 个桶只能装下 288 个不同的桶起点，而 [now-24h, now] 里
        // 恰好可能有 289 个（环的下标 mod 288 会让首尾两个桶撞在同一个槽上互相覆盖）。
        // 代价是最老的 ≤5 分钟落在窗口外 —— 如实写在 note 里（"按 5 分钟桶对齐"）。
        long oldestExclusive = nowEpoch - WINDOW_SECONDS;

        long[] statusClass = new long[STATUS_CLASSES];
        long[] categories = new long[CATEGORY_COUNT];
        Map<String, long[]> uas = new LinkedHashMap<>();
        long requests = 0L;
        long uaOverflow = 0L;
        long uaKeysDropped = 0L;
        List<DayStat> byDay = new ArrayList<>();
        List<HourStat> heatmap = new ArrayList<>();
        long dropped;
        long stale;

        synchronized (lock) {
            for (Bucket b : buckets) {
                if (b.startSecond <= oldestExclusive || b.startSecond > nowEpoch) {
                    continue;
                }
                requests += b.requests;
                for (int i = 0; i < STATUS_CLASSES; i++) {
                    statusClass[i] += b.statusClass[i];
                }
                for (int i = 0; i < CATEGORY_COUNT; i++) {
                    categories[i] += b.categories[i];
                }
                uaOverflow += b.uaOverflow;
                for (Map.Entry<String, Long> e : b.uas.entrySet()) {
                    long[] agg = uas.get(e.getKey());
                    if (agg != null) {
                        agg[0] += e.getValue();
                    } else if (uas.size() < globalUaSlots) {
                        uas.put(e.getKey(), new long[]{e.getValue()});
                    } else {
                        uaKeysDropped++;
                    }
                }
            }

            LocalDate today = LocalDate.now(clock);
            long oldestEpochDay = today.toEpochDay() - (DAYS - 1L);
            List<LocalDate> dates = new ArrayList<>(daily.keySet());
            dates.sort(Comparator.naturalOrder());
            for (LocalDate d : dates) {
                if (d.toEpochDay() < oldestEpochDay) {
                    continue;
                }
                DayAgg a = daily.get(d);
                if (a == null || a.requests <= 0) {
                    continue;
                }
                byDay.add(new DayStat(d.toString(), a.requests, statusOf(a.statusClass)));
                for (int h = 0; h < HOURS_PER_DAY; h++) {
                    if (a.hours[h] > 0) {
                        heatmap.add(new HourStat(d.toString(), h, a.hours[h]));
                    }
                }
            }
            dropped = droppedOutOfWindow;
            stale = staleSlotSkips;
        }

        List<CategoryCount> topCategories = new ArrayList<>();
        for (int i = 0; i < CATEGORY_COUNT; i++) {
            if (categories[i] >= t.minCount()) {
                topCategories.add(new CategoryCount(WebStatsCategory.ALL.get(i).wireName(), categories[i]));
            }
        }
        topCategories.sort(Comparator.comparingLong(CategoryCount::count).reversed()
                .thenComparing(CategoryCount::category));
        if (topCategories.size() > t.topCategories()) {
            topCategories = new ArrayList<>(topCategories.subList(0, t.topCategories()));
        }

        List<UaCount> topUas = new ArrayList<>();
        for (Map.Entry<String, long[]> e : uas.entrySet()) {
            if (e.getValue()[0] >= t.minCount()) {
                topUas.add(new UaCount(e.getKey(), e.getValue()[0]));
            }
        }
        topUas.sort(Comparator.comparingLong(UaCount::count).reversed().thenComparing(UaCount::ua));
        if (topUas.size() > t.topUas()) {
            topUas = new ArrayList<>(topUas.subList(0, t.topUas()));
        }

        return new Snapshot(requests, statusOf(statusClass), topCategories, topUas, byDay, heatmap,
                uaOverflow, uaKeysDropped, dropped, stale);
    }

    /** 便于测试/自检：当前 24h 窗口的桶数上限与 UA 槽上限（== 常量） */
    public int bucketCount() {
        return BUCKET_COUNT;
    }

    public int uaSlotsPerBucket() {
        return uaSlotsPerBucket;
    }

    public int globalUaSlots() {
        return globalUaSlots;
    }

    /** 当前内存里实际被占用的 UA 槽总数（内存上限自检用：必须 ≤ 288×24=6912） */
    public int occupiedUaSlots() {
        synchronized (lock) {
            int n = 0;
            for (Bucket b : buckets) {
                n += b.uas.size();
            }
            return n;
        }
    }

    /** 当前按天的条目数（必须 ≤ 7+2） */
    public int dayEntries() {
        synchronized (lock) {
            return daily.size();
        }
    }

    /** 状态码 → 类别下标（找不到的一律进 "other"） */
    static int statusClassIndex(int status) {
        if (status >= 200 && status <= 299) {
            return 0;
        }
        if (status >= 300 && status <= 399) {
            return 1;
        }
        if (status >= 400 && status <= 499) {
            return 2;
        }
        if (status >= 500 && status <= 599) {
            return 3;
        }
        return 4;
    }

    static StatusClass statusOf(long[] c) {
        return new StatusClass(c[0], c[1], c[2], c[3], c[4]);
    }

    /** 本类的 UA 清洗口径（供单测直接断言）：控制字符 → 空格、去 IP 字面量、截断到 uaMaxChars */
    String sanitizeUa(String raw) {
        String cleaned = WebStatsSanitizer.cleanText(raw, 200);
        if (cleaned.isEmpty()) {
            return "";
        }
        return WebStatsSanitizer.cleanText(WebStatsSanitizer.scrubIpLiterals(cleaned), uaMaxChars);
    }

    private void removeOldestDay() {
        LocalDate oldest = null;
        for (LocalDate d : daily.keySet()) {
            if (oldest == null || d.isBefore(oldest)) {
                oldest = d;
            }
        }
        if (oldest != null) {
            daily.remove(oldest);
        }
    }

    /** 一个 5 分钟桶（只有写线程/快照在锁内访问） */
    private static final class Bucket {
        long startSecond = Long.MIN_VALUE;
        long requests;
        final long[] statusClass = new long[STATUS_CLASSES];
        final long[] categories = new long[CATEGORY_COUNT];
        final Map<String, Long> uas = new LinkedHashMap<>();
        long uaOverflow;

        void reset(long start) {
            startSecond = start;
            requests = 0L;
            Arrays.fill(statusClass, 0L);
            Arrays.fill(categories, 0L);
            uas.clear();
            uaOverflow = 0L;
        }
    }

    /** 一天的聚合（requests + 状态类 + 24 个整点计数） */
    private static final class DayAgg {
        long requests;
        final long[] statusClass = new long[STATUS_CLASSES];
        final long[] hours = new long[HOURS_PER_DAY];
    }
}
