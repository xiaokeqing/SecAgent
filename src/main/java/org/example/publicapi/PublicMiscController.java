package org.example.publicapi;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.example.core.model.AlertSeverity;
import org.example.core.model.AlertSource;
import org.example.core.model.AlertType;
import org.example.core.model.SecurityAlert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

/**
 * 评测报告、口令自查、Web 统计与攻击故事域：/eval、/password、/webstats、/stories、/story、/story?id=。
 *
 * <p>本类是原 {@code PublicApiController}（已删除的委托门面）拆分出的按域 controller 之一：只做搬移，路径、参数、
 * 响应字段、状态码、缓存头与限流口径与原 god controller 逐字一致。
 * 共享状态与通用工具（快照缓存、出关脱敏、信封/缓存头）在 {@link PublicApiSupport} 里，
 * 由构造器注入；历史门面 {@code PublicApiController} 已删除，测试改为直接装配这些 controller。
 */
@RestController
@RequestMapping("/api/public")
public class PublicMiscController {

    private static final Logger logger = LoggerFactory.getLogger(PublicMiscController.class);

    private final PublicApiSupport support;

    /** /story 进程内缓存的 TTL：60 秒（与 /metrics 的 60s 快照同一口径）。 */
    static final long STORY_CACHE_TTL_MS = 60_000L;
    /** 缓存格数上限：key = 端点形状 + window + 来源，正常轮换只有十几种。 */
    static final int STORY_CACHE_MAX_ENTRIES = 32;

    /**
     * /story 与 /story?id= 共用的进程内缓存：读无锁，写用 volatile 整表替换 + 双检锁。
     *
     * <p>为什么整表替换而不是给每个 key 一个锁：读路径是绝大多数请求，必须无锁；写只在
     * 未命中/过期时发生，表最多 {@value #STORY_CACHE_MAX_ENTRIES} 格，复制一张小表的代价
     * 远小于每次请求都抢锁。键里带 window 是必须的 —— 不同窗口查的是不同的候选池与事件，
     * 只按来源存会让 6h 的结果顶掉 24h 的（同 {@code /stories} 不共用一个 Snapshot 的理由）。
     */
    private volatile Map<String, StoryCacheEntry> storyCache = Map.of();
    private final Object storyCacheLock = new Object();

    private record StoryCacheEntry(Map<String, Object> payload, long storedAtMs) {
    }

    public PublicMiscController(PublicApiSupport support) {
        this.support = support;
    }

    /**
     * <b>AI 质量真值</b>（C2 面板要的）：评测脚本产出的那份报告。
     *
     * <p>这些数字（要点命中 / 拒答 / 严格 / 引用 / 口癖命中率 + 样本量）是**评测跑出来的**，
     * 不是本服务能算的：它们由 {@code scripts/eval/} 那批离线脚本产出。所以本端点的口径是
     * "<b>把那份报告如实端出来</b>"——文件在就给值，不在就 {@code available=false} + 原因，
     * 绝不用 0 冒充"没测过"、也不用旧报告冒充新报告（旧报告由报告里的 {@code generatedAt} 自证）。
     */
    @GetMapping({"/eval", "/eval.js"})
    public ResponseEntity<Map<String, Object>> evalReport(HttpServletRequest req, HttpServletResponse res) {
        if (!support.rateLimiter.allow(support.clientIp(req))) {
            return support.tooMany(res);
        }
        return support.ok(support.evalCache.get(support.cacheSeconds, this::buildEval), res);
    }

    Map<String, Object> buildEval() {
        Map<String, Object> out = new LinkedHashMap<>();
        if (support.evalReportFile == null || support.evalReportFile.isBlank()) {
            out.put("available", false);
            out.put("reason", "EVAL_REPORT_NOT_CONFIGURED");
            out.put("note", "未配置 app.public-api.eval-report-file：本服务不自己算评测数字，"
                    + "也不以内置样本或 0 值顶替（0 会被误读成'测过但全错'）。");
            return out;
        }
        Object parsed = support.readJsonOrNull(support.evalReportFile);
        if (parsed == null) {
            out.put("available", false);
            out.put("reason", "EVAL_REPORT_UNREADABLE");
            out.put("note", "评测报告文件不存在或不是合法 JSON：" + support.evalReportFile);
            return out;
        }
        if (!(parsed instanceof Map<?, ?> m)) {
            out.put("available", false);
            out.put("reason", "EVAL_REPORT_SHAPE");
            out.put("note", "评测报告顶层必须是 JSON 对象");
            return out;
        }
        out.put("available", true);
        for (String k : PublicApiSupport.EVAL_REPORT_KEYS) {
            if (m.containsKey(k)) {
                out.put(k, m.get(k));
            }
        }
        out.put("source", support.evalReportFile);
        out.put("note", "数字来自离线评测报告原文（未重算、未四舍五入、未合并）；"
                + "唯一改动是把白名单字段挑出来。报告自身的 generatedAt 决定它有多新。");
        return out;
    }

    /**
     * <b>值得看的来源</b>：把同一个来源的「告警 → 诱饵端口 → 蜜罐登录 → 处置审计」四段
     * 各自的条数与首末时间列出来，并给出 <b>{@code gaps[]}</b>（哪几段确实没有数据）。
     *
     * <h3>它和 {@code /alerts} 的区别</h3>
     * {@code /alerts} 回答"现在有什么告警"（一条一条），本端点回答"哪些来源的故事是完整的"
     * （一个来源一行）。后者是博客"看一次攻击全过程"页面的入口列表。
     *
     * <h3>口径（三条都写进了测试）</h3>
     * <ol>
     *   <li><b>不许编</b>：某一段没有数据就写进 {@code gaps[]}；那一段本身"接没接上"
     *       由 {@code coverage.stageStatus} 单独回答（{@code OK} / {@code NOT_WIRED} / {@code UNKNOWN}）——
     *       "没接入"与"没发生"必须能分开读；</li>
     *   <li><b>内网/保留地址与我方 IP 不进榜</b>：它们在公开口径里都写成「内网/未知」，
     *       几个不同的内网地址会被合并成同一个显示值（实测 24h 里某个内网地址有 4 万+ 条），
     *       画出来就是"内网/未知 打了我们 4 万次"；排除数在 {@code coverage} 里如实给出；</li>
     *   <li><b>IP 按既有口径显示</b>（{@link PublicIpPolicy}，默认真实地址；掩码态逐字节回归）。</li>
     * </ol>
     *
     * <p>复用既有外壳：同一个限流器（20 次/分钟）、同一个 CORS 白名单、同一个 ETag 过滤器、
     * 同一个 15 秒 {@link Snapshot}（按 window 分开存）、同一个 {@code ok(...)}
     * （因此自动带 {@code ipDisclosure} 与内部资产名过滤），不新增任何公开面机制。
     */
    @GetMapping({"/stories", "/stories.js"})
    public ResponseEntity<Map<String, Object>> stories(
            @RequestParam(value = "window", required = false) String window,
            @RequestParam(value = "limit", required = false) String limit,
            HttpServletRequest req, HttpServletResponse res) {
        if (!support.rateLimiter.allow(support.clientIp(req))) {
            return support.tooMany(res);
        }
        Integer hours = AttackStoryService.parseWindowHours(window);
        if (hours == null) {
            return support.badRequest(res, "WINDOW_NOT_SUPPORTED",
                    "不支持的 window（只实现了 " + AttackStoryService.SUPPORTED_WINDOWS.stream()
                            .map(AttackStoryService::windowLabel).reduce((a, b) -> a + "/" + b).orElse("")
                            + "；其它窗口没有数据源验证，不猜）");
        }
        if (support.attackStoryService == null) {
            return support.ok(storyDisabled(hours, null), res);
        }
        // 缓存与 limit 归一都在 AttackStoryService 里（它按 window / src 分开存，
        // 单个 Snapshot 只存一份值，用在这里会把不同窗口的结果互相顶掉）
        return support.ok(support.attackStoryService.stories(hours, support.attackStoryService.parseLimit(limit)), res);
    }

    /**
     * <b>一个来源的事件流</b>：{@code ts / stage / kind / summary / severity 或 outcome}，
     * 按时间升序合并四段；外加每段的 {@code coverage}（查到多少条、哪些段读不到/未接入 + 原因）。
     *
     * <h3>为什么只服务"候选池里的来源"</h3>
     * 候选池 = 同一窗口内 {@code /stories} 用的那份聚合结果（最多 {@code top-sources} 个）。
     * 若允许任意 {@code src}，这个端点就变成"随便给个 IP 就能问'他有没有打过我们'"的查询器 ——
     * 那本身就是情报泄露，而且与"给榜上的攻击源画时间线"是两件事。
     * 不在池里一律 <b>404</b>（与 {@code /alerts/{aggId}} 的 404 同一形状）。
     *
     * <h3>只给摘要与结论</h3>
     * 规则描述文本固定顺序处理：<b>先隐口令</b>（与开关无关）→ <b>再按 IP 口径</b> → 截断；
     * 索引查询本身就是字段白名单（{@code data.password} / {@code data.message} / {@code full_log}
     * 根本不进入进程）。蜜罐命令时间线没有数据源 → {@code commandsAvailable=false}（不编）。
     */
    @GetMapping({"/story", "/story.js"})
    public ResponseEntity<Map<String, Object>> story(
            @RequestParam(value = "src", required = false) String src,
            @RequestParam(value = "window", required = false) String window,
            HttpServletRequest req, HttpServletResponse res) {
        if (!support.rateLimiter.allow(support.clientIp(req))) {
            return support.tooMany(res);
        }
        Integer hours = AttackStoryService.parseWindowHours(window);
        if (hours == null) {
            return support.badRequest(res, "WINDOW_NOT_SUPPORTED",
                    "不支持的 window（只实现了 " + AttackStoryService.SUPPORTED_WINDOWS.stream()
                            .map(AttackStoryService::windowLabel).reduce((a, b) -> a + "/" + b).orElse("")
                            + "）");
        }
        String ip = src == null ? "" : src.trim();
        if (ip.isEmpty()) {
            return support.badRequest(res, "MISSING_SRC", "缺少 src 参数（要查哪一个来源）");
        }
        if (support.attackStoryService == null) {
            return support.ok(storyDisabled(hours, ip), res);
        }
        // 只接受"公网字面量"这一种形状：形状不对直接 400，不拿它去查任何东西
        if (!AttackStoryService.isPublicIp(ip)) {
            return support.badRequest(res, "INVALID_SRC",
                    "src 必须是观测到的公网来源地址（IPv4/IPv6 字面量）；内网/保留地址不进入故事线");
        }
        Map<String, Object> data = cachedStory(storyCacheKey("story", ip, hours),
                () -> support.attackStoryService.story(ip, hours));
        if (data == null) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("code", 404);
            body.put("message", "该来源不在当前窗口的候选池里（可能是窗口外、我方 IP、内网地址，"
                    + "或这一段没有它的记录）；请先看 /api/public/stories");
            body.put("reason", "SOURCE_NOT_IN_WINDOW");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(body);
        }
        return support.ok(data, res);
    }

    /**
     * <b>一个 IP 的攻击链时间线（前端时间线视图专用，{@code ?id=} 变体）</b>。
     *
     * <p>与上面 {@code /story?src=} 的关系：同一条数据通路、同一个候选池口径
     * （{@link AttackStoryService#story(String, int)}），区别只在投影 —— 老端点给
     * {@code stages/coverage/gaps} 这类"覆盖度"字段，供"攻击故事"详情页解释每段接没接上；
     * 本变体只给前端时间线要的扁平 {@code events[]}，字段名按时间线约定
     * （{@code time/kind/rule/src/sev/count/detail}），并附四档严重度计数。
     *
     * <h3>形状约定（写进了 {@code PublicStoryControllerTest}）</h3>
     * <ul>
     *   <li>事件按时间<b>正序</b>，最多 {@value #TIMELINE_MAX_EVENTS} 条；{@code total} 是窗口内真实条数，
     *       不因截断而改小；</li>
     *   <li>数据源不可用 / 服务未装配 → {@code available:false} + {@code reason:"数据源不可用"}，
     *       {@code total:0}、{@code events:[]}、四档计数全 0 —— 不拿样本或 0 值冒充"没有攻击"；</li>
     *   <li>{@code id} 按 {@link PublicIpPolicy} 口径显示；{@code src} 用同一个显示值；</li>
     *   <li>复用同一个限流器、CORS 白名单、ETag 过滤器与 {@code ok(...)}（自动带 {@code ipDisclosure}
     *       与内部资产名过滤），不新增任何公开面机制。</li>
     * </ul>
     *
     * <p>用 {@code params="id"} 与既有的 {@code /story?src=} 区分：不带 {@code id} 的请求仍走老 handler，
     * 因此两个契约可以共存于同一路径；显式同时带 {@code id} 与 {@code src} 时本变体优先。
     *
     * <p>窗口参数同时接受 {@code window} 与 {@code hours}（前端时间线卡按字段名写成
     * {@code ?id=…&hours=24}）；两者都缺省 24h，同时出现时以 {@code window} 为准。
     * 取值仍只允许 {@link AttackStoryService#SUPPORTED_WINDOWS}，不认识的窗口直接 400。
     */
    @GetMapping(value = {"/story", "/story.js"}, params = "id")
    public ResponseEntity<Map<String, Object>> storyTimeline(
            @RequestParam(value = "id", required = false) String id,
            @RequestParam(value = "window", required = false) String window,
            @RequestParam(value = "hours", required = false) String hoursParam,
            HttpServletRequest req, HttpServletResponse res) {
        if (!support.rateLimiter.allow(support.clientIp(req))) {
            return support.tooMany(res);
        }
        String windowSpec = window != null && !window.isBlank() ? window : hoursParam;
        Integer hours = AttackStoryService.parseWindowHours(windowSpec);
        if (hours == null) {
            return support.badRequest(res, "WINDOW_NOT_SUPPORTED",
                    "不支持的 window（只实现了 " + AttackStoryService.SUPPORTED_WINDOWS.stream()
                            .map(AttackStoryService::windowLabel).reduce((a, b) -> a + "/" + b).orElse("")
                            + "；其它窗口没有数据源验证，不猜）");
        }
        String ip = id == null ? "" : id.trim();
        if (ip.isEmpty()) {
            return support.badRequest(res, "MISSING_ID",
                    "缺少 id 参数：要画时间线的 IP，例如 /api/public/story?id=45.155.205.233");
        }
        // 与老 /story 同一个公网字面量口径：形状不对直接 400，不拿它去查任何东西
        if (!AttackStoryService.isPublicIp(ip)) {
            return support.badRequest(res, "INVALID_IP",
                    "id 必须是公网 IP 字面量（IPv4/IPv6）；内网/保留地址、域名、带端口与网段写法一律不接受");
        }
        // 连投影结果一起缓存：window.start/end 每次请求都按"现在"算，只缓存上游 data 的话
        // 响应体每秒都在变，ETag 跟着每秒变 ⇒ 再验证永远拿不到 304。整份缓存 60s 后
        // 响应体逐字节稳定，PublicEtagFilter 才能把重复请求判成 304。
        return support.ok(cachedStory(storyCacheKey("timeline", ip, hours),
                () -> buildStoryTimeline(ip, hours)), res);
    }

    /** 把 {@link AttackStoryService#story(String, int)} 的载荷投影成时间线形状；null/不可用一律如实降级。 */
    Map<String, Object> buildStoryTimeline(String ip, int hours) {
        LocalDateTime now = LocalDateTime.now();
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("id", support.policy().display(ip));
        Map<String, Object> story = support.attackStoryService == null ? null : support.attackStoryService.story(ip, hours);
        if (story == null || !Boolean.TRUE.equals(story.get("available"))) {
            return timelineUnavailable(data, hours, now);
        }

        List<?> rawEvents = story.get("events") instanceof List<?> l ? l : List.of();
        List<Map<String, Object>> events = new ArrayList<>();
        Map<String, Integer> severity = emptySeverity();
        for (Object raw : rawEvents) {
            if (!(raw instanceof Map<?, ?> m)) {
                continue;
            }
            String sev = timelineText(m.get("severity"));
            if (sev != null && severity.containsKey(sev)) {
                severity.merge(sev, 1, Integer::sum);
            }
            if (events.size() >= PublicApiSupport.TIMELINE_MAX_EVENTS) {
                continue;
            }
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("time", timelineText(m.get("ts")));
            // stage 是机器可读的四段标识（alerts/decoyPorts/honeypotLogins/auditActions）
            event.put("kind", timelineText(m.get("stage")));
            // kind 是 ATT&CK 式的事件类型（暴力破解/诱饵端口/登录尝试/处置动作）
            event.put("rule", timelineText(m.get("kind")));
            event.put("src", support.policy().display(ip));
            event.put("sev", sev);
            event.put("count", 1);
            event.put("detail", timelineText(m.get("summary")));
            events.add(event);
        }
        // 服务端已按 ts 升序排过；这里再排一次，保证"本端点按时间正序"不依赖上游实现细节
        events.sort(Comparator.comparing((Map<String, Object> e) -> (String) e.get("time"),
                Comparator.nullsLast(Comparator.naturalOrder())));

        Map<String, Object> window = timelineWindow(hours, now);
        data.put("available", true);
        data.put("reason", null);
        data.put("total", rawEvents.size());
        data.put("window", window);
        data.put("firstSeen", timelineText(story.get("firstSeen")));
        data.put("lastSeen", timelineText(story.get("lastSeen")));
        data.put("severity", severity);
        data.put("events", events);
        return data;
    }

    /** 数据不足/数据源不可用：仍然是完整形状，但一个事件都不编。 */
    Map<String, Object> timelineUnavailable(Map<String, Object> data, int hours, LocalDateTime now) {
        data.put("available", false);
        data.put("reason", PublicApiSupport.TIMELINE_REASON_UNAVAILABLE);
        data.put("total", 0);
        data.put("window", timelineWindow(hours, now));
        data.put("firstSeen", null);
        data.put("lastSeen", null);
        data.put("severity", emptySeverity());
        data.put("events", List.of());
        return data;
    }

    /** 四档严重度计数固定按 CRITICAL/HIGH/MEDIUM/LOW 顺序输出；INFO 不属于这四档，不混进来。 */
    static Map<String, Integer> emptySeverity() {
        Map<String, Integer> severity = new LinkedHashMap<>();
        severity.put(AlertSeverity.CRITICAL.name(), 0);
        severity.put(AlertSeverity.HIGH.name(), 0);
        severity.put(AlertSeverity.MEDIUM.name(), 0);
        severity.put(AlertSeverity.LOW.name(), 0);
        return severity;
    }

    static Map<String, Object> timelineWindow(int hours, LocalDateTime now) {
        Map<String, Object> window = new LinkedHashMap<>();
        window.put("hours", hours);
        window.put("start", now.minusHours(hours).format(PublicApiSupport.FMT));
        window.put("end", now.format(PublicApiSupport.FMT));
        return window;
    }

    static String timelineText(Object raw) {
        if (raw == null) {
            return null;
        }
        String s = String.valueOf(raw).trim();
        return s.isEmpty() ? null : s;
    }

    /**
     * 60 秒进程内缓存的取数入口：命中直接返回上次的 Map，未命中才调 loader。
     *
     * <p>payload 允许为 null（= 该来源不在当前窗口的候选池里）：同一个 404 在窗口内
     * 也不必反复打索引进而保住"重复请求不打后端"。返回的 Map 不会在本类里被修改
     * （{@link PublicApiSupport#ok(Map, jakarta.servlet.http.HttpServletResponse)} 的
     * {@code ship(...)} 做的是深拷贝），所以缓存同一个实例是安全的。
     *
     * <p>双检锁：并发未命中时只有一个线程回源，其余线程在锁内看到刚写入的条目后直接返回。
     */
    Map<String, Object> cachedStory(String key, Supplier<Map<String, Object>> loader) {
        long now = System.currentTimeMillis();
        StoryCacheEntry hit = storyCache.get(key);
        if (hit != null && now - hit.storedAtMs() < STORY_CACHE_TTL_MS) {
            return hit.payload();
        }
        synchronized (storyCacheLock) {
            now = System.currentTimeMillis();
            hit = storyCache.get(key);
            if (hit != null && now - hit.storedAtMs() < STORY_CACHE_TTL_MS) {
                return hit.payload();
            }
            Map<String, Object> payload = loader.get();
            Map<String, StoryCacheEntry> next = new LinkedHashMap<>(storyCache);
            next.remove(key);
            if (next.size() >= STORY_CACHE_MAX_ENTRIES) {
                // 丢最早写入的一格：这里不是 LRU（读者无锁，维护访问顺序要抢锁），
                // 但窗口+来源的组合本来就只有十几种，够用且不会让缓存无界。
                next.remove(next.keySet().iterator().next());
            }
            next.put(key, new StoryCacheEntry(payload, System.currentTimeMillis()));
            storyCache = Collections.unmodifiableMap(next);
            return payload;
        }
    }

    /** 缓存键：window 用解析后的小时数归一（{@code 24} 与 {@code 24h} 命中同一格），形状区分两个端点。 */
    static String storyCacheKey(String shape, String ip, int hours) {
        String normalized = ip == null ? "" : ip.trim().toLowerCase(java.util.Locale.ROOT);
        return shape + "|" + hours + "|" + normalized;
    }

    /**
     * 故事线服务未装配时的降级载荷（与可用载荷同名同形，前端只判 available）。
     *
     * <p>两个端点的形状不同，所以按调用方补对应的空集合键：
     * {@code srcIp == null}（来自 {@code /stories}）补 {@code sources: []}，
     * 否则（来自 {@code /story}）补 {@code events: []}。混着返回会让页面
     * 把"候选列表"当"事件流"渲染。
     */
    Map<String, Object> storyDisabled(int windowHours, String srcIp) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", LocalDateTime.now().format(PublicApiSupport.FMT));
        data.put("cacheSeconds", Math.max(0, support.cacheSeconds));
        data.put("window", AttackStoryService.windowLabel(windowHours));
        data.put("windowHours", windowHours);
        data.put("available", false);
        data.put("reason", "STORY_DISABLED");
        data.put("note", "攻击故事线未装配（裁剪过的部署，或单测直接 new 控制器）："
                + "不返回任何来源/事件，也不用内部样本顶替");
        if (srcIp == null) {
            data.put("sources", List.of());
        } else {
            data.put("srcIp", support.policy().display(srcIp));
            data.put("events", List.of());
            data.put("eventCount", 0);
        }
        return data;
    }

    // ==================== 密码自查（/api/public/password；别名 /password.js）====================

    /**
     * 【你的密码在攻击者字典里吗】只读投影：{@code p} = 口令 SHA-256 的<b>前 5 位</b>（小写 hex）。
     *
     * <h3>为什么是"桶内 hash 的后 59 位"而不是只回一个 {@code bucketCount}</h3>
     * <ol>
     *   <li><b>只回计数，前端判不了"命中"</b>：{@code bucketCount} 是这 5 位前缀下
     *       <b>所有</b>口令的尝试次数合计 —— 1,048,576 个桶里撞前缀时它天然虚高，
     *       拿它当"你的口令被尝试过 N 次"是错的（页面文案必须写"同前缀桶合计"）。</li>
     *   <li><b>所以按公开 k-匿名查询的通行做法</b>：后端把桶内 hash 的<b>后 59 位</b>发出去，
     *       前端用 {@code crypto.subtle} 自己算完整 hash、自己比对末尾 59 位。
     *       后端全程<b>拿不到</b>口令，也拿不到"这个人查的是哪个 hash" —— 也就无法记录。</li>
     *   <li><b>取舍写在明处</b>：知道前缀的人能拿到该桶的 suffix 清单，但那需要先猜到
     *       口令的 SHA-256 前缀，与直接猜口令等价；且每桶最多 {@value PasswordDictionaryService#MAX_SUFFIXES_PER_BUCKET}
     *       条，超出置 {@code truncated:true}（前端遇到截断必须说"可能被截断，不代表不在字典里"）。</li>
     *   <li>{@code match} 恒为 {@code null}：后端没有口令，就不该假装能替你判定。字段保留是为了
     *       前端契约稳定 —— "谁判定"始终是前端。</li>
     * </ol>
     *
     * <h3>读不到时</h3>
     * 字典文件缺失/格式错 ⇒ 200 + {@code available:false} + {@code notes} 写清原因（{@code DICT_FILE_MISSING}
     * / {@code DICT_INVALID_FORMAT: …}），<b>不抛异常、不 500、不补数</b>。这是本端点最重要的诚实性要求：
     * "读不到"绝不能被渲染成"没查到"。
     */
    @GetMapping({"/password", "/password.js"})
    public ResponseEntity<Map<String, Object>> password(
            @RequestParam(value = "p", required = false) String p,
            HttpServletRequest req, HttpServletResponse res) {
        PublicAskRateLimiter limiter = passwordLimiter();
        String ip = support.clientIp(req);
        if (!limiter.allow(ip)) {
            return support.tooMany(res, limiter, "密码自查请求过于频繁（每 IP 每分钟 "
                    + limiter.limitPerMinute() + " 次），请稍后再试；这是防刷，不是限制你检查自己的口令");
        }
        if (!PasswordDictionaryService.isLowerHex(p, PasswordDictionaryService.PREFIX_HEX_CHARS)) {
            return support.badRequest(res, "INVALID_PREFIX",
                    "p 必须是口令 SHA-256 的前 " + PasswordDictionaryService.PREFIX_HEX_CHARS
                            + " 位小写十六进制（例如 /api/public/password?p=a1b2c）；本端点只收前缀，"
                            + "不收口令原文、不收大写 hex、也不收前 6 位以上的部分 hash");
        }

        PasswordDictionaryService.Snapshot snap = support.passwordDict == null
                ? PasswordDictionaryService.unavailable("DICT_NOT_WIRED")
                : support.passwordDict.snapshot();

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("prefix", p);
        data.put("match", null);
        data.put("available", snap.available());
        data.put("limits", passwordLimits());

        if (!snap.available()) {
            // 读不到：只写原因，不写"0 次"（0 会被读成"没被尝试过"，正是最危险的假阴性）
            data.put("bucketCount", null);
            data.put("bucketLastSeen", null);
            data.put("hashes", List.of());
            data.put("listed", List.of());
            data.put("truncated", false);
            data.put("notes", "读不到攻击者口令字典（" + snap.reason() + "）—— 不补数：这里没有记录，"
                    + "不代表这个口令不在攻击者字典里；请不要把这句读成\"安全\"");
        } else {
            PasswordDictionaryService.Bucket bucket = snap.bucket(p);
            int cap = Math.max(1, Math.min(support.passwordMaxHashes, PasswordDictionaryService.MAX_SUFFIXES_PER_BUCKET));
            if (bucket == null) {
                data.put("bucketCount", 0L);
                data.put("bucketLastSeen", null);
                data.put("hashes", List.of());
                data.put("listed", List.of());
                data.put("truncated", false);
                data.put("notes", "这个前缀下没有任何记录（字典生成于 " + nz(snap.generatedAt())
                        + "）—— 不代表绝对安全：攻击者字典不是全集，我们只统计自己蜜罐与公开弱口令榜里出现过的口令");
            } else {
                List<String> suffixes = bucket.suffixes();
                List<String> listed = bucket.listed();
                boolean truncated = suffixes.size() > cap || listed.size() > cap;
                data.put("bucketCount", bucket.count());
                data.put("bucketLastSeen", bucket.lastSeen());
                data.put("hashes", suffixes.size() > cap ? suffixes.subList(0, cap) : suffixes);
                data.put("listed", listed.size() > cap ? listed.subList(0, cap) : listed);
                data.put("truncated", truncated);
                data.put("notes", "bucketCount 是这 5 位前缀下**所有**口令的尝试次数合计（不是你这一个的次数）："
                        + "命中与否由页面用完整 hash 的后 " + PasswordDictionaryService.SUFFIX_HEX_CHARS
                        + " 位自行比对。hashes = 蜜罐里真实出现过的口令；listed = 只在公开弱口令榜里、"
                        + "蜜罐还没抓到过的口令 —— 两者文案必须分开，别把\"榜上有名\"写成\"被攻击者试过 N 次\"。"
                        + (truncated
                        ? "该桶有 " + suffixes.size() + " 条（榜单 " + listed.size() + " 条），只下发前 " + cap
                                + " 条（truncated:true）—— 你的口令不在这 " + cap
                                + " 条里时页面会显示\"未命中\"，那可能只是被截断了，不代表不在字典里。"
                        : ""));
            }
            data.put("generatedAt", snap.generatedAt());
            data.put("totalAttempts", snap.totalAttempts());
            data.put("unique", snap.unique());
        }

        return respondPassword(data, snap.available(), limiter, ip, res);
    }

    /** 密码自查的出口：自带 Cache-Control（public, max-age=5 分钟）与数据源标记，不复用 {@code ok(...)} */
    ResponseEntity<Map<String, Object>> respondPassword(
            Map<String, Object> data, boolean available, PublicAskRateLimiter limiter,
            String clientIp, HttpServletResponse res) {
        res.setHeader("Cache-Control", "public, max-age=" + Math.max(0, support.passwordCacheSeconds));
        res.setHeader("X-Data-Source", available ? "PASSWORD_DICT" : "PASSWORD_DICT_UNAVAILABLE");
        res.setHeader("X-RateLimit-Limit", String.valueOf(limiter.limitPerMinute()));
        res.setHeader("X-RateLimit-Remaining", String.valueOf(limiter.remaining(clientIp)));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", 200);
        body.put("message", "success");
        body.put("data", data);
        return ResponseEntity.ok(body);
    }

    /** 公开的限额口径：让页面能把"为什么只有 200 条"与"多久能再查一次"如实写出来 */
    Map<String, Object> passwordLimits() {
        Map<String, Object> limits = new LinkedHashMap<>();
        limits.put("perMinute", passwordLimiter().limitPerMinute());
        limits.put("maxHashesPerBucket", Math.max(1,
                Math.min(support.passwordMaxHashes, PasswordDictionaryService.MAX_SUFFIXES_PER_BUCKET)));
        limits.put("cacheSeconds", Math.max(0, support.passwordCacheSeconds));
        limits.put("prefixHexChars", PasswordDictionaryService.PREFIX_HEX_CHARS);
        limits.put("suffixHexChars", PasswordDictionaryService.SUFFIX_HEX_CHARS);
        return limits;
    }

    static String nz(String s) {
        return s == null || s.isBlank() ? "未知时间" : s;
    }

    /** 注入的限流器优先；没有 Spring 注入时用同口径的本地实例（仍然限流，不退化为不限） */
    PublicAskRateLimiter passwordLimiter() {
        PublicAskRateLimiter l = support.passwordRateLimiter;
        if (l != null) {
            return l;
        }
        PublicAskRateLimiter f = support.fallbackPasswordRateLimiter;
        if (f == null) {
            synchronized (this) {
                f = support.fallbackPasswordRateLimiter;
                if (f == null) {
                    f = new PublicAskRateLimiter(Math.max(1, support.passwordRequestsPerMinute));
                    support.fallbackPasswordRateLimiter = f;
                }
            }
        }
        return f;
    }

    /**
     * 访问日志聚合（<b>只聚合</b>）：HTTP 状态码分布 + 7 天按天 + 7×24 热力图 + 固定类别 TOP + UA TOP，
     * 供博客"监测中心"画图。
     *
     * <h3>站主 2026-10-14 拍板的七条口径（都写进了测试）</h3>
     * <ol>
     *   <li><b>只输出聚合，绝不输出任何 IP</b>（连掩码都不给），也不给"来源数"——
     *       "被多少人打、打得有多狠"本身就是情报；</li>
     *   <li>路径维度<b>只给固定类别枚举</b>（{@link org.example.accesslog.WebStatsCategory}），
     *       公网页面永不出现攻击者可控的原始字符串；</li>
     *   <li>窗口 = 默认近 24h，另给 7 天按天汇总与 7×24 小时桶（热力图）；</li>
     *   <li>滚动实现是<b>内存聚合器</b>（写线程顺手累加、固定内存上限），
     *       <b>请求路径上不读任何文件</b>（RUNBOOK §23）；</li>
     *   <li>入榜门槛：类别/UA 计数 ≥ {@code app.webstats.min-count}（默认 5）才出现，
     *       低于门槛的只进总量；</li>
     *   <li>状态码只到<b>类别</b>（2xx/3xx/4xx/5xx + other），不给具体码；</li>
     *   <li><b>不公开"疑似扫描占比"</b>（那等于公开检测能力边界）。</li>
     * </ol>
     *
     * <p>复用既有公开端点外壳（同一个限流器 20 次/分钟、同一个 CORS 白名单、同一个 ETag 过滤器、
     * 同一个 15 秒 {@link Snapshot}、同一个 {@code ok(...)} 信封 → 自动带 {@code ipDisclosure}
     * 与内部资产名过滤），不新增任何公开面机制。
     *
     * <p>不可用分支必须能区分：{@code WEBSTATS_DISABLED}（配置关掉）、{@code LOG_DISABLED}
     * （访问日志关掉）、{@code LOG_FILE_MISSING}、{@code LOG_UNREADABLE}、{@code BACKFILL_RUNNING}
     * （启动回填还没读完）、{@code WINDOW_EMPTY}（日志可读但 24h 内确实没有请求）——
     * <b>绝不用"空分布"冒充"这段时间太平"</b>。
     */
    @GetMapping({"/webstats", "/webstats.js"})
    public ResponseEntity<Map<String, Object>> webstats(HttpServletRequest req, HttpServletResponse res) {
        if (!support.rateLimiter.allow(support.clientIp(req))) {
            return support.tooMany(res);
        }
        return support.ok(support.webStatsCache.get(support.cacheSeconds, this::buildWebStats), res);
    }

    Map<String, Object> buildWebStats() {
        String now = support.generatedAt();
        org.example.accesslog.WebStatsService svc = support.webStatsService;
        if (svc == null || !svc.enabled()) {
            return buildWebStatsUnavailable("WEBSTATS_DISABLED",
                    "访问日志聚合已在配置中关闭（app.webstats.enabled=false）：本端点不返回任何分布，"
                            + "也不以 0 冒充'最近没有扫描'。", support.cacheSeconds, now);
        }
        org.example.accesslog.WebStatsService.Status st = svc.status();
        if (!st.accessLogEnabled()) {
            return buildWebStatsUnavailable("LOG_DISABLED",
                    "应用侧访问日志已关闭（app.accesslog.enabled=false）：没有数据源，"
                            + "本端点不返回任何分布（URL 级扫描在应用侧不可见）。", support.cacheSeconds, now);
        }
        if (!st.fileExists()) {
            return buildWebStatsUnavailable("LOG_FILE_MISSING",
                    "访问日志文件当前不存在（可能被删、正在轮转，或从未写入）：不返回分布。"
                            + "内存聚合器仍在计数，文件恢复后会自动恢复（探测间隔见配置）。", support.cacheSeconds, now);
        }
        if (!st.fileReadable()) {
            return buildWebStatsUnavailable("LOG_UNREADABLE",
                    "访问日志文件存在但读不出来（权限/被占用/不是普通文件）：不返回分布，"
                            + "也不以 0 冒充'这段时间太平'。", support.cacheSeconds, now);
        }
        org.example.accesslog.WebStatsAggregator.Thresholds th = webStatsThresholds();
        org.example.accesslog.WebStatsAggregator.Snapshot snap =
                svc.snapshot(java.time.OffsetDateTime.now(), th);
        if (snap.requests() <= 0) {
            // 窗口空 = 数据源可用但确实没有请求（不是故障）。回填还没读完时单独一个 reason：
            // 否则"刚重启还没读到日志"会被画成"24 小时零请求"。
            if (st.backfillRunning() || !st.backfillDone()) {
                return buildWebStatsUnavailable("BACKFILL_RUNNING",
                        "启动回填仍在后台进行（不阻塞启动）：暂不展示分布，"
                                + "以免把'还没读到'画成'没有请求'；稍后重试即可。", support.cacheSeconds, now);
            }
            return buildWebStatsUnavailable("WINDOW_EMPTY",
                    "访问日志可读，但最近 24 小时窗口内没有任何请求记录（不是故障，也不是被隐藏）。",
                    support.cacheSeconds, now);
        }
        return buildWebStatsAvailable(snap, st, support.cacheSeconds, now, th);
    }

    org.example.accesslog.WebStatsAggregator.Thresholds webStatsThresholds() {
        return new org.example.accesslog.WebStatsAggregator.Thresholds(
                Math.max(1, support.webStatsMinCount), Math.max(1, support.webStatsTopCategories), Math.max(0, support.webStatsTopUas));
    }

    /** 不可用载荷（字段名与可用载荷完全一致：前端只判 {@code available} 一个开关） */
    static Map<String, Object> buildWebStatsUnavailable(String reason, String note, int cacheSeconds, String now) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", now);
        data.put("cacheSeconds", cacheSeconds);
        data.put("window", "24h");
        data.put("available", false);
        data.put("reason", reason);
        data.put("totals", webStatsTotals(0L, org.example.accesslog.WebStatsAggregator.StatusClass.EMPTY));
        data.put("topCategories", List.of());
        data.put("topUas", List.of());
        data.put("byDay", List.of());
        data.put("heatmap", List.of());
        data.put("thresholds", webStatsThresholds(DEFAULT_WEBSTATS_THRESHOLDS));
        data.put("coverage", webStatsCoverage(null, null, null));
        data.put("note", note + " " + WEBSTATS_NOTE_SUFFIX);
        return data;
    }

    /** 缺口门槛兜底（没有注入配置时的默认值：≥5 次入榜） */
    static final org.example.accesslog.WebStatsAggregator.Thresholds DEFAULT_WEBSTATS_THRESHOLDS =
            org.example.accesslog.WebStatsAggregator.Thresholds.defaults();

    /**
     * 可用载荷（<b>纯函数</b>：除入参外不读任何状态，方便单测直接喂各种组合）。
     *
     * <p>出参字段就是公开契约：{@code generatedAt / cacheSeconds / window / available / reason /
     * totals / topCategories / topUas / byDay / heatmap / thresholds / coverage / note}
     * （+ 出口统一加的 {@code ipDisclosure}）。<b>只许新增，不许改名/删除</b>。
     */
    static Map<String, Object> buildWebStatsAvailable(org.example.accesslog.WebStatsAggregator.Snapshot snap,
                                                      org.example.accesslog.WebStatsService.Status st,
                                                      int cacheSeconds, String now,
                                                      org.example.accesslog.WebStatsAggregator.Thresholds th) {
        org.example.accesslog.WebStatsAggregator.Thresholds t =
                (th == null ? DEFAULT_WEBSTATS_THRESHOLDS : th).normalized();
        long requests = Math.max(0L, snap.requests());

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", now);
        data.put("cacheSeconds", cacheSeconds);
        data.put("window", "24h");
        data.put("available", true);
        data.put("reason", "OK");
        data.put("totals", webStatsTotals(requests, snap.statusClass()));

        List<Map<String, Object>> categories = new ArrayList<>();
        for (org.example.accesslog.WebStatsAggregator.CategoryCount c : snap.topCategories()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("category", c.category());
            m.put("count", c.count());
            m.put("sharePercent", webStatsSharePercent(c.count(), requests));
            categories.add(m);
        }
        data.put("topCategories", categories);

        List<Map<String, Object>> uas = new ArrayList<>();
        for (org.example.accesslog.WebStatsAggregator.UaCount u : snap.topUas()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ua", u.ua());
            m.put("count", u.count());
            uas.add(m);
        }
        data.put("topUas", uas);

        List<Map<String, Object>> byDay = new ArrayList<>();
        for (org.example.accesslog.WebStatsAggregator.DayStat d : snap.byDay()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("date", d.date());
            m.put("requests", d.requests());
            m.put("statusClass", webStatsStatusClassMap(d.statusClass()));
            byDay.add(m);
        }
        data.put("byDay", byDay);

        List<Map<String, Object>> heatmap = new ArrayList<>();
        for (org.example.accesslog.WebStatsAggregator.HourStat h : snap.heatmap()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("date", h.date());
            m.put("hour", h.hour());
            m.put("count", h.requests());
            heatmap.add(m);
        }
        data.put("heatmap", heatmap);

        data.put("thresholds", webStatsThresholds(t));
        data.put("coverage", webStatsCoverage(st, snap, t));
        data.put("note", webStatsNote(t) + " " + WEBSTATS_NOTE_SUFFIX);
        return data;
    }

    static Map<String, Object> webStatsTotals(long requests,
                                              org.example.accesslog.WebStatsAggregator.StatusClass sc) {
        Map<String, Object> totals = new LinkedHashMap<>();
        totals.put("requests", requests);
        totals.put("statusClass", webStatsStatusClassMap(sc));
        return totals;
    }

    /** 状态码只到类别（口径⑥）：key 固定为 2xx/3xx/4xx/5xx/other，永远是这五个 */
    static Map<String, Object> webStatsStatusClassMap(org.example.accesslog.WebStatsAggregator.StatusClass sc) {
        org.example.accesslog.WebStatsAggregator.StatusClass v =
                sc == null ? org.example.accesslog.WebStatsAggregator.StatusClass.EMPTY : sc;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("2xx", v.c2xx());
        m.put("3xx", v.c3xx());
        m.put("4xx", v.c4xx());
        m.put("5xx", v.c5xx());
        m.put("other", v.other());
        return m;
    }

    static Map<String, Object> webStatsThresholds(org.example.accesslog.WebStatsAggregator.Thresholds th) {
        org.example.accesslog.WebStatsAggregator.Thresholds t =
                (th == null ? DEFAULT_WEBSTATS_THRESHOLDS : th).normalized();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("minCount", t.minCount());
        m.put("topCategories", t.topCategories());
        m.put("topUas", t.topUas());
        return m;
    }

    /**
     * 覆盖度自证：<b>内存上限</b>（桶数/热力格数/UA 槽数）、回填与解析的实数、窗口外的丢弃数。
     *
     * <p>刻意<b>不</b>输出 {@code lastError} 原文：那是内部绝对路径/异常文本，
     * 属于"内部资产名"那一类，只给一个布尔。
     */
    static Map<String, Object> webStatsCoverage(org.example.accesslog.WebStatsService.Status st,
                                                org.example.accesslog.WebStatsAggregator.Snapshot snap,
                                                org.example.accesslog.WebStatsAggregator.Thresholds th) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("logReadable", st != null && st.fileReadable());
        m.put("backfillDone", st != null && st.backfillDone());
        m.put("backfillRunning", st != null && st.backfillRunning());
        m.put("backfilledRecords", st == null ? 0L : st.backfilledRecords());
        m.put("parsedRecords", st == null ? 0L : st.parsedRecords());
        m.put("skippedLines", st == null ? 0L : st.skippedLines());
        m.put("sourceError", st != null && st.lastError() != null && !st.lastError().isEmpty());
        m.put("bucketCount", st == null ? org.example.accesslog.WebStatsAggregator.BUCKET_COUNT : st.bucketCount());
        m.put("bucketSeconds", st == null ? org.example.accesslog.WebStatsAggregator.BUCKET_SECONDS : st.bucketSeconds());
        m.put("hourCells", st == null ? org.example.accesslog.WebStatsAggregator.HOUR_CELLS : st.hourCells());
        m.put("uaSlotsPerBucket", st == null ? org.example.accesslog.WebStatsAggregator.UA_SLOTS_PER_BUCKET : st.uaSlotsPerBucket());
        m.put("globalUaSlots", st == null ? org.example.accesslog.WebStatsAggregator.GLOBAL_UA_SLOTS : st.globalUaSlots());
        m.put("uaOverflowRows", snap == null ? 0L : snap.uaOverflowRows());
        m.put("uaKeysDropped", snap == null ? 0L : snap.uaKeysDropped());
        m.put("recordsOutsideWindow", snap == null ? 0L : snap.droppedOutOfWindow());
        m.put("bucketStaleSkips", snap == null ? 0L : snap.staleSlotSkips());
        return m;
    }

    /** 占比（百分数，保留两位）——只用于展示与门槛，不参与任何账目 */
    static double webStatsSharePercent(long count, long total) {
        if (total <= 0) {
            return 0d;
        }
        return Math.round(count * 10000.0d / total) / 100.0d;
    }

    static String webStatsNote(org.example.accesslog.WebStatsAggregator.Thresholds th) {
        org.example.accesslog.WebStatsAggregator.Thresholds t =
                (th == null ? DEFAULT_WEBSTATS_THRESHOLDS : th).normalized();
        return "只给聚合：不含任何 IP（连掩码 IP 都没有）、不含原始路径与查询串、不含来源数、不含疑似扫描占比。"
                + "路径只以固定类别出现（" + org.example.accesslog.WebStatsCategory.ALL.stream()
                .map(org.example.accesslog.WebStatsCategory::wireName).reduce((a, b) -> a + "/" + b).orElse("")
                + "），低于门槛（计数>=" + t.minCount() + "）的类别/UA 只计入总量。"
                + "statusClass 只到类别（2xx/3xx/4xx/5xx/other），不给具体状态码。";
    }

    /** 所有 webstats 响应共用的口径尾巴（含"缺格/缺天"的读法，防止读者自己脑补） */
    static final String WEBSTATS_NOTE_SUFFIX =
            "heatmap 是最近 7 天按日志行本地时间的整点桶（7×24=168 格，只列有请求的格，缺格=0）；"
                    + "byDay 只含日志里真实有请求的天（缺天=那天的日志已被轮转删除，或确实没有请求）；"
                    + "24h 窗口 = 最近 288 个 5 分钟桶（最老的 <=5 分钟落在窗口外）；时间取自日志行自带的时区偏移。";
}
