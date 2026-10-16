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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

/**
 * 公网只读端点：{@code /api/public/**}。
 *
 * <h3>它和自用界面接口的区别（这是本类的全部意义）</h3>
 * <ol>
 *   <li><b>匿名可访问</b>：不要求 Token。因此它只能返回"公开出去也不心疼"的数据 ——
 *       来源 IP 按 {@code app.public.mask-ips} 口径显示（默认显示观测到的真实地址，
 *       内网/保留写「内网/未知」）、不含内网目的地址与资产名、不含原始日志与完整 payload；
 *       <b>蜜罐口令只给结构</b>（"永不公开"清单，与开关无关）。</li>
 *   <li><b>字段白名单，不是黑名单</b>：出参按固定字段逐个挑出来放行。
 *       黑名单的问题是"新增字段默认就泄露"，而白名单是"新增字段默认不出现"。</li>
 *   <li><b>独立限流</b>（见 {@link PublicRateLimiter}）+ <b>应用内缓存</b>
 *       （默认 15 秒，并下发 {@code Cache-Control} 让边缘也缓存）。</li>
 *   <li><b>fail-closed</b>：数据源不是 REAL 时返回空数据 + 明确的 degraded 标记，
 *       绝不返回内置样本。宁可页面上写"数据源不可用"。</li>
 * </ol>
 *
 * <h3>为什么只有三个端点，而不是最初设想的五个</h3>
 * 蜜罐战报 / 红队评测 / 处置审计各自还需要独立的数据通路与脱敏口径，
 * 按"每期只做已验证的部分"推进 —— 那些端点跟着 P2 的页面一起加，
 * 避免先造出一批没人调用的公开端点（公开端点是攻击面，不是越多越好）。
 */
@RestController
@RequestMapping("/api/public")
public class PublicApiController {

    private static final Logger logger = LoggerFactory.getLogger(PublicApiController.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final DateTimeFormatter HOUR_FMT = DateTimeFormatter.ofPattern("HH:mm");

    /** 语音成功响应的媒体类型：{@code audio/mpeg}（实测线上带全站追加的 charset，见 {@link #tts}） */
    private static final MediaType TTS_AUDIO = MediaType.parseMediaType("audio/mpeg");

    @Autowired
    private PublicAlertSource source;

    @Autowired
    private PublicRateLimiter rateLimiter;

    /** 应用内快照有效期；同时作为 Cache-Control 的 max-age 下发给浏览器/边缘（默认 45s，见 application.yml 注释） */
    @Value("${app.public-api.cache-seconds:45}")
    private int cacheSeconds;

    /**
     * 定时预聚合的"年龄阈值比例"（对应下面 {@code warmPublicSnapshots}）。
     *
     * <p>快照年龄超过 {@code TTL × 本比例} 就主动刷新，默认 0.5（TTL 45s ⇒ 22.5s）。
     * 为什么不是"过期才刷"：过期才刷等于把现算留给下一个访客；提前刷 ⇒ 访客侧永远拿到热快照。
     * 为什么不是更小（例如 0.2）：那会把上游查询频率抬得比"有访客才算"更高，白白增加索引器压力。
     * 后台检查间隔由 {@code @Scheduled} 的 {@code warm-interval-ms}（默认 30s）决定。
     */
    @Value("${app.public-api.warm-threshold-ratio:0.5}")
    private double warmThresholdRatio;

    /**
     * 别名路径的 {@code stale-while-revalidate}：边缘先发旧值、后台再验证 ⇒ 用户侧不被回源卡住。
     *
     * <p>取两倍 TTL。max-age 本身**不再单独硬编码** —— 它必须与 {@code app.public-api.cache-seconds}
     * （快照 TTL）一致，否则会出现"快照已经 45 秒旧、却告诉缓存 15 秒"这种自相矛盾。
     */
    private static final int CACHE_ALIAS_SWR_SECONDS = 90;

    /**
     * 别名 ETag 的序列化器：把 Map 键排序 ⇒ ETag 只取决于内容、与插入顺序无关。
     *
     * <p>为什么不能直接用"完整响应体哈希"（{@link PublicEtagFilter} 的默认口径）：
     * 别名体里的 {@code cacheAgeSeconds} 每秒都在变，ETag 会跟着每秒变 ⇒ 再验证永远拿不到 304。
     */
    private static final ObjectMapper ETAG_MAPPER = new ObjectMapper()
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    /** 是否在公网端点暴露构建版本号。health 早已公开它，且它是开源仓库的提交号，不敏感 */
    @Value("${app.public-api.expose-build-sha:true}")
    private boolean exposeBuildSha;

    @Value("${app.build.sha:unknown}")
    private String buildSha;

    /** 构建时的源提交 / 产物指纹 / 构建时间：与 {@code /api/health} 同源（容器自述，非独立证据） */
    @Value("${app.build.source-sha:unknown}")
    private String buildSourceSha;

    @Value("${app.build.artifact-md5:unknown}")
    private String buildArtifactMd5;

    @Value("${app.build.time:unknown}")
    private String buildTime;

    /**
     * 发布信息文件（可选）：发布号 / 提交 / 切换时刻 / 文件数由**运维链**落地成本文件，本端点只读透传。
     * 为什么不由本服务自己算：发布切换发生在 srv2 上，本进程（srv1）读不到那个目录 ——
     * 读不到就写 {@code available=false}，绝不用进程启动时刻冒充"发布时间"。
     */
    @Value("${app.public-api.deploy-file:}")
    private String deployFile;

    /**
     * 评测报告文件（可选）：{@code scripts/eval/} 跑出来的真值报告，落在本文件里供端点透传。
     * 为什么本服务不自己算这些指标：它们要跑题库与评分器（离线、耗时长、依赖题库与知识库），
     * 放在请求路径上既不可能也不该做。
     */
    @Value("${app.public-api.eval-report-file:}")
    private String evalReportFile;

    /** 进程启动时刻（部署可追溯端点展示 uptime 用；类加载≈启动，误差在秒级） */
    private static final long STARTED_AT_MS = System.currentTimeMillis();

    /** 公开端点读 JSON 文件的大小上限：超过就按"读不到"处理，**不截断**（截断会发出半个真相） */
    private static final long JSON_FILE_MAX_BYTES = 256 * 1024L;

    /** 发布信息文件允许透传的键（白名单：不把运维文件的任意内容端到公网） */
    private static final List<String> DEPLOY_FILE_KEYS = List.of(
            "release", "releaseDir", "commit", "fileCount", "totalBytes", "switchedAt", "publishedAt", "host");

    /** 评测报告允许透传的键（白名单：正好是 C2 面板要的那几个真值 + 自证新鲜度用的 generatedAt） */
    private static final List<String> EVAL_REPORT_KEYS = List.of(
            "generatedAt", "sampleSize", "dataset", "model", "metrics", "keyPointHitRate",
            "refusalRate", "strictRate", "citationRate", "personaCatchphraseRate", "tabooRate");

    private final Snapshot overviewCache = new Snapshot();
    private final Snapshot alertsCache = new Snapshot();
    private final Snapshot honeypotCache = new Snapshot();
    private final Snapshot auditCache = new Snapshot();
    private final Snapshot latestCache = new Snapshot();

    /** ① 聚合端点（alerts+geo+honeypot 三合一）的快照：TTL 与其它端点同源（{@code cacheSeconds}） */
    private final Snapshot homeCache = new Snapshot();

    /** ①b 部署可追溯 / ② AI 质量真值：两者都是"读一个小 JSON + 白名单透传"，同样按快照 TTL 缓存 */
    private final Snapshot deployCache = new Snapshot();
    private final Snapshot evalCache = new Snapshot();

    // ==================== 公开面口径：IP 开关 + 内部资产名词表 ====================
    //
    // 【为什么集中在这里读】站主 2026-10-14 拍板：公开面显示观测到的真实来源 IP。
    // 但"要不要掩码"一旦在多个端点里各写一遍，就必然出现第三种口径（一个页面真实、
    // 一个页面掩码），而且【不会报错】。所以两个口径对象都只在本类注入一次，
    // 由 ship(...) 统一作用到所有公开响应上 —— 将来新增端点（例如 /api/public/geo）
    // 只要走 ok(...)，就自动获得同一套口径。

    /** IP 显示口径（配置 app.public.mask-ips；缺注入时按掩码兜底） */
    @Autowired(required = false)
    private PublicIpPolicy ipPolicy;

    /** 内部资产名停用词过滤（配置 app.public.asset-blocklist） */
    @Autowired(required = false)
    private PublicAssetFilter assetFilter;

    /** 没有 Spring 注入时的保守兜底（掩码态）：单测直接 new 控制器时走这条 */
    private static final PublicIpPolicy FAIL_CLOSED_POLICY = PublicIpPolicy.masking();

    /** 没有 Spring 注入时的默认资产词表（不能因为"没注入"就不过滤） */
    private static final PublicAssetFilter DEFAULT_ASSET_FILTER = PublicAssetFilter.defaults();

    private PublicIpPolicy policy() {
        PublicIpPolicy p = ipPolicy;
        return p != null ? p : FAIL_CLOSED_POLICY;
    }

    private PublicAssetFilter assets() {
        PublicAssetFilter f = assetFilter;
        return f != null ? f : DEFAULT_ASSET_FILTER;
    }

    /**
     * <b>公开响应出海的唯一闸门</b>：整棵 data 树过一遍内部资产名词表，
     * 并补上统一口径字段 {@code ipDisclosure}。
     *
     * <h3>为什么做成"过整棵树"而不是逐字段手工过滤</h3>
     * 逐字段过滤的失败模式是"新加了一个字段、忘了加过滤" —— 而它不会报错，
     * 只会静静地把资产名发出去。整棵树扫一遍则相反：默认就被过滤，漏不掉。
     * 代价是每次请求多一层拷贝（十几条记录的规模，可忽略）。
     *
     * <p>只过滤<b>值</b>，不动<b>键名</b>：键名是公开契约的字段名（改键名等于改接口），
     * 而资产名只可能出现在值里。
     */
    private Map<String, Object> ship(Map<String, Object> data) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (data != null) {
            data.forEach((k, v) -> out.put(k, scrubDeep(v)));
        }
        if (!out.containsKey(PublicIpPolicy.DISCLOSURE_FIELD)) {
            out.put(PublicIpPolicy.DISCLOSURE_FIELD, policy().disclosure());
        }
        return out;
    }

    private Object scrubDeep(Object v) {
        if (v instanceof String s) {
            return scrubText(s);
        }
        if (v instanceof Map<?, ?> m) {
            Map<String, Object> out = new LinkedHashMap<>();
            m.forEach((k, val) -> out.put(String.valueOf(k), scrubDeep(val)));
            return out;
        }
        if (v instanceof List<?> l) {
            List<Object> out = new ArrayList<>(l.size());
            for (Object o : l) {
                out.add(scrubDeep(o));
            }
            return out;
        }
        return v;
    }

    /**
     * 单个字符串的出关口径：<b>先资产名 scrub、再凭据脱敏</b>。
     *
     * <p>顺序不能反：出口是"先去掉内部资产名，再把口令字段隐去"。
     *
     * <p><b>为什么必须在这里补一道（2026-10-14 红线违反的修复）</b>：本方法原先只有
     * {@code assets().scrub(s)}，<b>从不做凭据脱敏</b>。{@code /honeypot} 是显式调
     * {@link CredentialStructure#hidePasswords(String)} 才干净的，而告警链路
     * （{@code buildAlerts()} → {@code publicAggregate()} / {@code publicAlert()}）
     * 一处都没调 —— 于是蜜罐规则原文里的 {@code 口令=<明文>} 随 {@code title} /
     * {@code ruleName} 直出公网（{@code /api/public/alerts} 与
     * {@code /api/public/alerts/{aggId}}）。泄漏的是攻击者猜的口令，但违反本站红线
     * "蜜罐完整口令永不上公网"。
     *
     * <p><b>为什么修在 {@code scrubDeep()} 而不是补在 {@code buildAlerts()} 里</b>：
     * {@code scrubDeep()} 是公开面<b>唯一的出海闸门</b>（见 {@link #ship}）。补在闸门上，
     * 今天所有端点一并覆盖，<b>以后新加的公开端点默认就是安全的</b>；补在某一个
     * {@code buildXxx()} 里则只修了那一条路径 —— 那正是这次出事的失败模式
     * （{@code /honeypot} 记得调、{@code /alerts} 忘了调）。这与 {@link #ship} 那
     * "过整棵树而不是逐字段手工过滤"的理由是同一条。
     *
     * <p>对 {@code /honeypot} 是双重保险：它本来就已把口令换成
     * {@link CredentialStructure#PASSWORD_HIDDEN}，而 {@code hidePasswords} 幂等
     * （占位符里没有 {@code 口令=…} 形状），所以<b>输出不变</b>。
     * {@code PublicHoneypotScrubPipelineTest} 钉住这一点。
     *
     * <p><b>为什么这里还要补一道 IP 口径（2026-10-16 收口）</b>：{@link PublicIpPolicy}
     * 的 {@link PublicIpPolicy#displayText(String)} 原先只在<b>少数几个</b>自由文本字段上
     * 被显式调用（{@code /honeypot} 的 detail、攻击故事、知识库片段、问答输出护栏……），
     * 而告警链路的 {@code title} / {@code ruleName} 一处都没调 —— 于是
     * {@code GET /api/public/alerts} 在真实态下把蜜罐规则原文里的<b>内网来源地址</b>
     * （线上实测 {@code 蜜罐(Dionaea): SMB 连接/认证尝试 来源=172.19.0.1:57386}）
     * 原样发到公网，而同一条记录的 {@code srcIp} 字段已经是「内网/未知」。
     * 违反的是 {@code PublicIpPolicy} 里"内网/保留/链路地址在任何口径下都不上公开面"
     * 这条<b>与开关无关</b>的硬约束（RUNBOOK §27.1："真实态下这类值一律写成「内网/未知」"）。
     *
     * <p>修法与口令那次<b>同源</b>：补在唯一的出海闸门上，而不是补在
     * {@code publicAggregate()} / {@code publicAlert()} 里。补在闸门上，今天所有端点一并覆盖，
     * 以后新加的公开端点默认就带 IP 口径；补在某一个 {@code buildXxx()} 里则只修了那一条路径
     * —— 那正是口令那次与这次共同的失败模式。
     *
     * <p><b>幂等 / 不改变既有输出</b>：
     * <ul>
     *   <li>真实态：结构化字段已经过 {@code display()}，公网地址原样、内网地址已是「内网/未知」，
     *       再过一遍 {@code maskInternalOnly} 逐字节不变；自由文本里的公网攻击源地址
     *       <b>照旧保留</b>（本站口径就是显示观测到的真实来源地址），只把内网/保留地址换掉。</li>
     *   <li>掩码态：{@code display()} 的产物形如 {@code 45.83.***.***}，
     *       不含"四段数字"，{@code maskAll} 不会再改它；原先自由文本里漏出来的完整 IP
     *       则被补上掩码 —— 这正是掩码态本来就该有的口径。</li>
     * </ul>
     * 回归：{@code PublicFreeTextIpGateTest}（两种口径 + 列表与下钻两条路径）。
     */
    private String scrubText(String s) {
        if (s == null || s.isEmpty()) {
            return s;
        }
        return policy().displayText(CredentialStructure.hidePasswords(assets().scrub(s)));
    }

    /** 处置审计只读读取器（读留痕文件，不注入任何处置 Bean —— 隔离测试会强校验） */
    @Autowired
    private PublicAuditReader auditReader;

    // ==================== P4：公开 AI 问答 + 知识库公开只读检索 ====================

    /** 公开问答业务实现（四道护栏 + state 归一化 + 输出脱敏） */
    @Autowired
    private PublicAskService publicAskService;

    /** 公开知识库检索（复用向量检索，但只出白名单字段） */
    @Autowired
    private PublicKbService publicKbService;

    /** 公开问答的独立限流器（默认 6 次/分钟，与只读端点的 20 次/分钟分开） */
    @Autowired
    @Qualifier("publicAskRateLimiter")
    private PublicAskRateLimiter publicAskRateLimiter;

    /**
     * 公开知识库检索的限流器。
     *
     * <p>与问答共用 {@link PublicAskRateLimiter} 这个实现，但注入的是<b>另一个实例</b> ——
     * 于是两者各自一份计数与各自一份上限（检索 20 次/分钟、问答 6 次/分钟）。
     * 为什么不用同一个实例：共用一个桶意味着"多刷几次检索"会顺手把问答的额度也占掉，
     * 而访客完全看不出这两件事为什么互相影响。
     */
    @Autowired
    @Qualifier("publicKbRateLimiter")
    private PublicAskRateLimiter publicKbRateLimiter;

    /** 每 IP 并发 1 守卫（匿名重操作不能靠限流兜住） */
    @Autowired
    private PublicConcurrencyGuard publicConcurrencyGuard;

    /**
     * 语音合成（{@code POST /api/public/tts}）。
     *
     * <p>{@code required = false}：装配不成立时端点必须<b>如实</b>返回
     * {@code 503 TTS_DISABLED}，而不是让整个公网控制器起不来（公开面是匿名可达的，
     * "语音坏了"不该把公开页面一起带走）。见 {@link #tts}。
     */
    @Autowired(required = false)
    private TtsService ttsService;

    /** 单次公开问答的请求体长度上限（比服务内的字符上限略宽，挡住超大 body） */
    @Value("${app.public-api.ask.max-body-chars:4000}")
    private int maxBodyChars;

    /**
     * 公开 AI 问答：<b>匿名可访问</b>，但必须过四道护栏。
     *
     * <h3>为什么匿名还要做这么多事</h3>
     * 公开的意义是"访客不用注册就能试一句"，代价是它会<b>调模型</b>（真金白银）。
     * 所以这里同时上四把锁：输入注入防护、输出护栏、脱敏、配额与限流；
     * 并且公开路径上的 RESPONDER <b>只解释、不调工具</b> —— 匿名访客永远无法触发处置。
     *
     * <h3>为什么用一次性返回而不是 SSE（第一步）</h3>
     * 项目既有纪律是"不做匿名常驻连接"（{@link PublicCorsInterceptor} 同源的取舍）。
     * 短连接 SSE 要另建一条只为公开页面服务的流式通道（含断连清理、背压、错误帧），
     * 属于"能上但不是这次必须"的部分：先把四道护栏与配额隔离做扎实，
     * 流式作为第二步单独上，避免把两件事的验收标准混在一起。
     * 页面侧因此按"一次性请求 + 明确的等待态"实现，不假装在流式输出。
     */
    @PostMapping("/ask")
    public ResponseEntity<Map<String, Object>> ask(@RequestBody(required = false) Map<String, Object> body,
                                                   HttpServletRequest req,
                                                   HttpServletResponse res) {
        String ip = clientIp(req);

        // ① 限流（每 IP 每分钟 N 次）—— 先于一切上游动作，包括并发登记
        if (!publicAskRateLimiter.allow(ip)) {
            return tooMany(res, publicAskRateLimiter, "公开问答请求过于频繁（每 IP 每分钟 "
                    + publicAskRateLimiter.limitPerMinute() + " 次），请稍后再试");
        }

        // ② 并发 1（每 IP 同时只允许一个在飞）
        if (!publicConcurrencyGuard.tryAcquire(ip)) {
            res.setHeader(HttpHeaders.RETRY_AFTER, "5");
            res.setHeader("X-Public-Concurrency", "1");
            Map<String, Object> b = new LinkedHashMap<>();
            b.put("code", 429);
            b.put("message", "同一来源同时只允许 1 个公开问答请求在飞，请等上一条返回后再试");
            b.put("reason", "per-ip-concurrency-limit");
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(b);
        }

        try {
            String question = extractQuestion(body);
            Map<String, Object> data = publicAskService.ask(question, ip);

            // 记一条"刚生成过的回答"，并把它的 textHash 一并发给前端 ——
            // 这是 /api/public/tts 的 textHash 闸【唯一】的文本来源：只有服务端
            // 自己产出过的回答才能被合成，前端永远不传文本。
            if (ttsService != null) {
                Object answer = data.get("answer");
                String textHash = answer == null ? null : ttsService.recordAnswer(String.valueOf(answer));
                if (textHash != null) {
                    data.put("ttsTextHash", textHash);
                }
            }

            // 一次性返回：公开问答的响应永不被边缘缓存（它是"这一次提问"的结果）
            res.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
            res.setHeader("X-Data-Source", "PUBLIC_ASK");
            res.setHeader("X-RateLimit-Limit", String.valueOf(publicAskRateLimiter.limitPerMinute()));
            res.setHeader("X-RateLimit-Remaining",
                    String.valueOf(Math.max(0, publicAskRateLimiter.remaining(ip))));

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("code", 200);
            out.put("message", "success");
            // POST 不走 ok(...)，但口径必须一样：同一个 ship(...)（资产名过滤 + ipDisclosure）
            out.put("data", ship(data));
            return ResponseEntity.ok(out);
        } catch (Exception e) {
            logger.warn("公开问答失败（已按 fail-closed 处理）：{}", e.getMessage());
            Map<String, Object> b = new LinkedHashMap<>();
            b.put("code", 500);
            b.put("message", "公开问答暂时不可用，请稍后再试");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(b);
        } finally {
            publicConcurrencyGuard.release(ip);
        }
    }

    /**
     * 公开知识库检索：<b>只读、匿名、掩码、限流</b>。
     *
     * <p>只返回经过白名单与脱敏的片段（标题 + 片段摘要 + 来源类型 + 可信度），
     * 不返回原始内部路径与文件名；内部文档即使被语义命中也不会出现在这里
     * （口径见 {@link org.example.knowledge.PublicKbVisibility}）。
     */
    @GetMapping({"/kb", "/kb.js"})
    public ResponseEntity<Map<String, Object>> kb(@RequestParam(value = "q", required = false) String q,
                                                  HttpServletRequest req,
                                                  HttpServletResponse res) {
        String ip = clientIp(req);
        if (!publicKbRateLimiter.allow(ip)) {
            return tooMany(res, publicKbRateLimiter, "知识库检索请求过于频繁（每 IP 每分钟 "
                    + publicKbRateLimiter.limitPerMinute() + " 次），请稍后再试");
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", LocalDateTime.now().format(FMT));
        data.put("query", q == null ? "" : q.trim());
        data.put("rule", publicKbService.ruleSummary());

        String query = q == null ? "" : q.trim();
        if (query.isEmpty()) {
            data.put("results", List.of());
            data.put("hitCount", 0);
            data.put("available", true);
            data.put("note", "未提供查询词（q）。");
            return ok(data, res);
        }
        if (query.length() > 200) {
            data.put("results", List.of());
            data.put("hitCount", 0);
            data.put("available", true);
            data.put("note", "查询词过长（上限 200 字符）。");
            return ok(data, res);
        }

        try {
            List<Map<String, Object>> results = publicKbService.search(query);
            data.put("results", results);
            data.put("hitCount", results.size());
            data.put("available", true);
            // 口径描述随开关而变：掩码态<b>逐字节保留改造前的说法</b>（掩码回归要求），
            // 真实态如实说明"显示的是观测到的真实来源地址"，不能嘴上还说"已掩码"。
            data.put("note", results.isEmpty()
                    ? "公开知识库未检索到相关片段（未命中就是未命中，不用别的数据顶替）。"
                    : (policy().masked()
                            ? "片段已截断并脱敏；IP 已掩码，内部路径与凭据不出现在响应里。"
                            : "片段已截断并脱敏；IP 显示观测到的真实来源地址（内网/保留地址一律写作「内网/未知」），"
                                    + "内部路径、凭据与内部资产名不出现在响应里。"));
        } catch (PublicKbService.PublicKbUnavailableException e) {
            // fail-closed：检索不可用就如实说不可用，不回空列表冒充"没有相关内容"
            data.put("results", List.of());
            data.put("hitCount", 0);
            data.put("available", false);
            data.put("note", "知识库检索不可用（向量检索异常）：未返回任何内容，也不以内置样本顶替。");
        }
        return ok(data, res);
    }

    /**
     * 语音合成：{@code POST /api/public/tts}（匿名可达，但有闸）。
     *
     * <h3>响应形状：成功给<b>音频字节</b>，失败给既有 JSON 信封</h3>
     * 成功时直接返回 {@code audio/mpeg} 字节（{@code <audio>} / {@code fetch→blob} 都能直接用，
     * 不必让前端再做 base64 解码，也不必让音频膨胀 33%）；失败一律走与其它公开端点
     * <b>同一个</b> JSON 信封（{@code code/message}）+ {@code reason} 码。
     * 理由：语音是这个端点唯一的"数据"，包一层 JSON 只会把二进制塞进 base64；
     * 而错误必须能被人和页面按 code/reason 处理 —— 两种形状各自做最擅长的事。
     *
     * <h3>复用的外壳</h3>
     * 限流复用 {@link PublicRateLimiter}（每 IP 每分钟，与其它公开端点同一本账）、
     * CORS/ETag 由既有拦截器与 Filter 按 {@code /api/public/**} 前缀统一处理、
     * 缓存头与 {@code ok(...)} 同一口径（{@code public, max-age=cacheSeconds}）；
     * 另加 {@code X-Tts-Cache: HIT|MISS} 让"这次有没有花上游的钱"一眼可见。
     *
     * <h3>请求体</h3>
     * {@code {"phraseId":"welcome"}} 或 {@code {"textHash":"<32 位十六进制>"}}，二者给一个。
     * <b>不认自由文本</b>（给了 text 字段也没用：一律 400 {@code TEXT_NOT_ALLOWED}）。
     *
     * <h3>实测形状（真起应用 + curl 核对过，不是推测）</h3>
     * <pre>
     * HTTP/1.1 200
     * Content-Type: audio/mpeg;charset=UTF-8
     * Cache-Control: public, max-age=15
     * X-Tts-Cache: MISS
     * </pre>
     * 那个 {@code charset=UTF-8} 是<b>全站</b>行为（{@code server.servlet.encoding.force=true}），
     * 不是本端点加的：既有端点 {@code /api/public/latest} 与 {@code /api/health} 同样是
     * {@code application/json;charset=UTF-8}。媒体类型仍是 {@code audio/mpeg}，
     * 播放器忽略该参数；测试按"媒体类型兼容"断言（{@code audio/mpeg}），
     * 不假装线上是逐字节相同的那一个字符串。
     */
    @PostMapping("/tts")
    public ResponseEntity<?> tts(@RequestBody(required = false) Map<String, Object> body,
                                 HttpServletRequest req,
                                 HttpServletResponse res) {
        String ip = clientIp(req);

        // ① 频率闸：与其它公开端点共用同一个限流器（同一本账，不另开一个桶）
        if (!rateLimiter.allow(ip)) {
            res.setHeader(HttpHeaders.RETRY_AFTER, "60");
            res.setHeader("X-RateLimit-Limit", String.valueOf(rateLimiter.limitPerMinute()));
            res.setHeader("X-RateLimit-Remaining", "0");
            return ttsError(res, 429, "RATE_LIMITED",
                    "语音请求过于频繁（每 IP 每分钟 " + rateLimiter.limitPerMinute() + " 次），请稍后再试");
        }

        if (ttsService == null) {
            return ttsError(res, 503, "TTS_DISABLED", "语音合成未启用（app.tts.enabled=false）");
        }

        try {
            TtsService.Result result = ttsService.synthesize(
                    bodyString(body, "phraseId"), bodyString(body, "textHash"), ip);
            // 与 ok(...) 同一口径：快照 TTL 就是下发出去的 max-age。
            // 音频内容是内容寻址的（同一个 voiceId+text 永远是同一份字节），
            // 但仍按公网统一 TTL 走，避免出现"这个端点的缓存语义和别的不一样"。
            res.setHeader(HttpHeaders.CACHE_CONTROL, "public, max-age=" + Math.max(0, cacheSeconds));
            res.setHeader("X-Tts-Cache", result.cacheHit() ? "HIT" : "MISS");
            res.setHeader("X-RateLimit-Limit", String.valueOf(rateLimiter.limitPerMinute()));
            return ResponseEntity.ok().contentType(TTS_AUDIO).body(result.audio());
        } catch (TtsService.TtsException e) {
            // 归一化的 reason 码：前端按它决定"隐藏 🔊 / 提示额度用完 / 提示稍后再试"。
            // message 是人话，绝不含 Key、上游原文或 URL 细节。
            logger.warn("公开 TTS 未完成：reason={} status={}", e.reason(), e.httpStatus());
            return ttsError(res, e.httpStatus(), e.reason(), e.userMessage());
        }
    }

    /**
     * 语音端点的失败响应：既有 JSON 信封 + {@code reason} 码（零 IP、零上游细节）。
     *
     * <p>{@code Cache-Control: no-store}：错误不该被边缘或浏览器缓存住 ——
     * 否则"额度明天恢复"这件事在访客那里可能要等缓存过期才生效。
     */
    private ResponseEntity<Map<String, Object>> ttsError(HttpServletResponse res, int status,
                                                         String reason, String message) {
        res.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", status);
        body.put("message", message);
        body.put("reason", reason);
        return ResponseEntity.status(status).contentType(MediaType.APPLICATION_JSON).body(body);
    }

    /** 请求体取字符串字段（非字符串值按其字面量处理；null 表示没给） */
    private static String bodyString(Map<String, Object> body, String key) {
        if (body == null) {
            return null;
        }
        Object value = body.get(key);
        return value == null ? null : String.valueOf(value);
    }

    /** 请求体取问题：只认 {@code question} / {@code q} 两个键，其余一律忽略 */
    private static String extractQuestion(Map<String, Object> body) {
        if (body == null) {
            return "";
        }
        Object v = body.get("question");
        if (v == null) {
            v = body.get("q");
        }
        return v == null ? "" : String.valueOf(v);
    }

    // ==================== 端点 ====================

    /** 首页状态条用：两台服务器在线状态 + 告警概览。载荷刻意做小。 */
    @GetMapping({"/overview", "/overview.js"})
    public ResponseEntity<Map<String, Object>> overview(HttpServletRequest req, HttpServletResponse res) {
        if (!rateLimiter.allow(clientIp(req))) {
            return tooMany(res);
        }
        Map<String, Object> data = overviewCache.get(cacheSeconds, this::buildOverview);
        return ok(data, res);
    }

    /** 告警看板用：聚合后的实时告警流 + 分布 + 24 小时趋势，一次请求拿全。 */
    @GetMapping({"/alerts", "/alerts.js"})
    public ResponseEntity<Map<String, Object>> alerts(HttpServletRequest req, HttpServletResponse res) {
        if (!rateLimiter.allow(clientIp(req))) {
            return tooMany(res);
        }
        Map<String, Object> data = alertsCache.get(cacheSeconds, this::buildAlerts);
        return ok(data, res);
    }

    /**
     * 聚合告警下钻：返回该簇内的原始明细（同样经过掩码与字段白名单）。
     *
     * <p>聚合口径与自用界面一致，所以 aggId 可以直接复用。
     */
    @GetMapping("/alerts/{aggId}")
    public ResponseEntity<Map<String, Object>> drillDown(@PathVariable("aggId") String aggId,
                                                         HttpServletRequest req,
                                                         HttpServletResponse res) {
        if (!rateLimiter.allow(clientIp(req))) {
            return tooMany(res);
        }

        List<Map<String, Object>> aggs = source.aggregated();
        Map<String, Object> hit = null;
        for (Map<String, Object> g : aggs) {
            if (aggId.equals(String.valueOf(g.get("aggId")))) {
                hit = g;
                break;
            }
        }
        if (hit == null) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("code", 404);
            body.put("message", "未找到聚合告警（可能已超出当前取数窗口）");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(body);
        }

        List<String> memberIds = asStringList(hit.get("memberIds"));
        Map<String, SecurityAlert> byId = new LinkedHashMap<>();
        for (SecurityAlert a : source.readAlerts()) {
            byId.put(a.getId(), a);
        }
        List<Map<String, Object>> members = new ArrayList<>();
        for (String mid : memberIds) {
            SecurityAlert a = byId.get(mid);
            if (a != null) {
                members.add(publicAlert(a));
            }
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", LocalDateTime.now().format(FMT));
        data.put("summary", publicAggregate(hit));
        data.put("members", members);
        data.put("memberCount", members.size());
        return ok(data, res);
    }

    /**
     * 蜜罐战报：连接/登录计数、账号口令 Top（<b>只给结构</b>）、来源分布、事件时间线。
     *
     * <p>来源 IP 按 {@code app.public.mask-ips} 口径显示（默认真实地址，内网/保留写「内网/未知」）；
     * 口令在任何口径下都只给长度/字符类/弱口令标记，永不给出原文。
     */
    @GetMapping({"/honeypot", "/honeypot.js"})
    public ResponseEntity<Map<String, Object>> honeypot(HttpServletRequest req, HttpServletResponse res) {
        if (!rateLimiter.allow(clientIp(req))) {
            return tooMany(res);
        }
        return ok(honeypotCache.get(cacheSeconds, this::buildHoneypot), res);
    }

    // ==================== ① 聚合端点：一次请求拿三块（弱网收益最大的一处） ====================

    /**
     * <b>内容页聚合端点</b>：一次请求拿回 {@code alerts + geo + honeypot} 三块。
     *
     * <h3>为什么要有它（2026-10-16 站主弱网实测的直接产物）</h3>
     * 手机热点（无代理）下首屏 TTFB ≈ 6s，而首屏要发 3 个公开请求
     * （{@code /api/public/alerts.js} + {@code geo.js} + {@code honeypot.js}）——
     * 每个请求各自付一次"客户端 → CF → 源站"的路程，三段路程串起来就是访客感知的"取数慢"。
     * 三合一后：**访客只付一次路程**，且**只消耗一份限流额度**（原来 3 个请求 = 3 次额度，
     * 20 次/分的上限被三个端点分掉）。
     *
     * <h3>口径：与单端点<b>逐字段一致</b>（不新增、不改名、不丢字段）</h3>
     * 每个子块单独过一次 {@link #ship(Map)}（因此各自带自己的 {@code ipDisclosure}），
     * 再嵌进 {@code data.alerts / data.geo / data.honeypot}。于是：
     * <pre>home.data.alerts ≡ alerts.data（逐字段相同）</pre>
     * 这条由 {@code PublicApiHomeEndpointTest} 用真实响应体断言，不靠人眼。
     *
     * <p>新鲜度三件套（{@code snapshotAt / cacheAgeSeconds / snapshotTtlSeconds}）仍在**信封层**，
     * 由 {@link #stampSnapshotFreshness(Map)} 统一盖 —— 它的值来自本端点自带快照的装载时刻
     * （{@link Snapshot#load} 在 loader 返回后打点），所以"这份聚合数据有多旧"是如实值。
     *
     * <p>缓存 / ETag / 429 / CORS 与其它端点走**同一条通路**：同一个 {@code ok(...)}、
     * 同一个别名口径（{@code max-age=45, stale-while-revalidate=90} + 按数据内容算的稳定 ETag）。
     */
    @GetMapping({"/home", "/home.js"})
    public ResponseEntity<Map<String, Object>> home(HttpServletRequest req, HttpServletResponse res) {
        if (!rateLimiter.allow(clientIp(req))) {
            return tooMany(res);
        }
        return ok(homeCache.get(cacheSeconds, this::buildHome), res);
    }

    /**
     * 组装聚合块：三个子块各走自己的快照缓存（各自 TTL / 各自后台预聚合 / 各自失败兜底），
     * 并各自 {@link #ship(Map)} 一次 —— 这一步是"逐字段一致"的关键：
     * 单端点的 {@code ok(...)} 会给 data 补 {@code ipDisclosure}，所以子块也必须补，
     * 否则聚合里的子块会少一个字段（而少字段不会报错，只会让前端的一个字段永远读不到）。
     */
    private Map<String, Object> buildHome() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("alerts", ship(alertsCache.get(cacheSeconds, this::buildAlerts)));
        out.put("geo", ship(geoCache.get(cacheSeconds, this::buildGeo)));
        out.put("honeypot", ship(honeypotCache.get(cacheSeconds, this::buildHoneypot)));
        return out;
    }

    // ==================== ①b 给 C2 面板线的两个只读端点 ====================

    /**
     * <b>部署可追溯</b>（C2 面板要的）：当前构建 + 容器启动时刻 + 可选的"发布信息"文件。
     *
     * <h3>为什么这些字段可信度分级写</h3>
     * {@code build.*} 来自容器环境变量与 {@code git.properties}（**自述**，health 端点已有同样口径：
     * 实测出现过"版本号是新的、容器里跑的是旧代码"，所以自述必须与证据分开写）；
     * 而 {@code release.*}（发布号/文件数/切换时刻）**在另一台机器上**（srv2 的 releases 目录），
     * 本进程读不到 ⇒ 只有在运维链把一份 JSON 落到 {@code app.public-api.deploy-file}
     * 指向的路径时才给值，否则如实 {@code available=false} + 原因，**绝不编造发布号与文件数**。
     */
    @GetMapping({"/deploy", "/deploy.js"})
    public ResponseEntity<Map<String, Object>> deploy(HttpServletRequest req, HttpServletResponse res) {
        if (!rateLimiter.allow(clientIp(req))) {
            return tooMany(res);
        }
        return ok(deployCache.get(cacheSeconds, this::buildDeploy), res);
    }

    private Map<String, Object> buildDeploy() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("generatedAt", generatedAt());

        Map<String, Object> build = new LinkedHashMap<>();
        build.put("sha", buildSha);
        build.put("sourceSha", buildSourceSha);
        build.put("artifactMd5", buildArtifactMd5);
        build.put("buildTime", buildTime);
        build.put("selfReported", true);   // 明确标注：这几个值是"容器自述"，不是独立证据
        out.put("build", build);

        Map<String, Object> runtime = new LinkedHashMap<>();
        runtime.put("startedAt", Instant.ofEpochMilli(STARTED_AT_MS)
                .atZone(ZoneId.systemDefault()).truncatedTo(ChronoUnit.SECONDS)
                .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
        runtime.put("uptimeSeconds", Math.max(0, (System.currentTimeMillis() - STARTED_AT_MS) / 1000));
        out.put("runtime", runtime);

        out.put("release", readDeployFile());
        out.put("available", true);   // 构建信息恒可得；release 的可得性由 release.available 单列
        out.put("note", "build.* 是容器自述（与 /api/health 同源）；release.* 来自 app.public-api.deploy-file，"
                + "取不到就写 available=false —— 不用 0 或猜测值冒充发布信息。");
        return out;
    }

    /** 发布信息文件（可选）：只透传白名单键，未配置/缺失/坏 JSON 一律如实说不可得 */
    private Map<String, Object> readDeployFile() {
        Map<String, Object> rel = new LinkedHashMap<>();
        if (deployFile == null || deployFile.isBlank()) {
            rel.put("available", false);
            rel.put("reason", "RELEASE_INFO_NOT_CONFIGURED");
            rel.put("note", "未配置 app.public-api.deploy-file（发布号在 srv2 的 releases 目录，本进程读不到）");
            return rel;
        }
        Object parsed = readJsonOrNull(deployFile);
        if (parsed == null) {
            rel.put("available", false);
            rel.put("reason", "RELEASE_INFO_UNREADABLE");
            rel.put("note", "发布信息文件不存在或不是合法 JSON：" + deployFile + "（不用旧值冒充新发布）");
            return rel;
        }
        if (!(parsed instanceof Map<?, ?> m)) {
            rel.put("available", false);
            rel.put("reason", "RELEASE_INFO_SHAPE");
            rel.put("note", "发布信息文件顶层必须是 JSON 对象");
            return rel;
        }
        rel.put("available", true);
        for (String k : DEPLOY_FILE_KEYS) {
            if (m.containsKey(k)) {
                rel.put(k, m.get(k));
            }
        }
        rel.put("source", "app.public-api.deploy-file");
        return rel;
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
        if (!rateLimiter.allow(clientIp(req))) {
            return tooMany(res);
        }
        return ok(evalCache.get(cacheSeconds, this::buildEval), res);
    }

    private Map<String, Object> buildEval() {
        Map<String, Object> out = new LinkedHashMap<>();
        if (evalReportFile == null || evalReportFile.isBlank()) {
            out.put("available", false);
            out.put("reason", "EVAL_REPORT_NOT_CONFIGURED");
            out.put("note", "未配置 app.public-api.eval-report-file：本服务不自己算评测数字，"
                    + "也不以内置样本或 0 值顶替（0 会被误读成'测过但全错'）。");
            return out;
        }
        Object parsed = readJsonOrNull(evalReportFile);
        if (parsed == null) {
            out.put("available", false);
            out.put("reason", "EVAL_REPORT_UNREADABLE");
            out.put("note", "评测报告文件不存在或不是合法 JSON：" + evalReportFile);
            return out;
        }
        if (!(parsed instanceof Map<?, ?> m)) {
            out.put("available", false);
            out.put("reason", "EVAL_REPORT_SHAPE");
            out.put("note", "评测报告顶层必须是 JSON 对象");
            return out;
        }
        out.put("available", true);
        for (String k : EVAL_REPORT_KEYS) {
            if (m.containsKey(k)) {
                out.put(k, m.get(k));
            }
        }
        out.put("source", evalReportFile);
        out.put("note", "数字来自离线评测报告原文（未重算、未四舍五入、未合并）；"
                + "唯一改动是把白名单字段挑出来。报告自身的 generatedAt 决定它有多新。");
        return out;
    }

    /**
     * 读一个小 JSON 文件（只读、限长、任何异常一律返回 null）。
     *
     * <p>为什么限长：这是公开端点的数据源，若被误指向一个巨大文件，会把一次 HTTP 请求
     * 变成一次全文件读取。超过上限就当"读不到"（而不是截断后当合法 JSON —— 那会发出半个真相）。
     */
    private Object readJsonOrNull(String path) {
        try {
            java.io.File f = new java.io.File(path);
            if (!f.isFile() || !f.canRead()) {
                return null;
            }
            if (f.length() > JSON_FILE_MAX_BYTES) {
                logger.warn("公开端点 JSON 文件超过上限（{} > {}）：按读不到处理", f.length(), JSON_FILE_MAX_BYTES);
                return null;
            }
            return new ObjectMapper().readValue(f, Map.class);
        } catch (Exception e) {
            logger.warn("公开端点读取 JSON 失败（{}）：{}", path, e.getMessage());
            return null;
        }
    }

    /** 处置审计（只读）：封禁记录 + 审计流水，IP 按开关口径显示，不含原始 detail。 */
    @GetMapping({"/audit", "/audit.js"})
    public ResponseEntity<Map<String, Object>> audit(HttpServletRequest req, HttpServletResponse res) {
        if (!rateLimiter.allow(clientIp(req))) {
            return tooMany(res);
        }
        return ok(auditCache.get(cacheSeconds, this::buildAudit), res);
    }

    /**
     * 最近一次同步 / 最近一条事件的聚合摘要。
     *
     * <h3>这个端点为什么存在（2026-10-13 收口）</h3>
     * 前端曾经调用 {@code /api/public/latest}，而它从未实现 —— 探测拿到 404 之后，
     * 页面上出现了一段技术免责文字（"latest 未就绪 HTTP 500 / 用 audit 替代"）。
     * 那段文字后来从前端移走了，但<b>端点本身仍然悬空</b>：谁都可以再调一次，
     * 然后再造一次同样的含糊提示。缺口只能二选一收口：实现它，或彻底删掉并写明"不得调用"。
     *
     * <p>这里选<b>实现</b>，理由：
     * <ol>
     *   <li>数据全部来自既有公开白名单口径（{@link PublicAlertSource#readAlerts()} 的
     *       掩码字段 + {@link PublicAuditReader} 的掩码记录），<b>没有新增任何数据面</b>：</li>
     *   <li>不放宽公开面 —— 它不返回标题、不返回内网目的地址、不返回聚合 id 与成员 id，
     *       只返回"窗口内多少条 / 什么等级分布 / 最近一次是什么时间、哪一类、来自哪个网段"；</li>
     *   <li>限流 / CORS / 掩码 / ETag 与其余公开端点走同一条通路（同一个 {@code Snapshot} 缓存、
     *       同一个 {@code ok(...)}，因此 ETag Filter 与 CORS 拦截器照样生效）。</li>
     * </ol>
     * 若将来需要"最近一条的标题"，那属于扩大公开面，必须在 RUNBOOK §10 里显式评审后再做 ——
     * 不要顺手加。
     *
     * <p>无数据时如实返回 {@code available=false} + 可读原因（machine-readable 的 {@code reason}
     * 与人读的 {@code note} 成对给出），绝不用 0 冒充"这段时间太平"。
     */
    @GetMapping({"/latest", "/latest.js"})
    public ResponseEntity<Map<String, Object>> latest(HttpServletRequest req, HttpServletResponse res) {
        if (!rateLimiter.allow(clientIp(req))) {
            return tooMany(res);
        }
        return ok(latestCache.get(cacheSeconds, this::buildLatest), res);
    }

    // ==================== 地理分布（离线库；设计见 docs/design-geo-endpoint.md，运维见 RUNBOOK §26） ====================

    /** 地理分布端点自己的快照（与 /alerts 分开：它的取数是一次独立的 indexer 聚合查询） */
    private final Snapshot geoCache = new Snapshot();

    /**
     * 离线地理库（<b>可为空</b>：裁剪过的部署 / 单测直接 new 控制器时就是 null）。
     * 空 → 端点按 {@code GEO_DB_MISSING} 如实降级，绝不假装"没有攻击"。
     */
    @Autowired(required = false)
    private org.example.geoip.GeoIpService geoIpService;

    /** 入榜门槛：少于这么多次的攻击不入榜（防"1 次探测就上公网地图"） */
    @Value("${app.public-api.geo.min-count:3}")
    private int geoMinCount;

    /** 占比门槛（%）：与条数门槛<b>同时</b>满足才入榜（防大窗口里的长尾噪声占满榜单） */
    @Value("${app.public-api.geo.min-share-percent:1.0}")
    private double geoMinSharePercent;

    /** 每个来源字段取多少个 IP 做聚合（terms size）；超出的长尾由 coverage 如实披露 */
    @Value("${app.public-api.geo.top-ips:1000}")
    private int geoTopIps;

    @Value("${app.public-api.geo.top-countries:20}")
    private int geoTopCountries;

    @Value("${app.public-api.geo.top-provinces:10}")
    private int geoTopProvinces;

    @Value("${app.public-api.geo.top-asns:10}")
    private int geoTopAsns;

    /**
     * 我方自己的公网出口 IP（逗号分隔）。
     *
     * <p>为什么必须有：实测 24 小时 {@code data.srcip} 里排第二的是 srv2 自己的公网 IP（180 条）、
     * 第三名是 srv1（15 条）—— 不排掉，"攻击来源 TOP"里会出现我们自己的服务器。
     * 默认空：<b>服务器真实 IP 不进仓库</b>，由部署时的 {@code APP_GEOIP_SELF_IPS} 注入。
     */
    @Value("${app.geoip.self-ips:}")
    private String geoSelfIps;

    /**
     * 攻击来源地理分布（<b>只聚合</b>）：国家 + 省份 + ASN + 时间桶，供博客大屏画"攻击来源分布"。
     *
     * <h3>三条红线（都写进了测试）</h3>
     * <ol>
     *   <li><b>不含任何 IP</b>：连掩码 IP 都不给。入参里必须有 IP（聚合要用），出参里一个都不许有 ——
     *       "某个 IP 被打了几次"本身就是情报；能公开的只有"哪个国家/省份被打了几次"。</li>
     *   <li><b>不含单条告警</b>：没有标题、没有规则名、没有逐条时间线、没有内网资产与目的地址。</li>
     *   <li><b>库不可用就说不可用</b>：{@code available=false} + 机读 {@code reason}
     *       （{@code GEO_DB_MISSING} / {@code GEO_DB_UNUSABLE} / {@code GEO_DB_LOADING} /
     *       {@code GEO_DISABLED}）+ 人读 {@code note}；<b>不返回空分布</b> ——
     *       "地理库没装好"和"这段时间没有攻击"必须能被区分开。</li>
     * </ol>
     *
     * <p>分母诚实披露（站主 2026-10-13 明确要求）：实测 24 小时有 11 万条告警，
     * 但只有约 700 条带来源 IP 字段（{@code data.srcip} / {@code data.src_ip} 两种形状都查）。
     * 所以响应里同时给 {@code totalAlerts / withSourceIp / geocoded / excludedInternal}，
     * 页面必须写"有来源 IP 的 N 条 / 总 M 条"，<b>不许把 700 条画成全量分布</b>。
     *
     * <p>复用既有公开端点外壳（同一个限流器 20 次/分钟、同一个 CORS 白名单、同一个 ETag 过滤器、
     * 同一个 15 秒 {@link Snapshot}、同一个 {@code ok(...)} 信封，因此也自动获得
     * {@code ship(...)} 的资产名过滤与 {@code ipDisclosure} 口径），不新增任何公开面机制。
     *
     * <p>署名：DB-IP Lite 是 CC BY 4.0，<b>必须在输出上署名</b> ——
     * 所以 {@code note} 与 {@code geoAttribution} 两处都带
     * {@link org.example.geoip.GeoIpService#ATTRIBUTION}。
     */
    @GetMapping({"/geo", "/geo.js"})
    public ResponseEntity<Map<String, Object>> geo(HttpServletRequest req, HttpServletResponse res) {
        if (!rateLimiter.allow(clientIp(req))) {
            return tooMany(res);
        }
        return ok(geoCache.get(cacheSeconds, this::buildGeo), res);
    }

    private Map<String, Object> buildGeo() {
        org.example.geoip.GeoIpService svc = geoIpService;
        if (svc == null) {
            // 没有地理库 Bean（例如裁剪过的部署）：与"库缺失"同一口径，不假装有数据
            return buildGeoUnavailable("GEO_DB_MISSING",
                    "地理富化未装配（没有 GeoIpService）：本端点不返回任何分布，也不以 0 冒充'没有攻击'。",
                    cacheSeconds, generatedAt());
        }
        if (!svc.ready()) {
            return buildGeoUnavailable(svc.reason(), geoUnavailableNote(svc), cacheSeconds, generatedAt());
        }
        return buildGeo(svc, source.geoWindow24h(geoTopIps), geoThresholds(), cacheSeconds,
                generatedAt(), geoSelfIps);
    }

    private static String geoUnavailableNote(org.example.geoip.GeoIpService svc) {
        return switch (svc.state()) {
            case DISABLED -> "地理富化已在配置中关闭（app.geoip.enabled=false）：不返回分布，也不以内置样本顶替。";
            case MISSING -> "离线地理库不存在（app.geoip.city-db 指向的文件/目录里没有 dbip-city-lite-*.csv.gz）："
                    + "请先跑 scripts/srv1-geoip-update.sh 落地 DB-IP Lite 库；本端点不返回任何数字。";
            case LOADING -> "离线地理库正在后台装载：稍后重试即可（这不是'没有攻击'）。";
            default -> "离线地理库读取失败（不是 gzip / 被截断 / 坏行超阈值 / 区间乱序）："
                    + "请按 RUNBOOK §26 回滚到上一份库文件；本次不返回任何分布。";
        };
    }

    private org.example.geoip.GeoAggregator.Thresholds geoThresholds() {
        return new org.example.geoip.GeoAggregator.Thresholds(
                Math.max(1, geoMinCount), Math.max(0d, geoMinSharePercent),
                Math.max(1, geoTopCountries), Math.max(1, geoTopProvinces), Math.max(1, geoTopAsns));
    }

    /** 不可用载荷（纯函数：字段名与可用载荷对齐，前端只判 {@code available} 一个开关） */
    static Map<String, Object> buildGeoUnavailable(String reason, String note, int cacheSeconds, String now) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", now);
        data.put("cacheSeconds", cacheSeconds);
        data.put("available", false);
        data.put("reason", reason);
        data.put("geoSource", null);
        data.put("geoAttribution", org.example.geoip.GeoIpService.ATTRIBUTION);
        data.put("window", "24h");
        data.put("coverage", org.example.geoip.GeoAggregator.emptyCoverage());
        data.put("byCountry", List.of());
        data.put("byProvinceCN", List.of());
        data.put("byAsnTop", List.of());
        data.put("trend", List.of());
        data.put("note", note + " " + org.example.geoip.GeoIpService.ATTRIBUTION);
        return data;
    }

    /**
     * 可用性判定 + 聚合（<b>纯函数</b>：除入参外不读任何状态）。
     *
     * <p>抽成 static 是为了能被单测直接喂各种组合（库不可用 / 数据源不可用 / 窗口为空 / 正常聚合），
     * 而不用起 Spring 上下文 —— 这些分支在真环境里几乎不可能同时复现。
     */
    static Map<String, Object> buildGeo(org.example.geoip.GeoIpService geo,
                                        org.example.geoip.GeoWindow window,
                                        org.example.geoip.GeoAggregator.Thresholds thresholds,
                                        int cacheSeconds, String now, String selfIps) {
        if (window == null || !window.available()) {
            String reason = window == null ? "DATA_SOURCE_UNAVAILABLE" : window.reason();
            String note = "DATA_SOURCE_UNAVAILABLE".equals(reason)
                    ? "告警数据源不可达（或未拿到真实数据）：本次不展示任何地理分布，也不以内置样本顶替。"
                    : reason + "；" + (window == null || window.note() == null ? "" : window.note());
            return buildGeoUnavailable(reason, note, cacheSeconds, now);
        }
        Map<String, Object> data = org.example.geoip.GeoAggregator.aggregate(
                new org.example.geoip.GeoAggregator.Inputs(
                        window.ipCounts(), window.alertsTotal24h(), window.alertsWithSourceIp24h(),
                        window.bucketsTruncated(), window.trend(), parseSelfIps(selfIps)),
                geo, thresholds, now);
        data.put("cacheSeconds", cacheSeconds);
        if (window.ipCounts().isEmpty()) {
            // 数据源可用但窗口内没有任何带来源 IP 的告警：仍然 available=true（不是故障），
            // 但必须把这句话写进 note —— 否则读者会把"地图上什么都没有"读成"全量分布为空"
            data.put("reason", "NO_DATA_IN_WINDOW");
            data.put("note", "数据源可用，但最近 24 小时没有任何带来源 IP 的告警（不是故障）。"
                    + org.example.geoip.GeoIpService.ATTRIBUTION);
        }
        return data;
    }

    /** 我方公网 IP 配置 → 集合（去空白、丢空项） */
    static java.util.Set<String> parseSelfIps(String csv) {
        java.util.Set<String> out = new java.util.LinkedHashSet<>();
        if (csv == null) {
            return out;
        }
        for (String s : csv.split(",")) {
            String v = s.trim();
            if (!v.isEmpty()) {
                out.add(v);
            }
        }
        return out;
    }

    // ==================== 攻击故事线（/stories + /story；设计见 docs/design-attack-story-endpoint.md，运维见 RUNBOOK §32） ====================

    /**
     * 攻击故事线服务（<b>可为空</b>：单测直接 new 控制器、或裁剪过的部署里就是 null）。
     *
     * <p>空 → 两个端点如实返回 {@code available=false + STORY_DISABLED}，
     * 绝不用"空事件流"冒充"这个来源什么都没做"。
     */
    @Autowired(required = false)
    private AttackStoryService attackStoryService;

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
        if (!rateLimiter.allow(clientIp(req))) {
            return tooMany(res);
        }
        Integer hours = AttackStoryService.parseWindowHours(window);
        if (hours == null) {
            return badRequest(res, "WINDOW_NOT_SUPPORTED",
                    "不支持的 window（只实现了 " + AttackStoryService.SUPPORTED_WINDOWS.stream()
                            .map(AttackStoryService::windowLabel).reduce((a, b) -> a + "/" + b).orElse("")
                            + "；其它窗口没有数据源验证，不猜）");
        }
        if (attackStoryService == null) {
            return ok(storyDisabled(hours, null), res);
        }
        // 缓存与 limit 归一都在 AttackStoryService 里（它按 window / src 分开存，
        // 单个 Snapshot 只存一份值，用在这里会把不同窗口的结果互相顶掉）
        return ok(attackStoryService.stories(hours, attackStoryService.parseLimit(limit)), res);
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
        if (!rateLimiter.allow(clientIp(req))) {
            return tooMany(res);
        }
        Integer hours = AttackStoryService.parseWindowHours(window);
        if (hours == null) {
            return badRequest(res, "WINDOW_NOT_SUPPORTED",
                    "不支持的 window（只实现了 " + AttackStoryService.SUPPORTED_WINDOWS.stream()
                            .map(AttackStoryService::windowLabel).reduce((a, b) -> a + "/" + b).orElse("")
                            + "）");
        }
        String ip = src == null ? "" : src.trim();
        if (ip.isEmpty()) {
            return badRequest(res, "MISSING_SRC", "缺少 src 参数（要查哪一个来源）");
        }
        if (attackStoryService == null) {
            return ok(storyDisabled(hours, ip), res);
        }
        // 只接受"公网字面量"这一种形状：形状不对直接 400，不拿它去查任何东西
        if (!AttackStoryService.isPublicIp(ip)) {
            return badRequest(res, "INVALID_SRC",
                    "src 必须是观测到的公网来源地址（IPv4/IPv6 字面量）；内网/保留地址不进入故事线");
        }
        Map<String, Object> data = attackStoryService.story(ip, hours);
        if (data == null) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("code", 404);
            body.put("message", "该来源不在当前窗口的候选池里（可能是窗口外、我方 IP、内网地址，"
                    + "或这一段没有它的记录）；请先看 /api/public/stories");
            body.put("reason", "SOURCE_NOT_IN_WINDOW");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(body);
        }
        return ok(data, res);
    }

    /**
     * 故事线服务未装配时的降级载荷（与可用载荷同名同形，前端只判 available）。
     *
     * <p>两个端点的形状不同，所以按调用方补对应的空集合键：
     * {@code srcIp == null}（来自 {@code /stories}）补 {@code sources: []}，
     * 否则（来自 {@code /story}）补 {@code events: []}。混着返回会让页面
     * 把"候选列表"当"事件流"渲染。
     */
    private Map<String, Object> storyDisabled(int windowHours, String srcIp) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", LocalDateTime.now().format(FMT));
        data.put("cacheSeconds", Math.max(0, cacheSeconds));
        data.put("window", AttackStoryService.windowLabel(windowHours));
        data.put("windowHours", windowHours);
        data.put("available", false);
        data.put("reason", "STORY_DISABLED");
        data.put("note", "攻击故事线未装配（裁剪过的部署，或单测直接 new 控制器）："
                + "不返回任何来源/事件，也不用内部样本顶替");
        if (srcIp == null) {
            data.put("sources", List.of());
        } else {
            data.put("srcIp", policy().display(srcIp));
            data.put("events", List.of());
            data.put("eventCount", 0);
        }
        return data;
    }

    /** 400：参数不合法（只回机读 reason + 人话，不回任何内部细节） */
    private ResponseEntity<Map<String, Object>> badRequest(HttpServletResponse res, String reason, String message) {
        res.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", 400);
        body.put("message", message);
        body.put("reason", reason);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    // ==================== 访问日志聚合（/api/public/webstats；设计见 docs/design-webstats-public-endpoint.md） ====================

    /** 聚合端点自己的快照（与 /geo 分开：它读的是内存聚合器，不碰 indexer） */
    private final Snapshot webStatsCache = new Snapshot();

    /**
     * 访问日志聚合数据面（<b>可为空</b>：单测直接 new 控制器、或裁剪过的部署里就是 null）。
     * 空 → 端点按 {@code WEBSTATS_DISABLED} 如实降级，绝不假装"最近没人扫"。
     */
    @Autowired(required = false)
    private org.example.accesslog.WebStatsService webStatsService;

    /** 入榜门槛（站主口径⑤：类别计数 ≥5 才进 topCategories，低于门槛的只进总量） */
    @Value("${app.webstats.min-count:5}")
    private int webStatsMinCount = 5;

    @Value("${app.webstats.top-categories:10}")
    private int webStatsTopCategories = 10;

    @Value("${app.webstats.top-uas:5}")
    private int webStatsTopUas = 5;

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
        if (!rateLimiter.allow(clientIp(req))) {
            return tooMany(res);
        }
        return ok(webStatsCache.get(cacheSeconds, this::buildWebStats), res);
    }

    private Map<String, Object> buildWebStats() {
        String now = generatedAt();
        org.example.accesslog.WebStatsService svc = webStatsService;
        if (svc == null || !svc.enabled()) {
            return buildWebStatsUnavailable("WEBSTATS_DISABLED",
                    "访问日志聚合已在配置中关闭（app.webstats.enabled=false）：本端点不返回任何分布，"
                            + "也不以 0 冒充'最近没有扫描'。", cacheSeconds, now);
        }
        org.example.accesslog.WebStatsService.Status st = svc.status();
        if (!st.accessLogEnabled()) {
            return buildWebStatsUnavailable("LOG_DISABLED",
                    "应用侧访问日志已关闭（app.accesslog.enabled=false）：没有数据源，"
                            + "本端点不返回任何分布（URL 级扫描在应用侧不可见）。", cacheSeconds, now);
        }
        if (!st.fileExists()) {
            return buildWebStatsUnavailable("LOG_FILE_MISSING",
                    "访问日志文件当前不存在（可能被删、正在轮转，或从未写入）：不返回分布。"
                            + "内存聚合器仍在计数，文件恢复后会自动恢复（探测间隔见配置）。", cacheSeconds, now);
        }
        if (!st.fileReadable()) {
            return buildWebStatsUnavailable("LOG_UNREADABLE",
                    "访问日志文件存在但读不出来（权限/被占用/不是普通文件）：不返回分布，"
                            + "也不以 0 冒充'这段时间太平'。", cacheSeconds, now);
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
                                + "以免把'还没读到'画成'没有请求'；稍后重试即可。", cacheSeconds, now);
            }
            return buildWebStatsUnavailable("WINDOW_EMPTY",
                    "访问日志可读，但最近 24 小时窗口内没有任何请求记录（不是故障，也不是被隐藏）。",
                    cacheSeconds, now);
        }
        return buildWebStatsAvailable(snap, st, cacheSeconds, now, th);
    }

    private org.example.accesslog.WebStatsAggregator.Thresholds webStatsThresholds() {
        return new org.example.accesslog.WebStatsAggregator.Thresholds(
                Math.max(1, webStatsMinCount), Math.max(1, webStatsTopCategories), Math.max(0, webStatsTopUas));
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
    private static final org.example.accesslog.WebStatsAggregator.Thresholds DEFAULT_WEBSTATS_THRESHOLDS =
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

    // ==================== 载荷组装 ====================

    private Map<String, Object> buildHoneypot() {
        Map<String, Object> raw = source.honeypotSummary(800);
        boolean available = Boolean.TRUE.equals(raw.get("available"));

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", LocalDateTime.now().format(FMT));
        data.put("cacheSeconds", cacheSeconds);
        data.put("available", available);
        data.put("commandsAvailable", Boolean.TRUE.equals(raw.get("commandsAvailable")));
        data.put("note", available
                ? (policy().masked()
                        ? "IP 已掩码到网段；命令时间线的数据源尚未接入（Wazuh 侧没有命令执行规则，不编造）"
                        : "IP 显示观测到的真实来源地址（内网/保留地址一律写作「内网/未知」）；"
                                + "口令只给结构，命令时间线的数据源尚未接入（Wazuh 侧没有命令执行规则，不编造）")
                : "蜜罐数据源不可达，本页不展示任何蜜罐数据");

        if (available) {
            data.put("total", raw.get("total"));
            data.put("connections", raw.get("connections"));
            data.put("logins", raw.get("logins"));
            data.put("loginFails", raw.get("loginFails"));
            data.put("sampled", raw.get("sampled"));
            // 【2026-10-14 修】账号口令 Top 不再原样透出。
            // 改造前的注释写着"那是攻击者试的弱口令，是战报的核心信息"——来源里确实是这么想的，
            // 但原样输出的是【完整口令】（键的形状是 "root / 123456"），而站主的硬约束是
            // 蜜罐抓到的完整口令/凭据永不上公网（与投诉无关，是硬伤害）。
            // 现在只出结构：用户名 + 长度 + 字符类 + 弱口令标记；key 仍是同一个键，
            // 值改成结构摘要（"root / 6 位·小写字母+数字·弱口令"），页面无需为"口令列"改结构。
            data.put("topCredentials", credentialShapes(raw.get("topCredentials")));
            data.put("topSources", topSourcesForPublic(raw.get("topSources"), policy()));
            data.put("topClients", raw.get("topClients"));
            data.put("timeline", timelineForPublic(raw.get("timeline"), policy()));
        }
        return data;
    }

    private Map<String, Object> buildAudit() {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", LocalDateTime.now().format(FMT));
        data.put("cacheSeconds", cacheSeconds);
        data.put("readOnly", true);
        data.put("summary", auditReader.summary());
        data.put("blocks", auditReader.blocks(20));
        data.put("actions", actionTextForPublic(auditReader.actions(30), policy()));
        return data;
    }

    /** {@code /latest} 的取数入口（控制器方法，便于测试时只换数据源） */
    private Map<String, Object> buildLatest() {
        List<SecurityAlert> alerts = source.readAlerts();
        String mode = source.mode();
        boolean available = source.realData() && !alerts.isEmpty();

        List<Map<String, Object>> blocks = auditReader == null ? List.of() : auditReader.blocks(1);
        return buildLatest(alerts, available, mode, source.windowSize(), cacheSeconds, generatedAt(),
                blocks, policy());
    }

    private String generatedAt() {
        return LocalDateTime.now().format(FMT);
    }

    /**
     * {@code /latest} 的载荷组装 —— <b>纯函数</b>（除入参外不读任何状态）。
     *
     * <p>抽成 static 是为了能被单测直接喂数据：这条端点的关键承诺是
     * "无数据时如实 available=false + reason"，而那个分支在真环境里很难复现
     * （要刚好把隧道掐在某一步）。给它一个纯函数入口，就能把每种失败形态都钉住。
     *
     * <h3>字段白名单（不加字段是纪律，不是偷懒）</h3>
     * 出参只有：生成时间、缓存秒数、可用性与原因、窗口大小与条数、等级分布、
     * 来源分布（已按口径处理）、最近一条事件的<b>时间/等级/类型/来源地址</b>、最近一次封禁的
     * <b>时间/地址/动作</b>，以及统一口径字段 {@code ipDisclosure}。
     * 刻意<b>不含</b>：标题、规则名、内网目的地址与资产名、聚合 id 与成员 id、原始日志、
     * reason 正文（可能含内网信息）。
     *
     * @param alerts       已经过 fail-closed 过滤的真实告警（内置样本已在数据源侧剔除）
     * @param available    数据源是否真的拿到了真实数据
     * @param mode         数据源模式（REAL / MOCK / OFF），如实回显
     * @param windowSize   取数窗口大小（口径说明用）
     * @param cacheSeconds 应用内快照 TTL，同时作为 Cache-Control 的 max-age
     * @param generatedAt  本次载荷生成时间
     * @param latestBlocks 最近一次封禁记录（已按口径处理；可为空）
     */
    static Map<String, Object> buildLatest(List<SecurityAlert> alerts, boolean available, String mode,
                                           int windowSize, int cacheSeconds, String generatedAt,
                                           List<Map<String, Object>> latestBlocks) {
        // 【保留这个 7 参重载】它等价于"掩码态"，也就是改造前的口径：
        // 既有的载荷口径测试（PublicApiLatestTest）用的就是它，因此它们
        // 一字不改仍然是"掩码回归"的证据。生产链路走下面带 policy 的重载。
        return buildLatest(alerts, available, mode, windowSize, cacheSeconds, generatedAt,
                latestBlocks, PublicIpPolicy.masking());
    }

    /**
     * {@link #buildLatest(List, boolean, String, int, int, String, List)} 的口径显式版本。
     *
     * @param policy IP 显示口径（唯一来源：{@code app.public.mask-ips}）
     */
    static Map<String, Object> buildLatest(List<SecurityAlert> alerts, boolean available, String mode,
                                           int windowSize, int cacheSeconds, String generatedAt,
                                           List<Map<String, Object>> latestBlocks, PublicIpPolicy policy) {
        PublicIpPolicy p = policy == null ? PublicIpPolicy.masking() : policy;
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", generatedAt);
        data.put("cacheSeconds", cacheSeconds);
        data.put("available", available);
        data.put("wazuhMode", mode);
        data.put("windowSize", windowSize);
        data.put("windowAlertCount", alerts == null ? 0 : alerts.size());

        if (!available) {
            // 如实说原因。两种"没有数据"必须区分开：数据源不可用 vs 确实这段时间没有告警 ——
            // 前者是故障，后者是常态，混在一起会让前端把"链路断了"渲染成"一切太平"。
            String reason = "REAL".equalsIgnoreCase(mode == null ? "" : mode.trim())
                    ? "NO_DATA_IN_WINDOW" : "DATA_SOURCE_UNAVAILABLE";
            data.put("reason", reason);
            data.put("note", "DATA_SOURCE_UNAVAILABLE".equals(reason)
                    ? "告警数据源不可达（或未拿到真实数据），本次不展示任何告警数字，也不以内置样本顶替"
                    : "数据源可用，但当前取数窗口内没有任何真实告警（不是故障）");
            data.put("latestEvent", null);
            data.put("latestBlock", latestBlocks == null || latestBlocks.isEmpty() ? null : latestBlocks.get(0));
            return data;
        }

        data.put("reason", "OK");
        data.put("note", p.masked()
                ? "字段全部来自公开白名单：来源 IP 已掩码到网段，不含标题/内网目的地址/聚合 id"
                : "字段全部来自公开白名单：来源 IP 显示观测到的真实地址（内网/保留地址写作「内网/未知」），"
                        + "不含标题/内网目的地址/聚合 id");

        data.put("severityCounts", severityCounts(alerts));
        data.put("sourceCounts", sourceCounts(alerts));

        SecurityAlert newest = newest(alerts);
        Map<String, Object> ev = new LinkedHashMap<>();
        ev.put("occurredAt", newest == null ? null : newest.getOccurredAt());
        putEnum(ev, "severity", newest == null ? null : newest.getSeverity());
        putEnum(ev, "type", newest == null ? null : newest.getType());
        putEnum(ev, "source", newest == null ? null : newest.getSource());
        ev.put("srcIp", p.display(newest == null ? null : newest.getSrcIp()));
        data.put("latestEvent", ev);
        data.put("latestBlock", latestBlocks == null || latestBlocks.isEmpty() ? null : latestBlocks.get(0));
        return data;
    }

    /** 等级分布（固定枚举顺序，前端不必自己兜底缺失档位） */
    private static List<Map<String, Object>> severityCounts(List<SecurityAlert> alerts) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (AlertSeverity s : AlertSeverity.values()) {
            out.add(bucketOf(s.name(), s.getLabel(),
                    alerts.stream().filter(a -> a.getSeverity() == s).count()));
        }
        return out;
    }

    /** 来源分布（固定枚举顺序） */
    private static List<Map<String, Object>> sourceCounts(List<SecurityAlert> alerts) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (AlertSource s : AlertSource.values()) {
            out.add(bucketOf(s.name(), s.getLabel(),
                    alerts.stream().filter(a -> a.getSource() == s).count()));
        }
        return out;
    }

    /** 窗口内最近一条（按 occurredAt 倒序；时间解析不了的一律排到最后，不拿它冒充"最近"） */
    private static SecurityAlert newest(List<SecurityAlert> alerts) {
        SecurityAlert best = null;
        LocalDateTime bestTime = null;
        for (SecurityAlert a : alerts) {
            LocalDateTime t = parseTime(a == null ? null : a.getOccurredAt());
            if (t == null) {
                continue;
            }
            if (bestTime == null || t.isAfter(bestTime)) {
                bestTime = t;
                best = a;
            }
        }
        return best;
    }

    /** {@link #bucket} 的 static 版本（{@link #buildLatest} 是静态方法，不能调实例方法） */
    private static Map<String, Object> bucketOf(String key, String label, long count) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("key", key);
        m.put("label", label);
        m.put("count", count);
        return m;
    }

    /** 审计流水的文本字段（reason）也过一遍 IP 口径与口令隐藏 —— 文本里可能内嵌 IP / 口令 */
    private static List<Map<String, Object>> actionTextForPublic(List<Map<String, Object>> in,
                                                                 PublicIpPolicy policy) {
        for (Map<String, Object> m : in) {
            Object reason = m.get("reason");
            if (reason != null) {
                // 先隐口令（与 IP 口径无关的硬约束），再按开关处理 IP
                m.put("reason", policy.displayText(CredentialStructure.hidePasswords(String.valueOf(reason))));
            }
        }
        return in;
    }

    /**
     * 账号口令 Top → <b>只给结构</b>（"永不公开完整口令"的执行点）。
     *
     * <p>输入形状：{@code [{key:"root / 123456", count:3113}]}（{@code key} 里含完整口令）。
     * 输出形状：{@code [{key:"root / 6 位·小写字母+数字·弱口令", count:3113,
     * username:"root", passwordLength:6, passwordCharClasses:"小写字母+数字", weakPassword:true}]}。
     * {@code key} / {@code count} 两个既有字段都保留（契约"只许新增字段"），
     * 新增的四个字段让页面能自己组装结构说明。口令原文字符<b>一个都不出现</b>。
     */
    static List<Map<String, Object>> credentialShapes(Object v) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (v instanceof List<?> l) {
            for (Object o : l) {
                if (o instanceof Map<?, ?> m) {
                    Map<String, Object> x = CredentialStructure.describe(
                            m.get("key") == null ? null : String.valueOf(m.get("key")));
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("key", x.get("key"));
                    entry.put("count", m.get("count"));
                    entry.put("username", x.get("username"));
                    entry.put("passwordLength", x.get("passwordLength"));
                    entry.put("passwordCharClasses", x.get("passwordCharClasses"));
                    entry.put("weakPassword", x.get("weakPassword"));
                    out.add(entry);
                }
            }
        }
        return out;
    }

    /** 把 [{key,count}] 里的 key 当来源 IP 处理（口径由 {@link PublicIpPolicy} 决定） */
    private static List<Map<String, Object>> topSourcesForPublic(Object v, PublicIpPolicy policy) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (v instanceof List<?> l) {
            for (Object o : l) {
                if (o instanceof Map<?, ?> m) {
                    Map<String, Object> x = new LinkedHashMap<>();
                    x.put("key", policy.display(m.get("key") == null ? null : String.valueOf(m.get("key"))));
                    x.put("count", m.get("count"));
                    out.add(x);
                }
            }
        }
        return out;
    }

    /**
     * 时间线 → 来源 IP + detail 文本（口径由 {@link PublicIpPolicy} 决定）。
     *
     * <p><b>2026-10-14 修</b>：{@code detail} 是蜜罐规则的<b>描述原文</b>，形状是
     * {@code 蜜罐: 攻击者"登录成功" 用户=root 口令=123456 来源=106.37.205.248}。
     * 改造前这里只对 IP 做掩码，<b>完整口令就这样随 timeline 出过公网</b>。
     * 现在先整段隐口令（与开关无关），再按口径处理 IP。
     */
    private static List<Map<String, Object>> timelineForPublic(Object v, PublicIpPolicy policy) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (v instanceof List<?> l) {
            for (Object o : l) {
                if (o instanceof Map<?, ?> m) {
                    Map<String, Object> x = new LinkedHashMap<>();
                    x.put("time", m.get("time"));
                    x.put("kind", m.get("kind"));
                    x.put("srcIp", policy.display(m.get("srcIp") == null ? null : String.valueOf(m.get("srcIp"))));
                    // detail 是规则描述原文，里面内嵌了完整 IP 与完整口令 —— 两者都必须处理，
                    // 否则前面结构化字段处理得再干净，这里照样漏（实测漏过一次）
                    x.put("detail", policy.displayText(CredentialStructure.hidePasswords(
                            m.get("detail") == null ? null : String.valueOf(m.get("detail")))));
                    out.add(x);
                }
            }
        }
        return out;
    }

    private Map<String, Object> buildOverview() {
        // 先取数、再判定可用性：若上游"连得上但查询失败"退回内置样本，
        // readAlerts() 会把样本剔除并把 mockFallback 置位，realData() 随后如实返回 false，
        // 于是响应里的 degraded=true（而不是拿样本当真实告警、还写 degraded=false）。
        List<SecurityAlert> raw = source.readAlerts();
        boolean real = source.realData();

        Map<String, Object> alerts = new LinkedHashMap<>();
        alerts.put("windowSize", source.windowSize());
        alerts.put("windowCount", raw.size());
        alerts.put("windowFull", raw.size() >= source.windowSize());
        alerts.put("windowDescription", "最近 " + source.windowSize() + " 条告警窗口"
                + (raw.size() >= source.windowSize() ? "（已取满，实际数量更多）" : ""));
        alerts.put("todayInWindow", countToday(raw));
        alerts.put("critical", countSeverity(raw, AlertSeverity.CRITICAL));
        alerts.put("high", countSeverity(raw, AlertSeverity.HIGH));
        alerts.put("bySeverity", severityStats(raw));
        alerts.put("bySource", sourceStats(raw));

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", LocalDateTime.now().format(FMT));
        data.put("cacheSeconds", cacheSeconds);
        data.put("nodes", nodes(real));
        data.put("alerts", alerts);
        data.put("dataSource", dataSource(real));
        return data;
    }

    private Map<String, Object> buildAlerts() {
        // 先取数、再判定可用性：若上游"连得上但查询失败"退回内置样本，
        // readAlerts() 会把样本剔除并把 mockFallback 置位，realData() 随后如实返回 false，
        // 于是响应里的 degraded=true（而不是拿样本当真实告警、还写 degraded=false）。
        List<SecurityAlert> raw = source.readAlerts();
        boolean real = source.realData();
        List<Map<String, Object>> aggs = source.aggregated();
        List<Map<String, Object>> publicList = new ArrayList<>();
        for (Map<String, Object> g : aggs) {
            publicList.add(publicAggregate(g));
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", LocalDateTime.now().format(FMT));
        data.put("cacheSeconds", cacheSeconds);
        data.put("dataSource", dataSource(real));
        data.put("windowSize", source.windowSize());
        data.put("rawTotal", raw.size());
        data.put("total", publicList.size());
        data.put("aggregated", source.aggregationEnabled());
        data.put("windowMinutes", source.aggregationWindowMinutes());
        data.put("list", publicList);
        data.put("stats", Map.of(
                "bySeverity", severityStats(raw),
                "bySource", sourceStats(raw),
                "byType", typeStats(raw),
                "trend", trend(raw)
        ));
        // 近 24 小时口径：KPI 的"严重/高危"与趋势图都取这一份 ——
        // 取数窗口会被低危网络告警刷屏，按时间范围聚合才是"这段时间到底怎么样"
        Map<String, Object> stats24h = source.summary24h();
        data.put("stats24h", stats24h);
        // 把 24h 聚合的机读状态也放进 dataSource：前端 Hero 的第一个数字取的是 stats24h，
        // 而"链路没起来(warming)"与"后端真的坏了(degraded)"要显示成不同的话。
        // 这里是【新增字段】，既有 available/degraded 口径不变。
        if (stats24h.get("state") != null) {
            data.put("stats24hState", stats24h.get("state"));
            data.put("stats24hReason", stats24h.get("reason"));
        }
        return data;
    }

    /** 两台服务器的在线状态。判据写清楚：不写"我觉得在线"。 */
    private List<Map<String, Object>> nodes(boolean dataLinkUp) {
        List<Map<String, Object>> nodes = new ArrayList<>();

        Map<String, Object> srv1 = new LinkedHashMap<>();
        srv1.put("id", "srv1");
        srv1.put("label", "服务机 · SecAgent");
        srv1.put("online", true);
        srv1.put("probe", "本进程正在响应");
        srv1.put("detail", exposeBuildSha ? ("build " + buildSha) : "");
        nodes.add(srv1);

        Map<String, Object> srv2 = new LinkedHashMap<>();
        srv2.put("id", "srv2");
        srv2.put("label", "数据机 · Wazuh / Suricata / Cowrie");
        srv2.put("online", dataLinkUp);
        srv2.put("probe", "indexer(9200) 经 SSH 隧道可达");
        srv2.put("detail", dataLinkUp ? "数据链路正常" : "数据链路不可达，告警不展示");
        nodes.add(srv2);

        return nodes;
    }

    private Map<String, Object> dataSource(boolean real) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("wazuhMode", source.mode());
        m.put("degraded", !real);
        m.put("note", real
                ? "网络告警（Suricata）经 Wazuh agent 采集后随 indexer 一起返回，来源已按规则分组判定"
                : "告警数据源不可达，本页不展示任何告警（不以内置样本代替）");
        return m;
    }

    /**
     * 聚合告警 → 公网字段白名单。
     *
     * <p>被<b>刻意丢掉</b>的字段：{@code dstIp} / {@code dstAsset} / {@code assets}
     * （内网拓扑）、{@code memberIds}（内部 id 集合）、{@code rawLog} / 完整 payload。
     */
    private Map<String, Object> publicAggregate(Map<String, Object> src) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("aggId", src.get("aggId"));
        m.put("count", src.get("count"));
        m.put("startTime", src.get("startTime"));
        m.put("endTime", src.get("endTime"));
        m.put("title", src.get("title"));
        m.put("ruleName", src.get("ruleName"));
        m.put("srcIp", policy().display(asString(src.get("srcIp"))));
        // 公开面【刻意】恒为 null：srcGeo 的内部形状是「国家|省|城市|ASN|机构」（GeoIpInfo.describe()），
        // 逐条输出它等于把"某个攻击者属于哪个机构"搬上公网页面；公开面的地理口径只有聚合
        // （GET /api/public/geo，见 docs/design-geo-endpoint.md）。
        // 键名保留、值保持空 —— 这正是本轮改造前它对真实告警的取值（内置样本不进公开面），
        // 所以不是语义变更，而是"不让新富化的数据从这条缝里漏出去"。测试：PublicApiGeoLeakTest。
        m.put("srcGeo", null);
        m.put("occurredAt", src.get("occurredAt"));
        m.put("status", src.get("status"));
        m.put("hitCount", src.get("hitCount"));
        putEnum(m, "severity", src.get("severity"));
        putEnum(m, "type", src.get("type"));
        putEnum(m, "source", src.get("source"));
        return m;
    }

    /** 原始告警 → 公网字段白名单（下钻明细用） */
    private Map<String, Object> publicAlert(SecurityAlert a) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", a.getId());
        m.put("title", a.getTitle());
        m.put("ruleName", a.getRuleName());
        m.put("srcIp", policy().display(a.getSrcIp()));
        // 同 publicAggregate：srcGeo 只在内网面可见，公开面恒为 null（口径见上）
        m.put("srcGeo", null);
        m.put("occurredAt", a.getOccurredAt());
        m.put("status", a.getStatus());
        m.put("hitCount", a.getCount());
        putEnum(m, "severity", a.getSeverity());
        putEnum(m, "type", a.getType());
        putEnum(m, "source", a.getSource());
        return m;
    }

    /** 枚举字段统一输出 {枚举名, 中文标签}，前端不必自己维护映射表 */
    private static void putEnum(Map<String, Object> target, String field, Object value) {
        if (value == null) {
            target.put(field, null);
            target.put(field + "Label", null);
            return;
        }
        if (value instanceof AlertSeverity s) {
            target.put(field, s.name());
            target.put(field + "Label", s.getLabel());
        } else if (value instanceof AlertSource s) {
            target.put(field, s.name());
            target.put(field + "Label", s.getLabel());
        } else if (value instanceof AlertType t) {
            target.put(field, t.name());
            target.put(field + "Label", t.getLabel());
        } else {
            target.put(field, String.valueOf(value));
            target.put(field + "Label", String.valueOf(value));
        }
    }

    // ==================== 统计 ====================

    private List<Map<String, Object>> severityStats(List<SecurityAlert> raw) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (AlertSeverity s : AlertSeverity.values()) {
            out.add(bucket(s.name(), s.getLabel(), countSeverity(raw, s)));
        }
        return out;
    }

    private List<Map<String, Object>> sourceStats(List<SecurityAlert> raw) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (AlertSource s : AlertSource.values()) {
            long c = raw.stream().filter(a -> a.getSource() == s).count();
            out.add(bucket(s.name(), s.getLabel(), c));
        }
        return out;
    }

    private List<Map<String, Object>> typeStats(List<SecurityAlert> raw) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (AlertType t : AlertType.values()) {
            long c = raw.stream().filter(a -> a.getType() == t).count();
            if (c > 0) {
                out.add(bucket(t.name(), t.getLabel(), c));
            }
        }
        return out;
    }

    private Map<String, Object> bucket(String key, String label, long count) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("key", key);
        m.put("label", label);
        m.put("count", count);
        return m;
    }

    /** 最近 24 小时按小时分桶 */
    private List<Map<String, Object>> trend(List<SecurityAlert> raw) {
        LocalDateTime now = LocalDateTime.now().withMinute(0).withSecond(0).withNano(0);
        Map<String, Long> buckets = new LinkedHashMap<>();
        for (int i = 23; i >= 0; i--) {
            buckets.put(now.minusHours(i).format(HOUR_FMT), 0L);
        }
        for (SecurityAlert a : raw) {
            LocalDateTime t = parseTime(a.getOccurredAt());
            if (t == null || t.isBefore(now.minusHours(24)) || t.isAfter(now.plusHours(1))) {
                continue;
            }
            buckets.merge(t.withMinute(0).format(HOUR_FMT), 1L, Long::sum);
        }
        List<Map<String, Object>> out = new ArrayList<>();
        buckets.forEach((k, v) -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("time", k);
            m.put("count", v);
            out.add(m);
        });
        return out;
    }

    private long countToday(List<SecurityAlert> raw) {
        String today = LocalDate.now().toString();
        return raw.stream()
                .filter(a -> a.getOccurredAt() != null && a.getOccurredAt().startsWith(today))
                .count();
    }

    private long countSeverity(List<SecurityAlert> raw, AlertSeverity s) {
        return raw.stream().filter(a -> a.getSeverity() == s).count();
    }

    private static LocalDateTime parseTime(String s) {
        if (s == null || s.isBlank()) {
            return null;
        }
        try {
            return LocalDateTime.parse(s.trim(), FMT);
        } catch (Exception e) {
            return null;
        }
    }

    // ==================== 限流 / 缓存 / 响应 ====================

    /**
     * 取调用方 IP。
     *
     * <p>线上流量经 Cloudflare 隧道进来，{@code remoteAddr} 是隧道侧地址、
     * 所有访客会落进同一个桶 —— 所以优先取 {@code CF-Connecting-IP}。
     * 边界说明：这两个头在<b>直连</b>场景下可伪造，因此它只用于限流，
     * 不作为任何安全判定依据（真正的边界在隧道与拦截器上）。
     */
    private String clientIp(HttpServletRequest req) {
        String cf = req.getHeader("CF-Connecting-IP");
        if (cf != null && !cf.isBlank()) {
            return cf.trim();
        }
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            int comma = xff.indexOf(',');
            return (comma > 0 ? xff.substring(0, comma) : xff).trim();
        }
        return req.getRemoteAddr();
    }

    private ResponseEntity<Map<String, Object>> ok(Map<String, Object> data, HttpServletResponse res) {
        res.setHeader(HttpHeaders.CACHE_CONTROL, "public, max-age=" + Math.max(0, cacheSeconds));
        res.setHeader("X-Data-Source", source.available() ? "WAZUH_REAL" : "UNAVAILABLE");
        res.setHeader("X-RateLimit-Limit", String.valueOf(rateLimiter.limitPerMinute()));

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", 200);
        body.put("message", "success");
        // 所有公开 GET 端点的共同出口：资产名过滤 + 统一 ipDisclosure（口径只有一个来源）
        Map<String, Object> shipped = ship(data);
        body.put("data", shipped);
        // 【缓存别名专属】旧路径（无 .js 后缀）不写下面任何一项 ⇒ 响应体与响应头逐字节不变。
        if (isCacheAliasRequest()) {
            res.setHeader(HttpHeaders.CACHE_CONTROL, aliasCacheControl());
            String stableEtag = cacheAliasEtag(shipped);
            if (stableEtag != null) {
                res.setHeader(HttpHeaders.ETAG, stableEtag);
            }
            stampSnapshotFreshness(body);
        }
        return ResponseEntity.ok(body);
    }

    /**
     * 别名路径的缓存头（max-age 与快照 TTL 同源：{@code app.public-api.cache-seconds}）。
     *
     * <h3>为什么 max-age 必须等于快照 TTL，而不是另一个数</h3>
     * 站点 {@code /alerts/} 页**每 40 秒轮询一次**（`layouts/partials/xk-demo/api-bind.html:41`
     * {@code REFRESH = 40000}，配 {@code :1003 setInterval(load, REFRESH)}）。边缘 TTL 若短于轮询间隔，
     * 每次轮询都落在"已过期"上 ⇒ 每 40 秒给源站 9 个请求（≈13.5/分，逼近公开面每 IP 20/分 的上限，
     * 而每次回源都消耗访客自己的额度）。现在快照 TTL 与边缘 TTL 都是 45s（> 40s 轮询间隔）⇒
     * 常规轮询落在有效期内的**快照**上 ⇒ 命中边缘、且源站那一腿是热的（3~5ms）。
     * 数据最旧 45 秒，由 {@code snapshotAt} + {@code Age} 如实呈现（红线 D4：被缓存不许假装更新）。
     *
     * <p>为什么不能各写一个数：只要两者不一致，就会出现"快照已经 45 秒旧、却告诉缓存 15 秒"或反之的
     * 自相矛盾 —— 而这类矛盾不会报错，只会在线上表现为"偶尔很慢"。
     *
     * <h3>为什么要 stale-while-revalidate</h3>
     * 即使再验证发生，边缘也**先把手上那份发出去**、在后台去源站确认 ⇒ 用户侧不会因为
     * "回源 + TLS + 边缘选择（实测曾命中 LHR 伦敦）"而卡住。这正是"加载很慢"的直接解药。
     *
     * <h3>⚠️ 浏览器侧 TTL 由 Cloudflare 决定，不由这里决定</h3>
     * 实测（2026-10-16 20:08，srv1）：本机直连 origin 得到 {@code public, max-age=45}；
     * 经 CF 得到的却是 {@code public, max-age=14400}（4 小时，SWR 被保留）—— 这是 zone 的
     * **Browser Cache TTL** 在覆写（CF 会把较短的 max-age 抬到该设置值）。
     * ⇒ 浏览器可能把这份数据缓存 4 小时。**前端因此必须用条件请求/`no-store` 语义取数**
     * （站点线 B2 那批），或由站主在 CF 控制台把 Browser Cache TTL 改为 "Respect Existing Headers"。
     * 这一条已写进契约文档，别让它留在线上而不写文档。
     */
    private String aliasCacheControl() {
        return "public, max-age=" + Math.max(0, cacheSeconds)
                + ", stale-while-revalidate=" + CACHE_ALIAS_SWR_SECONDS;
    }

    /**
     * 别名路径的**稳定 ETag**：只对"数据内容"算，不含 {@code snapshotAt} / {@code cacheAgeSeconds}
     * 这类每请求都在变的元数据。
     *
     * <h3>为什么必须这样算（实测的坑）</h3>
     * {@link PublicEtagFilter} 默认按**完整响应体**算 ETag。而别名响应体里的
     * {@code cacheAgeSeconds} 每秒都在变（实测：两次调用 {@code data} 完全相同，
     * 唯一差异是 {@code cacheAgeSeconds: 9 → 12}）⇒ ETag 每次都不同
     * ⇒ Cloudflare 的再验证**永远拿不到 304**，每次过期都变成一次完整的 200 回源。
     * 按"数据内容"算之后，同一快照窗口内 ETag 稳定 ⇒ 再验证可 304 ⇒ 回源从
     * "每 15 秒每端点 1 次"降到"数据真的变了才回源"。
     *
     * <p>序列化器把 Map 键排序 ⇒ ETag 与插入顺序无关，只取决于内容。
     * 计算失败返回 {@code null}：调用方不下发 ETag，退回过滤器按完整体算（如实降级，不假装稳定）。
     */
    private static String cacheAliasEtag(Map<String, Object> shipped) {
        try {
            return PublicEtagFilter.etagOf(ETAG_MAPPER.writeValueAsBytes(shipped));
        } catch (Exception e) {
            logger.warn("别名 ETag 计算失败，退回按完整响应体计算：{}", e.getMessage());
            return null;
        }
    }

    /**
     * 定时预聚合：把"读 indexer + 聚合"的现算成本**从访客请求路径搬到后台**。
     *
     * <h3>它解决什么</h3>
     * 站主实测："页面打开很快，但取数慢（约 10s 才出数据）"。根因之一就是
     * <b>冷快照要现算</b>：{@code alerts} 冷 3.7s / {@code webstats} 冷 4.1s / {@code honeypot} 冷 3.8s
     * （暖态 3~5ms）。快照一旦过期，第一个到达的访客就要替所有人付这笔钱。
     * 后台每 {@code warm-interval-ms}（默认 30s）检查一遍：只要某个快照的年龄超过
     * {@code TTL × warm-threshold-ratio}（默认 45s × 0.5 = 22.5s）就主动刷新 ⇒
     * 访客侧几乎永远命中热快照（目标：源站响应 ≤50ms，无论冷暖）。
     *
     * <h3>三个刻意的设计</h3>
     * <ol>
     *   <li><b>不比原来更频繁地查上游</b>：阈值取 TTL 的一半，而不是"每 30 秒无条件重算" ——
     *       后者会把上游查询量抬到"有访客才算"的几十倍；</li>
     *   <li><b>绝不阻塞、绝不抛</b>：任何端点刷新失败只记一条 WARN，保留旧快照
     *       （{@link Snapshot#refreshIfOlderThan} 内部已兜底）；整个方法再包一层 try/catch，
     *       保证"预聚合坏掉"不会影响任何请求、也不会让定时线程崩掉；</li>
     *   <li><b>与请求侧共用同一个 Snapshot 与同一把"刷新权"</b>：后台正在刷时，请求侧立刻拿旧值，
     *       两边不会同时打上游（也天然防击穿）。</li>
     * </ol>
     *
     * <p>为什么放在控制器里而不是单独一个 {@code @Component}：这些快照实例与各端点的 builder
     * 都是本类的私有成员，放在这里才能复用同一份实例 —— 换个类就得把这些状态暴出去，
     * 反而更容易出"两份缓存"的错。
     */
    @Scheduled(fixedDelayString = "${app.public-api.warm-interval-ms:30000}",
            initialDelayString = "${app.public-api.warm-initial-delay-ms:10000}")
    public void warmPublicSnapshots() {
        long maxAge = Math.max(1000L, (long) (Math.max(1, cacheSeconds) * 1000L * Math.max(0.1d, warmThresholdRatio)));
        int refreshed = 0;
        refreshed += warmOne(overviewCache, "overview", maxAge, this::buildOverview);
        refreshed += warmOne(alertsCache, "alerts", maxAge, this::buildAlerts);
        refreshed += warmOne(honeypotCache, "honeypot", maxAge, this::buildHoneypot);
        refreshed += warmOne(auditCache, "audit", maxAge, this::buildAudit);
        refreshed += warmOne(latestCache, "latest", maxAge, this::buildLatest);
        refreshed += warmOne(geoCache, "geo", maxAge, this::buildGeo);
        refreshed += warmOne(webStatsCache, "webstats", maxAge, this::buildWebStats);
        /* ★2026-10-16 补：**聚合端点也必须进预聚合**。
           漏了它的后果是线上实测出来的：`/api/public/home.js` 的 P50 = **29.9 秒**（min 868ms）——
           45 秒 TTL 一过，第一个访客就要替所有人现算三块（alerts+geo+honeypot），
           而单端点那些早就被后台刷热了 ⇒ 聚合反而比单端点慢 20 倍，与本端点"省一次路程"的初衷相反。
           **顺序有讲究**：放在三个子快照之后 —— 这样 buildHome() 只是"组合三份已热快照"（毫秒级），
           若放前面，它会触发三个子快照的冷现算，把后台这一轮拖成十几秒。 */
        refreshed += warmOne(homeCache, "home", maxAge, this::buildHome);
        if (refreshed > 0) {
            logger.debug("公网快照预聚合：本轮刷新 {} 个端点（年龄阈值 {}ms）", refreshed, maxAge);
        }
    }

    /** 单个端点的预聚合：任何异常都吞掉并记 WARN —— 预聚合坏掉不许影响请求或定时线程 */
    private int warmOne(Snapshot snapshot, String name, long maxAgeMillis, Supplier<Map<String, Object>> loader) {
        try {
            return snapshot.refreshIfOlderThan(maxAgeMillis, cacheSeconds, loader) ? 1 : 0;
        } catch (Exception e) {
            logger.warn("公网快照预聚合失败（{}，保留旧快照）：{}", name, e.getMessage());
            return 0;
        }
    }

    /**
     * 缓存别名请求的判定：URI 以 {@link PublicCorsInterceptor#CACHE_ALIAS_SUFFIX} 结尾。
     *
     * <p>为什么用 URI 而不是参数/Header：别名是<b>纯 URL 形状</b>的约定（Cloudflare 按扩展名
     * 决定是否缓存），任何请求头/查询参数都不能改变它 —— 也让"客户端加了 {@code ?cb=} 反而
     * 命中不到边缘缓存"这件事变得可解释（契约里明文禁止 cache-buster）。
     */
    private static boolean isCacheAliasRequest() {
        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        if (!(attrs instanceof ServletRequestAttributes sra)) {
            return false;
        }
        String uri = sra.getRequest().getRequestURI();
        return uri != null && uri.endsWith(PublicCorsInterceptor.CACHE_ALIAS_SUFFIX);
    }

    /**
     * 给别名响应体盖上"数据真实生成时刻"的戳（站主红线 D4：被缓存不等于可以假装更新）。
     *
     * <ul>
     *   <li>{@code snapshotAt} —— 本响应体内数据的真实生成时刻（ISO-8601 带时区）。页面显示
     *       "刚刚同步"必须用它，<b>不许</b>用接收响应的时刻；</li>
     *   <li>{@code cacheAgeSeconds} —— 生成本响应体时，这份数据已经有多旧（走快照的端点在快照
     *       命中时大于 0）；</li>
     *   <li>{@code snapshotTtlSeconds} —— 应用内快照 TTL，同时也是 {@code Cache-Control: max-age}
     *       的值（两者同一个来源 {@code app.public-api.cache-seconds}）。</li>
     * </ul>
     *
     * <p><b>真实年龄 = {@code cacheAgeSeconds} + 响应头 {@code Age}</b>：前者是"源站生成时它多旧"，
     * 后者是"边缘/中间缓存又放了多久"。{@code Age} 不是 CORS 安全响应头，所以别名路径在
     * {@code Access-Control-Expose-Headers} 里显式放行了它（见 {@link PublicCorsInterceptor}）。
     *
     * <p>{@code freshnessNote} 是给前端与未来的接手者读的<b>口径说明</b>（一句话，不参与判断）。
     */
    private void stampSnapshotFreshness(Map<String, Object> body) {
        Long marked = PublicSnapshotClock.peek();
        PublicSnapshotClock.clear();
        long now = System.currentTimeMillis();
        long generatedAt = marked == null ? now : marked;
        body.put("snapshotAt", Instant.ofEpochMilli(generatedAt)
                .atZone(ZoneId.systemDefault())
                .truncatedTo(ChronoUnit.SECONDS)
                .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
        body.put("cacheAgeSeconds", Math.max(0, (now - generatedAt) / 1000));
        body.put("snapshotTtlSeconds", Math.max(0, cacheSeconds));
        body.put("freshnessNote",
                "snapshotAt=本响应体内数据的真实生成时刻（页面按它显示同步时间）；"
                        + "cacheAgeSeconds=生成时它已有多旧；真实年龄=cacheAgeSeconds+响应头Age；"
                        + "禁止给本地址加 ?cb= 之类 cache-buster（会绕过边缘缓存）");
    }

    private ResponseEntity<Map<String, Object>> tooMany(HttpServletResponse res) {
        res.setHeader(HttpHeaders.RETRY_AFTER, "60");
        res.setHeader("X-RateLimit-Limit", String.valueOf(rateLimiter.limitPerMinute()));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", 429);
        body.put("message", "请求过于频繁，请稍后再试");
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(body);
    }

    /**
     * 429：带上"哪个限流器挡的、上限多少、还剩多少、多久能再试"。
     *
     * <p>为什么要多这几个字段：公开页面必须能显示人话（"请稍后再试"），
     * 而排障时最需要知道的恰恰是"被哪一条规则挡的" —— 只回一个裸 429，
     * 前端只能笼统提示，站主也只能靠猜。
     */
    private ResponseEntity<Map<String, Object>> tooMany(HttpServletResponse res,
                                                        PublicAskRateLimiter limiter,
                                                        String message) {
        res.setHeader(HttpHeaders.RETRY_AFTER, "60");
        res.setHeader("X-RateLimit-Limit", String.valueOf(limiter.limitPerMinute()));
        res.setHeader("X-RateLimit-Remaining", "0");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", 429);
        body.put("message", message);
        body.put("limitPerMinute", limiter.limitPerMinute());
        body.put("retryAfterSeconds", 60);
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(body);
    }

    @SuppressWarnings("unchecked")
    private static List<String> asStringList(Object v) {
        if (v instanceof List<?> l) {
            List<String> out = new ArrayList<>();
            for (Object o : l) {
                out.add(String.valueOf(o));
            }
            return out;
        }
        return Collections.emptyList();
    }

    private static String asString(Object v) {
        return v == null ? null : String.valueOf(v);
    }

    /**
     * 极简快照缓存：TTL 内直接返回上一次的结果；**过期时只让一个线程去算，其余线程立刻拿旧值**。
     *
     * <p>为什么值得要：公网页面每次刷新都会触发一次"读 indexer + 聚合"，
     * 而数据本身只按分钟级变化。缓存把上游查询量与访客数解耦，
     * 同时让"数据同步时间"变成一个可以如实展示的值（generatedAt）。
     *
     * <h3>为什么不阻塞（2026-10-16 晚改）</h3>
     * 旧实现是 {@code synchronized}：快照过期时，第一个请求进去现算（实测 alerts 冷 3.7s /
     * webstats 冷 4.1s），**同时到达的其他请求会被锁住一起等** —— 这就是站主看到的"页面打开快、
     * 取数慢（约 10s）"。现在改成：
     * <ul>
     *   <li>未过期 ⇒ 直接返回（3~5ms）；</li>
     *   <li>已过期 ⇒ 抢到"刷新权"的那个线程去算，**其余线程立刻返回旧值**（旧值只差几十秒，
     *       且由 {@code snapshotAt}/{@code cacheAgeSeconds} 如实标注年龄）；</li>
     *   <li>只有"从来没有过值"（应用刚起来）才会短暂等待，等待超时仍按 fail-closed 抛错，
     *       不返回空白 200。</li>
     * </ul>
     * 再配合 {@link #warmPublicSnapshots()} 的后台预聚合，"过期"这件事在正常情况下根本不会发生。
     */
    static final class Snapshot {

        private volatile Map<String, Object> value;
        private volatile long expiresAt;

        /** 上一次真正去加载（或首次加载）的时刻：别名响应体的 {@code snapshotAt} 用它 */
        private volatile long loadedAtMs;

        /** 是否有线程正在刷新：用它替代"锁"，保证请求侧不等现算（也天然防击穿） */
        private final AtomicBoolean refreshing = new AtomicBoolean(false);

        /** 首次无值时的等待上限（毫秒）：冷启动并发首访才会用到 */
        private static final long FIRST_WAIT_TIMEOUT_MS = 3000L;

        Map<String, Object> get(int ttlSeconds, Supplier<Map<String, Object>> loader) {
            Map<String, Object> cur = value;
            if (cur != null && System.currentTimeMillis() < expiresAt) {
                PublicSnapshotClock.mark(loadedAtMs);
                return cur;
            }
            if (!refreshing.compareAndSet(false, true)) {
                // 别的线程正在算：有旧值就**立刻**给旧值（不阻塞、不等待）
                if (cur != null) {
                    PublicSnapshotClock.mark(loadedAtMs);
                    return cur;
                }
                return awaitFirstValue(loader, ttlSeconds);
            }
            try {
                return load(ttlSeconds, loader);
            } finally {
                refreshing.set(false);
            }
        }

        /**
         * 定时预聚合用：值比 {@code maxAgeMillis} 旧（或还没有值）就刷新。
         *
         * <p>为什么按"年龄阈值"而不是"过期才刷"：过期才刷等于把现算留给下一个访客。
         * 阈值取 TTL 的一半（默认）⇒ 访客侧永远拿到热快照，而上游查询频率不会比原来更高。
         *
         * @return 本轮是否真的执行了刷新（有人在算时直接跳过，不排队）
         */
        boolean refreshIfOlderThan(long maxAgeMillis, int ttlSeconds, Supplier<Map<String, Object>> loader) {
            Map<String, Object> cur = value;
            if (cur != null && (System.currentTimeMillis() - loadedAtMs) <= maxAgeMillis) {
                return false;
            }
            if (!refreshing.compareAndSet(false, true)) {
                return false;
            }
            try {
                load(ttlSeconds, loader);
                return true;
            } finally {
                refreshing.set(false);
            }
        }

        /** 带异常兜底的真实加载：成功则发布新值；失败保留旧值，没有旧值才抛（fail-closed） */
        private Map<String, Object> load(int ttlSeconds, Supplier<Map<String, Object>> loader) {
            try {
                Map<String, Object> fresh = loader.get();
                long now = System.currentTimeMillis();
                value = fresh;
                loadedAtMs = now;
                expiresAt = now + Math.max(0, ttlSeconds) * 1000L;
                PublicSnapshotClock.mark(now);
                return fresh;
            } catch (Exception e) {
                // 刷新失败：有旧快照就继续用旧的（页面标注同步时间），
                // 没有旧快照就抛出，让调用方看到错误而不是"空白但 200"
                logger.warn("公网快照刷新失败：{}", e.getMessage());
                Map<String, Object> cur = value;
                if (cur != null) {
                    expiresAt = System.currentTimeMillis() + 5000L;
                    PublicSnapshotClock.mark(loadedAtMs);
                    return cur;
                }
                throw new IllegalStateException("公网快照刷新失败且无可用旧快照", e);
            }
        }

        /** 冷启动并发首访：另一个线程正在算且还没有值 —— 有限等待，超时抛错（不返回空白 200） */
        private Map<String, Object> awaitFirstValue(Supplier<Map<String, Object>> loader, int ttlSeconds) {
            long deadline = System.currentTimeMillis() + FIRST_WAIT_TIMEOUT_MS;
            while (System.currentTimeMillis() < deadline) {
                Map<String, Object> v = value;
                if (v != null) {
                    PublicSnapshotClock.mark(loadedAtMs);
                    return v;
                }
                try {
                    Thread.sleep(50L);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            throw new IllegalStateException("公网快照首次加载等待超时（另一个线程仍在计算）");
        }
    }
}
