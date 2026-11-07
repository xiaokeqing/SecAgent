package org.example.publicapi;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import java.time.Instant;
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
import org.springframework.stereotype.Component;

/**
 * {@code /api/public/**} 各域 controller 的共享状态与通用工具。
 *
 * <h3>为什么要有它</h3>
 * 公开面原先是单文件 god controller，但它的状态天生跨端点共享：
 * 快照缓存（overview/alerts/honeypot/audit/latest/home/deploy/eval/geo/webstats）必须<b>唯一实例</b>
 * （{@code /home} 直接组合其它端点同一批快照，{@code home.data.alerts} 要与 {@code alerts.data} 逐字段相同），
 * 出关脱敏口径（{@code ship/scrubText}）与响应信封（{@code ok/tooMany/badRequest}）也必须只有一份。
 * 所以这些状态与工具下沉到本类，按域拆出去的是<b>端点与端点私有的 builder</b>。
 *
 * <h3>测试怎么装配</h3>
 * 本仓库没有 {@code @SpringBootTest}：测试统一用 {@code new PublicApiTestAssembly()}
 * （测试源里的装配器）一次性拼出本类 + 五个按域 controller，再
 * {@code MockMvcBuilders.standaloneSetup(...)} 注册全部 controller；注入字段仍走
 * {@code ReflectionTestUtils.setField(assembly.support, …)}。历史门面
 * {@code PublicApiController} 已删除，不再有"注解 + 一行转发"的委托层。
 *
 * <p>本类刻意<b>不是</b>任何端点的 owner：它不持有 {@code @RequestMapping}，
 * 端点注解在五个按域 controller 上（{@code PublicAlertController}/{@code PublicHomeController}/
 * {@code PublicKbController}/{@code PublicGeoController}/{@code PublicMiscController}）。
 */
@Component
public class PublicApiSupport {

    static final Logger logger = LoggerFactory.getLogger(PublicApiSupport.class);

    static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    static final DateTimeFormatter HOUR_FMT = DateTimeFormatter.ofPattern("HH:mm");

    /** 时间线端点最多返回的事件条数（前端时间线一屏上限；total 仍给窗口内真实条数）。 */
    static final int TIMELINE_MAX_EVENTS = 200;

    /** 时间线端点数据源不可用时的统一 reason（与既有公开端点的"不编数据"口径一致）。 */
    static final String TIMELINE_REASON_UNAVAILABLE = "数据源不可用";

    /** 语音成功响应的媒体类型：{@code audio/mpeg}（实测线上带全站追加的 charset，见 {@link PublicKbController#tts}） */
    static final MediaType TTS_AUDIO = MediaType.parseMediaType("audio/mpeg");

    /** CosyVoice 返回 wav（24 kHz / mono / 16-bit）：媒体类型不能报 mpeg */
    static final MediaType TTS_AUDIO_WAV = MediaType.parseMediaType("audio/wav");

    @Autowired
    PublicAlertSource source;

    @Autowired
    PublicRateLimiter rateLimiter;

    // ==================== 密码自查（/api/public/password）====================
    //
    // 【数据从哪来】不是运行时读蜜罐日志：离线脚本 scripts/password-dict-build.py 在日志所在的机器上
    // 把 password 字段就地 SHA-256、按前 5 位分桶，只把「hash + 计数」写进索引文件；
    // 本服务只加载那个索引（格式与取舍见 PasswordDictionaryService 类注释）。
    // 【读不到时】文件缺失/格式错 ⇒ available:false + reason，服务照常启动、端点不 500 ——
    // 这条是硬要求：字典是"可选的富化数据"，它坏了不该让整页 500。

    /** 口令字典索引（可为空：裁剪过的部署 / 单测直接 new 控制器时就没有） */
    @Autowired(required = false)
    PasswordDictionaryService passwordDict;

    /**
     * 密码自查的独立限流器：默认 30 次/分钟（见 {@link PublicRateLimitersConfig}）。
     *
     * <p>为什么不复用 {@code rateLimiter}（20 次/分钟）：这个端点一次响应最多带 200 条 suffix，
     * 带宽比其它只读端点大一截；同时它又是"手动试一次"的低频动作 —— 30 次/分钟够用，
     * 但绝不跟着 README 里"把 20 调到 60"的调试习惯一起放宽。
     */
    @Autowired(required = false)
    @Qualifier("publicPasswordRateLimiter")
    PublicAskRateLimiter passwordRateLimiter;

    /** 兜底上限：没有 Spring 注入时（单测/裁剪部署）使用，仍然限流，不变成"不限" */
    @Value("${app.public-api.password.requests-per-minute:30}")
    int passwordRequestsPerMinute = 30;

    /** 密码自查的 Cache-Control max-age：字典按天重建，5 分钟缓存足够且能挡掉重复查询（默认 300） */
    @Value("${app.public-api.password.cache-seconds:300}")
    int passwordCacheSeconds = 300;

    /** 单桶最多下发多少条 suffix（超过就 truncated:true；默认 200） */
    @Value("${app.public-api.password.max-hashes:200}")
    int passwordMaxHashes = 200;

    volatile PublicAskRateLimiter fallbackPasswordRateLimiter;

    /** 应用内快照有效期；同时作为 Cache-Control 的 max-age 下发给浏览器/边缘（默认 45s，见 application.yml 注释） */
    @Value("${app.public-api.cache-seconds:45}")
    int cacheSeconds;

    /**
     * 定时预聚合的"年龄阈值比例"（对应下面 {@code warmPublicSnapshots}）。
     *
     * <p>快照年龄超过 {@code TTL × 本比例} 就主动刷新，默认 0.5（TTL 45s ⇒ 22.5s）。
     * 为什么不是"过期才刷"：过期才刷等于把现算留给下一个访客；提前刷 ⇒ 访客侧永远拿到热快照。
     * 为什么不是更小（例如 0.2）：那会把上游查询频率抬得比"有访客才算"更高，白白增加索引器压力。
     * 后台检查间隔由 {@code @Scheduled} 的 {@code warm-interval-ms}（默认 30s）决定。
     */
    @Value("${app.public-api.warm-threshold-ratio:0.5}")
    double warmThresholdRatio;

    /**
     * 别名路径的 {@code stale-while-revalidate}：边缘先发旧值、后台再验证 ⇒ 用户侧不被回源卡住。
     *
     * <p>取两倍 TTL。max-age 本身**不再单独硬编码** —— 它必须与 {@code app.public-api.cache-seconds}
     * （快照 TTL）一致，否则会出现"快照已经 45 秒旧、却告诉缓存 15 秒"这种自相矛盾。
     */
    static final int CACHE_ALIAS_SWR_SECONDS = 300;

    /**
     * 别名 ETag 的序列化器：把 Map 键排序 ⇒ ETag 只取决于内容、与插入顺序无关。
     *
     * <p>为什么不能直接用"完整响应体哈希"（{@link PublicEtagFilter} 的默认口径）：
     * 别名体里的 {@code cacheAgeSeconds} 每秒都在变，ETag 会跟着每秒变 ⇒ 再验证永远拿不到 304。
     */
    static final ObjectMapper ETAG_MAPPER = new ObjectMapper()
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    /** 是否在公网端点暴露构建版本号。health 早已公开它，且它是开源仓库的提交号，不敏感 */
    @Value("${app.public-api.expose-build-sha:true}")
    boolean exposeBuildSha;

    @Value("${app.build.sha:unknown}")
    String buildSha;

    /** 构建时的源提交 / 产物指纹 / 构建时间：与 {@code /api/health} 同源（容器自述，非独立证据） */
    @Value("${app.build.source-sha:unknown}")
    String buildSourceSha;

    @Value("${app.build.artifact-md5:unknown}")
    String buildArtifactMd5;

    @Value("${app.build.time:unknown}")
    String buildTime;

    /**
     * 发布信息文件（可选）：发布号 / 提交 / 切换时刻 / 文件数由**运维链**落地成本文件，本端点只读透传。
     * 为什么不由本服务自己算：发布切换发生在 srv2 上，本进程（srv1）读不到那个目录 ——
     * 读不到就写 {@code available=false}，绝不用进程启动时刻冒充"发布时间"。
     */
    @Value("${app.public-api.deploy-file:}")
    String deployFile;

    /**
     * 评测报告文件（可选）：{@code scripts/eval/} 跑出来的真值报告，落在本文件里供端点透传。
     * 为什么本服务不自己算这些指标：它们要跑题库与评分器（离线、耗时长、依赖题库与知识库），
     * 放在请求路径上既不可能也不该做。
     */
    @Value("${app.public-api.eval-report-file:}")
    String evalReportFile;

    /** 进程启动时刻（部署可追溯端点展示 uptime 用；类加载≈启动，误差在秒级） */
    static final long STARTED_AT_MS = System.currentTimeMillis();

    /** 公开端点读 JSON 文件的大小上限：超过就按"读不到"处理，**不截断**（截断会发出半个真相） */
    static final long JSON_FILE_MAX_BYTES = 256 * 1024L;

    /** 发布信息文件允许透传的键（白名单：不把运维文件的任意内容端到公网） */
    static final List<String> DEPLOY_FILE_KEYS = List.of(
            "release", "releaseDir", "commit", "fileCount", "totalBytes", "switchedAt", "publishedAt", "host",
            // 2026-10-18：/status/ 的部署面板要的三样一直显示「未取到」，因为白名单里没有它们。
            "builtAt", "files", "history");

    /** 评测报告允许透传的键（白名单：正好是 C2 面板要的那几个真值 + 自证新鲜度用的 generatedAt） */
    static final List<String> EVAL_REPORT_KEYS = List.of(
            "generatedAt", "sampleSize", "dataset", "model", "metrics", "keyPointHitRate",
            "refusalRate", "strictRate", "citationRate", "personaCatchphraseRate", "tabooRate");

    final Snapshot overviewCache = new Snapshot();

    final Snapshot alertsCache = new Snapshot();

    final Snapshot honeypotCache = new Snapshot();

    final Snapshot auditCache = new Snapshot();

    final Snapshot latestCache = new Snapshot();

    /** ① 聚合端点（alerts+geo+honeypot 三合一）的快照：TTL 与其它端点同源（{@code cacheSeconds}） */
    final Snapshot homeCache = new Snapshot();

    /** ①b 部署可追溯 / ② AI 质量真值：两者都是"读一个小 JSON + 白名单透传"，同样按快照 TTL 缓存 */
    final Snapshot deployCache = new Snapshot();

    final Snapshot evalCache = new Snapshot();

    // ==================== 公开面口径：IP 开关 + 内部资产名词表 ====================
    //
    // 【为什么集中在这里读】站主 2026-10-14 拍板：公开面显示观测到的真实来源 IP。
    // 但"要不要掩码"一旦在多个端点里各写一遍，就必然出现第三种口径（一个页面真实、
    // 一个页面掩码），而且【不会报错】。所以两个口径对象都只在本类注入一次，
    // 由 ship(...) 统一作用到所有公开响应上 —— 将来新增端点（例如 /api/public/geo）
    // 只要走 ok(...)，就自动获得同一套口径。

    /** IP 显示口径（配置 app.public.mask-ips；缺注入时按掩码兜底） */
    @Autowired(required = false)
    PublicIpPolicy ipPolicy;

    /** 内部资产名停用词过滤（配置 app.public.asset-blocklist） */
    @Autowired(required = false)
    PublicAssetFilter assetFilter;

    /** 没有 Spring 注入时的保守兜底（掩码态）：单测直接 new 控制器时走这条 */
    static final PublicIpPolicy FAIL_CLOSED_POLICY = PublicIpPolicy.masking();

    /** 没有 Spring 注入时的默认资产词表（不能因为"没注入"就不过滤） */
    static final PublicAssetFilter DEFAULT_ASSET_FILTER = PublicAssetFilter.defaults();

    PublicIpPolicy policy() {
        PublicIpPolicy p = ipPolicy;
        return p != null ? p : FAIL_CLOSED_POLICY;
    }

    PublicAssetFilter assets() {
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
    Map<String, Object> ship(Map<String, Object> data) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (data != null) {
            data.forEach((k, v) -> out.put(k, scrubDeep(v)));
        }
        if (!out.containsKey(PublicIpPolicy.DISCLOSURE_FIELD)) {
            out.put(PublicIpPolicy.DISCLOSURE_FIELD, policy().disclosure());
        }
        return out;
    }

    Object scrubDeep(Object v) {
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
    String scrubText(String s) {
        if (s == null || s.isEmpty()) {
            return s;
        }
        return policy().displayText(CredentialStructure.hidePasswords(assets().scrub(s)));
    }

    /** 处置审计只读读取器（读留痕文件，不注入任何处置 Bean —— 隔离测试会强校验） */
    @Autowired
    PublicAuditReader auditReader;

    // ==================== P4：公开 AI 问答 + 知识库公开只读检索 ====================

    /** 公开问答业务实现（四道护栏 + state 归一化 + 输出脱敏） */
    @Autowired
    PublicAskService publicAskService;

    /** 公开知识库检索（复用向量检索，但只出白名单字段） */
    @Autowired
    PublicKbService publicKbService;

    /** 公开问答的独立限流器（默认 6 次/分钟，与只读端点的 20 次/分钟分开） */
    @Autowired
    @Qualifier("publicAskRateLimiter")
    PublicAskRateLimiter publicAskRateLimiter;

    /**
     * 站主令牌校验器（用于「登录后问答不限次」）。
     *
     * <p>为什么公开面要认识自用面的令牌：站主登录后问的是<b>同一个公开问答端点</b>
     * （响应结构与访客完全一致，展示层不用分叉），只要求"别把站主当匿名访客限流"。
     * 换一条自用端点会让前端多一套响应契约，而这条需求只值一个头部判断。
     *
     * <p>失败一律回落匿名路径（{@code false}），<b>不在这里拒绝请求</b> —— 令牌坏了就是访客，
     * 该走限额就走限额；这条路径上任何异常都不得让问答本身不可用。
     */
    @Autowired(required = false)
    org.example.selfapi.UserTokenService ownerTokenService;

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
    PublicAskRateLimiter publicKbRateLimiter;

    /** 每 IP 并发 1 守卫（匿名重操作不能靠限流兜住） */
    @Autowired
    PublicConcurrencyGuard publicConcurrencyGuard;

    /**
     * 语音合成（{@code POST /api/public/tts}）。
     *
     * <p>{@code required = false}：装配不成立时端点必须<b>如实</b>返回
     * {@code 503 TTS_DISABLED}，而不是让整个公网控制器起不来（公开面是匿名可达的，
     * "语音坏了"不该把公开页面一起带走）。见 {@link #tts}。
     */
    @Autowired(required = false)
    TtsService ttsService;

    /**
     * 自由文本语音（{@code POST /api/public/tts/say}）的两道日额度。
     *
     * <p>为什么比短语表那条（默认 20 / 500）更紧、更松各一半：访客每问一句都要念一次，
     * 每 IP 放 30 次才够正常读几轮答案；而全局 300 是<b>成本闸</b> ——
     * 一次自由文本合成和一次短语合成花的是同一笔上游的钱，但自由文本没有短语表那种
     * "文本已定"的可预测性，所以全局只给 300。这两个数与短语表共用同一本落盘额度账。
     */
    @Value("${app.tts.say.per-ip-daily:30}")
    int ttsSayPerIpDaily;

    @Value("${app.tts.say.global-daily:300}")
    int ttsSayGlobalDaily;

    /** 单次公开问答的请求体长度上限（比服务内的字符上限略宽，挡住超大 body） */
    @Value("${app.public-api.ask.max-body-chars:4000}")
    int maxBodyChars;

    /**
     * 读一个小 JSON 文件（只读、限长、任何异常一律返回 null）。
     *
     * <p>为什么限长：这是公开端点的数据源，若被误指向一个巨大文件，会把一次 HTTP 请求
     * 变成一次全文件读取。超过上限就当"读不到"（而不是截断后当合法 JSON —— 那会发出半个真相）。
     */
    Object readJsonOrNull(String path) {
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

    // ==================== 地理分布（离线库；设计见 docs/design-geo-endpoint.md，运维见 RUNBOOK §26） ====================

    /** 地理分布端点自己的快照（与 /alerts 分开：它的取数是一次独立的 indexer 聚合查询） */
    final Snapshot geoCache = new Snapshot();

    /**
     * 离线地理库（<b>可为空</b>：裁剪过的部署 / 单测直接 new 控制器时就是 null）。
     * 空 → 端点按 {@code GEO_DB_MISSING} 如实降级，绝不假装"没有攻击"。
     */
    @Autowired(required = false)
    org.example.geoip.GeoIpService geoIpService;

    /** 入榜门槛：少于这么多次的攻击不入榜（防"1 次探测就上公网地图"） */
    @Value("${app.public-api.geo.min-count:3}")
    int geoMinCount;

    /** 占比门槛（%）：与条数门槛<b>同时</b>满足才入榜（防大窗口里的长尾噪声占满榜单） */
    @Value("${app.public-api.geo.min-share-percent:1.0}")
    double geoMinSharePercent;

    /** 每个来源字段取多少个 IP 做聚合（terms size）；超出的长尾由 coverage 如实披露 */
    @Value("${app.public-api.geo.top-ips:1000}")
    int geoTopIps;

    @Value("${app.public-api.geo.top-countries:20}")
    int geoTopCountries;

    @Value("${app.public-api.geo.top-provinces:10}")
    int geoTopProvinces;

    @Value("${app.public-api.geo.top-asns:10}")
    int geoTopAsns;

    /**
     * 我方自己的公网出口 IP（逗号分隔）。
     *
     * <p>为什么必须有：实测 24 小时 {@code data.srcip} 里排第二的是 srv2 自己的公网 IP（180 条）、
     * 第三名是 srv1（15 条）—— 不排掉，"攻击来源 TOP"里会出现我们自己的服务器。
     * 默认空：<b>服务器真实 IP 不进仓库</b>，由部署时的 {@code APP_GEOIP_SELF_IPS} 注入。
     */
    @Value("${app.geoip.self-ips:}")
    String geoSelfIps;

    // ==================== 攻击故事线（/stories + /story；设计见 docs/design-attack-story-endpoint.md，运维见 RUNBOOK §32） ====================

    /**
     * 攻击故事线服务（<b>可为空</b>：单测直接 new 控制器、或裁剪过的部署里就是 null）。
     *
     * <p>空 → 两个端点如实返回 {@code available=false + STORY_DISABLED}，
     * 绝不用"空事件流"冒充"这个来源什么都没做"。
     */
    @Autowired(required = false)
    AttackStoryService attackStoryService;

    /**
     * 「这个 IP 干过什么」的组装层（<b>可为空</b>：单测直接 new 控制器、裁剪过的部署里就是 null）。
     *
     * <p>空 → 端点如实返回 {@code available=false + IP_PROFILE_DISABLED} 且所有计数项为 null，
     * 绝不用"0 条"冒充"这个 IP 什么都没干"。
     */
    @Autowired(required = false)
    PublicIpProfileService ipProfileService;

    /** 400：参数不合法（只回机读 reason + 人话，不回任何内部细节） */
    ResponseEntity<Map<String, Object>> badRequest(HttpServletResponse res, String reason, String message) {
        res.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", 400);
        body.put("message", message);
        body.put("reason", reason);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    // ==================== 访问日志聚合（/api/public/webstats；设计见 docs/design-webstats-public-endpoint.md） ====================

    /** 聚合端点自己的快照（与 /geo 分开：它读的是内存聚合器，不碰 indexer） */
    final Snapshot webStatsCache = new Snapshot();

    /**
     * 访问日志聚合数据面（<b>可为空</b>：单测直接 new 控制器、或裁剪过的部署里就是 null）。
     * 空 → 端点按 {@code WEBSTATS_DISABLED} 如实降级，绝不假装"最近没人扫"。
     */
    @Autowired(required = false)
    org.example.accesslog.WebStatsService webStatsService;

    /** 入榜门槛（站主口径⑤：类别计数 ≥5 才进 topCategories，低于门槛的只进总量） */
    @Value("${app.webstats.min-count:5}")
    int webStatsMinCount = 5;

    @Value("${app.webstats.top-categories:10}")
    int webStatsTopCategories = 10;

    @Value("${app.webstats.top-uas:5}")
    int webStatsTopUas = 5;

    String generatedAt() {
        return LocalDateTime.now().format(FMT);
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
    String clientIp(HttpServletRequest req) {
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

    ResponseEntity<Map<String, Object>> ok(Map<String, Object> data, HttpServletResponse res) {
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
    String aliasCacheControl() {
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
    static String cacheAliasEtag(Map<String, Object> shipped) {
        try {
            return PublicEtagFilter.etagOf(ETAG_MAPPER.writeValueAsBytes(shipped));
        } catch (Exception e) {
            logger.warn("别名 ETag 计算失败，退回按完整响应体计算：{}", e.getMessage());
            return null;
        }
    }

    /**
     * 缓存别名请求的判定：URI 以 {@link PublicCorsInterceptor#CACHE_ALIAS_SUFFIX} 结尾。
     *
     * <p>为什么用 URI 而不是参数/Header：别名是<b>纯 URL 形状</b>的约定（Cloudflare 按扩展名
     * 决定是否缓存），任何请求头/查询参数都不能改变它 —— 也让"客户端加了 {@code ?cb=} 反而
     * 命中不到边缘缓存"这件事变得可解释（契约里明文禁止 cache-buster）。
     */
    static boolean isCacheAliasRequest() {
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
    void stampSnapshotFreshness(Map<String, Object> body) {
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

    ResponseEntity<Map<String, Object>> tooMany(HttpServletResponse res) {
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
    ResponseEntity<Map<String, Object>> tooMany(HttpServletResponse res,
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
    static List<String> asStringList(Object v) {
        if (v instanceof List<?> l) {
            List<String> out = new ArrayList<>();
            for (Object o : l) {
                out.add(String.valueOf(o));
            }
            return out;
        }
        return Collections.emptyList();
    }

    static String asString(Object v) {
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

        volatile Map<String, Object> value;
        volatile long expiresAt;

        /** 上一次真正去加载（或首次加载）的时刻：别名响应体的 {@code snapshotAt} 用它 */
        volatile long loadedAtMs;

        /** 是否有线程正在刷新：用它替代"锁"，保证请求侧不等现算（也天然防击穿） */
        final AtomicBoolean refreshing = new AtomicBoolean(false);

        /** 首次无值时的等待上限（毫秒）：冷启动并发首访才会用到 */
        static final long FIRST_WAIT_TIMEOUT_MS = 3000L;

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
        Map<String, Object> load(int ttlSeconds, Supplier<Map<String, Object>> loader) {
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
        Map<String, Object> awaitFirstValue(Supplier<Map<String, Object>> loader, int ttlSeconds) {
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
