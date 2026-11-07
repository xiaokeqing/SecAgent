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
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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
 *
 * <h3>拆分说明（2026-11：god controller → 按域 controller + 委托门面）</h3>
 * 端点实现已按域搬到 {@code PublicAlertController}/{@code PublicHomeController}/{@code PublicKbController}/
 * {@code PublicGeoController}/{@code PublicMiscController}，共享状态与通用工具下沉到
 * {@link PublicApiSupport}。
 *
 * <p><b>本类现在只是一层"为测试保留的委托门面"，默认不注册为 Spring Bean</b>：
 * {@code @ConditionalOnProperty(app.public-api.legacy-facade-bean=true)} 默认不满足，组件扫描会跳过它，
 * 生产环境里真正对外提供这 20 条路径的是那五个按域 controller（各自 {@code @RestController}），
 * 因此不会出现同一路径被注册两次的 {@code Ambiguous mapping}。
 *
 * <p>那为什么还要留着它、并且仍然标 {@code @RestController}？因为历史单测都是
 * {@code MockMvcBuilders.standaloneSetup(new PublicApiController())} + {@code ReflectionTestUtils.setField(...)}，
 * 而 standaloneSetup 只认带 {@code @Controller}/{@code @RestController} 的类作为 handler。保留原注解、
 * 原方法签名与原字段（字段经 {@link PublicApiSupport} 继承），每个方法一行转发到按域 controller，
 * 就能让这批单测零改动地继续覆盖真实实现；条件注解只在 Spring 容器里生效，不影响手工 new 出来的实例。
 */
@RestController
@RequestMapping("/api/public")
@ConditionalOnProperty(prefix = "app.public-api", name = "legacy-facade-bean", havingValue = "true")
public class PublicApiController extends PublicApiSupport {

    private final PublicAlertController alertController;
    private final PublicHomeController homeController;
    private final PublicKbController kbController;
    private final PublicGeoController geoController;
    private final PublicMiscController miscController;
    private final PublicSnapshotWarmer snapshotWarmer;

    public PublicApiController() {
        this.alertController = new PublicAlertController(this);
        this.geoController = new PublicGeoController(this);
        this.homeController = new PublicHomeController(this, alertController, geoController);
        this.kbController = new PublicKbController(this);
        this.miscController = new PublicMiscController(this);
        this.snapshotWarmer = new PublicSnapshotWarmer(this, alertController, homeController, geoController, miscController);
    }

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
        return kbController.ask(body, req, res);
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
        return kbController.kb(q, req, res);
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
        return kbController.tts(body, req, res);
    }

    /**
     * 自由文本语音：{@code POST /api/public/tts/say}，body {@code {"text":"…"}}。
     *
     * <h3>它为什么必须存在</h3>
     * 短语表那条线（{@link #tts}）只认服务端给过的文本。但"把 AI 回答念出来"这句话里的
     * 回答是<b>每次都不一样</b>的 —— 短语表天生覆盖不到。所以需要一个吃自由文本的出口。
     *
     * <h3>它凭什么敢吃自由文本</h3>
     * 把"滥用者想要的东西"逐项拿掉，剩下的就是安全的那个子集：
     * <ul>
     *   <li><b>长度 ≤60 字</b>：一次合成的成本有上界，也念不了整篇文档；</li>
     *   <li><b>字符集 = 日语（平假名/片假名/汉字/数字/标点）</b>：当不了通用朗读/翻译 API ——
     *       它连英文都念不出来（音色是日语复刻音色，念英文本来也听不出是什么）；</li>
     *   <li><b>每 IP 每天 30 次 + 全局每天 300 次</b>：与短语表共用同一本落盘额度账；</li>
     *   <li><b>磁盘缓存</b>：同一句只合成一次（内容寻址 {@code sha256(voiceId+text)}），
     *       热门台词重复请求不重复花钱；</li>
     *   <li><b>上游失败 502</b>：与短语表同一条归一化路径，<b>不打印上游响应体</b>
     *       （401/403 连片段都不打）。</li>
     * </ul>
     *
     * <p><b>与 {@code /tts} 不冲突</b>：那条路径的鉴权闸（短语表 / textHash）一行都没改；
     * 这是新增的第二个入口，不是对第一个入口的放宽。
     */
    @PostMapping("/tts/say")
    public ResponseEntity<?> ttsSay(@RequestBody(required = false) Map<String, Object> body,
                                    HttpServletRequest req,
                                    HttpServletResponse res) {
        return kbController.ttsSay(body, req, res);
    }

    // ==================== 端点 ====================

    /** 首页状态条用：两台服务器在线状态 + 告警概览。载荷刻意做小。 */
    @GetMapping({"/overview", "/overview.js"})
    public ResponseEntity<Map<String, Object>> overview(HttpServletRequest req, HttpServletResponse res) {
        return alertController.overview(req, res);
    }

    /** 告警看板用：聚合后的实时告警流 + 分布 + 24 小时趋势，一次请求拿全。 */
    @GetMapping({"/alerts", "/alerts.js"})
    public ResponseEntity<Map<String, Object>> alerts(HttpServletRequest req, HttpServletResponse res) {
        return alertController.alerts(req, res);
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
        return alertController.drillDown(aggId, req, res);
    }

    /**
     * 蜜罐战报：连接/登录计数、账号口令 Top（<b>只给结构</b>）、来源分布、事件时间线。
     *
     * <p>来源 IP 按 {@code app.public.mask-ips} 口径显示（默认真实地址，内网/保留写「内网/未知」）；
     * 口令在任何口径下都只给长度/字符类/弱口令标记，永不给出原文。
     */
    @GetMapping({"/honeypot", "/honeypot.js"})
    public ResponseEntity<Map<String, Object>> honeypot(HttpServletRequest req, HttpServletResponse res) {
        return alertController.honeypot(req, res);
    }

    // ==================== ① 聚合端点：一次请求拿三块（弱网收益最大的一处） ====================

    /**
     * <b>内容页聚合端点</b>：一次请求拿回 {@code alerts + geo + honeypot + audit + health} 五块。
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
     * 同一个别名口径（{@code max-age=45, stale-while-revalidate=300} + 按数据内容算的稳定 ETag）。
     *
     * <h3>2026-10-18 扩到五块的原因（站主实测）</h3>
     * 首屏英雄数字里最有说服力的两个数（「累计封禁」「护栏拦截」）来自 {@code /audit}，
     * {@code /status/} 页要的构建 SHA / 运行时长来自 {@code /health} —— 这两块原先都不在聚合里，
     * 于是弱网下首屏仍然要多付两次「客户端 → CF → 源站」的路程（实测每次 0.9~8 秒）。
     * 并进来后首屏只剩「HTML + 一个聚合请求」，且仍只消耗一份限流额度。
     * {@code audit} 与单端点 {@code /audit} 的 data **逐字段相同**（同一个 Snapshot、同一个 ship）；
     * {@code health} 是本控制器内可自证的那部分（构建自述 + 运行时长），不跨控制器取数。
     */
    @GetMapping({"/home", "/home.js"})
    public ResponseEntity<Map<String, Object>> home(HttpServletRequest req, HttpServletResponse res) {
        return homeController.home(req, res);
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
        return homeController.deploy(req, res);
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
        return miscController.evalReport(req, res);
    }

    /** 处置审计（只读）：封禁记录 + 审计流水，IP 按开关口径显示，不含原始 detail。 */
    @GetMapping({"/audit", "/audit.js"})
    public ResponseEntity<Map<String, Object>> audit(HttpServletRequest req, HttpServletResponse res) {
        return alertController.audit(req, res);
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
        return alertController.latest(req, res);
    }

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
        return geoController.geo(req, res);
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
        return miscController.stories(window, limit, req, res);
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
        return miscController.story(src, window, req, res);
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
        return miscController.storyTimeline(id, window, hoursParam, req, res);
    }

    /**
     * <b>「这个 IP 干过什么」</b>：一个来源 IP 的画像（个人版 AbuseIPDB）。
     *
     * <p>跨三个源聚合：索引里的告警 + 蜜罐会话（{@link PublicAlertSource#ipActivity}）、
     * 应用侧处置留痕（{@link PublicAuditReader#bansFor}）、GeoIP 库。字段：
     * {@code firstSeen/lastSeen/events/byKind/ports/credStructure/geo/banned}
     * （外加 {@code sources} 说明每个源接没接上、{@code notes[]} 逐项说明为什么是 null）。
     *
     * <h3>口径（与 /stories 同一套壳）</h3>
     * <ol>
     *   <li><b>不许编</b>：任何一项取不到就写 {@code null} 并在 {@code notes[]} 里写原因 ——
     *       "读不到"与"没有数据"必须能分开读；</li>
     *   <li><b>不混数据</b>：只按 {@code q} 这一个字面量查，不按网段、不按 ASN、不按"相近的地址"
     *       扩张，也不把别人的记录并进来；</li>
     *   <li><b>IP 严格校验</b>：只要 IPv4 字面量（非法 → 400）；内网/保留地址也 400
     *       （理由见 {@link PublicIpProfileService#isQueryable}）；</li>
     *   <li><b>口令只给结构</b>：{@link PublicApiController#credentialShapes} 把
     *       {@code root / 123456} 换成 {@code root / 6 位·纯数字·弱口令}，原文字符不出现。</li>
     * </ol>
     *
     * <p>复用既有外壳：同一个限流器（20 次/分钟）、同一个 CORS 白名单、同一个 ETag 过滤器、
     * 同一个 {@code cache-seconds} TTL（按 IP 分开存）、同一个 {@code ok(...)}
     * （因此自动带 {@code ipDisclosure} 与内部资产名过滤）。
     */
    @GetMapping({"/ip", "/ip.js"})
    public ResponseEntity<Map<String, Object>> ipProfile(
            @RequestParam(value = "q", required = false) String q,
            HttpServletRequest req, HttpServletResponse res) {
        return geoController.ipProfile(q, req, res);
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
        return miscController.password(p, req, res);
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
        return miscController.webstats(req, res);
    }

    /** 不可用载荷（纯函数：字段名与可用载荷对齐，前端只判 {@code available} 一个开关） */
    static Map<String, Object> buildGeoUnavailable(String reason, String note, int cacheSeconds, String now) {
        return PublicGeoController.buildGeoUnavailable(reason, note, cacheSeconds, now);
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
        return PublicGeoController.buildGeo(geo, window, thresholds, cacheSeconds, now, selfIps);
    }

    /** 我方公网 IP 配置 → 集合（去空白、丢空项） */
    static java.util.Set<String> parseSelfIps(String csv) {
        return PublicGeoController.parseSelfIps(csv);
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
        return PublicAlertController.buildLatest(alerts, available, mode, windowSize, cacheSeconds, generatedAt, latestBlocks);
    }

    /**
     * {@link #buildLatest(List, boolean, String, int, int, String, List)} 的口径显式版本。
     *
     * @param policy IP 显示口径（唯一来源：{@code app.public.mask-ips}）
     */
    static Map<String, Object> buildLatest(List<SecurityAlert> alerts, boolean available, String mode,
                                           int windowSize, int cacheSeconds, String generatedAt,
                                           List<Map<String, Object>> latestBlocks, PublicIpPolicy policy) {
        return PublicAlertController.buildLatest(alerts, available, mode, windowSize, cacheSeconds, generatedAt, latestBlocks, policy);
    }

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
        return PublicMiscController.buildWebStatsAvailable(snap, st, cacheSeconds, now, th);
    }

    /** 不可用载荷（字段名与可用载荷完全一致：前端只判 {@code available} 一个开关） */
    static Map<String, Object> buildWebStatsUnavailable(String reason, String note, int cacheSeconds, String now) {
        return PublicMiscController.buildWebStatsUnavailable(reason, note, cacheSeconds, now);
    }

    /** 占比（百分数，保留两位）——只用于展示与门槛，不参与任何账目 */
    static double webStatsSharePercent(long count, long total) {
        return PublicMiscController.webStatsSharePercent(count, total);
    }

    static String webStatsNote(org.example.accesslog.WebStatsAggregator.Thresholds th) {
        return PublicMiscController.webStatsNote(th);
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
        return PublicAlertController.credentialShapes(v);
    }

    /**
     * 出关脱敏的兼容壳：历史测试用 {@code getDeclaredMethod("ship", Map.class)} 直接打在旧类上，
     * 方法必须仍<b>声明在本类</b>（{@code getDeclaredMethod} 不看父类），实现转发到 {@link PublicApiSupport#ship}。
     */
    Map<String, Object> ship(Map<String, Object> data) {
        return super.ship(data);
    }

    /** 兼容壳：{@code PublicMaskedRegressionTest} 用 {@code getDeclaredMethod("buildHoneypot")} 打在旧类上 */
    Map<String, Object> buildHoneypot() {
        return alertController.buildHoneypot();
    }

    /** 兼容壳：{@code PublicMaskedRegressionTest} 用 {@code getDeclaredMethod("buildAudit")} 打在旧类上 */
    Map<String, Object> buildAudit() {
        return alertController.buildAudit();
    }

    /** 兼容壳：{@code PublicSnapshotWarmerTest} 直接 new 旧类后调它；定时任务本体在 {@link PublicSnapshotWarmer} */
    public void warmPublicSnapshots() {
        snapshotWarmer.warmPublicSnapshots();
    }
}
