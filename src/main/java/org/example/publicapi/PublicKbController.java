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
 * 问答与语音域：/ask、/kb、/tts、/tts/say。
 *
 * <p>本类是原 {@code PublicApiController}（已删除的委托门面）拆分出的按域 controller 之一：只做搬移，路径、参数、
 * 响应字段、状态码、缓存头与限流口径与原 god controller 逐字一致。
 * 共享状态与通用工具（快照缓存、出关脱敏、信封/缓存头）在 {@link PublicApiSupport} 里，
 * 由构造器注入；历史门面 {@code PublicApiController} 已删除，测试改为直接装配这些 controller。
 */
@RestController
@RequestMapping("/api/public")
public class PublicKbController {

    private static final Logger logger = LoggerFactory.getLogger(PublicKbController.class);

    private final PublicApiSupport support;

    public PublicKbController(PublicApiSupport support) {
        this.support = support;
    }

    /**
     * 这次公开问答是不是站主本人发的（决定要不要走「每 IP 每分钟 N 次」那道闸）。
     *
     * <p>判据只有一条：请求头 {@code X-User-Token} 通过自用面令牌校验。
     * 其余一切情况（没带、带错、服务未配置、校验抛异常）都判成<b>不是</b> ——
     * 宁可把站主当访客限一次流，也不能因为校验出问题把匿名限流整条打开。
     */
    boolean isOwnerAsk(HttpServletRequest req, String ip) {
        if (req == null) {
            return false;
        }
        String token = req.getHeader("X-User-Token");
        if (token == null || token.isBlank()) {
            return false;
        }
        if (support.ownerTokenService == null || !support.ownerTokenService.configured()) {
            return false;
        }
        try {
            org.example.selfapi.UserTokenService.Result r = support.ownerTokenService.check(ip, token);
            return r != null && r.ok();
        } catch (RuntimeException e) {
            logger.debug("站主令牌校验失败，按匿名处理：{}", e.toString());
            return false;
        }
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
        String ip = support.clientIp(req);

        // ① 限流（每 IP 每分钟 N 次）—— 先于一切上游动作，包括并发登记
        //    站主带有效 X-User-Token ⇒ 跳过这一道（他不限次），其余访客照旧。
        boolean owner = isOwnerAsk(req, ip);
        if (!owner && !support.publicAskRateLimiter.allow(ip)) {
            return support.tooMany(res, support.publicAskRateLimiter, "公开问答请求过于频繁（每 IP 每分钟 "
                    + support.publicAskRateLimiter.limitPerMinute() + " 次），请稍后再试");
        }

        // ② 并发 1（每 IP 同时只允许一个在飞）
        if (!support.publicConcurrencyGuard.tryAcquire(ip)) {
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
            // 要不要顺带一句日语语音（speakJa）：只有调用方显式要才做 ——
            // 那是一次额外的模型调用，关着声音的访客不该替别人付这笔钱。
            Map<String, Object> data = support.publicAskService.ask(question, ip, wantSpeakJa(body));

            // 记一条"刚生成过的回答"，并把它的 textHash 一并发给前端 ——
            // 这是 /api/public/tts 的 textHash 闸【唯一】的文本来源：只有服务端
            // 自己产出过的回答才能被合成，前端永远不传文本。
            if (support.ttsService != null) {
                Object answer = data.get("answer");
                String textHash = answer == null ? null : support.ttsService.recordAnswer(String.valueOf(answer));
                if (textHash != null) {
                    data.put("ttsTextHash", textHash);
                }
            }

            // 一次性返回：公开问答的响应永不被边缘缓存（它是"这一次提问"的结果）
            res.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
            res.setHeader("X-Data-Source", "PUBLIC_ASK");
            if (owner) {
                // 说清楚：这次没记限额。数字别写成假的"6"，否则日志里会以为被限过。
                res.setHeader("X-RateLimit-Limit", "owner-unlimited");
                res.setHeader("X-RateLimit-Remaining", "owner-unlimited");
                res.setHeader("X-Owner-Ask", "1");
            } else {
                res.setHeader("X-RateLimit-Limit", String.valueOf(support.publicAskRateLimiter.limitPerMinute()));
                res.setHeader("X-RateLimit-Remaining",
                        String.valueOf(Math.max(0, support.publicAskRateLimiter.remaining(ip))));
            }

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("code", 200);
            out.put("message", "success");
            // POST 不走 ok(...)，但口径必须一样：同一个 ship(...)（资产名过滤 + ipDisclosure）
            out.put("data", support.ship(data));
            return ResponseEntity.ok(out);
        } catch (Exception e) {
            logger.warn("公开问答失败（已按 fail-closed 处理）：{}", e.getMessage());
            Map<String, Object> b = new LinkedHashMap<>();
            b.put("code", 500);
            b.put("message", "公开问答暂时不可用，请稍后再试");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(b);
        } finally {
            support.publicConcurrencyGuard.release(ip);
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
        String ip = support.clientIp(req);
        if (!support.publicKbRateLimiter.allow(ip)) {
            return support.tooMany(res, support.publicKbRateLimiter, "知识库检索请求过于频繁（每 IP 每分钟 "
                    + support.publicKbRateLimiter.limitPerMinute() + " 次），请稍后再试");
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", LocalDateTime.now().format(PublicApiSupport.FMT));
        data.put("query", q == null ? "" : q.trim());
        data.put("rule", support.publicKbService.ruleSummary());

        String query = q == null ? "" : q.trim();
        if (query.isEmpty()) {
            data.put("results", List.of());
            data.put("hitCount", 0);
            data.put("available", true);
            data.put("note", "未提供查询词（q）。");
            return support.ok(data, res);
        }
        if (query.length() > 200) {
            data.put("results", List.of());
            data.put("hitCount", 0);
            data.put("available", true);
            data.put("note", "查询词过长（上限 200 字符）。");
            return support.ok(data, res);
        }

        try {
            List<Map<String, Object>> results = support.publicKbService.search(query);
            data.put("results", results);
            data.put("hitCount", results.size());
            data.put("available", true);
            // 口径描述随开关而变：掩码态<b>逐字节保留改造前的说法</b>（掩码回归要求），
            // 真实态如实说明"显示的是观测到的真实来源地址"，不能嘴上还说"已掩码"。
            data.put("note", results.isEmpty()
                    ? "公开知识库未检索到相关片段（未命中就是未命中，不用别的数据顶替）。"
                    : (support.policy().masked()
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
        return support.ok(data, res);
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
        String ip = support.clientIp(req);

        // ① 频率闸：与其它公开端点共用同一个限流器（同一本账，不另开一个桶）
        if (!support.rateLimiter.allow(ip)) {
            res.setHeader(HttpHeaders.RETRY_AFTER, "60");
            res.setHeader("X-RateLimit-Limit", String.valueOf(support.rateLimiter.limitPerMinute()));
            res.setHeader("X-RateLimit-Remaining", "0");
            return ttsError(res, 429, "RATE_LIMITED",
                    "语音请求过于频繁（每 IP 每分钟 " + support.rateLimiter.limitPerMinute() + " 次），请稍后再试");
        }

        if (support.ttsService == null) {
            return ttsError(res, 503, "TTS_DISABLED", "语音合成未启用（app.tts.enabled=false）");
        }

        try {
            TtsService.Result result = support.ttsService.synthesize(
                    bodyString(body, "phraseId"), bodyString(body, "textHash"), ip);
            // 与 ok(...) 同一口径：快照 TTL 就是下发出去的 max-age。
            // 音频内容是内容寻址的（同一个 voiceId+text 永远是同一份字节），
            // 但仍按公网统一 TTL 走，避免出现"这个端点的缓存语义和别的不一样"。
            res.setHeader(HttpHeaders.CACHE_CONTROL, "public, max-age=" + Math.max(0, support.cacheSeconds));
            res.setHeader("X-Tts-Cache", result.cacheHit() ? "HIT" : "MISS");
            res.setHeader("X-RateLimit-Limit", String.valueOf(support.rateLimiter.limitPerMinute()));
            MediaType media = (support.ttsService != null && support.ttsService.config().isCosyVoice()) ? PublicApiSupport.TTS_AUDIO_WAV : PublicApiSupport.TTS_AUDIO;
            return ResponseEntity.ok().contentType(media).body(result.audio());
        } catch (TtsService.TtsException e) {
            // 归一化的 reason 码：前端按它决定"隐藏 🔊 / 提示额度用完 / 提示稍后再试"。
            // message 是人话，绝不含 Key、上游原文或 URL 细节。
            logger.warn("公开 TTS 未完成：reason={} status={}", e.reason(), e.httpStatus());
            return ttsError(res, e.httpStatus(), e.reason(), e.userMessage());
        }
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
        String ip = support.clientIp(req);

        // ① 频率闸：与其它公开端点共用同一个限流器（同一本账，不另开一个桶）
        if (!support.rateLimiter.allow(ip)) {
            res.setHeader(HttpHeaders.RETRY_AFTER, "60");
            res.setHeader("X-RateLimit-Limit", String.valueOf(support.rateLimiter.limitPerMinute()));
            res.setHeader("X-RateLimit-Remaining", "0");
            return ttsError(res, 429, "RATE_LIMITED",
                    "语音请求过于频繁（每 IP 每分钟 " + support.rateLimiter.limitPerMinute() + " 次），请稍后再试");
        }

        if (support.ttsService == null) {
            return ttsError(res, 503, "TTS_DISABLED", "语音合成未启用（app.tts.enabled=false）");
        }

        try {
            TtsService.Result result = support.ttsService.say(
                    bodyString(body, "text"), ip, support.ttsSayPerIpDaily, support.ttsSayGlobalDaily);
            res.setHeader(HttpHeaders.CACHE_CONTROL, "public, max-age=" + Math.max(0, support.cacheSeconds));
            res.setHeader("X-Tts-Cache", result.cacheHit() ? "HIT" : "MISS");
            res.setHeader("X-RateLimit-Limit", String.valueOf(support.rateLimiter.limitPerMinute()));
            MediaType media = support.ttsService.config().isCosyVoice() ? PublicApiSupport.TTS_AUDIO_WAV : PublicApiSupport.TTS_AUDIO;
            return ResponseEntity.ok().contentType(media).body(result.audio());
        } catch (TtsService.TtsException e) {
            // 归一化的 reason 码（TEXT_TOO_LONG / TEXT_CHARSET_NOT_ALLOWED / PER_IP_DAILY_LIMIT …）
            // message 是人话，绝不含 Key、上游原文或 URL 细节。
            logger.warn("公开 TTS(say) 未完成：reason={} status={}", e.reason(), e.httpStatus());
            return ttsError(res, e.httpStatus(), e.reason(), e.userMessage());
        }
    }

    /**
     * 语音端点的失败响应：既有 JSON 信封 + {@code reason} 码（零 IP、零上游细节）。
     *
     * <p>{@code Cache-Control: no-store}：错误不该被边缘或浏览器缓存住 ——
     * 否则"额度明天恢复"这件事在访客那里可能要等缓存过期才生效。
     */
    ResponseEntity<Map<String, Object>> ttsError(HttpServletResponse res, int status,
                                                         String reason, String message) {
        res.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", status);
        body.put("message", message);
        body.put("reason", reason);
        return ResponseEntity.status(status).contentType(MediaType.APPLICATION_JSON).body(body);
    }

    /** 请求体取字符串字段（非字符串值按其字面量处理；null 表示没给） */
    static String bodyString(Map<String, Object> body, String key) {
        if (body == null) {
            return null;
        }
        Object value = body.get(key);
        return value == null ? null : String.valueOf(value);
    }

    /**
     * 请求体里的「要日语语音」开关：只认 {@code speakJa} 一个键。
     *
     * <p>为什么做成<b>显式 opt-in</b> 而不是无条件生成：{@code speakJa} 是一次真实的模型调用
     * （走公开池额度）。绝大多数访客是静音浏览的，替他们每次问答多花一份钱、多等最多 3 秒，
     * 换来的东西他们根本不会打开。所以"要不要"由调用方说 —— 前端只在
     * {@code __xkSound.on} 为真时才带这个字段。
     *
     * <p>接受的形态：布尔 {@code true}、数字 {@code 1}、字符串 {@code "true"/"1"/"yes"}（大小写不敏感）。
     * 其余一律当作"不要"——宁可少说一句，也不要解析出一个意外的 {@code true}。
     */
    static boolean wantSpeakJa(Map<String, Object> body) {
        if (body == null) {
            return false;
        }
        Object v = body.get("speakJa");
        if (v instanceof Boolean b) {
            return b;
        }
        String s = v == null ? "" : String.valueOf(v).trim();
        return s.equalsIgnoreCase("true") || s.equals("1") || s.equalsIgnoreCase("yes");
    }

    /** 请求体取问题：只认 {@code question} / {@code q} 两个键，其余一律忽略 */
    static String extractQuestion(Map<String, Object> body) {
        if (body == null) {
            return "";
        }
        Object v = body.get("question");
        if (v == null) {
            v = body.get("q");
        }
        return v == null ? "" : String.valueOf(v);
    }
}
