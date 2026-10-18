package org.example.publicapi;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.example.config.OutboundTimeouts;
import org.example.config.TtsConfig;
import org.example.llm.OutboundGuard;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

/**
 * 文字转语音的业务实现（{@code POST /api/public/tts} 的内核）：<b>三道闸 + 缓存</b>。
 *
 * <h3>三道闸（顺序即成本顺序，见 {@link #synthesize}）</h3>
 * <ol>
 *   <li><b>只认服务端给过的文本</b>：要么 {@code phraseId}（服务端短语表
 *       {@code app.tts.phrases.*}），要么 {@code textHash}（服务端"最近生成过的回答"的
 *       sha512 前 32 位）。<b>其它一律 400 {@code TEXT_NOT_ALLOWED}</b> ——
 *       匿名端点永不接受自由文本，否则等于公开一个"任意文字转语音"的花钱接口；</li>
 *   <li><b>长度</b>：超过 {@code app.tts.max-chars} → 400 {@code TEXT_TOO_LONG}；</li>
 *   <li><b>每日额度</b>：单 IP 与全局各一本账（{@link TtsQuotaStore}，落盘、重启不丢），
 *       超限 → 429 + 明确的 reason（{@code PER_IP_DAILY_LIMIT} / {@code GLOBAL_DAILY_LIMIT}）。</li>
 * </ol>
 *
 * <h3>缓存的位置（为什么在额度之前查）</h3>
 * {@code sha256(voiceId + "\n" + text)} → {@code <cacheDir>/<hash>.mp3}。命中直接返回、
 * <b>上游一次都不调</b>；而且<b>不吃每日额度</b> —— 缓存命中不花一分钱，
 * 若也算额度，访客"重播一次"就会少一次额度，而他完全看不出为什么。
 *
 * <h3>上游调用</h3>
 * 走既有 {@link OutboundGuard}（有界等待 + 每依赖熔断冷却 + 在飞上限）与统一超时矩阵
 * ({@link OutboundTimeouts}：connect 3s / read 12s / call 15s)。
 * 依赖键 {@value #DEP_TTS}，与其它出站链路<b>各自隔离</b>冷却，互不牵连。
 *
 * <h3>错误归一化（绝不把 Key 或上游原文透给前端）</h3>
 * 上游出的任何问题都归一成 reason 码（{@code UPSTREAM_TIMEOUT} / {@code UPSTREAM_HTTP_<code>} /
 * {@code UPSTREAM_BAD_BODY} / {@code UPSTREAM_IO}），响应里只有 reason 与人话，
 * 没有 Key、没有上游响应体、没有 URL 细节。细节只写服务端日志（且已截断）。
 */
@Service
public class TtsService {

    private static final Logger logger = LoggerFactory.getLogger(TtsService.class);

    /** OutboundGuard 依赖键：冷却按它隔离（别的链路挂了不影响语音，反之亦然） */
    public static final String DEP_TTS = "tts-fish-audio";

    /** 上游响应体上限：语音是 120 字符量级的短音频，超过这个数按"响应非法"处理 */
    static final int MAX_AUDIO_BYTES = 8 * 1024 * 1024;

    /** 上游失败时写进日志的响应片段长度（只服务端可见；绝不进响应） */
    private static final int LOG_SNIPPET_CHARS = 200;

    private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** textHash 的形态：sha512 十六进制的前 32 位 */
    private static final Pattern TEXT_HASH = Pattern.compile("[0-9a-f]{32}");

    private final TtsConfig config;
    private final OutboundTimeouts timeouts;
    private final OutboundGuard guard;
    private final OkHttpClient client;
    private final TtsCache cache;
    private final TtsQuotaStore quota;
    private final AtomicLong upstreamCalls = new AtomicLong();

    /** 最近生成过的回答：textHash → 文本，LRU（容量 {@code app.tts.history-size}） */
    private final Map<String, String> recentAnswers;

    public TtsService(TtsConfig config, OutboundTimeouts timeouts, OutboundGuard guard) {
        this.config = config;
        this.timeouts = timeouts == null ? OutboundTimeouts.defaults() : timeouts;
        this.guard = guard;
        this.client = buildClient();
        this.cache = new TtsCache(Path.of(config.getCacheDir()), config.getMaxCacheMb());
        this.quota = new TtsQuotaStore(Path.of(config.getQuotaFile()));
        int capacity = Math.max(1, config.getHistorySize());
        this.recentAnswers = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
                return size() > capacity;
            }
        };
    }

    /**
     * 合成一次语音。
     *
     * @param phraseId 服务端短语 id（与 textHash 二选一）
     * @param textHash 最近生成过的回答的 sha512 前 32 位（与 phraseId 二选一）
     * @param clientIp 调用方 IP（额度按它分桶）
     * @return 音频字节 + 是否缓存命中
     * @throws TtsException 任何被闸门/上游挡下的情况（带 httpStatus 与归一化 reason）
     */
    public Result synthesize(String phraseId, String textHash, String clientIp) {
        // 闸 0：总开关。关掉时前端据此隐藏 🔊（而不是显示一个点了报错的按钮）
        if (!config.isEnabled()) {
            throw new TtsException(503, "TTS_DISABLED", "语音合成未启用（app.tts.enabled=false）");
        }

        // 闸 1：只认服务端给过的文本
        String text = resolveText(phraseId, textHash);

        // 闸 2：长度
        if (text.length() > config.getMaxChars()) {
            throw new TtsException(400, "TEXT_TOO_LONG",
                    "文本长度 " + text.length() + " 超过上限 " + config.getMaxChars() + " 字符");
        }

        // 缓存：命中直接返回，不调上游、不吃额度
        String key = TtsCache.keyOf(config.getVoiceId(), text);
        byte[] cached = cache.get(key);
        if (cached != null) {
            logger.debug("TTS 缓存命中（{} 字节）：本轮未调上游", cached.length);
            return new Result(cached, true);
        }

        // Key 缺失：明确不可用，而且【在消耗额度之前】判定（没 Key 就不该记这笔账）
        if (!config.apiKeyConfigured()) {
            throw new TtsException(503, "KEY_MISSING", "上游 Key 未配置（APP_TTS_API_KEY）");
        }

        // 闸 3：每日额度（落盘，重启不丢）
        TtsQuotaStore.Decision decision =
                quota.tryConsume(clientIp, config.getPerIpDaily(), config.getGlobalDaily());
        if (!decision.allowed()) {
            String message = TtsQuotaStore.REASON_PER_IP.equals(decision.reason())
                    ? "本来源今日语音额度已用完（上限 " + decision.perIpLimit() + " 次/天），明日恢复"
                    : "本站今日语音额度已用完（全局上限 " + decision.globalLimit() + " 次/天），明日恢复";
            throw new TtsException(429, decision.reason(), message);
        }

        byte[] audio = callUpstream(text);
        cache.put(key, audio);
        return new Result(audio, false);
    }

    /**
     * 合成一段<b>服务端自己写的</b>文本（定时任务 / 日报专用），不经过短语表闸。
     *
     * <h3>它和上面两个入口的关系</h3>
     * <ul>
     *   <li>{@link #synthesize(String, String, String)}：公开端点，只认服务端给过的文本（短语表 / 最近回答）；</li>
     *   <li>{@link #say(String, String, int, int)}：公开端点，只认一段<b>字符集受限</b>的日语；</li>
     *   <li>本方法：<b>没有公开路由</b>，只由 {@code org.example.report.TtsSpeechSynthesizer} 调用，
     *       文本由日报服务自己生成（不是用户输入，也就没有"被当免费朗读 API"的面）。</li>
     * </ul>
     *
     * <h3>为什么不吃每日额度</h3>
     * {@code app.tts.per-ip-daily / global-daily} 是给<b>公开面</b>抗滥用的账：用完了页面上的 🔊 就哑了。
     * 定时任务每天固定一次、没有任何外部触发面，把它记进同一本账只会让公众额度被自己人吃掉。
     * 但它<b>仍然受总开关与 Key 判定约束</b>：没启用 / 没 Key 就明确失败，绝不静默产出空音频。
     *
     * <h3>为什么固定走 CosyVoice</h3>
     * 日报语音要的是"日语口语播报"，CosyVoice 的返回格式（24kHz wav）与它的语言能力是配套的。
     * provider 不是 cosyvoice 时直接拒绝，而不是悄悄换成另一个供应商 —— 换供应商是配置变更，
     * 不该由一次日报生成顺手做掉。
     *
     * @param text 服务端生成的播报文本（≤ {@code app.tts.max-chars}）
     * @return 音频字节（CosyVoice：wav）
     * @throws TtsException 未启用 / 没 Key / 超长 / 非 CosyVoice / 上游失败
     */
    public byte[] synthesize(String text) {
        if (!config.isEnabled()) {
            throw new TtsException(503, "TTS_DISABLED", "语音合成未启用（app.tts.enabled=false）");
        }
        String t = text == null ? "" : text.strip();
        if (t.isEmpty()) {
            throw new TtsException(400, "TEXT_EMPTY", "text 不能为空");
        }
        if (!config.isCosyVoice()) {
            throw new TtsException(503, "PROVIDER_NOT_COSYVOICE",
                    "日报语音需要 app.tts.provider=cosyvoice（当前 " + config.getProvider() + "）");
        }
        if (t.length() > config.getMaxChars()) {
            throw new TtsException(400, "TEXT_TOO_LONG",
                    "文本长度 " + t.length() + " 超过上限 " + config.getMaxChars() + " 字符");
        }
        if (!config.apiKeyConfigured()) {
            throw new TtsException(503, "KEY_MISSING", "上游 Key 未配置（APP_TTS_API_KEY）");
        }
        byte[] audio = callCosyVoice(t);
        if (audio == null || audio.length == 0) {
            throw new TtsException(502, "UPSTREAM_EMPTY", "上游返回空音频");
        }
        return audio;
    }

    /**
     * 合成一段<b>自由文本</b>（{@code /api/public/tts/say} 专用）。
     *
     * <h3>它和 {@link #synthesize} 的关系：同一条管道，只换了<em>入口闸</em></h3>
     * 短语表那条线（{@code /api/public/tts}）的红线是"只认服务端给过的文本"。
     * 那条线<b>不动</b>：这个方法是<b>另一个</b>方法，闸 1 从"查表"换成了
     * {@link JapaneseSpeakText#isSpeakableJa}（日语字符集白名单）+ 更短的长度上限。
     *
     * <p>换句话说：自由文本这条路能说出来的东西，是<b>一段有限长度、字符集受限的日语</b>；
     * 它不能代理任意文本 —— 而"任意文本"正是滥用者想要的东西（拿它当免费翻译/朗读 API、
     * 或者把整篇英文文档念出来）。所以长度与字符集不是体验参数，是防滥用的一部分。
     * 后面几道闸（磁盘缓存、Key 判定、每日额度、上游调用）与短语表那条<b>逐字相同，
     * 且共用同一本额度账</b> —— 真实的钱是同一笔，账就该是同一本。
     *
     * @param text        要念的日语（≤ {@link JapaneseSpeakText#SAY_MAX_CHARS} 码点）
     * @param clientIp    调用方 IP（额度按它分桶）
     * @param perIpDaily  本端点每 IP 每日上限（{@code app.tts.say.per-ip-daily}）
     * @param globalDaily 本端点全局每日上限（{@code app.tts.say.global-daily}）
     * @return 音频字节 + 是否缓存命中
     * @throws TtsException 400 文本不合规 / 429 额度 / 503 未启用或缺 Key / 502 上游失败
     */
    public Result say(String text, String clientIp, int perIpDaily, int globalDaily) {
        // 闸 0：总开关（与短语表同一条口径）
        if (!config.isEnabled()) {
            throw new TtsException(503, "TTS_DISABLED", "语音合成未启用（app.tts.enabled=false）");
        }

        // 闸 1：自由文本的入口检查 —— 长度 + 字符集。
        // 注意这里【不做】任何"修正"：不做繁简转换、不删非法字符、不截断。
        // 静默改写输入会让调用方以为它念的是自己给的那句话。
        String t = text == null ? "" : text.strip();
        if (t.isEmpty()) {
            throw new TtsException(400, "TEXT_EMPTY", "text 不能为空");
        }
        int chars = JapaneseSpeakText.length(t);
        if (chars > JapaneseSpeakText.SAY_MAX_CHARS) {
            throw new TtsException(400, "TEXT_TOO_LONG",
                    "自由文本语音上限 " + JapaneseSpeakText.SAY_MAX_CHARS + " 字符（本次 " + chars + " 字符）");
        }
        if (!JapaneseSpeakText.isSpeakableJa(t)) {
            throw new TtsException(400, "TEXT_CHARSET_NOT_ALLOWED",
                    "只接受日语：平假名 / 片假名 / 汉字 / 数字 / 标点");
        }

        // 缓存：同 voiceId + 同文本只合成一次（内容寻址，和短语表那条共用一个缓存目录）
        String key = TtsCache.keyOf(config.getVoiceId(), t);
        byte[] cached = cache.get(key);
        if (cached != null) {
            logger.debug("TTS(say) 缓存命中（{} 字节）：本轮未调上游", cached.length);
            return new Result(cached, true);
        }

        // Key 缺失：在扣额度之前判定（没 Key 就不该记这笔账）
        if (!config.apiKeyConfigured()) {
            throw new TtsException(503, "KEY_MISSING", "上游 Key 未配置（APP_TTS_API_KEY）");
        }

        // 闸 2：每日额度（与短语表共用同一本落盘账；上限用本端点自己的两个数）
        TtsQuotaStore.Decision decision = quota.tryConsume(clientIp, perIpDaily, globalDaily);
        if (!decision.allowed()) {
            String message = TtsQuotaStore.REASON_PER_IP.equals(decision.reason())
                    ? "本来源今日自由语音额度已用完（上限 " + decision.perIpLimit() + " 次/天），明日恢复"
                    : "本站今日自由语音额度已用完（全局上限 " + decision.globalLimit() + " 次/天），明日恢复";
            throw new TtsException(429, decision.reason(), message);
        }

        byte[] audio = callUpstream(t);
        cache.put(key, audio);
        return new Result(audio, false);
    }

    /**
     * 记录一条"刚生成过的回答"，返回它的 textHash（sha512 前 32 位）。
     *
     * <p>这是 textHash 闸的<b>唯一</b>文本来源：只有服务端自己产出过、并且刚被记录的回答
     * 才能被合成。空白回答返回 null（不记、也就不可能被合成）。
     * 进程内 LRU，容量 {@code app.tts.history-size}（重启即空，这是刻意的：
     * 跨重启保留"回答原文"意味着要落盘用户可见内容，代价与风险都更大）。
     */
    public String recordAnswer(String answer) {
        if (answer == null || answer.isBlank()) {
            return null;
        }
        String text = answer.trim();
        String hash = sha512Prefix(text);
        synchronized (recentAnswers) {
            recentAnswers.put(hash, text);
        }
        return hash;
    }

    /** 最近记录的回答条数（自检/测试用） */
    public int recentAnswerCount() {
        synchronized (recentAnswers) {
            return recentAnswers.size();
        }
    }

    /** 真正发出去的上游调用次数（自检/测试断言"缓存命中不调上游"用） */
    public long upstreamCallCount() {
        return upstreamCalls.get();
    }

    /** 生效配置（只读） */
    public TtsConfig config() {
        return config;
    }

    /** 缓存条目数（自检/测试用） */
    public int cacheFileCount() {
        return cache.fileCount();
    }

    /** 缓存目录当前字节数（自检/测试用） */
    public long cacheTotalBytes() {
        return cache.totalBytes();
    }

    /** 已生效的每日额度快照 */
    public TtsQuotaStore.Snapshot quotaSnapshot() {
        return quota.snapshot();
    }

    // ==================== 内部实现 ====================

    private String resolveText(String phraseId, String textHash) {
        boolean hasPhrase = phraseId != null && !phraseId.isBlank();
        boolean hasHash = textHash != null && !textHash.isBlank();
        if (hasPhrase && hasHash) {
            throw new TtsException(400, "BAD_REQUEST", "phraseId 与 textHash 只能给一个");
        }
        if (hasPhrase) {
            String text = config.getPhrases().get(phraseId.trim());
            if (text == null) {
                throw new TtsException(400, "TEXT_NOT_ALLOWED",
                        "未知 phraseId（服务端短语表里没有它，且不接受自由文本）");
            }
            return text;
        }
        if (hasHash) {
            String hash = textHash.trim().toLowerCase(Locale.ROOT);
            if (!TEXT_HASH.matcher(hash).matches()) {
                throw new TtsException(400, "TEXT_NOT_ALLOWED", "textHash 形态不合法（应为 32 位十六进制）");
            }
            String text;
            synchronized (recentAnswers) {
                text = recentAnswers.get(hash);
            }
            if (text == null) {
                throw new TtsException(400, "TEXT_NOT_ALLOWED",
                        "textHash 不在服务端最近生成过的回答里（不接受自由文本）");
            }
            return text;
        }
        throw new TtsException(400, "TEXT_NOT_ALLOWED", "必须给 phraseId 或 textHash（本端点不接受自由文本）");
    }

    /**
     * 调上游。异常一律归一化（见类注释），且绝不把上游原文/Key 带进异常消息。
     */
    private byte[] callUpstream(String text) {
        if (config.isCosyVoice()) {
            return callCosyVoice(text);
        }
        String url = endpoint(config.getBaseUrl());
        String payload = buildPayload(text);
        try {
            return guard.call(DEP_TTS, timeouts.getCallTimeoutMs(), () -> {
                Request request = new Request.Builder()
                        .url(url)
                        .header("Authorization", "Bearer " + config.getApiKey())
                        // 接口形状（POST /v1/tts、Bearer、model 走请求头、响应 audio/mpeg）
                        // 来自 Fish Audio 的 OpenAPI 描述；未用真实 Key 验证过，见 RUNBOOK §30。
                        .header("model", config.getModel())
                        .header("Content-Type", "application/json")
                        .post(RequestBody.create(payload, JSON))
                        .build();
                upstreamCalls.incrementAndGet();
                Response response;
                try {
                    response = client.newCall(request).execute();
                } catch (IOException transportError) {
                    // 传输层失败：按 DeepSeek 链路同一口径补开冷却 ——
                    // OkHttp 的 read timeout 会先于守卫的 callTimeout 触发，
                    // 不在这里开冷却的话，60s 熔断永远不会生效。
                    guard.openCircuit(DEP_TTS);
                    throw new TtsException(isTimeout(transportError) ? 504 : 502,
                            isTimeout(transportError) ? "UPSTREAM_TIMEOUT" : "UPSTREAM_IO",
                            isTimeout(transportError) ? "上游超时，请稍后再试" : "上游连接失败，请稍后再试");
                }
                try (response) {
                    if (!response.isSuccessful()) {
                        // 只记状态码与截断片段（服务端可见）；响应里只给 UPSTREAM_HTTP_<code>。
                        // 401/403 不打印响应体（可能回显 Key 片段）——与 DeepSeek 链路同一纪律。
                        int code = response.code();
                        if (code != 401 && code != 403) {
                            logger.warn("TTS 上游返回 HTTP {}（片段已截断，仅服务端日志）：{}",
                                    code, snippet(response));
                        } else {
                            logger.warn("TTS 上游返回 HTTP {}（鉴权失败；按纪律不打印响应体）", code);
                        }
                        if (code == 401 || code == 403) {
                            guard.openCircuit(DEP_TTS);
                        }
                        throw new TtsException(502, "UPSTREAM_HTTP_" + code, "上游返回 " + code);
                    }
                    byte[] audio = readAudioBounded(response);
                    if (audio.length == 0) {
                        throw new TtsException(502, "UPSTREAM_BAD_BODY", "上游返回了空音频");
                    }
                    return audio;
                }
            });
        } catch (TtsException e) {
            throw e;
        } catch (Exception e) {
            // OutboundGuard 的三种"依赖不可用"（有界等待超时 / 冷却期 / 并发已满）都从这里出来。
            // 对前端是同一件事（现在不可用），所以归一成同一个 reason；区别只写日志。
            Throwable cause = e.getCause();
            if (cause instanceof TtsException inner) {
                throw inner;
            }
            logger.warn("TTS 出站调用未完成（依赖 {}，冷却剩余 {} ms）：{}",
                    DEP_TTS, guard.cooldownRemainingMs(DEP_TTS), e.getMessage());
            throw new TtsException(504, "UPSTREAM_TIMEOUT", "上游暂时不可用（超时或熔断冷却中），请稍后再试");
        }
    }

    /**
     * CosyVoice（DashScope）合成：两步 —— 先 POST 拿签名 OSS 短链，再 GET 那个链拿 wav 字节。
     *
     * <p>为什么不把签名链直接给前端：签名有 {@code Expires}（实测一小时量级），
     * 当长期资源用会过期；而且给前端链等于把计费账单与缓存控制权一并交出去。
     */
    private byte[] callCosyVoice(String text) {
        String base = config.getBaseUrl() == null ? "" : config.getBaseUrl().trim();
        if (base.isEmpty()) {
            throw new TtsException(503, "CONFIG_INVALID", "未配置 CosyVoice 端点（APP_TTS_BASE_URL）");
        }
        /* ★COSY-PATH：APP_TTS_BASE_URL 只填域名（https://dashscope.aliyuncs.com），
           路径必须在这里拼；之前直接 POST 到根路径，上游回 404。
           若以后把完整地址写进配置，不重复拼。 */
        String url = base.endsWith("/api/v1/services/audio/tts/SpeechSynthesizer")
                ? base
                : (base.endsWith("/") ? base.substring(0, base.length() - 1) : base)
                  + "/api/v1/services/audio/tts/SpeechSynthesizer";
        ObjectNode body = MAPPER.createObjectNode();
        body.put("model", config.getModel());
        ObjectNode input = body.putObject("input");
        input.put("text", text);
        input.put("voice", config.getVoiceId());
        input.put("format", "wav");
        input.put("sample_rate", 24000);
        String payload = body.toString();

        try {
            return guard.call(DEP_TTS, timeouts.getCallTimeoutMs(), () -> {
            Request request = new Request.Builder()
                    .url(url)
                    .header("Authorization", "Bearer " + config.getApiKey())
                    .header("Content-Type", "application/json")
                    .post(RequestBody.create(payload, JSON))
                    .build();
            upstreamCalls.incrementAndGet();
            Response response;
            try {
                response = client.newCall(request).execute();
            } catch (IOException transportError) {
                guard.openCircuit(DEP_TTS);
                throw new TtsException(isTimeout(transportError) ? 504 : 502,
                        isTimeout(transportError) ? "UPSTREAM_TIMEOUT" : "UPSTREAM_IO",
                        isTimeout(transportError) ? "上游超时，请稍后再试" : "上游连接失败，请稍后再试");
            }
            String audioUrl;
            try (response) {
                String raw = response.body() == null ? "" : response.body().string();
                if (!response.isSuccessful()) {
                    int code = response.code();
                    if (code != 401 && code != 403) {
                        logger.warn("CosyVoice 上游返回 HTTP {}（片段已截断，仅服务端日志）：{}", code, truncate(raw));
                    } else {
                        guard.openCircuit(DEP_TTS);
                        logger.warn("CosyVoice 上游鉴权失败 HTTP {}（按纪律不打印响应体）", code);
                    }
                    throw new TtsException(502, "UPSTREAM_HTTP_" + code, "上游返回 " + code);
                }
                try {
                    audioUrl = MAPPER.readTree(raw).path("output").path("audio").path("url").asText("");
                } catch (IOException parseError) {
                    throw new TtsException(502, "UPSTREAM_BAD_BODY", "上游返回了非 JSON");
                }
                if (audioUrl.isBlank()) {
                    throw new TtsException(502, "UPSTREAM_BAD_BODY", "上游没给音频地址");
                }
            }
            return fetchAudio(audioUrl);
            });
        } catch (TtsException e) {
            throw e;
        } catch (Exception e) {
            Throwable cause = e.getCause();
            if (cause instanceof TtsException inner) {
                throw inner;
            }
            logger.warn("CosyVoice 出站调用未完成（冷却剩余 {} ms）：{}",
                    guard.cooldownRemainingMs(DEP_TTS), e.getMessage());
            throw new TtsException(504, "UPSTREAM_TIMEOUT", "上游暂时不可用（超时或熔断冷却中），请稍后再试");
        }
    }

    /** 拿签名 OSS 短链下载音频（不带 Authorization：签名已在 URL 里） */
    private byte[] fetchAudio(String audioUrl) {
        Request request = new Request.Builder().url(audioUrl).get().build();
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new TtsException(502, "UPSTREAM_HTTP_" + response.code(), "音频下载失败 " + response.code());
            }
            byte[] audio = readAudioBounded(response);
            if (audio.length == 0) {
                throw new TtsException(502, "UPSTREAM_BAD_BODY", "上游返回了空音频");
            }
            return audio;
        } catch (IOException io) {
            throw new TtsException(502, "UPSTREAM_IO", "音频下载失败");
        }
    }

    private static String truncate(String raw) {
        if (raw == null) {
            return "";
        }
        return raw.length() <= 300 ? raw : raw.substring(0, 300) + "…";
    }

    /** 请求地址：base-url 末尾斜杠归一化后拼 {@code /v1/tts}；已写到 /v1 的也接受 */
    static String endpoint(String baseUrl) {
        String base = (baseUrl == null || baseUrl.isBlank()) ? TtsConfig.DEFAULT_BASE_URL : baseUrl.trim();
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        return base.endsWith("/v1") ? base + "/tts" : base + "/v1/tts";
    }

    private String buildPayload(String text) {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("text", text);
        body.put("format", "mp3");
        if (!config.getVoiceId().isBlank()) {
            body.put("reference_id", config.getVoiceId());
        }
        return body.toString();
    }

    /** 有界读取上游音频：声明长度或实际读取超过上限都按"响应非法"处理（不截断后当音频发出去） */
    private static byte[] readAudioBounded(Response response) throws IOException {
        ResponseBody body = response.body();
        if (body == null) {
            return new byte[0];
        }
        String declared = response.header("Content-Length");
        if (declared != null) {
            try {
                if (Long.parseLong(declared.trim()) > MAX_AUDIO_BYTES) {
                    throw new TtsException(502, "UPSTREAM_BAD_BODY", "上游声明音频过大");
                }
            } catch (NumberFormatException ignored) {
                // 声明值不是数字：不看它，靠下面的有界读取兜住
            }
        }
        try (InputStream in = body.byteStream()) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                if (out.size() + n > MAX_AUDIO_BYTES) {
                    throw new TtsException(502, "UPSTREAM_BAD_BODY", "上游音频超过上限");
                }
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        }
    }

    /** 上游响应片段（截断；只用于服务端日志） */
    private static String snippet(Response response) {
        try {
            ResponseBody body = response.body();
            if (body == null) {
                return "(无响应体)";
            }
            String text = body.string();
            return text.length() > LOG_SNIPPET_CHARS ? text.substring(0, LOG_SNIPPET_CHARS) + "…" : text;
        } catch (IOException e) {
            return "(响应体读取失败)";
        }
    }

    private static boolean isTimeout(IOException e) {
        return e instanceof SocketTimeoutException
                || String.valueOf(e.getMessage()).toLowerCase(Locale.ROOT).contains("timeout");
    }

    private OkHttpClient buildClient() {
        Duration connect = Duration.ofMillis(timeouts.getConnectTimeoutMs());
        Duration read = Duration.ofMillis(timeouts.getReadTimeoutMs());
        Duration call = Duration.ofMillis(timeouts.getCallTimeoutMs());
        return new OkHttpClient.Builder()
                .connectTimeout(connect)
                .readTimeout(read)
                .writeTimeout(read)
                .callTimeout(call)
                .build();
    }

    /** sha512 十六进制的前 32 位（与前端/文档约定的 textHash 形态） */
    static String sha512Prefix(String text) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-512").digest(text.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(32);
            for (byte b : digest) {
                if (sb.length() >= 32) {
                    break;
                }
                sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
            }
            return sb.substring(0, 32);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-512 不可用：无法计算 textHash", e);
        }
    }

    /**
     * 一次成功合成。
     *
     * @param audio    音频字节（mp3）
     * @param cacheHit true = 直接来自本地缓存（本轮没有调上游、也没有吃每日额度）
     */
    public record Result(byte[] audio, boolean cacheHit) {
    }

    /**
     * 被闸门或上游挡下时的异常：带 HTTP 状态码与<b>归一化 reason</b>。
     *
     * <p>{@link #getMessage()} 是给前端看的人话，绝不包含 Key、上游响应体或 URL 细节
     * （细节只写服务端日志）。
     */
    public static class TtsException extends RuntimeException {

        private final int httpStatus;
        private final String reason;

        public TtsException(int httpStatus, String reason, String userMessage) {
            super(userMessage);
            this.httpStatus = httpStatus;
            this.reason = reason;
        }

        public int httpStatus() {
            return httpStatus;
        }

        public String reason() {
            return reason;
        }

        public String userMessage() {
            return String.valueOf(getMessage());
        }
    }
}
