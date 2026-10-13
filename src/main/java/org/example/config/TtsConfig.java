package org.example.config;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 文字转语音（{@code POST /api/public/tts}）的<b>不可变值对象</b>。
 *
 * <h3>为什么它不是 {@code @Configuration}（这里是曾经真的起不来的一处）</h3>
 * 与 {@link DeepSeekConfig} 同一个形状与同一个理由：本类被两件事用 ——
 * ① 作为"真正生效的配置"被 {@code TtsService} 注入；② 被单测直接
 * {@code new TtsConfig(...)} 构造。如果它自己既是 {@code @Configuration}
 * 又在里面用 {@code @Bean} 产出同类型对象，Spring 会拿到同名同类型的两个定义，
 * 实测启动即失败：
 * <pre>
 * BeanDefinitionStoreException: Invalid bean definition with name 'ttsConfig'
 * defined in org.example.config.TtsConfig:
 * &#64;Bean definition illegally overridden by existing bean definition
 * </pre>
 * 所以装配点被挪到 {@link TtsOutboundConfig}。
 *
 * <h3>为什么单独一个类，而不是在服务里散落 {@code @Value}</h3>
 * 启动自检要打印的值必须来自<b>真正被用来发请求</b>的那个对象，否则日志会骗人
 * （"配置改了但 Bean 没拿到"这件事本项目已经踩过）。
 *
 * <h3>Key 为什么没有默认值</h3>
 * {@link #getApiKey()} 默认空串，只从环境变量 {@code APP_TTS_API_KEY} 注入。
 * 写死一个默认值等于把凭据放进仓库；空串的含义是明确的"没配"，
 * 端点会如实返回 {@code KEY_MISSING}，绝不静默变成"可用"。
 *
 * <h3>为什么只做"收紧"方向的钳制</h3>
 * 与 {@link DeepSeekConfig} 同一口径：{@code max-chars} 是<b>成本闸</b>，
 * 配得比上限还大不是"更宽容"，而是"一个匿名请求就能让上游合成一大段音频"。
 * 所以超过 {@link #MAX_CHARS_CEILING} 一律夹回上限；非法值（0/负数）取默认值，
 * 绝不退化成"不限长度"。
 */
public class TtsConfig {

    /** 默认关闭：站主还没给 Key；关掉时端点如实返回 {@code TTS_DISABLED}（前端据此隐藏 🔊） */
    public static final boolean DEFAULT_ENABLED = false;

    /** 单次合成文本长度上限（字符）默认值 */
    public static final int DEFAULT_MAX_CHARS = 120;

    /** 单 IP 每日合成次数上限默认值 */
    public static final int DEFAULT_PER_IP_DAILY = 20;

    /** 全局（所有 IP 合计）每日合成次数上限默认值 */
    public static final int DEFAULT_GLOBAL_DAILY = 500;

    /** 缓存目录大小上限默认值（MB） */
    public static final int DEFAULT_MAX_CACHE_MB = 64;

    /** "最近生成过的回答"进程内 LRU 容量默认值（可配） */
    public static final int DEFAULT_HISTORY_SIZE = 200;

    /** Fish Audio 的模型档位（请求头 model；s1 / s2-pro，见 RUNBOOK §30 的接口形状说明） */
    public static final String DEFAULT_MODEL = "s1";

    /** 上游基地址默认值 */
    public static final String DEFAULT_BASE_URL = "https://api.fish.audio";

    /** 缓存目录默认值（落在已挂载、已备份的 data 目录） */
    public static final String DEFAULT_CACHE_DIR = "data/tts-cache";

    /** 每日额度落盘文件默认值（重启不丢） */
    public static final String DEFAULT_QUOTA_FILE = "data/tts-quota.json";

    /** 长度上限的硬顶：配置值超过它一律夹回（"只许收紧不许放大"，见类注释） */
    public static final int MAX_CHARS_CEILING = 600;

    private final boolean enabled;
    private final String voiceId;
    private final String model;
    private final String baseUrl;
    private final String apiKey;
    private final int maxChars;
    private final int perIpDaily;
    private final int globalDaily;
    private final String cacheDir;
    private final int maxCacheMb;
    private final String quotaFile;
    private final int historySize;
    private final Map<String, String> phrases;

    /**
     * @param enabled   总开关；false 时端点返回 503 {@code TTS_DISABLED}
     * @param voiceId   Fish Audio 的音色/模型 id（{@code reference_id}），可为空（用上游默认音色）
     * @param model     模型档位（请求头 {@code model}）
     * @param baseUrl   上游基地址
     * @param apiKey    上游 Key；空 = 没配（端点返回 {@code KEY_MISSING}）
     * @param maxChars  单次文本长度上限；非正数取默认值，超过 {@link #MAX_CHARS_CEILING} 夹回
     * @param perIpDaily 单 IP 每日上限；非正数取默认值
     * @param globalDaily 全局每日上限；非正数取默认值
     * @param cacheDir  音频缓存目录
     * @param maxCacheMb 缓存目录上限（MB）；非正数取默认值
     * @param quotaFile 每日额度落盘文件
     * @param historySize "最近生成过的回答"LRU 容量；非正数取默认值
     * @param phrases   服务端短语表（phraseId → 文本），null/空 = 只允许 textHash 路径
     */
    public TtsConfig(boolean enabled,
                     String voiceId,
                     String model,
                     String baseUrl,
                     String apiKey,
                     int maxChars,
                     int perIpDaily,
                     int globalDaily,
                     String cacheDir,
                     int maxCacheMb,
                     String quotaFile,
                     int historySize,
                     Map<String, String> phrases) {
        this.enabled = enabled;
        this.voiceId = text(voiceId, "");
        this.model = text(model, DEFAULT_MODEL);
        this.baseUrl = text(baseUrl, DEFAULT_BASE_URL);
        this.apiKey = text(apiKey, "");
        this.maxChars = clamp(maxChars, DEFAULT_MAX_CHARS, MAX_CHARS_CEILING);
        this.perIpDaily = clamp(perIpDaily, DEFAULT_PER_IP_DAILY, Integer.MAX_VALUE);
        this.globalDaily = clamp(globalDaily, DEFAULT_GLOBAL_DAILY, Integer.MAX_VALUE);
        this.cacheDir = text(cacheDir, DEFAULT_CACHE_DIR);
        this.maxCacheMb = clamp(maxCacheMb, DEFAULT_MAX_CACHE_MB, Integer.MAX_VALUE);
        this.quotaFile = text(quotaFile, DEFAULT_QUOTA_FILE);
        this.historySize = clamp(historySize, DEFAULT_HISTORY_SIZE, Integer.MAX_VALUE);
        this.phrases = copyPhrases(phrases);
    }

    /** 全部取默认值（关闭、无 Key），供单测与无 Spring 环境使用 */
    public static TtsConfig defaults() {
        return new TtsConfig(DEFAULT_ENABLED, "", DEFAULT_MODEL, DEFAULT_BASE_URL, "", DEFAULT_MAX_CHARS,
                DEFAULT_PER_IP_DAILY, DEFAULT_GLOBAL_DAILY, DEFAULT_CACHE_DIR, DEFAULT_MAX_CACHE_MB,
                DEFAULT_QUOTA_FILE, DEFAULT_HISTORY_SIZE, Map.of());
    }

    private static String text(String value, String fallback) {
        return (value == null || value.isBlank()) ? fallback : value.trim();
    }

    private static int clamp(int configured, int fallback, int max) {
        if (configured <= 0) {
            return fallback;
        }
        return Math.min(configured, max);
    }

    private static Map<String, String> copyPhrases(Map<String, String> raw) {
        if (raw == null || raw.isEmpty()) {
            return Map.of();
        }
        Map<String, String> out = new LinkedHashMap<>();
        raw.forEach((k, v) -> {
            if (k != null && !k.isBlank() && v != null && !v.isEmpty()) {
                out.put(k.trim(), v);
            }
        });
        return Collections.unmodifiableMap(out);
    }

    public boolean isEnabled() {
        return enabled;
    }

    public String getVoiceId() {
        return voiceId;
    }

    public String getModel() {
        return model;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    /** 上游 Key；<b>调用方绝不可把它写进日志或响应</b>（只用于 Authorization 头） */
    public String getApiKey() {
        return apiKey;
    }

    /** 是否配了 Key（供启动自检与 {@code KEY_MISSING} 判定；不暴露 Key 内容） */
    public boolean apiKeyConfigured() {
        return !apiKey.isBlank();
    }

    public int getMaxChars() {
        return maxChars;
    }

    public int getPerIpDaily() {
        return perIpDaily;
    }

    public int getGlobalDaily() {
        return globalDaily;
    }

    public String getCacheDir() {
        return cacheDir;
    }

    public int getMaxCacheMb() {
        return maxCacheMb;
    }

    public String getQuotaFile() {
        return quotaFile;
    }

    public int getHistorySize() {
        return historySize;
    }

    /** 服务端短语表（不可变）；<b>只有</b>这里的文本与"最近生成过的回答"能被合成 */
    public Map<String, String> getPhrases() {
        return phrases;
    }

    /**
     * 供启动自检与排障：<b>绝不包含 Key 内容</b>，只写 {@code key=SET|MISSING}。
     *
     * <p>与 {@code DeepSeekLlmProvider.describe()} 同一口径：日志会被采集与长期保存，
     * "打印配置"不能变成打印凭据。
     */
    public String describe() {
        return "enabled=" + enabled
                + " voiceId=" + (voiceId.isEmpty() ? "(upstream-default)" : voiceId)
                + " model=" + model
                + " baseUrl=" + baseUrl
                + " key=" + (apiKeyConfigured() ? "SET" : "MISSING")
                + " phrases=" + phrases.size()
                + " maxChars=" + maxChars
                + " perIpDaily=" + perIpDaily
                + " globalDaily=" + globalDaily
                + " cacheDir=" + cacheDir
                + " maxCacheMb=" + maxCacheMb
                + " quotaFile=" + quotaFile
                + " historySize=" + historySize;
    }

    @Override
    public String toString() {
        return describe();
    }
}
