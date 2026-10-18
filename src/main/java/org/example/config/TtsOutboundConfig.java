package org.example.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

/**
 * 文字转语音（{@code POST /api/public/tts}）配置的<b>装配点</b>。
 *
 * <h3>为什么 {@code @Bean} 不写在 {@link TtsConfig} 里面（真实启动事故）</h3>
 * 见 {@link TtsConfig} 的类注释与 {@link DeepSeekOutboundConfig}：
 * 值对象自己既是 {@code @Configuration} 又产出同类型 Bean 时，启动即
 * {@code BeanDefinitionStoreException}（同名同类型两个定义）。
 * 本仓库没有全量 {@code @SpringBootTest}，这种缺陷"编译绿、单测绿、只有容器起不来"，
 * 所以装配点独立成类，并由 {@code TtsConfigContractTest} 用 {@code ApplicationContextRunner}
 * 把"能装配起来"钉成一条单测。
 *
 * <h3>Key 从哪来</h3>
 * 只经环境变量 {@code APP_TTS_API_KEY}（yml 里写成 {@code ${APP_TTS_API_KEY:}}，
 * 默认空）。空 = 明确"没配"：端点返回 {@code KEY_MISSING}，绝不静默变成可用。
 *
 * <h3>启动自检</h3>
 * 装配完成时打一行 {@code TTS-SELFCHECK}，内容来自<b>真正被注入服务</b>的那个对象
 * （{@link TtsConfig#describe()}，只写 {@code key=SET|MISSING}，绝不含 Key 内容）。
 * 排障时先看这一行，不要只看配置文件 —— "配置改了但 Bean 没拿到"不会报错。
 */
@Configuration
public class TtsOutboundConfig {

    private static final Logger logger = LoggerFactory.getLogger(TtsOutboundConfig.class);

    /**
     * TTS 的全部生效配置（含服务端短语表）。
     *
     * <p>短语表在装配期读一次（{@link TtsPhrases#load}）：请求路径上不做文件 IO。
     */
    @Bean
    public TtsConfig ttsConfig(
            @Value("${app.tts.enabled:false}") boolean enabled,
            @Value("${app.tts.voice-id:}") String voiceId,
            @Value("${app.tts.model:s1}") String model,
            @Value("${app.tts.base-url:https://api.fish.audio}") String baseUrl,
            @Value("${app.tts.api-key:}") String apiKey,
            @Value("${app.tts.max-chars:120}") int maxChars,
            @Value("${app.tts.per-ip-daily:20}") int perIpDaily,
            @Value("${app.tts.global-daily:500}") int globalDaily,
            @Value("${app.tts.cache-dir:data/tts-cache}") String cacheDir,
            @Value("${app.tts.max-cache-mb:64}") int maxCacheMb,
            @Value("${app.tts.quota-file:data/tts-quota.json}") String quotaFile,
            @Value("${app.tts.history-size:200}") int historySize,
            @Value("${app.tts.phrases-file:" + TtsPhrases.DEFAULT_LOCATION + "}") String phrasesFile,
            @Value("${app.tts.provider:fish}") String provider) {
        Map<String, String> phrases = TtsPhrases.load(phrasesFile);
        TtsConfig config = new TtsConfig(enabled, voiceId, model, baseUrl, apiKey, maxChars, perIpDaily,
                globalDaily, cacheDir, maxCacheMb, quotaFile, historySize, phrases, provider);
        logger.info("TTS-SELFCHECK {}", config.describe());
        return config;
    }
}
