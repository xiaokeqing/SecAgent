package org.example.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 服务端 TTS 短语表的<b>读取器</b>（{@code app.tts.phrases.*}）。
 *
 * <h3>为什么短语表是"白名单"而不是"默认文本"</h3>
 * {@code POST /api/public/tts} 是匿名端点。若接受自由文本，等于把"任意文字转语音"
 * 这个花钱能力公开（还能被拿来合成任意内容的口播）。所以：<b>表里没有的 phraseId
 * 一律 400 {@code TEXT_NOT_ALLOWED}</b>，绝不回落成"拿请求里的 text 字段凑合"。
 *
 * <h3>为什么读取在服务启动时一次完成</h3>
 * 请求路径上不做文件 IO（本项目 §23 的教训：请求路径上做 IO = 整站 502）。
 * 短语表是启动期数据，读一次进内存，之后只做 Map 查表。
 *
 * <h3>读不到时的行为（fail-closed）</h3>
 * 打 WARN 并按<b>空表</b>处理：后果是所有 phraseId 都 400，而不是"随便合成"。
 * 刻意不在启动期抛异常：短语表坏掉不该让整个应用起不来（textHash 路径仍然可用），
 * 但也绝不静默 —— 应用启动日志里有一行 {@code TTS-SELFCHECK}，里面有 {@code phrases=N}。
 */
public final class TtsPhrases {

    private static final Logger logger = LoggerFactory.getLogger(TtsPhrases.class);

    /** 默认位置：resources 里的 tts-phrases.yml（键的路径就是 app.tts.phrases.*） */
    public static final String DEFAULT_LOCATION = "classpath:tts-phrases.yml";

    /** 短语表在 yaml 里的路径 */
    public static final String KEY_PATH = "app.tts.phrases";

    private TtsPhrases() {
    }

    /**
     * 从 Spring 资源位置读取短语表。
     *
     * @param location {@code classpath:...} 或 {@code file:...}；空则用 {@link #DEFAULT_LOCATION}
     * @return 不可变短语表；读不到/结构不对时为空表（fail-closed，见类注释）
     */
    public static Map<String, String> load(String location) {
        String loc = (location == null || location.isBlank()) ? DEFAULT_LOCATION : location.trim();
        try {
            Resource resource = new DefaultResourceLoader().getResource(loc);
            if (!resource.exists()) {
                logger.warn("TTS 短语表不存在（{}）：按空表处理，phraseId 一律 400 TEXT_NOT_ALLOWED", loc);
                return Map.of();
            }
            try (InputStream in = resource.getInputStream()) {
                Map<String, String> phrases = fromYaml(new String(in.readAllBytes(), StandardCharsets.UTF_8));
                if (phrases.isEmpty()) {
                    logger.warn("TTS 短语表里没有任何 {}.* 条目（{}）：按空表处理", KEY_PATH, loc);
                }
                return phrases;
            }
        } catch (Exception e) {
            logger.warn("TTS 短语表读取失败（{}）：{} —— 按空表处理（fail-closed，绝不变成\"随便合成\"）",
                    loc, e.getMessage());
            return Map.of();
        }
    }

    /**
     * 解析一份 yaml 文本里的 {@code app.tts.phrases}。
     *
     * <p>结构不对（缺键 / 不是映射）返回空表，不抛异常：调用方按"没配短语"处理。
     */
    @SuppressWarnings("unchecked")
    public static Map<String, String> fromYaml(String yaml) {
        Object cursor = new Yaml().load(yaml);
        for (String key : KEY_PATH.split("\\.")) {
            if (!(cursor instanceof Map<?, ?> map)) {
                return Map.of();
            }
            cursor = map.get(key);
        }
        if (!(cursor instanceof Map<?, ?> phrases)) {
            return Map.of();
        }
        Map<String, String> out = new LinkedHashMap<>();
        phrases.forEach((k, v) -> {
            if (k != null && v != null) {
                String text = String.valueOf(v);
                if (!text.isBlank()) {
                    out.put(String.valueOf(k).trim(), text);
                }
            }
        });
        return Collections.unmodifiableMap(out);
    }
}
