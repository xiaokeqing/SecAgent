package org.example.publicapi;

import org.example.llm.LlmProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * 把中文回答压成<b>一句 40 字以内的日语口语</b>（{@code speakJa}）。
 *
 * <h3>它为什么必须"可有可无"</h3>
 * 这条链路上唯一不可商量的是<b>回答本体</b>。语音是锦上添花：
 * 模型超时、额度用完、返回了英文、返回了 60 字的长句 —— 任何一种情况都只能是
 * {@code speakJa = null}（前端退回纯字幕），<b>绝不能</b>变成 5xx、也不能拖慢回答上屏。
 *
 * <p>所以这里有三个刻意的设计：
 * <ol>
 *   <li><b>硬超时 3 秒</b>：用独立的线程池 + {@code Future.get(3s)}，而不是指望上游自己快点返回。
 *       超时后取消任务、丢弃结果；调用方的等待时间有一个确定的上界。</li>
 *   <li><b>失败只记类型，不记内容</b>：上游抛出的 message 里可能带着响应体片段（含 Key 探测回显、
 *       内部提示词），所以日志只写异常<b>类名</b>。</li>
 *   <li><b>产物过白名单</b>：模型输出不做"尽力修补"，而是按
 *       {@link JapaneseSpeakText#cleanGenerated} 判定形状 —— 不合规就是 null。</li>
 * </ol>
 *
 * <h3>它会不会白花钱</h3>
 * 会：这一次改写是一次真实的模型调用（公开池额度）。所以<b>只有请求方显式要</b>
 * （{@code askBody.speakJa = true}，前端仅在"声音已开"时才带）才会触发 ——
 * 关着声音的访客一次都不多花。这也是为什么开关放在请求体里而不是响应侧无条件生成。
 */
@Component
public class PublicSpeakJaWriter {

    private static final Logger logger = LoggerFactory.getLogger(PublicSpeakJaWriter.class);

    /** 系统提示：把"只输出一句日语"这句话放在系统位，比塞在用户位更稳 */
    static final String SYSTEM_PROMPT =
            "你是日语口语改写器。只输出一句自然的日语口语，不带解释、不带引号、不带换行、不带任何标注。";

    /** 用户提示（项目要求逐字写死的那一段，后面接中文原文） */
    static final String USER_PROMPT_PREFIX =
            "把下面这段中文全要点压成一句 40 字以内的日语口语，不要解释、不要标点以外的符号，只输出那句话。\n\n";

    /** 改写预算（毫秒）：超过就当这次没有声音 */
    static final long TIMEOUT_MS = 3000L;

    /** 送去改写的中文原文上限（回答可能很长，取开头足够压出一句话） */
    private static final int MAX_SOURCE_CHARS = 1200;

    /**
     * 专用于这条线的线程池：最多 2 个在飞，超出的直接拒绝（= 这次没有声音）。
     *
     * <p>为什么不复用 Spring 的公共线程池：这条线是<b>可丢弃</b>的，它不该在高峰期占住
     * 别人的线程；被拒绝在这里是正常结果，不是故障。
     */
    private static final ThreadPoolExecutor POOL = new ThreadPoolExecutor(
            0, 2, 60L, TimeUnit.SECONDS, new SynchronousQueue<>(),
            r -> {
                Thread t = new Thread(r, "public-speak-ja");
                t.setDaemon(true);
                return t;
            });

    /**
     * {@code required = false}：单测与"没配模型"的部署里这条线直接不出声，
     * 而不是让公开问答因为缺一个润色器起不来。
     */
    @Autowired(required = false)
    private LlmProvider llmProvider;

    /**
     * 生成一句日语口语。
     *
     * @param chineseAnswer 回答本体（中文，可为多行）
     * @return 可直接送去合成的日语；任何失败都是 {@code null}
     */
    public String rewrite(String chineseAnswer) {
        if (chineseAnswer == null || chineseAnswer.isBlank()) {
            return null;
        }
        LlmProvider provider = llmProvider;
        if (provider == null || !provider.available()) {
            return null;
        }
        String source = clip(chineseAnswer.strip(), MAX_SOURCE_CHARS);

        Future<String> future;
        try {
            future = POOL.submit(() -> provider.generate(SYSTEM_PROMPT, USER_PROMPT_PREFIX + source));
        } catch (RejectedExecutionException e) {
            logger.info("日语改写并发已满（2 个在飞），本次不出声");
            return null;
        }

        try {
            String raw = future.get(TIMEOUT_MS, TimeUnit.MILLISECONDS);
            String cleaned = JapaneseSpeakText.cleanGenerated(raw);
            if (cleaned == null) {
                // 只记"不合规"，不记模型原文：它可能引用了被护栏脱敏过的内部痕迹
                logger.info("日语改写产物不合规（长度或字符集），本次不出声");
            }
            return cleaned;
        } catch (TimeoutException e) {
            future.cancel(true);
            logger.info("日语改写超出预算 {} ms，已丢弃（speakJa = null）", TIMEOUT_MS);
            return null;
        } catch (InterruptedException e) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            return null;
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            logger.info("日语改写失败，本次不出声（原因类型：{}）",
                    cause == null ? e.getClass().getSimpleName() : cause.getClass().getSimpleName());
            return null;
        } catch (RuntimeException e) {
            logger.info("日语改写异常收口，本次不出声（原因类型：{}）", e.getClass().getSimpleName());
            return null;
        }
    }

    private static String clip(String s, int max) {
        if (s.length() <= max) {
            return s;
        }
        return s.substring(0, max);
    }
}
