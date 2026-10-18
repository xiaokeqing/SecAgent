package org.example.report;

import org.example.publicapi.TtsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

/**
 * 把 {@link TtsService} 接成日报的 {@link DailyDigestService.SpeechSynthesizer}。
 *
 * <h3>为什么要在中间放这一层</h3>
 * 日报与 {@code /api/public/tts} 走的是<b>同一条合成管道</b>，但不是同一个入口：
 * 公开端点只认服务端短语表（防止被当免费朗读 API），而日报的稿子是服务端自己写的。
 * 于是日报走 {@link TtsService#synthesize(String)}（内部方法：不经短语表、不占公开额度），
 * 而那个方法<b>只</b>从这里被调用 —— 公开面上没有任何路径能到达它。
 *
 * <p>这层虽然薄，但它是"日报依赖 TTS，TTS 不依赖日报"的边界：反过来写，
 * 以后想单独测日报就得把整个 TTS 装配起来（含 OkHttp、额度账、磁盘缓存）。
 */
@Component
public class TtsSpeechSynthesizer implements DailyDigestService.SpeechSynthesizer {

    private static final Logger logger = LoggerFactory.getLogger(TtsSpeechSynthesizer.class);

    private final ObjectProvider<TtsService> tts;

    public TtsSpeechSynthesizer(ObjectProvider<TtsService> tts) {
        this.tts = tts;
    }

    @Override
    public byte[] synthesize(String text) {
        TtsService svc = tts.getIfAvailable();
        if (svc == null) {
            throw new IllegalStateException("TtsService 未装配（app.tts.enabled=false 时仍会装配，此处是裁剪部署）");
        }
        byte[] audio = svc.synthesize(text);
        logger.info("日报语音合成完成：{} 字节（provider={}）", audio.length, svc.config().getProvider());
        return audio;
    }

    /** CosyVoice 返回 wav（24kHz/单声道/16bit），Fish Audio 返回 mp3 —— 后缀必须与之一致。 */
    @Override
    public String extension() {
        TtsService svc = tts.getIfAvailable();
        if (svc == null) {
            return "wav";
        }
        return svc.config().isCosyVoice() ? "wav" : "mp3";
    }
}
