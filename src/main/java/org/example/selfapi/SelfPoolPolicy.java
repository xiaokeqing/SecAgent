package org.example.selfapi;

import org.example.service.ModelQuotaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 自用池的口径（入口预算 / 字符上限 / max_tokens）集中一处。
 *
 * <h3>为什么要单独一个类，而不是散在控制器里</h3>
 * 这三个值会一起被三处读到：控制器（入口校验与响应回显）、文档、以及将来的 provider 侧
 * （按身份下发 max_tokens）。散着放，下一次改动必然只改一处 ——
 * 表现是"接口说上限 4000，实际 1200"，而它不会报错。
 *
 * <h3>max_tokens 的诚实标注（见设计文档 §4.2）</h3>
 * 模型出口目前读<b>全局</b> {@code app.llm.max-tokens}（当前 2000）。
 * 想让自用池单独用 4000，必须改两个 provider 的请求构造（DashScope / DeepSeek），
 * 属于下一批的改动范围。这里先把口径钉住并留 TODO，
 * <b>不</b>为了自用池去放宽全局键 —— 那会同时放宽公开面与评测面。
 */
@Component
public class SelfPoolPolicy {

    /** 指数：自用池标识（前端据此显示"自用池"而不是"公开演示"） */
    public static final String POOL = "self";

    /** 提问/请求体字符上限（站主口径：入口 4000 字符） */
    @Value("${app.user.max-body-chars:4000}")
    private int maxBodyChars;

    /** 单次提问总预算（站主口径：截止 60 s） */
    @Value("${app.user.deadline-ms:60000}")
    private long deadlineMs;

    /**
     * 自用池的输出上限口径。
     *
     * <p><b>TODO(SELF-MAX-TOKENS)</b>：目前模型出口读全局 {@code app.llm.max-tokens}=2000；
     * 要让这个 4000 真正生效，需要在 {@code DashScopeLlmProvider} / {@code DeepSeekLlmProvider}
     * 的请求构造处按 {@link SelfIdentity#isSelfRequest()} 取本值。
     * 本批次<b>不</b>改 provider（不扩 scope），所以它目前只是"口径声明 + 契约"。
     */
    @Value("${app.user.max-tokens:4000}")
    private int maxTokens;

    @Autowired(required = false)
    private ModelQuotaService quotaService;

    public int maxBodyChars() {
        return Math.max(1, maxBodyChars);
    }

    public long deadlineMs() {
        return deadlineMs > 0 ? deadlineMs : 60000L;
    }

    public int maxTokens() {
        return Math.max(1, maxTokens);
    }

    /** 自用池额度快照（软上限语义：超过也照服务，只如实标注） */
    public Map<String, Object> quotaSnapshot() {
        Map<String, Object> m = new LinkedHashMap<>();
        ModelQuotaService q = quotaService;
        // 【形状必须稳定】pool / softLimit 先放，再谈"服务在不在"：
        // 前端与站主自检脚本都会先读这两个键来判断"这是哪本账、是不是软上限"。
        // 把它们放在 null 检查之后，就会让"配额服务未接入"时的响应形状与别的情况不同 ——
        // 前端读到 null，表现是"页面显示未登录或空白"，排查时却看不出跟配额有什么关系。
        m.put("pool", POOL);
        m.put("softLimit", true);
        if (q == null) {
            m.put("available", false);
            m.put("limit", 0);
            m.put("used", 0);
            m.put("remaining", 0);
            m.put("softLimitReached", false);
            m.put("note", "配额服务未接入（裁剪部署或单测）：不假装有额度，也不假装已用完。");
            return m;
        }
        int limit = q.getSelfSoftLimit();
        int used = q.getSelfUsedToday();
        m.put("available", q.isEnabled());
        m.put("limit", limit);
        m.put("used", used);
        m.put("remaining", Math.max(0, limit - used));
        m.put("softLimitReached", used >= limit);
        m.put("storeFile", "data/model-quota-self.json");
        m.put("note", softLimitReachedNote(limit));
        return m;
    }

    /**
     * 软上限文案（纯函数，便于单测逐字钉住「不硬停」这句话）。
     *
     * <p>为什么"到点只提醒"要写进响应体而不只是日志：站主会在页面上看到它 ——
     * 如果页面什么都不说，使用者无从知道"今天已经用超了"，那就不是"提醒"。
     */
    static String softLimitReachedNote(int limit) {
        return "这是【自用】独立额度池：软上限 " + limit + " 次/日，达到后仍会继续服务（只提醒、不硬停）；"
                + "不占用公开演示池，也不占用评测池。";
    }
}
