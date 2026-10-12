package org.example.service;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 模型调用配额（按自然日计数），防止接口被滥用导致成本失控（对应 OWASP LLM10 无限制消费）。
 *
 * <h3>为什么现在有两个计数器（而不是把上限调大）</h3>
 * 改造前只有一份额度：评测脚本用管理员账号跑卷，一次两卷约 50 次模型调用，
 * 而用户日额度就是 50 —— <b>跑完评测当天所有真实用户都被"额度已用完"挡住</b>。
 * 给评测放宽额度如果只改 {@code app.quota.daily-limit}，等于同时放宽所有人。
 * <p>
 * 现在按调用来源分派：
 * <ul>
 *   <li>普通身份 → {@code app.quota.daily-limit}（默认 200），持久化 {@code data/model-quota.json}；</li>
 *   <li>评测身份（{@code /api/chat} + {@code app.eval.token}）→ {@code app.quota.eval-daily-limit}，
 *       持久化 {@code data/model-quota-eval.json}。</li>
 * </ul>
 * 两份计数<b>互不影响</b>：用户额度耗尽不影响评测，评测跑多少也不占用户额度。
 * 两个计数器都按自然日持久化（沿用已修的机制），跨重启累计。
 */
@Service
public class ModelQuotaService {

    private static final Logger logger = LoggerFactory.getLogger(ModelQuotaService.class);

    @Value("${app.quota.enabled:true}")
    private boolean enabled;

    /** 每日模型调用上限（chat / chat_stream / ai_ops 各计一次）—— 普通用户 */
    @Value("${app.quota.daily-limit:200}")
    private int dailyLimit;

    /** 计数持久化位置（相对容器工作目录）—— 普通用户 */
    @Value("${app.quota.store-file:data/model-quota.json}")
    private String storeFile;

    /**
     * 每日模型调用上限 —— <b>评测身份专用</b>。
     *
     * <p>默认 60：够跑一次安全卷（18 例）或质量卷（7 例 + 1 探针）还有富余，
     * 但不足以被拿来当"免费无限额度"刷。（方案里写的是 200，实施时按"够跑卷 + 不至于敞开刷"取了 60。）
     */
    @Value("${app.quota.eval-daily-limit:60}")
    private int evalDailyLimit;

    /** 评测计数持久化位置 —— 与用户计数【不同文件】，这是"分开计数"最直接的证据 */
    @Value("${app.quota.eval-store-file:data/model-quota-eval.json}")
    private String evalStoreFile;

    private final Counter user = new Counter();
    private final Counter eval = new Counter();

    @PostConstruct
    public void init() {
        user.limit = dailyLimit;
        user.storeFile = storeFile;
        eval.limit = evalDailyLimit;
        eval.storeFile = evalStoreFile;

        user.load("普通");
        eval.load("评测");

        logger.info("模型配额服务: enabled={}, 每日上限={}, 当日已用={}, 计数文件={}",
                enabled, dailyLimit, getUsedToday(), storeFile);
        logger.info("模型配额服务（评测身份独立计数）: 每日上限={}, 当日已用={}, 计数文件={}",
                evalDailyLimit, getEvalUsedToday(), evalStoreFile);
    }

    /** 尝试占用一次调用：true 通过，false 表示当日已超限（普通用户额度） */
    public synchronized boolean tryAcquire() {
        return acquire(user, "用户");
    }

    /**
     * 尝试占用一次调用 —— <b>评测身份专用计数器</b>。
     *
     * <p>与 {@link #tryAcquire()} 完全独立：任一方耗尽都不影响另一方。
     */
    public synchronized boolean tryAcquireEval() {
        return acquire(eval, "评测");
    }

    private boolean acquire(Counter c, String label) {
        if (!enabled) {
            return true;
        }
        LocalDate today = LocalDate.now();
        if (!today.equals(c.day)) {
            c.day = today;
            c.used.set(0);
        }
        if (c.used.get() >= c.limit) {
            logger.warn("当日模型调用已达上限 {}（{}额度，已用 {}）", c.limit, label, c.used.get());
            return false;
        }
        c.used.incrementAndGet();
        c.persist();
        return true;
    }

    /** 普通用户额度：当日已用 */
    public int getUsedToday() {
        return user.current();
    }

    /** 评测额度：当日已用 */
    public int getEvalUsedToday() {
        return eval.current();
    }

    /** 普通用户额度：当日上限 */
    public int getDailyLimit() {
        return dailyLimit;
    }

    /** 评测额度：当日上限 */
    public int getEvalDailyLimit() {
        return evalDailyLimit;
    }

    /**
     * 一个独立的日计数器（额度上限 + 持久化文件 + 当日已用）。
     *
     * <p>为什么抽出来：两个计数器的逻辑必须完全一致 —— 如果各写一份，
     * 迟早出现"用户那个修了跨日清零、评测那个忘了"的情况，
     * 而表现是"评测额度偶尔多算一天"，看不出是 bug。
     */
    private static final class Counter {

        int limit;
        String storeFile;
        final AtomicInteger used = new AtomicInteger(0);
        volatile LocalDate day = LocalDate.now();

        int current() {
            return LocalDate.now().equals(day) ? used.get() : 0;
        }

        /**
         * 载入当日已用计数。
         *
         * <p><b>为什么必须持久化（实测教训）</b>：原实现把计数放在内存里（`AtomicInteger`），
         * 而"每日上限"是成本护栏 —— 结果**重启容器即归零**：配额耗尽后一次部署就能继续刷模型，
         * 上限形同虚设。现在按自然日持久化到文件，跨重启累计。
         */
        void load(String label) {
            day = LocalDate.now();
            try {
                Path p = Path.of(storeFile);
                if (!Files.isReadable(p)) {
                    return;
                }
                String raw = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
                com.fasterxml.jackson.databind.JsonNode n =
                        new com.fasterxml.jackson.databind.ObjectMapper().readTree(raw);
                String savedDay = n.path("date").asText("");
                int usedToday = n.path("used").asInt(0);
                if (day.toString().equals(savedDay)) {
                    used.set(Math.max(0, usedToday));
                } else {
                    used.set(0);   // 跨日：清零并立刻落盘，避免旧日期残留
                    persist();
                }
            } catch (Exception e) {
                logger.warn("{}配额计数载入失败（按 0 起算）: {}", label, e.getMessage());
                used.set(0);
            }
        }

        void persist() {
            try {
                Path p = Path.of(storeFile);
                if (p.getParent() != null) {
                    Files.createDirectories(p.getParent());
                }
                String json = "{\"date\":\"" + day + "\",\"used\":" + used.get() + "}";
                Files.write(p, json.getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) {
                logger.warn("配额计数持久化失败（计数仍在内存中生效）: {}", e.getMessage());
            }
        }
    }
}
