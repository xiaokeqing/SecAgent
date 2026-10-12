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
 * <h3>为什么现在有三个计数器（而不是把上限调大）</h3>
 * 改造前只有一份额度：评测脚本用管理员账号跑卷，一次两卷约 50 次模型调用，
 * 而用户日额度就是 50 —— <b>跑完评测当天所有真实用户都被"额度已用完"挡住</b>。
 * 给评测放宽额度如果只改 {@code app.quota.daily-limit}，等于同时放宽所有人。
 * <p>
 * 现在按调用来源分派：
 * <ul>
 *   <li>普通身份 → {@code app.quota.daily-limit}（默认 200），持久化 {@code data/model-quota.json}；</li>
 *   <li>评测身份（{@code /api/chat} + {@code app.eval.token}）→ {@code app.quota.eval-daily-limit}，
 *       持久化 {@code data/model-quota-eval.json}；</li>
 *   <li><b>匿名公开演示</b>（{@code /api/public/ask}）→ {@code app.quota.public-daily-limit}（默认 30），
 *       持久化 {@code data/model-quota-public.json}（P4 新增）。</li>
 * </ul>
 * 三份计数<b>互不影响</b>：用户额度耗尽不影响评测，评测跑多少也不占用户额度；
 * 公开端点被公网刷爆同样不会让站主自己用不了系统 —— 这正是"公开"最容易被忽略的代价。
 * 三个计数器都按自然日持久化（沿用已修的机制），跨重启累计。
 */
@Service
public class ModelQuotaService {

    /**
     * 调用来源。三个池子，三本账。
     *
     * <p>把它做成显式枚举而不是三个 boolean：调用点必须回答"我是谁"，
     * 而将来若再多一类来源（例如"定时巡检"），漏改的地方会编译不过，
     * 而不是静默落进用户池 —— 后者不会报错，只会悄悄吃掉站主的额度。
     */
    public enum Identity {
        /** 站主 / 登录用户 */
        USER,
        /** 评测身份（独立凭据） */
        EVAL,
        /** 匿名公开演示（/api/public/ask） */
        PUBLIC
    }

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

    /**
     * 每日模型调用上限 —— <b>匿名公开演示专用</b>（P4）。
     *
     * <p>默认 30：公开问答界面上线后，谁都能匿名提问，这个数字是<b>成本上限</b>而不是
     * 用户体验指标 —— 宁可让第 31 个访客看到"今日公开演示额度已用完"，
     * 也不能让一次公网刷取把站主自己的额度（或评测额度）吃光。
     *
     * <p>它与另外两个池子<b>完全独立</b>：用户在界面上提问不受此值影响，
     * 公开访客提问也不消耗用户额度。
     */
    @Value("${app.quota.public-daily-limit:30}")
    private int publicDailyLimit;

    /** 公开演示计数持久化位置 —— 与用户/评测都不同文件 */
    @Value("${app.quota.public-store-file:data/model-quota-public.json}")
    private String publicStoreFile;

    private final Counter user = new Counter();
    private final Counter eval = new Counter();
    private final Counter publicDemo = new Counter();

    @PostConstruct
    public void init() {
        user.limit = dailyLimit;
        user.storeFile = storeFile;
        eval.limit = evalDailyLimit;
        eval.storeFile = evalStoreFile;
        publicDemo.limit = publicDailyLimit;
        publicDemo.storeFile = publicStoreFile;

        user.load("普通");
        eval.load("评测");
        publicDemo.load("公开演示");

        logger.info("模型配额服务: enabled={}, 每日上限={}, 当日已用={}, 计数文件={}",
                enabled, dailyLimit, getUsedToday(), storeFile);
        logger.info("模型配额服务（评测身份独立计数）: 每日上限={}, 当日已用={}, 计数文件={}",
                evalDailyLimit, getEvalUsedToday(), evalStoreFile);
        logger.info("模型配额服务（匿名公开演示独立计数）: 每日上限={}, 当日已用={}, 计数文件={}",
                publicDailyLimit, getPublicUsedToday(), publicStoreFile);
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

    /**
     * 尝试占用一次调用 —— <b>匿名公开演示专用计数器</b>（P4）。
     *
     * <p>与用户池、评测池都独立。公开端点是匿名可达的，因此这里的上限是
     * "被刷爆时的止损线"：耗尽只影响公开问答，不影响站主自用、也不影响评测。
     */
    public synchronized boolean tryAcquirePublic() {
        return acquire(publicDemo, "公开演示");
    }

    /**
     * 按<b>调用来源</b>分派到对应的计数器（模型出口唯一入口）。
     *
     * <h3>为什么要这一个方法，而不是让调用点自己 if/else</h3>
     * 额度分派写错不会有任何报错，只会把账记到别的池子上 ——
     * 表现是"某天站主突然没额度了"，而查起来毫无线索。
     * 把分派收口在一个方法里，配合 {@link Identity} 枚举，
     * 新增来源时由编译器提醒（而不是靠人记得）。
     */
    public synchronized boolean tryAcquire(Identity identity) {
        switch (identity == null ? Identity.USER : identity) {
            case EVAL:
                return acquire(eval, "评测");
            case PUBLIC:
                return acquire(publicDemo, "公开演示");
            case USER:
            default:
                return acquire(user, "用户");
        }
    }

    /**
     * 该身份今天是否还有余额（<b>只读，不计数</b>）。
     *
     * <p>为什么要暴露它：公开问答端点需要在调用上游之前<b>先问一句"还有额度吗"</b> ——
     * 这样额度用尽时页面拿到的是"今日公开演示额度已用完"，
     * 而不是一条含混的"编排链路不可用"。两者对访客的含义完全不同，
     * 而后者会把"我们没额度了"伪装成"系统坏了"，属于项目明令禁止的静默降级。
     *
     * <p>它不保证"下一步一定拿到额度"（并发下仍可能被别人抢走）——
     * 真正的扣减与拦截始终在 {@link #tryAcquire()} 那一层。
     */
    public synchronized boolean hasRemaining(Identity identity) {
        if (!enabled) {
            return true;
        }
        Counter c = switch (identity == null ? Identity.USER : identity) {
            case EVAL -> eval;
            case PUBLIC -> publicDemo;
            case USER -> user;
        };
        return c.current() < c.limit;
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

    /** 公开演示额度：当日已用 */
    public int getPublicUsedToday() {
        return publicDemo.current();
    }

    /** 普通用户额度：当日上限 */
    public int getDailyLimit() {
        return dailyLimit;
    }

    /** 评测额度：当日上限 */
    public int getEvalDailyLimit() {
        return evalDailyLimit;
    }

    /** 公开演示额度：当日上限 */
    public int getPublicDailyLimit() {
        return publicDailyLimit;
    }

    /** 配额机制是否启用（公开端点会如实标注"配额未启用"，不假装有上限） */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * 一个独立的日计数器（额度上限 + 持久化文件 + 当日已用）。
     *
     * <p>为什么抽出来：三个计数器的逻辑必须完全一致 —— 如果各写一份，
     * 迟早出现"用户那个修了跨日清零、公开那个忘了"的情况，
     * 而表现是"公开额度偶尔多算一天"，看不出是 bug。
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
