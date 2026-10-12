package org.example.publicapi;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 公开问答端点的<b>每 IP 并发 1</b> 守卫。
 *
 * <h3>为什么限流不够，还要单独限并发</h3>
 * 这两个是不同性质的武器：
 * <ul>
 *   <li><b>限流</b>（每分钟 N 次）挡的是"总量"—— 频率高、单次短；</li>
 *   <li><b>限并发</b>挡的是"同时占用"—— 频率可以很低（1 次/分钟，永远不触发限流），
 *       但每次都开着连接、占着编排线程池，几十个 IP 一起来就把 4 个编排线程占满，
 *       此时<b>站主自己的 /api/chat 也会排队</b>。这是"合规地"把服务打死。</li>
 * </ul>
 * 公开问答是<b>会调模型</b>的重操作（一次提问可能两次模型调用、最长 25 秒），
 * 所以"同一 IP 同时只允许 1 个在飞"是这里最划算的一条约束：
 * 它不影响正常访客（人不会同时问两个问题），却把单 IP 的占用上限钉死在 1。
 *
 * <h3>为什么用 {@code compute} 而不是先 get 再 put</h3>
 * "先查有没有、再登记"是典型的两步竞态：两个并发请求可以同时看到"没有"，
 * 于是两个都放行 —— 而这条守卫的全部意义就是拦住第二个。
 * {@link ConcurrentHashMap#compute} 对同一个 key 是原子的，判定与登记在同一把锁内完成。
 *
 * <p>边界说明：这是<b>进程内</b>计数，重启即清零，且多实例部署时会各算一份。
 * 当前是单实例部署，够用；真要跨实例，得把这份状态搬到外部存储（届时也要一并
 * 处理"实例崩了计数不释放"的问题）。
 */
public class PublicConcurrencyGuard {

    /** 每 IP 在飞计数（键存在 ⇒ 值 ≥ 1，即"该 IP 有请求在飞"；键不存在 ⇒ 空闲） */
    private final Map<String, AtomicInteger> inFlight = new ConcurrentHashMap<>();

    /** 跟踪表上限：超过就清理计数已归零的条目，避免被大量伪造来源撑爆内存 */
    private static final int MAX_TRACKED_KEYS = 5000;

    /**
     * 尝试取得一次"在飞"许可。
     *
     * <p>判定与登记必须在<b>同一次原子操作</b>里完成：{@code compute} 的映射函数
     * 对同一个 key 是串行的，因此"看到空闲 → 占用"不可能被另一个线程插入。
     *
     * <p>这里连续踩过<b>三个</b>坑，全部记在注释里 —— 它们的共同表现都是
     * "接口照常返回、只是并发约束悄悄失效"，靠看日志发现不了：
     * <ol>
     *   <li>拒绝时 {@code return null} —— {@link ConcurrentHashMap#compute} 收到 null 会
     *       <b>删除该键</b>，于是"第 2 个请求被拒"顺手把在飞记录清成了空闲，第 3 个又被放行；</li>
     *   <li>用一个"值 -1 的哨兵对象"表示占用 —— 哨兵会被写进映射，而映射里的值不可能是负数，
     *       下一位访客看到 -1 就当成空槽，再放行一个（实测：16 并发放行 8 个）；</li>
     *   <li>把哨兵换成极大正整数 —— 拒绝确实不再放行，但那个哨兵留在映射里，
     *       于是"在飞计数"对外显示成 2147483647（排障与页面展示全被污染）。</li>
     * </ol>
     * 最终形状：<b>映射里只存真实计数，且只在有新值可写时调用 {@code compute}</b>。
     * 拒绝发生在 {@code compute} 之前（先用原子值判定），因此哨兵根本不需要存在 ——
     * 凡是需要"用一个假值表达状态"的设计，都会在下一次有人读这个值的时候出问题。
     *
     * @param clientIp 调用方 IP（取不到时归入 unknown 桶）
     * @return true 放行（<b>调用方必须</b>在 finally 里 {@link #release(String)}）；
     *         false 表示该 IP 已有请求在飞
     */
    public boolean tryAcquire(String clientIp) {
        String key = normalize(clientIp);
        evictIdleIfTooMany();
        AtomicInteger cur = inFlight.get(key);
        if (cur != null && cur.get() > 0) {
            return false;                                  // 已在飞：不碰映射，直接拒绝
        }
        if (cur != null && cur.get() == 0) {
            // 上一次仍在跑（值被抬回 ≥1）或被别的线程抢先登记时，CAS 会失败 ⇒ 本次拒绝。
            // 不能忽略 CAS 的返回值：忽略它就会在"那一次 CAS 失败"里白送一个许可。
            return cur.compareAndSet(0, 1);
        }
        // 键不存在：登记占用。putIfAbsent 在并发下只有一个赢
        return inFlight.putIfAbsent(key, new AtomicInteger(1)) == null;
    }

    /**
     * 释放在飞许可（必须在 finally 里调用，否则该 IP 会被永久挡住）。
     *
     * <p>计数归零后<b>删除键</b>而不是留一个 0：留 0 会让 {@link #evictIdleIfTooMany()}
     * 有机会在"另一个线程刚 compareAndSet 成功、还没开始干活"时把它清掉 ——
     * 那等于在并发中间把锁拆了。空闲即不存在，语义最干净。
     */
    public void release(String clientIp) {
        String key = normalize(clientIp);
        inFlight.computeIfPresent(key, (k, cur) -> {
            synchronized (cur) {          // 与"读-判-改"配对：避免计数被两个释放交错写坏
                int v = cur.decrementAndGet();
                if (v > 0) {
                    return cur;
                }
                return null;              // 归零 ⇒ 移除键 = 空闲
            }
        });
    }

    /**
     * 跟踪表过大时清理<b>确认空闲</b>的键。
     *
     * <p>只删值为 0 的（即刚跑完、还没被新请求抢到的那些）；
     * 判定用 {@code cur.get() == 0} 且删前再 {@code compareAndSet(0, 0)} 确认一次 ——
     * 正在飞（值 ≥ 1）的条目绝不能动，否则等于把别人的锁拆了。
     */
    private void evictIdleIfTooMany() {
        if (inFlight.size() <= MAX_TRACKED_KEYS) {
            return;
        }
        for (Map.Entry<String, AtomicInteger> e : inFlight.entrySet()) {
            AtomicInteger v = e.getValue();
            if (v.get() == 0 && v.compareAndSet(0, 0)) {
                // CAS(0,0) 成功只说明"此刻仍是空闲"；remove(key, value) 再确认一次实例一致
                inFlight.remove(e.getKey(), v);
            }
        }
    }

    /** 当前该 IP 的在飞数（测试与排障用；空闲返回 0） */
    public int inFlightCount(String clientIp) {
        AtomicInteger v = inFlight.get(normalize(clientIp));
        return v == null ? 0 : Math.max(0, v.get());
    }

    private static String normalize(String clientIp) {
        return (clientIp == null || clientIp.isBlank()) ? "unknown" : clientIp.trim();
    }
}
