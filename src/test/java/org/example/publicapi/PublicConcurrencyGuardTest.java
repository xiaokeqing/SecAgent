package org.example.publicapi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 「每 IP 并发 1」守卫的行为测试（P4）。
 *
 * <h3>为什么限流之外还要单独测并发</h3>
 * 限流挡"总量"，并发挡"同时占用"。一个攻击者可以用 1 次/分钟的频率（永远不触发限流）
 * 一直占着编排线程池里的一个位置，几十个 IP 一起来就把 4 个编排线程占满 ——
 * 站主自己的 {@code /api/chat} 于是排队。这条约束的全部价值在于"第二个必须被拒"，
 * 而"先查再登记"的两步实现会<b>静默放行</b>第二个：表现是接口正常，
 * 只是并发上限形同虚设。所以这里既测单线程的拒/放，也用真并发撞一次。
 */
class PublicConcurrencyGuardTest {

    @Test
    @DisplayName("同一 IP：第 1 个在飞时第 2 个被拒；释放后可以再进")
    void secondInFlightIsRejectedThenRecovers() {
        PublicConcurrencyGuard guard = new PublicConcurrencyGuard();

        assertTrue(guard.tryAcquire("47.96.1.2"), "第一个请求应取得许可");
        assertFalse(guard.tryAcquire("47.96.1.2"), "同一 IP 的第二个并发请求必须被拒（并发 1）");
        assertEquals(1, guard.inFlightCount("47.96.1.2"), "被拒的请求不得污染在飞计数（实测曾被写成 -1 / MAX_VALUE）");
        assertFalse(guard.tryAcquire("47.96.1.2"), "重复尝试仍然被拒（拒绝不能顺手把在飞记录清掉）");
        assertEquals(1, guard.inFlightCount("47.96.1.2"), "连续被拒后计数仍必须是 1");

        guard.release("47.96.1.2");
        assertEquals(0, guard.inFlightCount("47.96.1.2"));
        assertTrue(guard.tryAcquire("47.96.1.2"), "释放后必须能重新进入（否则该 IP 被永久挡住）");
        guard.release("47.96.1.2");
    }

    @Test
    @DisplayName("不同 IP 互不影响：A 在飞不挡 B")
    void differentIpsAreIndependent() {
        PublicConcurrencyGuard guard = new PublicConcurrencyGuard();
        assertTrue(guard.tryAcquire("10.1.1.1"));
        assertTrue(guard.tryAcquire("10.1.1.2"), "另一个 IP 的并发请求不该被 A 挡住");
        guard.release("10.1.1.1");
        guard.release("10.1.1.2");
    }

    @Test
    @DisplayName("取不到 IP 时归入 unknown 桶：同样只允许 1 个在飞")
    void unknownBucketIsAlsoSingleFlight() {
        PublicConcurrencyGuard guard = new PublicConcurrencyGuard();
        assertTrue(guard.tryAcquire(null));
        assertFalse(guard.tryAcquire(""), "空白与 null 是同一个桶，第二个必须被拒");
        guard.release(null);
        assertTrue(guard.tryAcquire("  "));
        guard.release("  ");
    }

    @Test
    @DisplayName("真并发撞同一 IP：最多只有 1 个能拿到许可（两步实现会在这里翻车）")
    void concurrentAcquireAdmitsExactlyOne() throws Exception {
        PublicConcurrencyGuard guard = new PublicConcurrencyGuard();
        int threads = 16;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger admitted = new AtomicInteger();
        List<Boolean> results = new ArrayList<>();

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            for (int i = 0; i < threads; i++) {
                pool.submit(() -> {
                    try {
                        start.await();
                        boolean ok = guard.tryAcquire("203.0.113.77");
                        synchronized (results) {
                            results.add(ok);
                        }
                        if (ok) {
                            admitted.incrementAndGet();
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        done.countDown();
                    }
                });
            }
            start.countDown();
            assertTrue(done.await(10, TimeUnit.SECONDS), "并发任务未在超时内完成");

            assertEquals(1, admitted.get(), "16 个并发请求里必须只有 1 个取得许可");
            assertEquals(1, guard.inFlightCount("203.0.113.77"));
            long okCount = results.stream().filter(Boolean::booleanValue).count();
            assertEquals(1, okCount, "返回 true 的只能有一个");
        } finally {
            pool.shutdownNow();
            guard.release("203.0.113.77");
        }
    }
}
