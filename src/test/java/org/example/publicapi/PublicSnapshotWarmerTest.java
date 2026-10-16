package org.example.publicapi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 「源站那一腿」的两条修法（B 批）：<b>快照不再阻塞请求</b> + <b>后台定时预聚合</b>。
 *
 * <h3>它防的是什么</h3>
 * 站主实测"页面打开很快，但取数慢（约 10s）"，根因之一是冷快照要现算
 * （{@code alerts} 冷 3.7s / {@code webstats} 冷 4.1s，暖态 3~5ms）。旧实现是 {@code synchronized}：
 * 过期时第一个请求现算，<b>同时到达的其他请求一起被锁住等</b>。本类钉住三条：
 * <ol>
 *   <li>TTL 内第二次请求<b>不触发重算</b>（否则等于没缓存）；</li>
 *   <li>过期且有人在算时，另一个请求<b>立刻拿到旧值、不等</b>（这是"取数慢"的直接解药）；</li>
 *   <li>预聚合按"年龄阈值"刷新：没到阈值<b>不刷</b>（不白打上游），到阈值就刷（访客侧永远是热快照）。</li>
 * </ol>
 */
class PublicSnapshotWarmerTest {

    /** 便于构造：{@code Snapshot} 是控制器的包内可见静态嵌套类 */
    private static PublicApiController.Snapshot snapshot() {
        return new PublicApiController.Snapshot();
    }

    @Test
    @DisplayName("TTL 内第二次请求不触发重算（否则缓存等于没做）")
    void secondRequestWithinTtlDoesNotReload() {
        PublicApiController.Snapshot s = snapshot();
        AtomicInteger loads = new AtomicInteger();

        Map<String, Object> first = s.get(45, () -> Map.of("n", loads.incrementAndGet()));
        Map<String, Object> second = s.get(45, () -> Map.of("n", loads.incrementAndGet()));

        assertEquals(1, loads.get(), "TTL 内第二次请求不得再算一次");
        assertSame(first, second, "TTL 内应返回同一份快照对象");
    }

    @Test
    @DisplayName("★过期且有人在算：另一个请求立刻拿旧值，绝不阻塞等待现算")
    void staleValueIsServedWithoutBlockingWhileAnotherThreadRefreshes() throws Exception {
        PublicApiController.Snapshot s = snapshot();
        // ttl=0 ⇒ 先建一份"立即过期"的初值（这样后面的 get 才会真的尝试刷新）
        s.get(0, () -> Map.of("v", 1));

        CountDownLatch computing = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Thread refresher = new Thread(() -> s.get(0, () -> {
            computing.countDown();
            try {
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return Map.of("v", 2);
        }));
        refresher.setDaemon(true);
        refresher.start();
        assertTrue(computing.await(5, java.util.concurrent.TimeUnit.SECONDS), "刷新线程应已进入现算");

        long t0 = System.currentTimeMillis();
        Map<String, Object> served = s.get(0, () -> {
            throw new AssertionError("有人正在算时，这个请求不该自己去算");
        });
        long elapsed = System.currentTimeMillis() - t0;

        assertEquals(1, served.get("v"), "应立刻返回旧值（不是新值，也不是空）");
        assertTrue(elapsed < 500, "必须立刻返回旧值，不能等现算（实测耗时 " + elapsed + "ms）");

        release.countDown();
        refresher.join(5000);
    }

    @Test
    @DisplayName("预聚合：没到年龄阈值不刷，到了就刷（且会推进快照时刻）")
    void refreshIfOlderThanRespectsThreshold() {
        PublicApiController.Snapshot s = snapshot();
        AtomicInteger loads = new AtomicInteger();
        s.get(45, () -> Map.of("n", loads.incrementAndGet()));
        assertEquals(1, loads.get());

        assertFalse(s.refreshIfOlderThan(60_000L, 45, () -> Map.of("n", loads.incrementAndGet())),
                "年龄没到阈值就不该刷新（否则白打上游、频率比原来还高）");
        assertEquals(1, loads.get());

        assertTrue(s.refreshIfOlderThan(0L, 45, () -> Map.of("n", loads.incrementAndGet())),
                "年龄超过阈值必须刷新");
        assertEquals(2, loads.get(), "刷新应真的重新计算并推进快照");
    }

    @Test
    @DisplayName("没有旧值 + 刷新失败：仍然 fail-closed 抛错（不返回空白 200）")
    void firstLoadFailureStillFailsClosed() {
        PublicApiController.Snapshot s = snapshot();
        try {
            s.get(45, () -> {
                throw new IllegalStateException("上游挂了");
            });
            throw new AssertionError("首次加载失败必须抛错，不能返回空数据");
        } catch (IllegalStateException expected) {
            assertNotNull(expected.getMessage());
        }
    }

    @Test
    @DisplayName("有旧值 + 刷新失败：继续用旧值（不抛错、不把页面变成空白）")
    void refreshFailureKeepsStaleValue() {
        PublicApiController.Snapshot s = snapshot();
        s.get(0, () -> Map.of("v", 1));   // ttl=0 ⇒ 立即过期，下面的 get 才会真的去刷新
        Map<String, Object> out = s.get(0, () -> {
            throw new IllegalStateException("上游挂了");
        });
        assertEquals(1, out.get("v"), "刷新失败时应保留旧快照（页面上标注真实的 snapshotAt 即可）");
    }

    @Test
    @DisplayName("预聚合方法本身绝不能被上游异常打断（协作对象全缺也不能抛）")
    void warmPublicSnapshotsNeverThrows() {
        PublicApiController controller = new PublicApiController();
        // 刻意不注入任何协作对象（source / geoip / accesslog 都是 null）：
        // 预聚合必须把它们当作"这一轮刷不了"，而不是把异常抛给定时线程。
        controller.warmPublicSnapshots();
        controller.warmPublicSnapshots();
    }
}
