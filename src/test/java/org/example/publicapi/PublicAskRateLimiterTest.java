package org.example.publicapi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 公开问答限流器的行为测试。
 *
 * <h3>这条测试防的是什么</h3>
 * 限流"看起来有"和"真的生效"是两件事：这个端点是匿名可达的，
 * 一旦判定写错（比如把 {@code <=} 写成 {@code <}、或者把窗口比较写反），
 * 表现是"接口照常返回 200"——没有任何报错，只是额度（真金白银）被刷掉。
 * 所以这里断言的是<b>第 N+1 次必须被拒</b>，而不是断言配置读到几。
 */
class PublicAskRateLimiterTest {

    @Test
    @DisplayName("每 IP 每分钟 N 次：第 N 次放行、第 N+1 次 429")
    void blocksAfterLimitWithinSameMinute() {
        PublicAskRateLimiter limiter = new PublicAskRateLimiter(6);

        for (int i = 1; i <= 6; i++) {
            assertTrue(limiter.allow("203.0.113.9"), "第 " + i + " 次应放行");
        }
        assertFalse(limiter.allow("203.0.113.9"), "第 7 次必须被拒（默认 6 次/分钟）");
        assertFalse(limiter.allow("203.0.113.9"), "超限后继续请求仍然被拒");
        assertEquals(0, limiter.remaining("203.0.113.9"), "剩余次数不得为负");
    }

    @Test
    @DisplayName("不同 IP 各自计数：一个 IP 打满不影响另一个")
    void countersArePerIp() {
        PublicAskRateLimiter limiter = new PublicAskRateLimiter(2);

        assertTrue(limiter.allow("198.51.100.1"));
        assertTrue(limiter.allow("198.51.100.1"));
        assertFalse(limiter.allow("198.51.100.1"), "该 IP 已打满");

        assertTrue(limiter.allow("198.51.100.2"), "另一个 IP 必须从零开始计数");
        assertTrue(limiter.allow("198.51.100.2"));
        assertFalse(limiter.allow("198.51.100.2"));
    }

    @Test
    @DisplayName("取不到 IP 时归入 unknown 桶（不是「不限流」）")
    void nullIpSharesUnknownBucket() {
        PublicAskRateLimiter limiter = new PublicAskRateLimiter(1);

        assertTrue(limiter.allow(null), "第一次（无 IP）放行");
        assertFalse(limiter.allow("   "), "空白 IP 与 null 归入同一个桶，第二次必须被拒");
    }

    @Test
    @DisplayName("配置写错（0 / 负数）时按 1 处理（fail-closed，绝不变成不限流）")
    void invalidLimitFallsBackToStrictest() {
        PublicAskRateLimiter zero = new PublicAskRateLimiter(0);
        assertEquals(1, zero.limitPerMinute(), "0 必须按 1 处理");
        assertTrue(zero.allow("1.2.3.4"));
        assertFalse(zero.allow("1.2.3.4"), "上限 1：第二次就要被拒");

        PublicAskRateLimiter negative = new PublicAskRateLimiter(-5);
        assertEquals(1, negative.limitPerMinute(), "负数必须按 1 处理");
    }

    @Test
    @DisplayName("剩余次数如实反映窗口内已用量")
    void remainingReflectsUsage() {
        PublicAskRateLimiter limiter = new PublicAskRateLimiter(3);
        assertEquals(3, limiter.remaining("1.1.1.1"), "尚未请求时剩余=上限");
        limiter.allow("1.1.1.1");
        assertEquals(2, limiter.remaining("1.1.1.1"));
        limiter.allow("1.1.1.1");
        limiter.allow("1.1.1.1");
        assertEquals(0, limiter.remaining("1.1.1.1"));
    }
}
