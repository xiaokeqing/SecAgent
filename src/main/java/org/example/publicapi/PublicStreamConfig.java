package org.example.publicapi;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;

/**
 * 实时推送（SSE）的基础设施 Bean。
 *
 * <p>为什么单独抽一个配置类，而不是在 {@link PublicStreamService} 里
 * {@code Executors.newSingleThreadScheduledExecutor()}：
 * <ul>
 *   <li>线程归 Spring 容器管理，应用关闭时能确定地 {@code shutdownNow}，不会留下悬挂的守护线程；</li>
 *   <li>单测可以注入"立即执行 / 手动驱动"的调度器，不必真的等 15 秒；</li>
 *   <li>{@link Clock} 抽出来后，测试能把时间快进到心跳点，断言"15 秒一次"而不 sleep。</li>
 * </ul>
 *
 * <p>注意：本类<b>不</b>开启 {@code @EnableScheduling} —— 项目里已有调度配置，
 * 这里只提供两个普通 Bean，避免和既有 {@code @Scheduled}（Suricata 增量摄取等）重复注册。
 */
@Configuration
public class PublicStreamConfig {

    /**
     * 单线程调度器：心跳与增量推送都是轻量操作（写 socket + 遍历几十个 emitter），
     * 1 个线程足够；多线程反而会让同一连接上的帧并发写入，顺序不可控。
     *
     * <p>用 daemon 线程：即使某次 {@code shutdownNow} 没来得及执行，
     * 也不会阻止 JVM 退出（典型的"Ctrl+C 后进程卡着不退"就是非守护线程造成的）。
     */
    @Bean(name = "publicStreamScheduler", destroyMethod = "shutdownNow")
    public ScheduledExecutorService publicStreamScheduler() {
        ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(1, runnable -> {
            Thread thread = new Thread(runnable, "public-stream-sse");
            thread.setDaemon(true);
            return thread;
        });
        // 任务被取消后立即从队列移除，避免长时间运行时队列里堆满已取消的周期任务
        executor.setRemoveOnCancelPolicy(true);
        return executor;
    }

    /**
     * 系统时区的时钟。生产上就是 {@link Clock#systemDefaultZone()}；
     * 单测注入可变时钟（{@code MutableClock}）把时间推到心跳点。
     */
    @Bean
    public Clock publicStreamClock() {
        return Clock.systemDefaultZone();
    }
}
