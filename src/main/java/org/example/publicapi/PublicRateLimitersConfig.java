package org.example.publicapi;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

/**
 * 公开端点的<b>限流器实例装配</b>（P4：问答 6 次/分钟、检索 20 次/分钟）。
 *
 * <h3>为什么用 {@code @Bean} 而不是给 {@link PublicAskRateLimiter} 加 {@code @Component}</h3>
 * 这个限流器要<b>两个各自独立的实例</b>（各自一份计数、各自一份上限）。
 * 加 {@code @Component} 只能得到一个单例；若在控制器里手动 {@code new}，
 * 上限就绕开了配置体系（改 yml 不生效），这正是本项目反复踩过的"配置看起来改了、实际没生效"。
 *
 * <p>所以这里显式创建两个 Bean、用 {@link Environment} 分别读取各自的配置键：
 * <pre>
 *   app.public-api.ask.requests-per-minute = 6     （会花钱：调模型）
 *   app.public-api.kb.requests-per-minute  = 20    （会花钱：调 embedding）
 * </pre>
 *
 * <h3>为什么 Bean 名称要写死</h3>
 * 控制器用 {@code @Qualifier("publicAskRateLimiter")} 精确指定，
 * 避免将来新增第三个限流器时"按类型注入"注入到错的那个 ——
 * 那种错不会报错，只会让某个端点的上限变成另一个端点的。
 */
@Configuration
public class PublicRateLimitersConfig {

    /** 公开问答限流器：默认 6 次/分钟（一次提问可能两次模型调用） */
    @Bean("publicAskRateLimiter")
    public PublicAskRateLimiter publicAskRateLimiter(Environment env) {
        return new PublicAskRateLimiter(
                env.getProperty("app.public-api.ask.requests-per-minute", Integer.class, 6));
    }

    /** 公开知识库检索限流器：默认 20 次/分钟（与既有只读端点同量级） */
    @Bean("publicKbRateLimiter")
    public PublicAskRateLimiter publicKbRateLimiter(Environment env) {
        return new PublicAskRateLimiter(
                env.getProperty("app.public-api.kb.requests-per-minute", Integer.class, 20));
    }

    /**
     * 密码自查限流器：默认 <b>30 次/分钟</b>。
     *
     * <p>为什么是 30（既不是 6 也不是 20）：它不花钱（纯内存查表），但一次响应最多带 200 条
     * 59 位 hex，带宽比其它只读端点大一截；而"检查自己的口令"又是手动、低频的动作。
     * 单独一个 Bean 是因为改上限时不该顺手动到问答（6）与只读端点（20）——
     * 这条教训已经写进本类的类注释。
     */
    @Bean("publicPasswordRateLimiter")
    public PublicAskRateLimiter publicPasswordRateLimiter(Environment env) {
        return new PublicAskRateLimiter(
                env.getProperty("app.public-api.password.requests-per-minute", Integer.class, 30));
    }

    /**
     * 每 IP 并发 1 守卫。
     *
     * <p>做成 Bean 而不是给类加 {@code @Component}：它<b>必须有状态</b>（在飞计数），
     * 由容器持有单例是最不容易被"某处 new 了一个新的、于是约束失效"的写法。
     * 这也是启动时实测踩到的：控制器注入它，但类上没标 {@code @Component}，
     * 容器直接拒绝启动（fail-closed 生效，没有静默变成"不限并发"）。
     */
    @Bean
    public PublicConcurrencyGuard publicConcurrencyGuard() {
        return new PublicConcurrencyGuard();
    }
}
