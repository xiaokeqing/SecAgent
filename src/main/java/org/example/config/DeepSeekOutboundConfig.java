package org.example.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * DeepSeek 出站超时的<b>装配点</b>。
 *
 * <h3>为什么@Bean 不写在 {@link DeepSeekConfig} 里面（真实启动事故）</h3>
 * {@link DeepSeekConfig} 是一个被单测直接 {@code new} 的不可变值对象。让它自己既是
 * {@code @Configuration} 又 {@code @Bean} 产出同类型对象时，两个 Bean 定义同名同类型，
 * 实测容器启动即失败：
 * <pre>
 * BeanDefinitionStoreException: Invalid bean definition with name 'deepSeekConfig'
 * defined in org.example.config.DeepSeekConfig:
 * &#64;Bean definition illegally overridden by existing bean definition
 * </pre>
 * 这种"能编译、单测全绿、只有启动才崩"的缺陷在本项目已经发生过一次
 * （见 {@code SpringBeanConstructorTest} 的类注释：CI 绿 → 镜像上生产 → 崩溃循环），
 * 所以装配点独立成类，并用 {@code DeepSeekWiringTest} 把"能装配起来"钉成一条单测。
 *
 * <h3>为什么形状是 {@code @Bean} + 不可变值对象</h3>
 * 与 {@link OutboundConfig} → {@link OutboundTimeouts} 同一口径：配置写在哪个键、
 * 客户端真正用到什么，是<b>同一个对象</b>。启动自检打印的就是它，
 * 因此不会出现"日志说 3s、代码其实用 10s"。
 */
@Configuration
public class DeepSeekOutboundConfig {

    /**
     * DeepSeek 对话链路的三项出站超时。
     *
     * <p>默认值刻意<b>引</b> {@code app.outbound.*} 而不是各写一个常数：
     * "这个项目里出站超时只有一个口径"这件事应当在配置层就看得见。
     * 需要更短预算时用 {@code app.llm.deepseek.*} 覆盖（只许收紧，见 {@link DeepSeekConfig}）。
     */
    @Bean
    public DeepSeekConfig deepSeekConfig(
            @Value("${app.llm.deepseek.connect-timeout-ms:${app.outbound.connect-timeout-ms:3000}}") long connectTimeoutMs,
            @Value("${app.llm.deepseek.read-timeout-ms:${app.outbound.read-timeout-ms:12000}}") long readTimeoutMs,
            @Value("${app.llm.deepseek.call-timeout-ms:${app.outbound.call-timeout-ms:15000}}") long callTimeoutMs) {
        return new DeepSeekConfig(connectTimeoutMs, readTimeoutMs, callTimeoutMs);
    }
}
