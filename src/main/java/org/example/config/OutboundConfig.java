package org.example.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 出站超时的装配点。
 *
 * <p>刻意做成 {@code @Bean} + 不可变值对象（而不是在客户端里散落 {@code @Value}）：
 * 这样"配置写在哪"与"客户端真正用到什么"是同一个对象，
 * 启动自检打印出来的也就一定是运行期生效值，不会出现"日志说 3s、代码其实用 10s"。
 */
@Configuration
public class OutboundConfig {

    /**
     * 三类出站链路（Wazuh 管理 API / Wazuh indexer / SSH 直连）共用的超时值。
     *
     * <p>刻意不给每个依赖单独留一套配置项：统一规范的意义就在于"不该有第二个数"。
     * 若将来确有依赖需要不同预算，也应显式写在 {@code app.outbound.*} 下面，
     * 而不是回到客户端里各自 @Value。
     */
    @Bean
    public OutboundTimeouts outboundTimeouts(
            @Value("${app.outbound.connect-timeout-ms:3000}") long connectTimeoutMs,
            @Value("${app.outbound.read-timeout-ms:12000}") long readTimeoutMs,
            @Value("${app.outbound.call-timeout-ms:15000}") long callTimeoutMs) {
        return new OutboundTimeouts(connectTimeoutMs, readTimeoutMs, callTimeoutMs);
    }
}
