package org.example.notify;

import org.example.config.OutboundTimeouts;
import org.example.llm.OutboundGuard;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 通知中枢的装配点。
 *
 * <p>做成显式 {@code @Bean} 而不是在 {@link NotificationService} 里 new 一个 OkHttpClient，
 * 理由和 {@code OutboundConfig} 一样：<b>让"配置写在哪"与"客户端真正用到什么"是同一个对象</b>，
 * 启动自检打印出来的才是运行期生效值。
 */
@Configuration
public class NotificationConfig {

    @Value("${app.notify.timeout-ms:10000}")
    private long notifyTimeoutMs;

    /**
     * webhook 传送器（真实 HTTP）。
     *
     * <p>{@link OutboundGuard} 用 {@link ObjectProvider} 取：单测里没有这个 Bean 也能装配，
     * 退化行为是"只有传输层超时"（由 {@code HttpWebhookTransport.guardEnabled()} 如实暴露给自检）。
     */
    @Bean
    public HttpWebhookTransport notificationTransport(ObjectProvider<OutboundTimeouts> timeoutsProvider,
                                                      ObjectProvider<OutboundGuard> guardProvider) {
        return new HttpWebhookTransport(timeoutsProvider.getIfAvailable(),
                guardProvider.getIfAvailable(), notifyTimeoutMs);
    }

    @Bean
    public NotificationService notificationService(HttpWebhookTransport transport,
                                                   NotificationAudit audit) {
        return new NotificationService(transport, audit);
    }

    /** 给领域侧用的门面（把"哪里该通知"与"怎么发"分开） */
    @Bean
    public SecurityEventNotifier securityEventNotifier(NotificationService notificationService) {
        return new SecurityEventNotifier(notificationService);
    }
}
