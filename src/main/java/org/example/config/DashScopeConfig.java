package org.example.config;

import okhttp3.OkHttpClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.OkHttp3ClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import java.time.Duration;

/**
 * DashScope API 配置
 * 用于配置超时时间等参数
 */
@Configuration
public class DashScopeConfig {

    /**
     * 建连超时（毫秒）。<b>必须短</b>：实测阻断出网（DROP，无 RST）时，
     * 卡住的是 TCP 建连（线程转储证据：`NioSocketImpl.timedFinishConnect`），
     * 而建连对线程中断无反应，长超时会让线程长时间占住。
     */
    @Value("${spring.ai.dashscope.chat.options.connect-timeout:3000}")
    private long connectTimeout;

    /** 读超时（毫秒）：等对端响应的时间，可适当长于建连 */
    @Value("${spring.ai.dashscope.chat.options.read-timeout:12000}")
    private long readTimeout;

    /** 单次调用总时长上限（毫秒）：兜住"读超时之上还有重试/重定向"的情况 */
    @Value("${spring.ai.dashscope.chat.options.call-timeout:15000}")
    private long callTimeout;

    /**
     * 旧配置项（180000ms）保留兼容，但<b>不再使用</b> —— 实测它会让断网请求挂满 3 分钟、
     * 客户端拿不到任何响应。现在改为 connect/read/call 三项分别配置。
     */
    @Value("${spring.ai.dashscope.chat.options.timeout:180000}")
    private long legacyTimeout;

    /**
     * 配置 RestClient.Builder，设置超时时间
     * Spring AI 会自动使用这个 Bean
     */
    @Bean
    public RestClient.Builder restClientBuilder() {
        // connect/read/call 分开设置：建连短、读取适中、总时长封顶
        OkHttpClient okHttpClient = new OkHttpClient.Builder()
                .connectTimeout(Duration.ofMillis(connectTimeout))
                .readTimeout(Duration.ofMillis(readTimeout))
                .writeTimeout(Duration.ofMillis(readTimeout))
                .callTimeout(Duration.ofMillis(callTimeout))
                .build();

        // 创建 RestClient.Builder 并配置 OkHttpClient
        return RestClient.builder()
                .requestFactory(new OkHttp3ClientHttpRequestFactory(okHttpClient));
    }
}
