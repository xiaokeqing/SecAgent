package org.example.config;

import org.example.publicapi.PublicApiCorsProcessor;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.servlet.handler.AbstractHandlerMapping;

import jakarta.servlet.http.HttpServletRequest;

/**
 * 让公网端点（{@code /api/public/**}）的 CORS 判定<b>不走 Spring 自带的那一套</b>，
 * 改由 {@link org.example.publicapi.PublicCorsInterceptor} 按
 * {@code app.public-api.allowed-origins} 独占处理。
 *
 * <h3>为什么必须做到"让开"，而不是"再叠加一层判定"</h3>
 * Spring MVC 会给每个匹配到 CORS 配置的处理器链<b>最前面</b>插入自己的
 * {@code CorsInterceptor}（预检请求更是直接换成 {@code PreFlightHandler}）。
 * 它先于所有自写拦截器执行，所以：
 * <ul>
 *   <li>如果两套规则同时生效，浏览器看到的是两者的<b>并集</b> —— 等于最宽松的那一份在起作用，
 *       "收紧"变成纸面动作；</li>
 *   <li>更隐蔽的是：自写拦截器里看起来"没回 ACAO"，但头早就被 Spring 发出去了
 *       （配置像收敛了、行为没有）。</li>
 * </ul>
 *
 * <h3>怎么让开</h3>
 * 把处理器映射的 {@link CorsConfigurationSource} 换成一层薄包装：
 * 公网路径返回 {@code null}（Spring 就不插入自己的 CORS 拦截器，也不加任何 CORS 头），
 * 其余路径原样委托给原配置（业务端点行为完全不变）。
 * 同时装上 {@link PublicApiCorsProcessor} 作为保险：
 * 即使将来配置源被换回默认实现，公网路径也仍然不经过 {@code DefaultCorsProcessor}。
 */
@Configuration
public class CorsIsolationConfig {

    /**
     * 作用在所有 {@link AbstractHandlerMapping} 上（RequestMapping/资源/欢迎页等）。
     * 用 {@code BeanPostProcessor} 而不是 {@code WebMvcConfigurer} 的原因：
     * Spring 6.1 的 {@code WebMvcConfigurer} <b>没有</b> {@code extendHandlerMapping}
     * 之类的钩子，{@code CorsRegistration} 也没有 {@code excludePathPatterns}，
     * 因此"精确地只改 CORS"这件事只能在 Bean 初始化后做。
     */
    @Bean
    public static BeanPostProcessor publicCorsIsolationPostProcessor() {
        return new BeanPostProcessor() {
            @Override
            public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
                if (bean instanceof AbstractHandlerMapping mapping) {
                    CorsConfigurationSource original = mapping.getCorsConfigurationSource();
                    mapping.setCorsConfigurationSource(new PublicCorsIsolatingSource(original));
                    mapping.setCorsProcessor(new PublicApiCorsProcessor(original));
                }
                return bean;
            }
        };
    }

    /**
     * 配置源包装：公网路径 → {@code null}（不参与 Spring 的 CORS 处理），其余委托原配置。
     */
    static final class PublicCorsIsolatingSource implements CorsConfigurationSource {

        private final CorsConfigurationSource delegate;

        PublicCorsIsolatingSource(CorsConfigurationSource delegate) {
            this.delegate = delegate;
        }

        @Override
        public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
            if (PublicApiCorsProcessor.isPublicPath(request.getRequestURI())) {
                return null;
            }
            return delegate == null ? null : delegate.getCorsConfiguration(request);
        }
    }
}
