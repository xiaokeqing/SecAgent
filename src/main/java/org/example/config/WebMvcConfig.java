package org.example.config;

import org.example.security.ApiTokenInterceptor;
import org.example.security.RateLimitInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Web MVC 配置
 * 配置静态资源、跨域（默认收敛到本机来源）和 API Token 鉴权拦截器。
 */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    @Autowired
    private ApiTokenInterceptor apiTokenInterceptor;

    @Autowired
    private RateLimitInterceptor rateLimitInterceptor;

    @Autowired
    private org.example.security.RbacInterceptor rbacInterceptor;

    /** 允许的跨域来源，逗号分隔；默认仅本机，不再使用通配符 "*" */
    @Value("${app.cors.allowed-origins:http://localhost:9900,http://127.0.0.1:9900}")
    private String[] allowedOrigins;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins(allowedOrigins)
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .maxAge(3600);
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // 先限流、后鉴权、最后做角色权限控制；静态资源不经过 /api，不拦截
        registry.addInterceptor(rateLimitInterceptor)
                .addPathPatterns("/api/**", "/milvus/**");
        registry.addInterceptor(apiTokenInterceptor)
                .addPathPatterns("/api/**", "/milvus/**");
        registry.addInterceptor(rbacInterceptor)
                .addPathPatterns("/api/**");
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/**")
                .addResourceLocations("classpath:/static/");
    }
}
