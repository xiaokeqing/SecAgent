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

    /**
     * 公网只读端点的 CORS 白名单拦截器。
     *
     * <p>为什么要把它和全局 CORS 分开：{@code /api/public/**} 是<b>匿名可达面</b>，
     * 它的来源白名单是一道独立的安全边界。共用 {@code app.cors.allowed-origins} 时，
     * "为了本地调试把界面来源放宽"会顺手让公网端点也接受新来源 —— 而这件事不会有任何报错。
     * 所以公网端点由它独占处理，白名单来自 {@code app.public-api.allowed-origins}，
     * 并把 Spring 自带的 CORS 处理让开（见 {@link CorsIsolationConfig}）。
     */
    @Autowired
    private org.example.publicapi.PublicCorsInterceptor publicCorsInterceptor;

    /** 允许的跨域来源，逗号分隔；默认仅本机，不再使用通配符 "*" */
    @Value("${app.cors.allowed-origins:http://localhost:9900,http://127.0.0.1:9900}")
    private String[] allowedOrigins;

    /**
     * 全局 CORS 只配"业务端点"需要的来源，<b>公网端点的来源白名单不放在这里</b>。
     *
     * <p>为什么要分开看：{@code /api/public/**} 是匿名可达面，它的来源白名单是另一道边界。
     * 共用一份配置时，"为了本地调试放宽界面来源"会顺手放宽公网端点，而且不会报错。
     */
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
        // 公网端点的 CORS 白名单（含 OPTIONS 预检）。放在鉴权之后：
        // 这些路径本来就在白名单里，顺序不影响；但预检请求必须能到这一层拿到 204。
        registry.addInterceptor(publicCorsInterceptor)
                .addPathPatterns("/api/public/**");
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/**")
                .addResourceLocations("classpath:/static/");
    }
}
