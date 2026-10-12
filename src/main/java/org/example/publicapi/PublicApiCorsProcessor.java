package org.example.publicapi;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsProcessor;
import org.springframework.web.cors.DefaultCorsProcessor;

import java.io.IOException;

/**
 * 公网只读端点（{@code /api/public/**}）的 CORS 白名单。
 *
 * <h3>它修的是什么</h3>
 * 线上为了让博客工作台能调这些端点，全局 CORS 被配成了"回显任意 Origin"。
 * 结果是<b>任何网站</b>都能借访客的浏览器读取安全大屏数据（还被 Cloudflare 缓存加速）。
 * 公开端点本身匿名可读，所以这不是访问控制问题 —— 它的问题是"别人能把我们的数据
 * 挂到自己页面上当成自己的"，以及来源不可控带来的滥用面。
 *
 * <h3>为什么做成 {@link CorsProcessor} 而不是拦截器</h3>
 * Spring MVC 给每个匹配到 CORS 配置的处理器链<b>最前面</b>插入自己的
 * {@code CorsInterceptor}/{@code PreFlightHandler}，它先于所有自写拦截器执行 ——
 * 对预检请求甚至根本不会走到自写拦截器（直接由 PreFlightHandler 应答）。
 * 所以"收紧 CORS"必须发生在<b>那个处理器环里</b>，否则会出现最糟的情况：
 * 自写拦截器看起来没回 ACAO，但 Spring 的回显头早就发出去了 —— 配置看着收敛了，行为没有。
 *
 * <h3>判定逻辑</h3>
 * <ul>
 *   <li>{@code /api/public/**} —— 返回 {@code null} 配置，Spring 这一层完全不参与，
 *       由 {@link PublicCorsInterceptor} 按 {@code app.public-api.allowed-origins} 独占判定
 *       （避免两套规则取并集，等于最宽松的那份在起作用）；</li>
 *   <li>其他路径 —— 原样交给 Spring 默认处理器与原有配置（行为不变）。</li>
 * </ul>
 */
public class PublicApiCorsProcessor implements CorsProcessor {

    /** 公网端点路径前缀 */
    static final String PUBLIC_PATH_PREFIX = "/api/public";

    private final CorsConfigurationSource delegate;
    private final CorsProcessor defaultProcessor = new DefaultCorsProcessor();

    public PublicApiCorsProcessor(CorsConfigurationSource delegate) {
        this.delegate = delegate;
    }

    @Override
    public boolean processRequest(CorsConfiguration config, HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        if (isPublicPath(request.getRequestURI())) {
            // 公网端点：Spring 不参与（不加任何 CORS 头；预检由自写拦截器应答）
            return true;
        }
        return defaultProcessor.processRequest(config, request, response);
    }

    /**
     * 该请求在这层是否已有 CORS 配置（公网端点恒为 null）。
     *
     * <p>Spring 的 {@code AbstractHandlerMapping} 先调用它取得配置，
     * 拿到 null 就不会插入自己的 CORS 拦截器 —— 这正是"把公网端点让出去"的开关。
     */
    public CorsConfiguration configurationFor(HttpServletRequest request) {
        if (isPublicPath(request.getRequestURI())) {
            return null;
        }
        return delegate == null ? null : delegate.getCorsConfiguration(request);
    }

    public static boolean isPublicPath(String uri) {
        if (uri == null) {
            return false;
        }
        // 边界判定与 ApiTokenInterceptor 的通配白名单同口径：
        // "/api/public" 本身或 "/api/public/..." 才算，"/api/publicfoo" 不算
        return PUBLIC_PATH_PREFIX.equals(uri) || uri.startsWith(PUBLIC_PATH_PREFIX + "/");
    }
}
