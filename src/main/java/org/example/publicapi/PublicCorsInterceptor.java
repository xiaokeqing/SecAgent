package org.example.publicapi;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 公网只读端点（{@code /api/public/**}）的 <b>CORS 白名单</b>。
 *
 * <h3>它修的是什么</h3>
 * 原来的写法是 {@code registry.addMapping("/**").allowedOrigins(...)}，
 * 而线上为了让博客工作台能调这些端点，配成了"回显任意 Origin"。
 * 于是<b>任何网站</b>都能从访客浏览器里读取这个安全大屏的数据 ——
 * 对外部访问者来说它等于一个开放的 JSON API（还被 Cloudflare 缓存/加速）。
 *
 * <p>现在的规则很简单：<b>只有白名单里的来源会收到 {@code Access-Control-Allow-Origin}</b>，
 * 其他来源照常拿到响应体（curl / 服务端调用不受影响），但浏览器会拦下读取。
 *
 * <h3>为什么单独一套配置，而不是复用 {@code app.cors.allowed-origins}</h3>
 * 公网端点是匿名可达面，它的来源白名单和"自用界面能不能跨域"是两件不同的事：
 * 共用一份配置时，"为了本地调试把界面来源放宽"会顺手让公网端点也接受新来源，
 * 而且不会报错。所以 {@link org.example.config.WebMvcConfig} 把
 * {@code /api/public/**} 从全局 CORS 里排除，由本拦截器独占处理。
 *
 * <h3>边界</h3>
 * 这里的判定<b>只用于浏览器同源策略</b>，不是访问控制：非白名单来源照样能拿到数据
 * （公开端点本来就是匿名可读的）。它挡的是"别的网站借访客浏览器读我们的数据并展示成自己的"。
 */
@Component
public class PublicCorsInterceptor implements HandlerInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(PublicCorsInterceptor.class);

    /**
     * 预检允许的方法。
     *
     * <p>必须带上 {@code POST}：P4 的公开问答（{@code POST /api/public/ask}）是浏览器发起的
     * 跨域 JSON 请求，会先发预检；只回 {@code GET, OPTIONS} 的话预检不通过，
     * 页面表现为"请求根本没发出去"（而 curl 测试一切正常，很容易误判成前端 bug）。
     */
    private static final String ALLOW_METHODS = "GET, POST, OPTIONS";
    private static final String ALLOW_HEADERS = "If-None-Match, Content-Type, Accept, Origin, CF-Connecting-IP, X-Forwarded-For, X-User-Token";
    private static final String EXPOSE_HEADERS =
            "ETag, Cache-Control, X-Data-Source, X-RateLimit-Limit, Retry-After, "
                    + "X-RateLimit-Remaining, X-Public-Concurrency";
    private static final String MAX_AGE = "3600";

    /**
     * 缓存别名路径的后缀（Cloudflare 默认按扩展名决定是否缓存，{@code /api/public/alerts}
     * 这种无扩展名路径**必然** {@code DYNAMIC}、每次回源；实测本 zone：{@code .js}/{@code .txt}
     * 命中默认缓存列表，{@code .json}/{@code .xml} 不命中）。
     *
     * <p>别名是<b>纯增量路由</b>：同一个控制器方法、同一份 payload、同一套口径；旧路径一字不变。
     */
    static final String CACHE_ALIAS_SUFFIX = ".js";

    /**
     * 别名路径额外放行的响应头：{@code Age}（真实年龄 = 体内 {@code cacheAgeSeconds} + 本头）。
     * {@code Access-Control-Expose-Headers} 必须显式列出，否则跨域下 JS 读不到。
     */
    private static final String ALIAS_EXPOSE_HEADERS = EXPOSE_HEADERS + ", Age";

    /** 允许的跨域来源（逗号分隔）。默认只有博客域名与本机预览端口，<b>不含通配符</b>。 */
    @Value("${app.public-api.allowed-origins:https://xiaokeqing.cn,https://www.xiaokeqing.cn,http://localhost:1313,http://127.0.0.1:1313}")
    private String allowedOriginsConfig;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        // ① 每个公开请求开始时重置"快照时刻"记录（线程池复用，必须清）
        PublicSnapshotClock.clear();
        PublicSnapshotClock.mark(System.currentTimeMillis());

        // ② 缓存别名路径：另一套 CORS 口径（详见下方注释），与白名单口径互不干扰
        if (isCacheAlias(request)) {
            return handleCacheAlias(request, response);
        }

        String origin = request.getHeader(HttpHeaders.ORIGIN);
        boolean allowed = isAllowed(origin);

        if (allowed) {
            // 精确回显白名单里的那个来源：不能让浏览器复用别的来源的判定结果
            response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin);
            // 白名单是按来源逐个判定的，必须带 Vary —— 否则边缘/CDN 会把
            // A 来源的响应（带 ACAO）直接回给 B 来源
            response.setHeader(HttpHeaders.VARY, "Origin");
        } else if (origin != null && !origin.isBlank()) {
            // 刻意不写任何 Access-Control-* 头。写 "null" 或"回显非白名单来源"都等于没设白名单。
            logger.debug("公网端点：来源不在白名单，不下发 CORS 头 origin={}", origin);
        }

        // 预检：白名单来源直接 204 结束，不进控制器（不做一次无意义的上游取数）
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            if (allowed) {
                response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, ALLOW_METHODS);
                response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS, ALLOW_HEADERS);
                response.setHeader(HttpHeaders.ACCESS_CONTROL_MAX_AGE, MAX_AGE);
                response.setStatus(HttpStatus.NO_CONTENT.value());
            } else {
                // 非白名单预检：不回 CORS 头，浏览器判定失败（403 语义由"缺少 ACAO"表达）
                response.setStatus(HttpStatus.FORBIDDEN.value());
            }
            return false;
        }

        if (allowed) {
            response.setHeader(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, EXPOSE_HEADERS);
        }
        return true;
    }

    /** 本请求是否走缓存别名路径（URI 以 {@link #CACHE_ALIAS_SUFFIX} 结尾） */
    static boolean isCacheAlias(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri != null && uri.endsWith(CACHE_ALIAS_SUFFIX);
    }

    /**
     * 缓存别名路径的 CORS 处置 —— <b>为什么不回显来源、也不下 {@code Vary: Origin}</b>：
     *
     * <ol>
     *   <li><b>为什么可以用 {@code *}</b>：实测（2026-10-16）同一端点在
     *       {@code https://xiaokeqing.cn} / {@code https://www.xiaokeqing.cn} /
     *       {@code https://example.com} / 无 Origin 四种情形下，响应体<b>逐字节一致</b>
     *       （把秒级 {@code generatedAt} 这类时间字段剔除后比对）—— 载荷里没有任何随来源变化的东西，
     *       所以"给所有人同一个响应"不会串味。</li>
     *   <li><b>为什么必须去掉 {@code Vary: Origin}</b>：带 `Vary` 的响应在边缘缓存上的命中率会打折
     *       （而这个端点的全部意义就是让 Cloudflare 能缓存它 —— 实测本 zone 的 {@code /api/public/*}
     *       因无扩展名而 100% {@code DYNAMIC}）。用 {@code *} 就不需要按来源分桶。</li>
     *   <li><b>代价（写在这里，别被忘掉）</b>：白名单原本的作用是"别让别的网站借访客浏览器
     *       读我们的数据并展示成自己的"；别名路径放弃这层浏览器侧限制（数据本来也是公开只读的，
     *       服务端 {@code curl} 一直能读）。<b>旧路径仍然严格按白名单回显</b> —— 折中是有意的。</li>
     *   <li><b>安全头</b>：别名故意用 {@code .js} 扩展名换取可缓存性，因此必须显式
     *       {@code X-Content-Type-Options: nosniff}，防止"扩展名是 .js 于是被当脚本执行"
     *       的误判路径（Content-Type 仍是 {@code application/json}，见 controller 的返回类型）。</li>
     * </ol>
     */
    private boolean handleCacheAlias(HttpServletRequest request, HttpServletResponse response) {
        response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*");
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, ALIAS_EXPOSE_HEADERS);

        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, ALLOW_METHODS);
            response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS, ALLOW_HEADERS);
            response.setHeader(HttpHeaders.ACCESS_CONTROL_MAX_AGE, MAX_AGE);
            response.setStatus(HttpStatus.NO_CONTENT.value());
            return false;
        }
        return true;
    }

    /** 是否命中白名单 —— 逐字精确比较（不做前缀/子串匹配，避免 "xiaokeqing.cn.evil.com" 这类绕过） */
    public boolean isAllowed(String origin) {
        if (origin == null || origin.isBlank()) {
            return false;
        }
        return allowedOrigins().contains(origin.trim());
    }

    /** 解析配置中的白名单（去空白、丢空项） */
    public Set<String> allowedOrigins() {
        Set<String> out = new LinkedHashSet<>();
        if (allowedOriginsConfig == null) {
            return out;
        }
        for (String raw : allowedOriginsConfig.split(",")) {
            String v = raw.trim();
            if (!v.isEmpty()) {
                out.add(v);
            }
        }
        return out;
    }

    /** 供测试与文档展示 */
    public List<String> allowedOriginList() {
        return new ArrayList<>(allowedOrigins());
    }
}
