package org.example.publicapi;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 公网只读端点（{@code /api/public/**}）的 <b>ETag / 304</b> 支持。
 *
 * <h3>为什么加它</h3>
 * 这些端点每次都把完整 JSON 返回一遍（含 24 小时趋势与告警列表），
 * 而内容在 {@code app.public-api.cache-seconds}（默认 15 秒）内是不变的。
 * 有了 ETag，浏览器/边缘层第二次请求只要带 {@code If-None-Match} 就能拿到
 * <b>304 + 空 body</b> —— 省的是流量与解析。
 *
 * <h3>为什么是 Filter 而不是 HandlerInterceptor</h3>
 * ETag 必须基于<b>完整的响应体字节</b>算，而"计算"要发生在"写回真实响应"之前。
 * 这需要替换 {@code HttpServletResponse} 对象，而 Spring MVC 的
 * {@code HandlerInterceptor.postHandle} 拿到的仍是原始 response
 * （{@code DispatcherServlet} 只在 preHandle 路径上认 {@code WebUtils.RESPONSE_ATTRIBUTE}），
 * 换进去的包装不会被 postHandle 看到。Servlet Filter 才是能真正换掉 response 的那一层 ——
 * 这也是 Spring 自己的 {@code ShallowEtagHeaderFilter} 的做法。
 *
 * <h3>刻意不动的东西</h3>
 * <ul>
 *   <li>{@code app.public-api.requests-per-minute}（20 次/分钟）限流照旧：<b>304 也计入</b>
 *       （限流在拦截器里、本 Filter 之前就已计数）。否则"带 If-None-Match 就能免费刷"会成为绕过口子。</li>
 *   <li>{@code cacheSeconds}（15 秒）快照 TTL 与 {@code Cache-Control: max-age} 语义照旧 ——
 *       ETag 只描述"这一份响应体是什么"，不改变它多久过期。</li>
 * </ul>
 *
 * <h3>判定范围</h3>
 * 只有 <b>GET + 2xx + 未提交 + 非 {@code no-store}</b> 的响应参与 ETag/304，其余原样放行 ——
 * 不改动错误响应与流式响应的语义。
 */
@Component
public class PublicEtagFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(PublicEtagFilter.class);

    /** 只处理这个前缀下的路径；其余路径连包装都不做（零影响） */
    static final String PUBLIC_PATH_PREFIX = "/api/public/";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (!request.getRequestURI().startsWith(PUBLIC_PATH_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        ContentCachingResponseWrapper wrapper = new ContentCachingResponseWrapper(response);
        try {
            chain.doFilter(request, wrapper);
            applyEtag(request, wrapper);
        } finally {
            // 必须显式写回：ContentCachingResponseWrapper 默认【不】把内容透传，
            // 漏掉这一步会导致公网端点全部返回空 body（而且状态码还是 200，非常隐蔽）。
            wrapper.copyBodyToResponse();
        }
    }

    /**
     * 计算 ETag 并处理条件请求。包装体已经拿到完整 body，但尚未写回真实响应。
     */
    void applyEtag(HttpServletRequest request, ContentCachingResponseWrapper wrapper) {
        if (!isEligible(request, wrapper)) {
            return;
        }
        byte[] body = wrapper.getContentAsByteArray();
        String etag = etagOf(body);
        // ETag 必须在下发响应体之前给出（304 的判定也依赖它）
        wrapper.setHeader(HttpHeaders.ETAG, etag);

        if (etagMatches(request.getHeader(HttpHeaders.IF_NONE_MATCH), etag)) {
            logger.debug("公网端点 304 命中: {} {}", request.getMethod(), request.getRequestURI());
            wrapper.setStatus(HttpStatus.NOT_MODIFIED.value());
            // 304 不带实体：清空缓冲，后面的 copyBodyToResponse 将写出空 body。
            // （不清理的话会把上一次的 2xx body 一起发出去 —— RFC 9110 明确禁止 304 带 body）
            wrapper.resetBuffer();
        }
    }

    /** 与 Spring {@code ShallowEtagHeaderFilter} 同口径的适用性判定 */
    boolean isEligible(HttpServletRequest request, ContentCachingResponseWrapper wrapper) {
        if (wrapper.isCommitted()) {
            return false;
        }
        int status = wrapper.getStatus();
        if (status < 200 || status >= 300) {
            return false;
        }
        if (!HttpMethod.GET.matches(request.getMethod())) {
            return false;
        }
        String cacheControl = wrapper.getHeader(HttpHeaders.CACHE_CONTROL);
        if (cacheControl != null && cacheControl.contains("no-store")) {
            return false;
        }
        return wrapper.getContentAsByteArray().length > 0;
    }

    /** 响应体字节 → ETag（SHA-256 前 16 字节十六进制，够避免碰撞又不太长） */
    static String etagOf(byte[] body) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(body);
            StringBuilder sb = new StringBuilder(2 + 16 * 2);
            sb.append('"');
            for (int i = 0; i < 16; i++) {
                sb.append(String.format("%02x", digest[i]));
            }
            sb.append('"');
            return sb.toString();
        } catch (Exception e) {
            // 算法缺失属于环境异常：退化成时间戳 ETag（语义仍正确，只是命中率略低）
            return "\"" + System.currentTimeMillis() + "\"";
        }
    }

    /** 供测试与文档：对任意载荷算 ETag（与线上同算法） */
    public String etagForData(Map<String, Object> body) {
        try {
            return etagOf(new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsBytes(body));
        } catch (Exception e) {
            return etagOf(String.valueOf(body).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
    }

    /** 便捷重载：直接对 {@code {"code":200,"message":..,"data":data}} 算 ETag */
    public String etagForPublicPayload(Object data) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", 200);
        body.put("message", "success");
        body.put("data", data);
        return etagForData(body);
    }

    /**
     * {@code If-None-Match} 判定。
     *
     * <p>按 HTTP 语义支持 {@code *}（任意匹配）与逗号分隔的多个 ETag；
     * 比较时忽略 {@code W/} 弱校验前缀（我们发的是强 ETag，兼容客户端的弱比较写法）。
     */
    static boolean etagMatches(String ifNoneMatch, String etag) {
        if (ifNoneMatch == null || ifNoneMatch.isBlank() || etag == null) {
            return false;
        }
        String header = ifNoneMatch.trim();
        if ("*".equals(header)) {
            return true;
        }
        for (String candidate : header.split(",")) {
            String c = candidate.trim();
            if (c.startsWith("W/")) {
                c = c.substring(2).trim();
            }
            if (c.equals(etag)) {
                return true;
            }
        }
        return false;
    }
}
