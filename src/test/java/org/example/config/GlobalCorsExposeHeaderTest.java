package org.example.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 全局 CORS（业务端点 / 自用面）的<b>响应头可读性</b>契约测试。
 *
 * <h3>它防的是什么</h3>
 * 2026-10-16 站点线报了一个"一切正常但功能坏掉"的缺陷：跨域下
 * {@code Retry-After} <b>不在</b> CORS 的"安全列表响应头"之内，所以缺了
 * {@code Access-Control-Expose-Headers} 时，浏览器里
 * {@code response.headers.get('Retry-After')} <b>恒为 null</b>：
 * 请求 200/429 都正常、服务端日志正常，只有"限流提示的秒数永远显示兜底值"。
 *
 * <p>这条缺陷<b>编译期、单测、curl 全都看不出来</b>（curl 不执行同源策略），
 * 只有真浏览器才暴露。所以这里把"配置里确实配了 expose"钉成一条断言 ——
 * 至少让"有人把这行删掉"这件事在 CI 上就失败。
 *
 * <p>不用 {@code @SpringBootTest}（本仓库没有全量上下文测试，见
 * {@code DeepSeekWiringTest} 的说明），而是直接调用生产代码的
 * {@link WebMvcConfig#addCorsMappings(CorsRegistry)}，用一个能读出注册结果的
 * {@link CorsRegistry} 子类取回真实的 {@link CorsConfiguration}。
 */
class GlobalCorsExposeHeaderTest {

    /** 取出 {@code addCorsMappings} 真正注册进去的配置（{@code getCorsConfigurations} 是 protected） */
    private static final class CapturingRegistry extends CorsRegistry {
        Map<String, CorsConfiguration> captured() {
            return getCorsConfigurations();
        }
    }

    private CorsConfiguration globalCors(String... allowedOrigins) {
        WebMvcConfig config = new WebMvcConfig();
        ReflectionTestUtils.setField(config, "allowedOrigins", allowedOrigins);

        CapturingRegistry registry = new CapturingRegistry();
        config.addCorsMappings(registry);

        Map<String, CorsConfiguration> registered = registry.captured();
        assertNotNull(registered, "读不到 CORS 注册结果：Spring 内部 API 变了，本测试需同步更新");
        CorsConfiguration cors = registered.get("/**");
        assertNotNull(cors, "全局 CORS 必须注册在 /** 上（业务端点与 /api/user/** 都靠它）");
        return cors;
    }

    @Test
    @DisplayName("【核心】Retry-After 必须在 Access-Control-Expose-Headers 里（否则浏览器读不到，秒数永远显示兜底值）")
    void retryAfterIsExposedToBrowser() {
        CorsConfiguration cors = globalCors("https://xiaokeqing.cn");

        List<String> exposed = cors.getExposedHeaders();
        assertNotNull(exposed, "必须显式配 exposedHeaders：不配就不下发 Access-Control-Expose-Headers，"
                + "而 Retry-After 不在 CORS 安全列表响应头里 —— 浏览器会读到 null");
        assertTrue(exposed.stream().anyMatch(h -> "Retry-After".equalsIgnoreCase(h)),
                "Access-Control-Expose-Headers 里必须含 Retry-After，实际=" + exposed);
    }

    @Test
    @DisplayName("来源白名单不得出现通配符（放宽来源不能顺手把响应头变成全网可读）")
    void originWhitelistIsStillExplicit() {
        CorsConfiguration cors = globalCors("https://xiaokeqing.cn");

        assertEquals(List.of("https://xiaokeqing.cn"), cors.getAllowedOrigins(),
                "全局 CORS 的允许来源应逐个精确列出");
        assertFalse(cors.getAllowedOrigins().contains("*"), "本项目禁止 CORS 通配符来源");
    }

    @Test
    @DisplayName("请求头仍放行（预检必须允许 x-user-token；expose 是响应侧，不能顺手收紧请求侧）")
    void allowedHeadersStillPermitUserToken() {
        CorsConfiguration cors = globalCors("https://xiaokeqing.cn");

        List<String> allowed = cors.getAllowedHeaders();
        assertNotNull(allowed, "allowedHeaders 必须有值，否则自用面的 X-User-Token 预检会失败");
        assertTrue(allowed.contains("*") || allowed.stream().anyMatch(h -> "X-User-Token".equalsIgnoreCase(h)),
                "预检必须放行 X-User-Token，实际=" + allowed);
    }
}
