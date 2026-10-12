package org.example.publicapi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 公网端点 ETag / 304 测试。
 *
 * <h3>防的是什么</h3>
 * 加 ETag 的收益是"第二次请求省流量"，但改错了会变成两种事故：
 * <ol>
 *   <li><b>内容变了还回 304</b> —— 访客看到过期数据，且没有任何报错（最坏的一种，静默错误）；</li>
 *   <li><b>304 却带 body</b>，或限流被绕过（带 If-None-Match 就免费刷）。</li>
 * </ol>
 * 所以这里既断言"命中就 304 且不带实体"，也断言"内容不同必须 200 + 新 ETag"，
 * 以及"非 2xx、非 GET 不参与判定"。
 */
class PublicEtagFilterTest {

    private final PublicEtagFilter filter = new PublicEtagFilter();

    /** 把一份响应体写进缓存包装（等价于控制器写完、尚未提交的状态） */
    private static ContentCachingResponseWrapper respond(String body) throws Exception {
        MockHttpServletResponse raw = new MockHttpServletResponse();
        ContentCachingResponseWrapper wrapper = new ContentCachingResponseWrapper(raw);
        wrapper.getOutputStream().write(body.getBytes(StandardCharsets.UTF_8));
        return wrapper;
    }

    private static MockHttpServletRequest get(String ifNoneMatch) {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/public/overview");
        if (ifNoneMatch != null) {
            req.addHeader("If-None-Match", ifNoneMatch);
        }
        return req;
    }

    @Test
    @DisplayName("首次请求：带 ETag，保持 200 与完整 body")
    void firstRequestGetsEtagAndFullBody() throws Exception {
        ContentCachingResponseWrapper wrapper = respond("{\"code\":200,\"data\":{\"n\":1}}");
        filter.applyEtag(get(null), wrapper);

        String etag = wrapper.getHeader("ETag");
        assertNotNull(etag, "首访也必须拿到 ETag，否则客户端没有可用的缓存校验值");
        assertTrue(etag.startsWith("\"") && etag.endsWith("\""), "ETag 必须是带引号的实体标签：" + etag);
        assertEquals(200, wrapper.getStatus(), "未命中时状态必须保持 200");
        assertEquals("{\"code\":200,\"data\":{\"n\":1}}",
                new String(wrapper.getContentAsByteArray(), StandardCharsets.UTF_8),
                "未命中时 body 必须完好");
    }

    @Test
    @DisplayName("【核心】带相同 If-None-Match 的第二次请求 → 304 且不带实体")
    void matchingEtagYields304WithoutBody() throws Exception {
        ContentCachingResponseWrapper first = respond("{\"code\":200,\"data\":{\"n\":1}}");
        filter.applyEtag(get(null), first);
        String etag = first.getHeader("ETag");

        ContentCachingResponseWrapper second = respond("{\"code\":200,\"data\":{\"n\":1}}");
        filter.applyEtag(get(etag), second);

        assertEquals(304, second.getStatus(), "ETag 命中必须返回 304");
        assertEquals(0, second.getContentAsByteArray().length, "304 不得带响应体（RFC 9110）");
        assertEquals(etag, second.getHeader("ETag"), "304 必须带上判定用的 ETag，否则客户端无法更新缓存");
    }

    @Test
    @DisplayName("【核心】内容变了 → 必须 200 + 新 ETag（静默返回旧数据是最坏的一种错）")
    void changedBodyYieldsNewEtagAnd200() throws Exception {
        ContentCachingResponseWrapper first = respond("{\"code\":200,\"data\":{\"n\":1}}");
        filter.applyEtag(get(null), first);
        String etag1 = first.getHeader("ETag");

        ContentCachingResponseWrapper second = respond("{\"code\":200,\"data\":{\"n\":2}}");
        filter.applyEtag(get(etag1), second);

        assertEquals(200, second.getStatus(), "内容已变化，不能回 304");
        assertNotEquals(etag1, second.getHeader("ETag"), "内容变了 ETag 必须变");
        assertTrue(new String(second.getContentAsByteArray(), StandardCharsets.UTF_8).contains("\"n\":2"),
                "变化后的 body 必须完整返回");
    }

    @Test
    @DisplayName("If-None-Match 语义：* 命中；逗号分隔列表命中任意一个；不匹配则 200")
    void ifNoneMatchSemantics() throws Exception {
        String etag = PublicEtagFilter.etagOf("payload".getBytes(StandardCharsets.UTF_8));

        assertTrue(PublicEtagFilter.etagMatches("*", etag), "* 表示任意匹配");
        assertTrue(PublicEtagFilter.etagMatches(etag, etag));
        assertTrue(PublicEtagFilter.etagMatches("\"other\", " + etag, etag), "列表里命中一个即可");
        assertTrue(PublicEtagFilter.etagMatches("W/" + etag, etag), "弱校验前缀应被忽略后比较");
        assertFalse(PublicEtagFilter.etagMatches("\"other\"", etag));
        assertFalse(PublicEtagFilter.etagMatches(null, etag), "没有该头就是不命中");
        assertFalse(PublicEtagFilter.etagMatches("", etag));
        assertFalse(PublicEtagFilter.etagMatches(etag, null));
    }

    @Test
    @DisplayName("非 GET、非 2xx、no-store 都不参与 ETag 判定（不改变错误响应语义）")
    void ineligibleResponsesAreLeftAlone() throws Exception {
        // 非 GET
        MockHttpServletRequest post = new MockHttpServletRequest("POST", "/api/public/overview");
        ContentCachingResponseWrapper wrapper = respond("{}");
        filter.applyEtag(post, wrapper);
        assertNull(wrapper.getHeader("ETag"), "POST 不该有 ETag");

        // 非 2xx
        ContentCachingResponseWrapper notFound = respond("{\"code\":404}");
        notFound.setStatus(404);
        filter.applyEtag(get(null), notFound);
        assertNull(notFound.getHeader("ETag"), "404 不该有 ETag");

        // no-store
        ContentCachingResponseWrapper noStore = respond("{}");
        noStore.setHeader("Cache-Control", "no-store");
        filter.applyEtag(get(null), noStore);
        assertNull(noStore.getHeader("ETag"), "标注 no-store 的响应不该被 ETag 缓存");

        // 空 body
        ContentCachingResponseWrapper empty = respond("");
        filter.applyEtag(get(null), empty);
        assertNull(empty.getHeader("ETag"), "空体没有可校验的内容");
    }

    @Test
    @DisplayName("同一份内容两次计算得到同一个 ETag（确定性的，否则缓存永远不会命中）")
    void etagIsDeterministic() {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", "2026-10-12 10:00:00");
        data.put("count", 3);
        String a = filter.etagForPublicPayload(data);
        String b = filter.etagForPublicPayload(new LinkedHashMap<>(data));
        assertEquals(a, b, "相同内容必须得到相同 ETag");

        data.put("count", 4);
        assertNotEquals(a, filter.etagForPublicPayload(data), "内容变化必须改变 ETag");
    }
}
