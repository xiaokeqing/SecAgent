package org.example.controller;

import org.example.publicapi.PublicAlertSource;
import org.example.publicapi.PublicIpPolicy;
import org.example.publicapi.PublicStreamService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code GET /api/public/stream} 的 HTTP 契约测试（standalone MockMvc，不启整个上下文）。
 *
 * <h3>断言什么</h3>
 * <ul>
 *   <li>200 + {@code text/event-stream}：Content-Type 错了 EventSource 直接不解析；</li>
 *   <li>{@code Cache-Control: no-cache, no-transform} 与 {@code X-Accel-Buffering: no}：
 *       这是"中间层不许缓存/不许压缩/不许攒缓冲"的三道保险，缺一条线上就可能"30 秒来一坨"；</li>
 *   <li>首帧是 {@code event: hello} 而不是 {@code {"code":...}} 信封；</li>
 *   <li>连接满时 503 + Retry-After，语义是"稍后重试"，不是 500。</li>
 * </ul>
 *
 * <p>告警帧的字段形态由 {@code PublicStreamServiceTest} 覆盖；这里只保证"HTTP 层能建连、能拿到首帧"。
 */
class PublicStreamControllerTest {

    private static final class StubSource extends PublicAlertSource {
        private final List<Map<String, Object>> items = new ArrayList<>();

        @Override
        public String mode() {
            return "REAL";
        }

        @Override
        public boolean realData() {
            return true;
        }

        @Override
        public int aggregationWindowMinutes() {
            return 5;
        }

        @Override
        public List<Map<String, Object>> aggregated() {
            return items;
        }
    }

    /** 记录最近一次建出来的 emitter，方便测试收尾（否则 MockMvc 的 async request 会一直挂着） */
    private static final class TestableService extends PublicStreamService {
        private SseEmitter last;

        private TestableService(PublicAlertSource source, Clock clock, int maxClients) {
            super(source, PublicIpPolicy.masking(), clock,
                    Executors.newSingleThreadScheduledExecutor(), 1000, 15000, 15000, maxClients);
        }

        @Override
        public SseEmitter subscribe() {
            this.last = super.subscribe();
            return this.last;
        }
    }

    private static Clock clock() {
        return Clock.fixed(Instant.parse("2026-11-07T04:00:00Z"), ZoneId.of("Asia/Shanghai"));
    }

    @Test
    @DisplayName("【核心】200 + text/event-stream + 防缓冲响应头 + 首帧 hello（不是 JSON 信封）")
    void streamSpeaksSseNotJsonEnvelope() throws Exception {
        TestableService service = new TestableService(new StubSource(), clock(), 10);
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new PublicStreamController(service)).build();

        MvcResult result = mvc.perform(get("/api/public/stream"))
                .andExpect(status().isOk())
                .andExpect(request().asyncStarted())
                .andExpect(header().string(HttpHeaders.CONTENT_TYPE, containsString("text/event-stream")))
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-cache, no-transform"))
                .andExpect(header().string("X-Accel-Buffering", "no"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andReturn();

        assertNotNull(service.last, "控制器必须真的向服务注册了一条连接");
        String body = result.getResponse().getContentAsString();
        try {
            assertTrue(body.startsWith("event: hello\ndata: "),
                    "SSE 首帧必须是 hello 事件；实际响应体：" + body);
            assertTrue(body.contains("\"mode\":\"REAL\""), "hello 要带数据源模式");
            assertTrue(body.contains("\"windowMinutes\":5"), "hello 要带聚合窗口，前端才知道时间范围");
            assertFalse(body.contains("\"code\""),
                    "SSE 不走 {code,message,data} 信封（EventSource 只按 event/data 行解析）");
        } finally {
            service.last.complete(); // 收尾，避免异步请求悬挂
        }
    }

    @Test
    @DisplayName("在线连接满时返回 503 + Retry-After:10（可重试，不是 500）")
    void fullCapacityReturns503() throws Exception {
        TestableService service = new TestableService(new StubSource(), clock(), 1);
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new PublicStreamController(service)).build();

        // 占满唯一名额
        mvc.perform(get("/api/public/stream"))
                .andExpect(status().isOk())
                .andExpect(request().asyncStarted());

        try {
            mvc.perform(get("/api/public/stream"))
                    .andExpect(status().isServiceUnavailable())
                    .andExpect(header().string(HttpHeaders.RETRY_AFTER, "10"))
                    .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"));
        } finally {
            if (service.last != null) {
                service.last.complete();
            }
        }
    }
}
