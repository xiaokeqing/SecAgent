package org.example.controller;

import org.example.publicapi.PublicStreamService;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

/**
 * 作战室实时攻击流的公开只读端点：{@code GET /api/public/stream}。
 *
 * <p>这是公网匿名可达面，和 {@code /api/public/alerts} 一样属于只读数据；
 * 区别只在于传输方式：SSE 是长连接，事件格式是 {@code event:}/{@code data:} 行，
 * <b>不走</b> {@code {code,message,data}} REST 信封 —— EventSource 只按行解析，
 * 包一层 envelope 前端就没法复用列表页的渲染函数了。
 *
 * <p>为什么新建控制器而不是塞进公开面的 god controller：
 * 那个类已经两千多行、且所有方法都是"短请求 + 一次 JSON"；SSE 的注册/断连/心跳
 * 生命周期完全不同，混在一起最容易在 {@code onCompletion} 漏清理。这里只做
 * "建连接 + 下响应头"，推送逻辑全在 {@link PublicStreamService}。
 */
@RestController
@RequestMapping("/api/public")
public class PublicStreamController {

    private final PublicStreamService streamService;

    public PublicStreamController(PublicStreamService streamService) {
        this.streamService = streamService;
    }

    /**
     * 建立一条 SSE 连接。
     *
     * <p>响应头说明：
     * <ul>
     *   <li>{@code Cache-Control: no-cache, no-transform}：禁止中间层缓存/改写（CF 的
     *       "Rocket Loader / 自动压缩"就属于改写，会把流缓冲住）；</li>
     *   <li>{@code X-Accel-Buffering: no}：nginx 的代理缓冲开关，不写这一行 nginx 会把
     *       整段响应攒够 buffer 再发，前端看到的是"每 30 秒来一大坨"而不是实时流；</li>
     *   <li>{@code X-Content-Type-Options: nosniff}：与其它公网端点一致，别让浏览器猜类型。</li>
     * </ul>
     *
     * <p>在线连接达到上限时返回 503 + {@code Retry-After}: 浏览器 EventSource 会按
     * 这个间隔自动重连，不会把已经建好的连接静默掐掉。
     */
    @GetMapping(value = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public ResponseEntity<SseEmitter> stream() {
        SseEmitter emitter = streamService.subscribe();
        if (emitter == null) {
            // 不是 500：这是"容量满了，稍后再来"，语义上可重试
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .header(HttpHeaders.RETRY_AFTER, "10")
                    .header(HttpHeaders.CACHE_CONTROL, CacheControl.noStore().getHeaderValue())
                    .contentType(MediaType.APPLICATION_JSON)
                    .build();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_EVENT_STREAM)
                // no-transform 是防 gzip/防 CF 自动压缩的关键：SSE 一旦被压缩，
                // 中间层会等压缩块攒满才 flush，实时性直接没了。
                .header(HttpHeaders.CACHE_CONTROL, "no-cache, no-transform")
                .header("X-Accel-Buffering", "no")
                .header("X-Content-Type-Options", "nosniff")
                .body(emitter);
    }
}
