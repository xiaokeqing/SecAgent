package org.example.event;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 历史安全事件归档接口（登录即可访问）。
 * GET /api/events            列表（可按 severity/status/keyword 筛选）
 * GET /api/events/{id}       事件详情
 * POST /api/events/archive   把当前实时告警归档为历史事件
 * PUT /api/events/{id}/status 更新处置状态
 * GET /api/events/{id}/pdf   导出单事件 PDF 报告（附件下载）
 */
@RestController
@RequestMapping("/api/events")
public class EventController {

    private static final Logger logger = LoggerFactory.getLogger(EventController.class);

    @Autowired
    private EventStore eventStore;

    @Autowired
    private EventPdfService pdfService;

    @GetMapping
    public Map<String, Object> list(@RequestParam(required = false) String severity,
                                    @RequestParam(required = false) String status,
                                    @RequestParam(required = false) String keyword) {
        Map<String, Object> body = ok();
        List<SecurityEvent> data = eventStore.list(severity, status, keyword);
        body.put("data", data);
        body.put("message", "success，共 " + data.size() + " 条");
        return body;
    }

    @GetMapping("/{id}")
    public ResponseEntity<Map<String, Object>> get(@PathVariable String id) {
        SecurityEvent e = eventStore.get(id);
        if (e == null) {
            return ResponseEntity.status(404).body(err(404, "事件不存在: " + id));
        }
        Map<String, Object> body = ok();
        body.put("data", e);
        return ResponseEntity.ok(body);
    }

    @PostMapping("/archive")
    public ResponseEntity<Map<String, Object>> archive() {
        SecurityEvent e = eventStore.archiveFromCurrent();
        Map<String, Object> body = ok();
        body.put("message", "已归档当前告警");
        body.put("data", e);
        return ResponseEntity.ok(body);
    }

    @PutMapping("/{id}/status")
    public ResponseEntity<Map<String, Object>> updateStatus(@PathVariable String id,
                                                             @RequestBody(required = false) StatusRequest req) {
        String status = req == null ? null : req.getStatus();
        String handler = req == null ? null : req.getHandler();
        SecurityEvent e = eventStore.updateStatus(id, status, handler);
        if (e == null) {
            return ResponseEntity.status(404).body(err(404, "事件不存在: " + id));
        }
        Map<String, Object> body = ok();
        body.put("message", "状态已更新");
        body.put("data", e);
        return ResponseEntity.ok(body);
    }

    @GetMapping(value = "/{id}/pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> pdf(@PathVariable String id) {
        SecurityEvent e = eventStore.get(id);
        if (e == null) {
            return ResponseEntity.notFound().build();
        }
        try {
            byte[] bytes = pdfService.buildReport(e);
            String fileName = "SecAgent安全事件报告_" + id + ".pdf";
            String encoded = URLEncoder.encode(fileName, StandardCharsets.UTF_8).replace("+", "%20");
            HttpHeaders h = new HttpHeaders();
            h.setContentType(MediaType.APPLICATION_PDF);
            h.set(HttpHeaders.CONTENT_DISPOSITION,
                    "attachment; filename*=UTF-8''" + encoded);
            h.setContentLength(bytes.length);
            return ResponseEntity.ok().headers(h).body(bytes);
        } catch (Exception ex) {
            logger.error("导出事件 PDF 失败: {}", ex.getMessage(), ex);
            return ResponseEntity.internalServerError().build();
        }
    }

    private static Map<String, Object> ok() {
        Map<String, Object> body = new HashMap<>();
        body.put("code", 200);
        body.put("message", "success");
        return body;
    }

    private static Map<String, Object> err(int code, String msg) {
        Map<String, Object> body = new HashMap<>();
        body.put("code", code);
        body.put("message", msg);
        return body;
    }

    @lombok.Data
    public static class StatusRequest {
        private String status;
        private String handler;
    }
}
