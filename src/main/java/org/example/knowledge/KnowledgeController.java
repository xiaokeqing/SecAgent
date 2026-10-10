package org.example.knowledge;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 知识库多类别 / 待审核 / 自动写入接口。
 *
 * <p>权限（由 RbacInterceptor 强制）：
 * <ul>
 *   <li>GET /categories、GET /search、POST /submit、GET /approved —— 登录即可；</li>
 *   <li>GET /pending、POST /approve/{id}、POST /reject/{id} —— 仅管理员。</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/kb")
public class KnowledgeController {

    private static final Logger logger = LoggerFactory.getLogger(KnowledgeController.class);

    @Autowired
    private KnowledgeCatalog catalog;

    @Autowired
    private KnowledgeSearchService searchService;

    @Autowired
    private KnowledgePendingService pendingService;

    /** 类别列表（含各类分片计数与文件清单） */
    @GetMapping("/categories")
    public ResponseEntity<Map<String, Object>> categories() {
        Map<String, Object> body = ok();
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("categories", catalog.stats());
        data.put("autoWrite", pendingService.isAutoWrite());
        body.put("data", data);
        return ResponseEntity.ok(body);
    }

    /** 知识检索：?query= &category=（category 为空或"全部"表示不筛选） */
    @GetMapping("/search")
    public ResponseEntity<Map<String, Object>> search(@RequestParam(required = false) String query,
                                                       @RequestParam(required = false) String category) {
        Map<String, Object> body = ok();
        body.put("data", searchService.search(query, category));
        return ResponseEntity.ok(body);
    }

    /** 提交知识（登录即可）：{content, category}；注入检测命中会以 400 + 原因返回 */
    @PostMapping("/submit")
    public ResponseEntity<Map<String, Object>> submit(@RequestBody SubmitRequest req,
                                                     @RequestAttribute(value = "secagent.user", required = false) String actor) {
        Map<String, Object> body = new HashMap<>();
        try {
            KbEntry e = pendingService.submit(
                    req == null ? null : req.getContent(),
                    req == null ? null : req.getCategory(),
                    KnowledgePendingService.SOURCE_MANUAL,
                    actor);
            body.put("code", 200);
            body.put("message", "已提交，等待管理员审核");
            body.put("data", e);
            return ResponseEntity.ok(body);
        } catch (IllegalArgumentException e) {
            body.put("code", 400);
            body.put("message", e.getMessage());
            return ResponseEntity.badRequest().body(body);
        }
    }

    /** 待审核列表（仅管理员） */
    @GetMapping("/pending")
    public ResponseEntity<Map<String, Object>> pending() {
        Map<String, Object> body = ok();
        body.put("data", pendingService.listPending());
        return ResponseEntity.ok(body);
    }

    /** 审核通过（仅管理员） */
    @PostMapping("/approve/{id}")
    public ResponseEntity<Map<String, Object>> approve(@PathVariable String id,
                                                      @RequestAttribute(value = "secagent.user", required = false) String actor) {
        Map<String, Object> body = new HashMap<>();
        try {
            KbEntry e = pendingService.approve(id, actor);
            body.put("code", 200);
            body.put("message", "已通过，进入已通过库（待向量化）");
            body.put("data", e);
            return ResponseEntity.ok(body);
        } catch (IllegalArgumentException e) {
            body.put("code", 400);
            body.put("message", e.getMessage());
            return ResponseEntity.badRequest().body(body);
        }
    }

    /** 审核驳回（仅管理员） */
    @PostMapping("/reject/{id}")
    public ResponseEntity<Map<String, Object>> reject(@PathVariable String id,
                                                      @RequestAttribute(value = "secagent.user", required = false) String actor) {
        Map<String, Object> body = new HashMap<>();
        try {
            pendingService.reject(id, actor);
            body.put("code", 200);
            body.put("message", "已驳回");
            return ResponseEntity.ok(body);
        } catch (IllegalArgumentException e) {
            body.put("code", 400);
            body.put("message", e.getMessage());
            return ResponseEntity.badRequest().body(body);
        }
    }

    /** 已通过列表（登录即可） */
    @GetMapping("/approved")
    public ResponseEntity<Map<String, Object>> approved() {
        Map<String, Object> body = ok();
        body.put("data", pendingService.listApproved());
        return ResponseEntity.ok(body);
    }

    private static Map<String, Object> ok() {
        Map<String, Object> body = new HashMap<>();
        body.put("code", 200);
        body.put("message", "success");
        return body;
    }

    @lombok.Data
    public static class SubmitRequest {
        private String content;
        private String category;
    }
}
