package org.example.eval;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 红队回归评测接口（登录即可访问）。
 * POST /api/eval/run?model=   跑一次评测（复测=新 run）
 * GET  /api/eval/runs         历史 run 列表（摘要）
 * GET  /api/eval/runs/{id}    单个 run 详情
 * POST /api/eval/compare?a=&b= 两个 run 指标差值
 * GET  /api/eval/cases        内置用例集
 */
@RestController
@RequestMapping("/api/eval")
public class EvalController {

    @Autowired
    private RedTeamEvalService evalService;

    @PostMapping("/run")
    public Map<String, Object> run(@RequestParam(required = false) String model) {
        Map<String, Object> body = ok();
        body.put("data", evalService.run(model));
        body.put("message", "评测完成");
        return body;
    }

    @GetMapping("/runs")
    public Map<String, Object> runs() {
        Map<String, Object> body = ok();
        List<Map<String, Object>> data = evalService.listRuns();
        body.put("data", data);
        body.put("message", "success，共 " + data.size() + " 次运行");
        return body;
    }

    @GetMapping("/runs/{id}")
    public ResponseEntity<Map<String, Object>> getRun(@PathVariable String id) {
        Map<String, Object> r = evalService.getRun(id);
        if (r == null) {
            Map<String, Object> body = new HashMap<>();
            body.put("code", 404);
            body.put("message", "run 不存在: " + id);
            return ResponseEntity.status(404).body(body);
        }
        Map<String, Object> body = ok();
        body.put("data", r);
        return ResponseEntity.ok(body);
    }

    @PostMapping("/compare")
    public ResponseEntity<Map<String, Object>> compare(@RequestParam String a, @RequestParam String b) {
        Map<String, Object> result = evalService.compare(a, b);
        if (Boolean.FALSE.equals(result.get("found"))) {
            return ResponseEntity.status(404).body(result);
        }
        Map<String, Object> body = ok();
        body.put("data", result);
        return ResponseEntity.ok(body);
    }

    @GetMapping("/cases")
    public Map<String, Object> cases() {
        Map<String, Object> body = ok();
        body.put("data", evalService.listCases());
        return body;
    }

    private static Map<String, Object> ok() {
        Map<String, Object> body = new HashMap<>();
        body.put("code", 200);
        body.put("message", "success");
        return body;
    }
}
