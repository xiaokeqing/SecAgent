package org.example.eval;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 评测留痕（<b>与真实处置审计物理隔离</b>）。
 *
 * <h3>为什么不复用 {@code AuditService}</h3>
 * 评测流量必须"可追溯但不污染观测数据"。如果评测的模拟处置也写进
 * {@code data/response-audit.json}，会有两个直接后果：
 * <ol>
 *   <li>公网端点 {@code /api/public/audit} 会把它当成真实处置动作展示出去
 *       （"封禁总数"凭空上涨，而实际什么都没封）；</li>
 *   <li>真实处置审计里混入大量模拟记录，事后追溯真实封禁要人工挑拣。</li>
 * </ol>
 * 所以评测侧写自己的文件 {@code data/response-audit.eval.json}，
 * 每条带 {@code evalRunId}，可回答"这轮评测做了什么"。
 *
 * <p><b>写失败不影响评测</b>：留痕是旁路，不该让研判请求为它失败 —— 但会打 WARN，
 * 不静默吞掉（静默失败正是"看着成功、留痕全空"的事故形态）。
 */
@Service
public class EvalAuditService {

    private static final Logger logger = LoggerFactory.getLogger(EvalAuditService.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    /** 评测留痕独立文件：刻意与 response.audit-file 不同，保证不混入真实审计 */
    @Value("${app.eval.audit-file:data/response-audit.eval.json}")
    private String evalAuditFile;

    /** 内存里保留的评测留痕（供本进程内查询；文件是持久化副本） */
    private final List<Map<String, Object>> records = new java.util.concurrent.CopyOnWriteArrayList<>();

    public String filePath() {
        return evalAuditFile;
    }

    /** 追加一条评测留痕并整体落盘，返回记录本身 */
    public synchronized Map<String, Object> append(String evalRunId, String action, String target,
                                                   String detail, String mode) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("evalRunId", evalRunId);
        r.put("time", LocalDateTime.now().format(FMT));
        r.put("actor", org.example.security.EvalIdentity.USERNAME);
        r.put("action", action);
        r.put("target", target);
        r.put("mode", mode);
        r.put("simulated", true);
        r.put("detail", detail);
        records.add(r);

        try {
            Path p = Paths.get(evalAuditFile);
            Path parent = p.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.write(p, objectMapper.writeValueAsBytes(new ArrayList<>(records)),
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
        } catch (Exception e) {
            logger.warn("评测留痕写盘失败（评测结果不受影响，但该轮留痕缺失）: {}", e.getMessage());
        }
        return r;
    }

    /** 已记录的评测留痕条数（排查用） */
    public int size() {
        return records.size();
    }

    /** 该文件路径下的原始文本（排查用；读不到返回 null） */
    public String raw() {
        try {
            Path p = Paths.get(evalAuditFile);
            return Files.isReadable(p) ? new String(Files.readAllBytes(p), StandardCharsets.UTF_8) : null;
        } catch (Exception e) {
            return null;
        }
    }
}
