package org.example.response;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 处置审计服务。
 * 线程安全地把每一个处置相关动作（建议/待审/批准/驳回/已执行/被护栏拦截）追加持久化到
 * {@code response.audit-file}（JSON 数组）。启动时加载已有记录，写回时整体落盘。
 */
@Service
public class AuditService {

    private static final Logger logger = LoggerFactory.getLogger(AuditService.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    @Value("${response.audit-file:data/response-audit.json}")
    private String auditFilePath;

    /** 内存审计日志，新记录在尾部 */
    private final List<ResponseAudit> records = new CopyOnWriteArrayList<>();

    @PostConstruct
    public void init() {
        Path p = Paths.get(auditFilePath);
        try {
            File f = p.toFile();
            if (f.exists() && f.length() > 0) {
                byte[] bytes = Files.readAllBytes(p);
                List<ResponseAudit> loaded = objectMapper.readValue(bytes, new TypeReference<List<ResponseAudit>>() {});
                records.addAll(loaded);
                logger.info("处置审计加载完成：{} 条记录，来自 {}", records.size(), auditFilePath);
            } else {
                logger.info("处置审计文件不存在，将新建：{}", auditFilePath);
            }
        } catch (Exception e) {
            logger.warn("处置审计文件读取失败，将从空记录开始：{}", e.getMessage());
        }
    }

    /** 追加一条审计记录并持久化，返回带 id/time 的完整记录 */
    public synchronized ResponseAudit append(ResponseAudit a) {
        if (a.getId() == null || a.getId().isEmpty()) {
            a.setId("AUD-" + UUID.randomUUID().toString().substring(0, 8));
        }
        if (a.getTime() == null || a.getTime().isEmpty()) {
            a.setTime(LocalDateTime.now().format(FMT));
        }
        records.add(a);
        flush();
        return a;
    }

    /** 按动作 / 是否成功筛选，默认按时间倒序（最新在前） */
    public List<ResponseAudit> list(String action, Boolean success) {
        List<ResponseAudit> out = new ArrayList<>();
        for (int i = records.size() - 1; i >= 0; i--) {
            ResponseAudit r = records.get(i);
            if (action != null && !action.isEmpty() && !action.equals(r.getAction())) {
                continue;
            }
            if (success != null && success != r.isSuccess()) {
                continue;
            }
            out.add(r);
        }
        return out;
    }

    private void flush() {
        try {
            Path p = Paths.get(auditFilePath);
            File parent = p.toFile().getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            Files.write(p, objectMapper.writeValueAsBytes(records));
        } catch (Exception e) {
            logger.error("处置审计写回失败：{}", e.getMessage());
        }
    }
}
