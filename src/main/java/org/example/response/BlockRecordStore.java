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
 * 封禁记录存储。
 *
 * <p>线程安全地把每一条真正执行成功的封禁 IP 动作持久化到 {@code response.blocks-file}
 * （JSON 数组，默认 data/blocked-ips.json）。启动时加载已有记录，写回时整体落盘，
 * 风格与 {@link AuditService} 一致。记录带到期时间，由 {@link UnblockScheduler} 到期自动解封。
 */
@Service
public class BlockRecordStore {

    private static final Logger logger = LoggerFactory.getLogger(BlockRecordStore.class);
    static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    @Value("${response.blocks-file:data/blocked-ips.json}")
    private String blocksFilePath;

    /** 内存封禁记录，新记录在尾部 */
    private final List<BlockRecord> records = new CopyOnWriteArrayList<>();

    @PostConstruct
    public void init() {
        Path p = Paths.get(blocksFilePath);
        try {
            File f = p.toFile();
            if (f.exists() && f.length() > 0) {
                byte[] bytes = Files.readAllBytes(p);
                List<BlockRecord> loaded = objectMapper.readValue(bytes, new TypeReference<List<BlockRecord>>() {});
                records.addAll(loaded);
                long active = loaded.stream().filter(r -> !r.isUnblocked()).count();
                logger.info("封禁记录加载完成：{} 条（其中生效中 {} 条），来自 {}", loaded.size(), active, blocksFilePath);
            } else {
                logger.info("封禁记录文件不存在，将新建：{}", blocksFilePath);
            }
        } catch (Exception e) {
            logger.warn("封禁记录文件读取失败，将从空记录开始：{}", e.getMessage());
        }
    }

    /** 登记一条新生效的封禁记录并持久化 */
    public synchronized BlockRecord register(String ip, int durationMinutes, String source,
                                            String actor, String auditId, String mode) {
        BlockRecord r = new BlockRecord();
        r.setId("BLK-" + UUID.randomUUID().toString().substring(0, 8));
        r.setIp(ip);
        r.setDurationMinutes(durationMinutes);
        r.setSource(source);
        r.setActor(actor);
        r.setAuditId(auditId);
        LocalDateTime now = LocalDateTime.now();
        r.setCreatedAt(now.format(FMT));
        r.setExpiresAt(now.plusMinutes(durationMinutes).format(FMT));
        r.setUnblocked(false);
        records.add(r);
        flush();
        logger.info("登记封禁记录 {}：IP={} 时长={}min 到期={} 来源={}", r.getId(), ip, durationMinutes, r.getExpiresAt(), source);
        return r;
    }

    /** 标记某条记录为已解封并持久化 */
    public synchronized void markUnblocked(String id, String unblockMode) {
        for (BlockRecord r : records) {
            if (r.getId().equals(id) && !r.isUnblocked()) {
                r.setUnblocked(true);
                r.setUnblockedAt(LocalDateTime.now().format(FMT));
                r.setUnblockMode(unblockMode);
                flush();
                return;
            }
        }
    }

    /** 全部封禁记录（最新在前），供前端展示 */
    public List<BlockRecord> listAll() {
        List<BlockRecord> out = new ArrayList<>();
        for (int i = records.size() - 1; i >= 0; i--) {
            out.add(records.get(i));
        }
        return out;
    }

    /**
     * 找出"已到期且仍未解封"的记录。
     * 解析 expiresAt 失败的记录跳过并告警，避免脏数据卡死调度。
     */
    public List<BlockRecord> findDueForUnblock() {
        LocalDateTime now = LocalDateTime.now();
        List<BlockRecord> due = new ArrayList<>();
        for (BlockRecord r : records) {
            if (r.isUnblocked()) continue;
            try {
                LocalDateTime exp = LocalDateTime.parse(r.getExpiresAt(), FMT);
                if (!exp.isAfter(now)) {
                    due.add(r);
                }
            } catch (Exception e) {
                logger.warn("封禁记录 {} 到期时间无法解析（{}），跳过本轮解封", r.getId(), r.getExpiresAt());
            }
        }
        return due;
    }

    private void flush() {
        try {
            Path p = Paths.get(blocksFilePath);
            File parent = p.toFile().getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            Files.write(p, objectMapper.writeValueAsBytes(records));
        } catch (Exception e) {
            logger.error("封禁记录写回失败：{}", e.getMessage());
        }
    }
}
