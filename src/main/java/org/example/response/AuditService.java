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

    /**
     * 状态锁：<b>只保护内存状态</b>（追加记录、取快照）。
     *
     * <p>以前 {@code append()} 是 {@code synchronized} 且在里面直接 {@code flush()} ——
     * 锁被"整份文件的序列化 + 写盘"占住，并发 append 的尾延迟等于一次磁盘写。
     * 现在锁内只做内存追加，序列化/落盘移到锁外（由 {@link #writeLock} 单独串行化）。
     */
    private final Object stateLock = new Object();

    /**
     * 落盘锁：让"快照 + 序列化 + 原子替换"成为单线程顺序执行。
     *
     * <p>为什么必须有它：如果多个线程各自"取快照→写文件"，两次写可能乱序落地，
     * 后完成的那次反而写了更旧的快照 → 丢记录。
     * 这里在<b>持落盘锁时取快照</b>，于是：每次写到的都是"此刻最新的完整状态"，
     * 而每次 append 都会触发一次写 —— 最后完成的那次必然包含全部记录。
     */
    private final java.util.concurrent.locks.ReentrantLock writeLock =
            new java.util.concurrent.locks.ReentrantLock();

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

    /**
     * 追加一条审计记录并持久化，返回带 id/time 的完整记录。
     *
     * <p>锁内只改内存（补 id/time + 入列表），序列化与落盘在锁外完成 ——
     * 因此并发 append 不再互相等待磁盘。
     */
    public ResponseAudit append(ResponseAudit a) {
        synchronized (stateLock) {
            if (a.getId() == null || a.getId().isEmpty()) {
                a.setId("AUD-" + UUID.randomUUID().toString().substring(0, 8));
            }
            if (a.getTime() == null || a.getTime().isEmpty()) {
                a.setTime(LocalDateTime.now().format(FMT));
            }
            records.add(a);
        }
        persist();
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

    /**
     * 落盘：持落盘锁 → 状态锁内取快照（纯内存） → 锁外序列化 + 原子替换。
     *
     * <p>同步写（不是异步队列）是刻意的：留痕的调用方（处置/审批）本来就要等一次落盘才返回，
     * 但<b>它们不再需要持有业务锁等待</b>——这才是本次重构要消除的长尾。
     */
    private void persist() {
        writeLock.lock();
        try {
            List<ResponseAudit> snapshot;
            synchronized (stateLock) {
                snapshot = new ArrayList<>(records);
            }
            AtomicJsonFile.write(objectMapper, auditFilePath, snapshot);
        } catch (Exception e) {
            logger.error("处置审计写回失败：{}", e.getMessage());
        } finally {
            writeLock.unlock();
        }
    }
}
