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

    /**
     * 状态锁：<b>只保护内存状态</b>（登记/标记解封/取快照）。
     *
     * <p>与 {@link AuditService} 同因同治：原来 {@code register/markUnblocked} 是
     * {@code synchronized} 且在锁内 {@code flush()}，锁被整份文件的写盘占住，
     * 并发处置的尾延迟等于一次磁盘写。现在锁内只改内存。
     */
    private final Object stateLock = new Object();

    /** 落盘锁：让"快照 + 序列化 + 原子替换"顺序执行，避免乱序写覆盖掉新记录 */
    private final java.util.concurrent.locks.ReentrantLock writeLock =
            new java.util.concurrent.locks.ReentrantLock();

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

    /** 登记一条新生效的封禁记录并持久化（锁内只改内存，落盘在锁外） */
    public BlockRecord register(String ip, int durationMinutes, String source,
                                String actor, String auditId, String mode) {
        return register(ip, durationMinutes, source, actor, auditId, mode, null, false, mode, null);
    }

    /**
     * 登记一条新生效的封禁记录（带集合式封禁的元数据）。
     *
     * <p>参数：threatClass 攻击类型档位；policyDerived 时长是否来自策略；
     * backend 实际后端（IPSET/IPTABLES/WAZUH/MOCK）；command 实际下发的命令。
     * 这些字段在旧 JSON 里不存在，Jackson 反序列化时会留空/默认，兼容历史文件。
     */
    public BlockRecord register(String ip, int durationMinutes, String source,
                                String actor, String auditId, String mode,
                                String threatClass, boolean policyDerived,
                                String backend, String command) {
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
        r.setThreatClass(threatClass);
        r.setPolicyDerived(policyDerived);
        r.setBackend(backend);
        r.setCommand(command);
        synchronized (stateLock) {
            records.add(r);
        }
        persist();
        logger.info("登记封禁记录 {}：IP={} 时长={}min 类型={} 后端={} 到期={} 来源={}",
                r.getId(), ip, durationMinutes, threatClass, backend, r.getExpiresAt(), source);
        return r;
    }

    /** 标记某条记录为已解封并持久化（锁内只改内存，落盘在锁外） */
    public void markUnblocked(String id, String unblockMode) {
        boolean changed = false;
        synchronized (stateLock) {
            for (BlockRecord r : records) {
                if (r.getId().equals(id) && !r.isUnblocked()) {
                    r.setUnblocked(true);
                    r.setUnblockedAt(LocalDateTime.now().format(FMT));
                    r.setUnblockMode(unblockMode);
                    changed = true;
                    break;
                }
            }
        }
        if (changed) {
            persist();
        }
    }

    /**
     * 按 IP 批量标记解封（回滚单个 IP 时用）。
     *
     * <p>为什么按 IP 而不是按记录 ID：同一个 IP 可能被多次封禁（扫描一次、爆破一次），
     * iptables/ipset 里最终只留一条条目。回滚时如果不把这批记录一起标掉，
     * 调度器会在下轮把"已经解封的 IP"再解封一次 —— 无害但会制造假审计。
     *
     * @return 实际被标记的记录条数
     */
    public int markUnblockedByIp(String ip, String unblockMode) {
        int changed = 0;
        String now = LocalDateTime.now().format(FMT);
        synchronized (stateLock) {
            for (BlockRecord r : records) {
                if (!r.isUnblocked() && r.getIp() != null && r.getIp().equals(ip)) {
                    r.setUnblocked(true);
                    r.setUnblockedAt(now);
                    r.setUnblockMode(unblockMode);
                    changed++;
                }
            }
        }
        if (changed > 0) {
            persist();
            logger.info("按 IP 标记解封 {} 条记录：{} 模式={}", changed, ip, unblockMode);
        }
        return changed;
    }

    /** 生效中的封禁记录（未解封），回滚全量时按 IP 去重后逐条清 */
    public List<BlockRecord> listActive() {
        List<BlockRecord> out = new ArrayList<>();
        for (BlockRecord r : records) {
            if (!r.isUnblocked()) {
                out.add(r);
            }
        }
        return out;
    }

    /** 全部封禁记录（最新在前），供前端展示 */
    public List<BlockRecord> listAll() {        List<BlockRecord> out = new ArrayList<>();
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

    /** 落盘：持落盘锁 → 状态锁内取快照（纯内存） → 锁外序列化 + 原子替换 */
    private void persist() {
        writeLock.lock();
        try {
            List<BlockRecord> snapshot;
            synchronized (stateLock) {
                snapshot = new ArrayList<>(records);
            }
            AtomicJsonFile.write(objectMapper, blocksFilePath, snapshot);
        } catch (Exception e) {
            logger.error("封禁记录写回失败：{}", e.getMessage());
        } finally {
            writeLock.unlock();
        }
    }
}
