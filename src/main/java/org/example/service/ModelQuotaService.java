package org.example.service;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 模型调用配额（按自然日计数），防止接口被滥用导致成本失控（对应 OWASP LLM10 无限制消费）。
 */
@Service
public class ModelQuotaService {

    private static final Logger logger = LoggerFactory.getLogger(ModelQuotaService.class);

    @Value("${app.quota.enabled:true}")
    private boolean enabled;

    /** 每日模型调用上限（chat / chat_stream / ai_ops 各计一次） */
    @Value("${app.quota.daily-limit:200}")
    private int dailyLimit;

    /** 计数持久化位置（相对容器工作目录） */
    @Value("${app.quota.store-file:data/model-quota.json}")
    private String storeFile;

    private final AtomicInteger counter = new AtomicInteger(0);
    private volatile LocalDate day = LocalDate.now();

    @PostConstruct
    public void init() {
        load();
        logger.info("模型配额服务: enabled={}, 每日上限={}, 当日已用={}, 计数文件={}",
                enabled, dailyLimit, getUsedToday(), storeFile);
    }

    /**
     * 载入当日已用计数。
     *
     * <p><b>为什么必须持久化（实测教训）</b>：原实现把计数放在内存里（`AtomicInteger`），
     * 而"每日上限"是成本护栏 —— 结果**重启容器即归零**：配额耗尽后一次部署就能继续刷模型，
     * 上限形同虚设。现在按自然日持久化到文件，跨重启累计。
     */
    private void load() {
        day = LocalDate.now();
        try {
            java.nio.file.Path p = java.nio.file.Path.of(storeFile);
            if (!java.nio.file.Files.isReadable(p)) {
                return;
            }
            String raw = new String(java.nio.file.Files.readAllBytes(p), java.nio.charset.StandardCharsets.UTF_8);
            com.fasterxml.jackson.databind.JsonNode n =
                    new com.fasterxml.jackson.databind.ObjectMapper().readTree(raw);
            String savedDay = n.path("date").asText("");
            int used = n.path("used").asInt(0);
            if (day.toString().equals(savedDay)) {
                counter.set(Math.max(0, used));
            } else {
                counter.set(0);   // 跨日：清零并立刻落盘，避免旧日期残留
                persist();
            }
        } catch (Exception e) {
            logger.warn("配额计数载入失败（按 0 起算）: {}", e.getMessage());
            counter.set(0);
        }
    }

    private void persist() {
        try {
            java.nio.file.Path p = java.nio.file.Path.of(storeFile);
            if (p.getParent() != null) {
                java.nio.file.Files.createDirectories(p.getParent());
            }
            String json = "{\"date\":\"" + day + "\",\"used\":" + counter.get() + "}";
            java.nio.file.Files.write(p, json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (Exception e) {
            logger.warn("配额计数持久化失败（计数仍在内存中生效）: {}", e.getMessage());
        }
    }

    /** 尝试占用一次调用：true 通过，false 表示当日已超限 */
    public synchronized boolean tryAcquire() {
        if (!enabled) {
            return true;
        }
        LocalDate today = LocalDate.now();
        if (!today.equals(day)) {
            day = today;
            counter.set(0);
        }
        if (counter.get() >= dailyLimit) {
            logger.warn("当日模型调用已达上限 {}（已用 {}）", dailyLimit, counter.get());
            return false;
        }
        counter.incrementAndGet();
        persist();
        return true;
    }

    public int getUsedToday() {
        return LocalDate.now().equals(day) ? counter.get() : 0;
    }
}
