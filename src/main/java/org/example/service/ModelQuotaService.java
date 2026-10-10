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

    private final AtomicInteger counter = new AtomicInteger(0);
    private volatile LocalDate day = LocalDate.now();

    @PostConstruct
    public void init() {
        logger.info("模型配额服务: enabled={}, 每日上限={}", enabled, dailyLimit);
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
            logger.warn("当日模型调用已达上限 {}", dailyLimit);
            return false;
        }
        counter.incrementAndGet();
        return true;
    }

    public int getUsedToday() {
        return LocalDate.now().equals(day) ? counter.get() : 0;
    }
}
