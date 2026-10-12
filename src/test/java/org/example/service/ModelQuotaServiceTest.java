package org.example.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 评测独立额度的核心行为测试。
 *
 * <h3>这条测试防的是什么（真问题）</h3>
 * 改造前评测与管理员的日额度是<b>同一份</b>：跑一轮两卷约 50 次模型调用，
 * 用户额度就是 50 —— 跑完评测当天真实用户全部被"额度已用完"挡住。
 * 验收标准很具体：<b>人为把用户额度耗尽后，评测仍可跑</b>；反之亦然。
 * <p>
 * 光看配置（两个 limit 字段）证明不了这件事 —— 真正要证明的是
 * "计数走的是两个独立的计数器、写的是两个独立的文件"。
 * 所以这里直接断言计数与落盘文件，而不是断言配置值。
 */
class ModelQuotaServiceTest {

    private ModelQuotaService service;

    @TempDir
    Path tmp;

    @BeforeEach
    void setUp() {
        service = new ModelQuotaService();
        ReflectionTestUtils.setField(service, "enabled", true);
        ReflectionTestUtils.setField(service, "dailyLimit", 3);
        ReflectionTestUtils.setField(service, "storeFile", tmp.resolve("model-quota.json").toString());
        ReflectionTestUtils.setField(service, "evalDailyLimit", 5);
        ReflectionTestUtils.setField(service, "evalStoreFile", tmp.resolve("model-quota-eval.json").toString());
        service.init();
    }

    @Test
    @DisplayName("【核心】用户额度耗尽后，评测额度仍然可用（互不挤占）")
    void evalQuotaSurvivesUserQuotaExhaustion() {
        assertTrue(service.tryAcquire(), "第 1 次用户调用应通过");
        assertTrue(service.tryAcquire(), "第 2 次用户调用应通过");
        assertTrue(service.tryAcquire(), "第 3 次用户调用应通过");
        assertFalse(service.tryAcquire(), "用户额度（3）耗尽后必须拒绝");
        assertEquals(3, service.getUsedToday(), "用户计数器停在限额上");

        // 关键断言：用户额度已耗尽，评测调用必须照常成功
        assertEquals(0, service.getEvalUsedToday(), "评测计数器不受用户调用影响");
        assertTrue(service.tryAcquireEval(), "用户额度耗尽后，评测第 1 次调用必须通过");
        assertTrue(service.tryAcquireEval(), "评测第 2 次调用必须通过");
        assertEquals(2, service.getEvalUsedToday(), "只有评测计数器在增长");
        assertEquals(3, service.getUsedToday(), "用户计数器保持不动");
    }

    @Test
    @DisplayName("评测额度耗尽后同样不影响用户额度（反向隔离）")
    void userQuotaSurvivesEvalQuotaExhaustion() {
        for (int i = 0; i < 5; i++) {
            assertTrue(service.tryAcquireEval(), "评测第 " + (i + 1) + " 次应通过");
        }
        assertFalse(service.tryAcquireEval(), "评测额度（5）耗尽后必须拒绝");

        assertEquals(0, service.getUsedToday(), "用户计数器不受评测调用影响");
        assertTrue(service.tryAcquire(), "评测额度耗尽后，用户调用必须照常通过");
        assertEquals(1, service.getUsedToday());
    }

    @Test
    @DisplayName("两个计数器落在两个独立文件里（这是「分开计数」最直接的证据）")
    void countersPersistToSeparateFiles() throws Exception {
        service.tryAcquire();
        service.tryAcquireEval();
        service.tryAcquireEval();

        String userJson = Files.readString(tmp.resolve("model-quota.json"), StandardCharsets.UTF_8);
        String evalJson = Files.readString(tmp.resolve("model-quota-eval.json"), StandardCharsets.UTF_8);

        assertTrue(userJson.contains("\"used\":1"), "用户计数文件应为 used=1，实际：" + userJson);
        assertTrue(evalJson.contains("\"used\":2"), "评测计数文件应为 used=2，实际：" + evalJson);
        assertTrue(tmp.resolve("model-quota-eval.json").toFile().exists(), "评测计数文件必须真实落盘");
    }

    @Test
    @DisplayName("跨重启累计：重新载入后两份计数各自延续")
    void countersSurviveRestart() {
        service.tryAcquire();
        service.tryAcquireEval();

        ModelQuotaService restarted = new ModelQuotaService();
        ReflectionTestUtils.setField(restarted, "enabled", true);
        ReflectionTestUtils.setField(restarted, "dailyLimit", 3);
        ReflectionTestUtils.setField(restarted, "storeFile", tmp.resolve("model-quota.json").toString());
        ReflectionTestUtils.setField(restarted, "evalDailyLimit", 5);
        ReflectionTestUtils.setField(restarted, "evalStoreFile", tmp.resolve("model-quota-eval.json").toString());
        restarted.init();

        assertEquals(1, restarted.getUsedToday(), "重启后用户计数应延续");
        assertEquals(1, restarted.getEvalUsedToday(), "重启后评测计数应延续");
    }

    @Test
    @DisplayName("配额总开关关闭时两个计数器都放行（本地开发行为不变）")
    void disabledQuotaAllowsEverything() {
        ReflectionTestUtils.setField(service, "enabled", false);
        for (int i = 0; i < 10; i++) {
            assertTrue(service.tryAcquire(), "关闭配额后用户调用应放行");
            assertTrue(service.tryAcquireEval(), "关闭配额后评测调用应放行");
        }
    }
}
