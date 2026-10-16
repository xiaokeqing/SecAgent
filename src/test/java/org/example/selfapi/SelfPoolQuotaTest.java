package org.example.selfapi;

import org.example.llm.ModelQuotaGate;
import org.example.service.ModelQuotaService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 自用池的<b>软上限</b>与身份分派测试。
 *
 * <h3>这条测试守的是站主的一句话</h3>
 * 「自用额度不设硬上限（或软上限如 500/日，<b>到点提醒不硬停</b>）」。
 * 这句话在代码里对应一个很容易被「顺手改掉」的实现细节：
 * {@link ModelQuotaService#tryAcquireSelfSoft()} <b>恒返回 true</b>。
 * 如果哪天有人把它改成硬停，站主会在某一天突然进不去自己的系统，
 * 而<b>不会有任何报错</b> —— 所以这里用断言把它钉住。
 *
 * <p>同时钉住「第四本账」：自用池的计数与另外三本互不挤占，
 * 且落的是<b>第四个文件</b>（光看配置值证明不了这一点）。
 */
class SelfPoolQuotaTest {

    private ModelQuotaService service;

    @TempDir
    Path tmp;

    @BeforeEach
    void setUp() {
        service = new ModelQuotaService();
        ReflectionTestUtils.setField(service, "enabled", true);
        ReflectionTestUtils.setField(service, "dailyLimit", 2);
        ReflectionTestUtils.setField(service, "storeFile", tmp.resolve("model-quota.json").toString());
        ReflectionTestUtils.setField(service, "evalDailyLimit", 2);
        ReflectionTestUtils.setField(service, "evalStoreFile", tmp.resolve("model-quota-eval.json").toString());
        ReflectionTestUtils.setField(service, "publicDailyLimit", 2);
        ReflectionTestUtils.setField(service, "publicStoreFile", tmp.resolve("model-quota-public.json").toString());
        ReflectionTestUtils.setField(service, "selfDailySoftLimit", 3);
        ReflectionTestUtils.setField(service, "selfStoreFile", tmp.resolve("model-quota-self.json").toString());
        service.init();
        SelfIdentity.end();
    }

    @AfterEach
    void tearDown() {
        SelfIdentity.end();
    }

    @Test
    @DisplayName("【核心】软上限：达到 3 次后仍返回 true，只是「已达标」标记为真")
    void softLimitNeverHardStops() {
        assertFalse(service.isSelfSoftLimitReached(), "一开始没到软上限");
        for (int i = 1; i <= 3; i++) {
            assertTrue(service.tryAcquireSelfSoft(), "第 " + i + " 次必须通过");
        }
        assertEquals(3, service.getSelfUsedToday());
        assertTrue(service.isSelfSoftLimitReached(), "第 3 次后应标记为已达软上限");

        // 关键断言：达到软上限后【继续放行】（站主口径：到点提醒不硬停）
        for (int i = 4; i <= 10; i++) {
            assertTrue(service.tryAcquireSelfSoft(), "软上限之后第 " + i + " 次仍必须放行（不硬停）");
        }
        assertEquals(10, service.getSelfUsedToday(), "超过软上限仍然继续计数（如实记账）");
        assertEquals(3, service.getSelfSoftLimit(), "软上限值本身不变");
    }

    @Test
    @DisplayName("第四本账：自用池与用户/评测/公开池互不挤占")
    void selfPoolIsIndependentFromOtherThreePools() {
        // 先把另外三个池子全部打满
        assertTrue(service.tryAcquire());
        assertTrue(service.tryAcquire());
        assertFalse(service.tryAcquire(), "用户池（2）应已耗尽");
        assertTrue(service.tryAcquireEval());
        assertTrue(service.tryAcquireEval());
        assertFalse(service.tryAcquireEval(), "评测池（2）应已耗尽");
        assertTrue(service.tryAcquirePublic());
        assertTrue(service.tryAcquirePublic());
        assertFalse(service.tryAcquirePublic(), "公开池（2）应已耗尽");

        // 自用池一个都没用过，必须照常可用
        assertEquals(0, service.getSelfUsedToday(), "自用计数不受另外三池影响");
        assertTrue(service.tryAcquireSelfSoft(), "三池全满时自用池仍然可用");
        assertEquals(1, service.getSelfUsedToday());
        assertEquals(2, service.getUsedToday(), "用户计数保持不动");
        assertEquals(2, service.getPublicUsedToday(), "公开计数保持不动");
    }

    @Test
    @DisplayName("按 Identity.SELF 分派也走软路径（模型出口的身份分派只有这一处口径）")
    void dispatchBySelfIdentityUsesSoftPath() {
        for (int i = 0; i < 6; i++) {
            assertTrue(service.tryAcquire(ModelQuotaService.Identity.SELF),
                    "SELF 身份分派必须永不拒绝（第 " + (i + 1) + " 次）");
        }
        assertEquals(6, service.getSelfUsedToday(), "SELF 分派确实记在自用账上");
        // 软上限语义下 hasRemaining 只用于展示：超过软上限后它为 false，但调用仍然放行
        assertFalse(service.hasRemaining(ModelQuotaService.Identity.SELF),
                "超过软上限时 hasRemaining 应如实为 false（它是展示值，不是放行判据）");
        assertTrue(service.tryAcquire(ModelQuotaService.Identity.SELF),
                "即便 hasRemaining 为 false，软上限下调用仍必须放行");
    }

    @Test
    @DisplayName("配额开关关闭时自用池同样放行（与另外三池口径一致）")
    void disabledQuotaStillAllowsSelf() {
        ReflectionTestUtils.setField(service, "enabled", false);
        assertTrue(service.tryAcquireSelfSoft());
    }

    // ==================== 身份分派闸门 ====================

    @Test
    @DisplayName("配额闸门：自用标注 ⇒ SELF 账本；未标注 ⇒ USER 账本")
    void gateMapsSelfIdentityToSelfPool() {
        ModelQuotaGate gate = new ModelQuotaGate(providerOf(service));

        assertSame(ModelQuotaService.Identity.USER, gate.currentIdentity(), "没标注时按普通用户池");

        SelfIdentity.markSelfRequest();
        assertSame(ModelQuotaService.Identity.SELF, gate.currentIdentity(),
                "自用标注必须映射到 SELF 池（漏了它只会静默记错账）");

        // 软上限下 checkAndAcquire 不得抛异常（抛了就等于硬停）
        for (int i = 0; i < 10; i++) {
            gate.checkAndAcquire();
        }
        assertEquals(10, service.getSelfUsedToday(), "闸门记账应落在自用池上");
        assertEquals(0, service.getUsedToday(), "不得记到普通用户池上");

        SelfIdentity.end();
        assertSame(ModelQuotaService.Identity.USER, gate.currentIdentity(), "清理后回到用户池");
        assertEquals("自用", ModelQuotaGate.label(ModelQuotaService.Identity.SELF),
                "失败提示要能一眼看出是哪本账");
    }

    @Test
    @DisplayName("自用池额度快照如实标注软上限（响应里必须能读出「只提醒不停」）")
    void quotaSnapshotDisclosesSoftLimit() {
        SelfPoolPolicy policy = new SelfPoolPolicy();
        ReflectionTestUtils.setField(policy, "quotaService", service);

        Map<String, Object> before = policy.quotaSnapshot();
        assertEquals("self", before.get("pool"));
        assertEquals(3, before.get("limit"));
        assertEquals(0, before.get("used"));
        assertEquals(Boolean.TRUE, before.get("softLimit"));
        assertEquals(Boolean.FALSE, before.get("softLimitReached"));
        assertFalse(String.valueOf(before.get("note")).contains("已用完"), "软上限不该说用完了");

        for (int i = 0; i < 3; i++) {
            service.tryAcquireSelfSoft();
        }
        Map<String, Object> after = policy.quotaSnapshot();
        assertEquals(Boolean.TRUE, after.get("softLimitReached"));
        String note = String.valueOf(after.get("note"));
        assertTrue(note.contains("仍会继续服务"), "达到软上限的文案必须明确说继续服务：" + note);
        assertTrue(note.contains("不硬停"), "文案必须点明不硬停：" + note);
    }

    @Test
    @DisplayName("自用池口径：入口 4000 字符 / 60 s / max_tokens 4000（与公开面 1200 字符 / 25 s 不同）")
    void poolLimitsMatchStationOwnerSpec() {
        SelfPoolPolicy policy = new SelfPoolPolicy();
        ReflectionTestUtils.setField(policy, "maxBodyChars", 4000);
        ReflectionTestUtils.setField(policy, "deadlineMs", 60000L);
        ReflectionTestUtils.setField(policy, "maxTokens", 4000);

        assertEquals(4000, policy.maxBodyChars());
        assertEquals(60000L, policy.deadlineMs());
        assertEquals(4000, policy.maxTokens());
        // 配置写 0 / 负数时应回落到安全默认，而不是变成无限制
        ReflectionTestUtils.setField(policy, "maxBodyChars", 0);
        ReflectionTestUtils.setField(policy, "deadlineMs", 0L);
        assertEquals(1, policy.maxBodyChars(), "0 夹到最小值，绝不等于不限");
        assertEquals(60000L, policy.deadlineMs(), "0 回落默认预算");
    }

    /** 极简 ObjectProvider：只实现闸门用得到的 {@code getIfAvailable()} */
    private static ObjectProvider<ModelQuotaService> providerOf(ModelQuotaService value) {
        return new ObjectProvider<>() {
            @Override
            public ModelQuotaService getObject() {
                return value;
            }

            @Override
            public ModelQuotaService getObject(Object... args) {
                return value;
            }

            @Override
            public ModelQuotaService getIfAvailable() {
                return value;
            }

            @Override
            public ModelQuotaService getIfUnique() {
                return value;
            }
        };
    }
}
