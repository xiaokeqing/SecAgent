package org.example.controller;

import org.example.vector.ScoredDoc;
import org.example.vector.VectorStoreGateway;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * U5（部分收口）：{@code GET /api/health} 是<b>匿名可达</b>的端点，它返回的字段就等于
 * "任何访客都能看见"的契约。审计问题单 U5 点名了三样：构建指纹、<b>提交标题</b>、mock 开关。
 *
 * <h3>为什么只钉这两条</h3>
 * <ol>
 *   <li><b>提交标题必须消失</b>：它写的是内部 RUNBOOK 章节号、待办描述与"别再回显口令"
 *       这类修复细节 —— 等于把内部工程叙事挂到公网；</li>
 *   <li><b>四个指纹字段必须保留</b>：{@code scripts/srv1-redeploy.sh} 与
 *       {@code scripts/srv1-rollback.sh} 靠 {@code status / fingerprintMismatch /
 *       embeddedGitCommit / artifactMd5} 判定"这次部署是否成功"。把它们一起删掉，
 *       重建后的部署校验会直接失败并<b>自动回滚</b> —— 那才是真正的发布事故。</li>
 * </ol>
 * 于是"完整收口 health"必须与这些脚本（以及站点侧 {@code /api/health} 的消费端）同批改，
 * 属独立批次；本类是防止"顺手把提交标题加回来"的回归用例。
 */
class HealthControllerTest {

    /** 最小替身：health() 只用到 count() 与 backend() */
    private static final class StubVectorStore implements VectorStoreGateway {
        @Override
        public void upsert(String id, String content, List<Float> vector, Map<String, Object> metadata) {
            // 只读用例：不写
        }

        @Override
        public long deleteBySource(String source) {
            return 0;
        }

        @Override
        public List<ScoredDoc> search(List<Float> queryVector, int topK) {
            return List.of();
        }

        @Override
        public long count() {
            return 318;
        }

        @Override
        public String backend() {
            return "memory";
        }
    }

    private static Map<String, Object> healthBody() {
        HealthController c = new HealthController();
        ReflectionTestUtils.setField(c, "vectorStore", new StubVectorStore());
        ReflectionTestUtils.setField(c, "buildSha", "da9d1dbaed054ad24c2b469cd09ca8695b6192d0");
        ReflectionTestUtils.setField(c, "sourceSha", "unknown");
        ReflectionTestUtils.setField(c, "artifactMd5", "ac7e643e5ce56e5d1e19fc3f3fc3fec3");
        ReflectionTestUtils.setField(c, "buildTime", "unknown");
        return c.health();
    }

    @Test
    @DisplayName("U5：匿名健康端点不再返回提交标题（内部章节号/待办描述那一项）")
    void doesNotLeakCommitMessage() {
        Map<String, Object> h = healthBody();
        assertFalse(h.containsKey("embeddedGitCommitMessage"),
                "提交标题属于内部工程叙事，不得出现在匿名端点上：" + h);
    }

    @Test
    @DisplayName("U5 第2段：匿名端点不再返回 mock 开关与内部口径长文案（字段名的误读面）")
    void doesNotLeakMockSwitchesNorInternalNotes() {
        Map<String, Object> h = healthBody();
        // 这两个是 AI 工具层的能力开关，字段名会被读成"线上在混 mock 数据" ⇒ 已移出匿名端点。
        // 想核这两项请看容器启动日志里的 "Mock模式: …" 行（QueryMetricsTools/QueryLogsTools）。
        assertFalse(h.containsKey("alertsMockEnabled"), "mock 开关不得出现在匿名端点上：" + h.keySet());
        assertFalse(h.containsKey("logsMockEnabled"), "mock 开关不得出现在匿名端点上：" + h.keySet());
        // 内部口径长文案（解释哪个字段是硬证据）属于运行手册内容，同样不出现。
        assertFalse(h.containsKey("buildShaNote"), "构建自述长文案不得出现在匿名端点上：" + h.keySet());
        assertFalse(h.containsKey("fingerprint"), "内部指纹口径长文案不得出现在匿名端点上：" + h.keySet());
    }

    @Test
    @DisplayName("U5：部署/回滚门禁依赖的指纹字段必须保留（删了会让重建后校验失败并自动回滚）")
    void keepsDeployGateFields() {
        Map<String, Object> h = healthBody();
        assertTrue(h.containsKey("status"), "srv1-redeploy.sh 要求 status=ok：" + h.keySet());
        assertTrue(h.containsKey("fingerprintMismatch"), "门禁要求 fingerprintMismatch=false：" + h.keySet());
        assertTrue(h.containsKey("embeddedGitCommit"), "门禁要求 embeddedGitCommit==revision：" + h.keySet());
        assertTrue(h.containsKey("artifactMd5"), "门禁要求 artifactMd5==label：" + h.keySet());
        assertEquals(318L, h.get("documentVectors"), "向量条数是迁移手册的核对口径，不能顺手删：" + h);
    }
}
