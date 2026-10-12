package org.example.knowledge;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 知识库「公开可见性」口径的测试（P4）。
 *
 * <h3>这条测试防的是什么</h3>
 * 公开检索是匿名可达的，而它的输入是<b>向量相似度</b> —— 也就是说
 * "哪些文档会被检索到"完全由语义决定。一旦可见性判定写松，
 * 一份内部文档会在某次提问里被语义命中，然后原样出现在公网页面上：
 * 接口 200、页面正常、没人会收到任何告警。
 *
 * <p>所以这里覆盖的不只是"白名单里的放行"，更是每一类<b>必须拒绝</b>的形状：
 * 内部路径、未标注来源、白名单之外的目录，以及"看着像但在别的目录下"的同名陷阱。
 * 口径本身（为什么用"白名单命中才放行"而不是"标记为内部才隐藏"）写在
 * {@link PublicKbVisibility} 的类注释里。
 */
class PublicKbVisibilityTest {

    private PublicKbVisibility visibility;

    @BeforeEach
    void setUp() {
        visibility = new PublicKbVisibility();
        ReflectionTestUtils.setField(visibility, "allowedRootsRaw", "security-docs,data/kb-approved");
        ReflectionTestUtils.setField(visibility, "allowedSourceTypesRaw", "community");
        ReflectionTestUtils.setField(visibility, "deniedKeywordsRaw", "internal");
        visibility.init();
    }

    // ==================== 放行 ====================

    @Test
    @DisplayName("内置安全知识（security-docs 下的绝对路径）参与公开检索")
    void allowsBuiltinSecurityDocs() {
        assertTrue(visibility.isPublic(
                "F:/7AAA/AI/SecAgent/sec-agent/security-docs/02-路径穿越漏洞原理与防御.md",
                "02-路径穿越漏洞原理与防御.md", "community"));
        assertNull(visibility.denyReason(
                "/opt/secagent/security-docs/17-SSH暴力破解与Linux应急响应.md",
                "17-SSH暴力破解与Linux应急响应.md", "community"));
    }

    @Test
    @DisplayName("人工审核通过的知识（data/kb-approved）参与公开检索")
    void allowsApprovedKnowledge() {
        assertTrue(visibility.isPublic(
                "/opt/secagent/data/kb-approved/2026-10-12-case-001.md",
                "2026-10-12-case-001.md", "community"));
    }

    @Test
    @DisplayName("来源类型大小写不敏感（配置写 Community 也要命中）")
    void sourceTypeIsCaseInsensitive() {
        assertTrue(visibility.isPublic(
                "security-docs/01-OWASP-Top10-安全概览.md", "01-OWASP-Top10-安全概览.md", "Community"));
    }

    // ==================== 拒绝 ====================

    @Test
    @DisplayName("路径命中内部关键词即拒绝（即使它躺在白名单目录里）")
    void deniesInternalKeyword() {
        String reason = visibility.denyReason(
                "security-docs/internal/04-面试必背20问.md", "04-面试必背20问.md", "community");
        assertNotNull(reason, "internal 目录下的文档必须被拒绝");
        assertTrue(reason.contains("internal"), "拒绝原因应指出命中哪个关键词：" + reason);

        assertFalse(visibility.isPublic(
                "docs/internal/修改与验证说明.md", "修改与验证说明.md", "community"),
                "docs/internal 也不得参与公开检索");
    }

    @Test
    @DisplayName("路径不在白名单根目录之下即拒绝（含「名字像但在别处」的陷阱）")
    void deniesPathsOutsideAllowedRoots() {
        // 真实事故形状：备份目录 / 别人机器上的同名目录
        assertFalse(visibility.isPublic(
                "/tmp/security-docs-backup/17-内部应急手册.md",
                "17-内部应急手册.md", "community"),
                "同名文件放在 /tmp 下不得被放行");

        assertFalse(visibility.isPublic(
                "/home/dev/notes/meeting.md", "meeting.md", "community"),
                "白名单之外的目录一律拒绝");

        assertNotNull(visibility.denyReason(
                "F:/7AAA/AI/blog/content/posts/roadmap.md", "roadmap.md", "community"));
    }

    @Test
    @DisplayName("缺少 _source_type 标注即拒绝（未标注来源的文档最需要隔离）")
    void deniesWhenSourceTypeMissing() {
        assertNotNull(visibility.denyReason(
                "security-docs/02-路径穿越漏洞原理与防御.md", "02-路径穿越漏洞原理与防御.md", null),
                "没有来源类型标注时必须拒绝（不能「没标注就默认公开」）");
        assertNotNull(visibility.denyReason(
                "security-docs/02-路径穿越漏洞原理与防御.md", "02-路径穿越漏洞原理与防御.md", "  "));
    }

    @Test
    @DisplayName("来源类型不在白名单即拒绝（例如私有/内部标注）")
    void deniesUnknownSourceType() {
        assertNotNull(visibility.denyReason(
                "security-docs/02-路径穿越漏洞原理与防御.md", "02-路径穿越漏洞原理与防御.md", "private"));
        assertNotNull(visibility.denyReason(
                "security-docs/02-路径穿越漏洞原理与防御.md", "02-路径穿越漏洞原理与防御.md", "vendor"),
                "默认白名单只有 community；vendor 要放开必须显式配置");
    }

    @Test
    @DisplayName("连来源路径都没有时拒绝（fail-closed，不猜）")
    void deniesWhenNoPathAtAll() {
        assertNotNull(visibility.denyReason(null, null, "community"));
        assertNotNull(visibility.denyReason("", "  ", "community"));
    }

    @Test
    @DisplayName("Windows 反斜杠路径与正斜杠等价（元数据来自不同机器）")
    void normalizesBackslashes() {
        assertTrue(visibility.isPublic(
                "F:\\7AAA\\AI\\SecAgent\\sec-agent\\security-docs\\05-命令注入漏洞原理与防御.md",
                "05-命令注入漏洞原理与防御.md", "community"),
                "反斜杠路径也必须能正确判断为「在白名单目录下」");
    }

    // ==================== 口径自述 ====================

    @Test
    @DisplayName("口径自述如实暴露当前生效的白名单（页面要显示，站主也要能自查）")
    void exposesEffectiveRules() {
        List<String> roots = visibility.allowedRoots();
        assertEquals(2, roots.size(), "应有两个允许根目录：" + roots);
        assertTrue(roots.contains("security-docs"));
        assertTrue(roots.contains("data/kb-approved"));
        assertEquals(List.of("community"), visibility.allowedSourceTypes());
    }

    @Test
    @DisplayName("配置写空时：允许根目录为空表示不限目录，但来源类型仍必须命中白名单")
    void emptyRootsMeansNoDirectoryRestriction() {
        PublicKbVisibility permissive = new PublicKbVisibility();
        ReflectionTestUtils.setField(permissive, "allowedRootsRaw", "");
        ReflectionTestUtils.setField(permissive, "allowedSourceTypesRaw", "community");
        ReflectionTestUtils.setField(permissive, "deniedKeywordsRaw", "internal");
        permissive.init();

        assertTrue(permissive.isPublic("/anywhere/doc.md", "doc.md", "community"),
                "根目录留空 = 不限制目录（由部署者显式选择）");
        assertNotNull(permissive.denyReason("/anywhere/doc.md", "doc.md", null),
                "但来源类型这一关依旧不能被绕过");
    }
}
