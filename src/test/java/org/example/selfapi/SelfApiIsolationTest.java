package org.example.selfapi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 自用面（{@code /api/user/**}）的<b>代码层隔离</b>测试。
 *
 * <h3>它和 {@code PublicApiIsolationTest} 是两条对称的锁</h3>
 * 公开面那条锁的是「公开包不得出现处置/管理能力」（公开面是匿名可达的）。
 * 本条锁的是<b>反向</b>的两件事：
 * <ol>
 *   <li><b>自用包不得依赖公开面的任何代码</b>（含只读的也一样）——
 *       两条面共用一份代码时，"改自用面"会顺手改掉公开面的行为，
 *       而这种耦合不会报错，只会让"公开面到底给了什么"变得说不清。
 *       自用面需要知识检索时，自己写 {@link SelfKbService}（可见性口径仍复用
 *       {@code knowledge.PublicKbVisibility} 那份唯一定义）。</li>
 *   <li><b>自用包不得出现处置/审批/封禁能力</b> —— 自用面比公开面权限大，
 *       但"大"不等于"能封 IP"：处置动作有它自己的端点、审批与审计链路
 *       （{@code /api/response/**}，管理员角色 + 人工审批）。自用令牌不该是一条绕过它们的捷径。</li>
 * </ol>
 *
 * <p>为什么做成测试而不是写在文档里：违背约定的 diff 看起来只是多了一行 {@code import}，
 * 评审时极易漏过，而后果是安全边界悄悄变宽。
 */
class SelfApiIsolationTest {

    /** 相对模块根目录（Surefire 的工作目录就是模块根） */
    private static final String PACKAGE_DIR = "src/main/java/org/example/selfapi";

    /** 禁止出现的包引用（任何形式） */
    private static final List<String> FORBIDDEN_PACKAGES = List.of(
            "org.example.publicapi");

    /**
     * 禁止出现的能力符号清单。
     *
     * <p>写成"只有真的接上写能力才会出现"的具体名字（与公开面那条同一纪律）：
     * 宽泛的词会误报，而一条被关掉的测试等于没有。
     */
    private static final List<String> FORBIDDEN_SYMBOLS = List.of(
            "SshBlockExecutor",
            "runActiveResponse",
            "ResponseGuard",
            "ResponseController",
            "BlockRecordStore",
            "UnblockScheduler",
            "ApprovalService",
            "ActiveResponseResult",
            "SecurityActionTools",
            "/api/response");

    @Test
    @DisplayName("【核心】自用包不得引用公开面包（两条面各改各的，谁也别顺手调谁）")
    void selfApiPackageDoesNotDependOnPublicApiPackage() throws Exception {
        List<String> violations = new ArrayList<>();
        List<Path> files = javaFiles();
        for (Path p : files) {
            String content = Files.readString(p);
            for (String bad : FORBIDDEN_PACKAGES) {
                if (content.contains(bad)) {
                    violations.add(p.getFileName() + " → " + bad);
                }
            }
        }
        assertTrue(violations.isEmpty(),
                "自用包出现了对公开面包的引用，必须复制/自建（见类注释第 1 条）：" + violations);
    }

    @Test
    @DisplayName("自用包不得出现处置/审批/封禁能力（自用令牌不是绕过审批的捷径）")
    void selfApiPackageHasNoActiveResponseCapability() throws Exception {
        List<String> violations = new ArrayList<>();
        for (Path p : javaFiles()) {
            String content = Files.readString(p);
            for (String bad : FORBIDDEN_SYMBOLS) {
                if (content.contains(bad)) {
                    violations.add(p.getFileName() + " → " + bad);
                }
            }
        }
        assertTrue(violations.isEmpty(),
                "自用包出现了处置/审批能力引用，必须走 /api/response 那条独立链路：" + violations);
    }

    @Test
    @DisplayName("自用面必须由独立拦截器鉴权，且路径判定带边界（防同前缀路径被静默放行）")
    void selfSurfaceHasItsOwnGuardedInterceptor() {
        assertTrue(SelfTokenInterceptor.isSelfPath("/api/user/status"));
        assertFalse(SelfTokenInterceptor.isSelfPath("/api/user-admin"),
                "边界判定必须挡住 /api/user 加后缀这类同前缀路径");
        assertFalse(SelfTokenInterceptor.isSelfPath("/api/public/ask"),
                "公开面不得被自用拦截器接管");
        assertTrue("X-User-Token".equals(SelfTokenInterceptor.TOKEN_HEADER),
                "请求头名是前端契约的一部分，改动必须同步站点线");
    }

    @Test
    @DisplayName("隔离测试自身有效：确实扫到了自用包里的 Java 文件")
    void testItselfIsEffective() throws Exception {
        List<Path> files = javaFiles();
        assertFalse(files.isEmpty(), "自用包里一个 Java 文件都没扫到，测试本身失效了（目录=" + PACKAGE_DIR + "）");
        assertTrue(files.size() >= 5,
                "自用面应当至少有 5 个源文件（令牌/拦截器/控制器/窗口/策略），实际 " + files.size());
    }

    private static List<Path> javaFiles() throws Exception {
        Path dir = Path.of(PACKAGE_DIR);
        assertTrue(Files.isDirectory(dir),
                "找不到自用包目录（测试工作目录应为模块根）：" + dir.toAbsolutePath());
        try (Stream<Path> files = Files.list(dir)) {
            return files.filter(f -> f.toString().endsWith(".java")).toList();
        }
    }
}
