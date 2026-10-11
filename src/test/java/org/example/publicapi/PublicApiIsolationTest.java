package org.example.publicapi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 公网端点的<b>代码层隔离</b>测试。
 *
 * <h3>这条测试防的是什么</h3>
 * {@code /api/public/**} 是匿名可访问的。它的安全性不能只靠"我记得别注入处置 Bean"
 * —— 因为违背这条约定时<b>不会有任何报错</b>：接口照常返回 200，
 * 只是匿名访问者所在的 Spring 上下文里多了一个能封 IP、能改配置的对象。
 * 这类问题在代码评审里也容易漏，因为 diff 看起来只是加了一个 {@code @Autowired}。
 *
 * <p>所以把它变成一条会失败的测试：公网包源码里出现禁用符号，直接构建失败。
 * 这比写在文档里的约定可靠 —— 文档不会拦住任何人。
 */
class PublicApiIsolationTest {

    /** 相对模块根目录（Surefire 的工作目录就是模块根） */
    private static final String PACKAGE_DIR = "src/main/java/org/example/publicapi";

    /**
     * 禁用符号清单。
     *
     * <p>注意这里没写宽泛的 "Response" —— 因为 {@code ResponseEntity} 属于正常用法。
     * 清单要写成"只有真的接上写能力才会出现"的具体名字，否则测试会因为误报被关掉，
     * 而一条被关掉的测试等于没有。
     */
    private static final List<String> FORBIDDEN = List.of(
            "SshBlockExecutor",
            "runActiveResponse",
            "ResponseGuard",
            "ResponseController",
            "BlockRecordStore",
            "UnblockScheduler",
            "ApprovalService",
            "ActiveResponseResult",
            "/api/response");

    @Test
    @DisplayName("公网匿名端点包内不得出现任何处置/管理能力")
    void publicApiPackageStaysReadOnly() throws Exception {
        Path dir = Path.of(PACKAGE_DIR);
        assertTrue(Files.isDirectory(dir),
                "找不到公网包目录（测试工作目录应为模块根）：" + dir.toAbsolutePath());

        List<String> violations = new ArrayList<>();
        try (Stream<Path> files = Files.list(dir)) {
            List<Path> javaFiles = files.filter(f -> f.toString().endsWith(".java")).toList();
            assertTrue(!javaFiles.isEmpty(), "公网包里一个 Java 文件都没扫到，测试本身失效了");

            for (Path p : javaFiles) {
                String content = Files.readString(p);
                for (String bad : FORBIDDEN) {
                    if (content.contains(bad)) {
                        violations.add(p.getFileName() + " → " + bad);
                    }
                }
            }
        }

        assertTrue(violations.isEmpty(),
                "公网包出现了写能力/管理能力的引用，必须把它们移出该包：" + violations);
    }
}
