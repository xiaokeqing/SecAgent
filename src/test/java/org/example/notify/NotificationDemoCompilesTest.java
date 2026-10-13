package org.example.notify;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 守住 {@code src/test/resources/demo} 里的本地验证程序<b>始终能编译</b>。
 *
 * <h3>为什么这条测试值得存在</h3>
 * 那个 demo 的用途是"让手机之外的人也能看见通知真的发出去了"（RUNBOOK §19 的验证步骤），
 * 但它<b>不在任何编译路径上</b>：放在 test/resources 里既不会被 javac 编到，
 * 也不会被 mvn test 跑到。于是它最可能的结局是：某次改了
 * {@code NotificationService} 的字段名/构造签名之后，demo 静默失效 ——
 * 而下一个照 RUNBOOK 做验证的人会以为"是我环境的问题"，
 * 而不是"文档里的命令已经过期了"。
 *
 * <p>这里用 JDK 自带的编译器 API 把它真编一遍：编译不过就是构建失败。
 */
class NotificationDemoCompilesTest {

    @Test
    @DisplayName("本地验证程序（demo）必须能编译 —— 否则 RUNBOOK §19 的验证步骤已经过期")
    void demoSourceCompiles(@TempDir Path outDir) throws Exception {
        Path src = Path.of("src/test/resources/demo/org/example/notify/NotificationDemo.java");
        assertTrue(Files.isRegularFile(src), "找不到本地验证程序（RUNBOOK §19 引用了它）：" + src.toAbsolutePath());

        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        assertNotNull(compiler, "当前 JDK 不含编译器（需要一个 JDK 而不是 JRE 才能跑这条测试）");

        ByteArrayOutputStream err = new ByteArrayOutputStream();
        List<String> args = new ArrayList<>(List.of(
                "-encoding", "UTF-8",
                "-d", outDir.toString(),
                src.toString()));
        int rc;
        try (PrintStream errStream = new PrintStream(err, true, StandardCharsets.UTF_8)) {
            rc = compiler.run(null, null, errStream, args.toArray(new String[0]));
        }
        assertEquals(0, rc, "本地验证程序编译失败（RUNBOOK §19 的命令需要同步更新）：\n" + err);
    }
}
