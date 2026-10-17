package org.example.testkit;

import org.example.selfapi.UserTokenAuditWriter;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * 全局扩展（见 src/test/resources/junit-platform.properties 的 autodetection）。
 *
 * <p>目的：user-token 审计是<b>异步守护线程</b>写的，而 JUnit 在一个用例结束时立刻删 @TempDir。
 * 两者撞上时 Windows 报 {@code Failed to delete temp directory}，这个偶发失败今晚已经三次
 * 把后端发版卡在 {@code mvn package}。
 *
 * <p>做法：用例前恢复写入；用例后等写线程排空、再置 halted，保证删除发生时没有在途写。
 * 生产路径完全不受影响（这两个开关只有测试调用）。
 */
public class AuditQuiesceExtension implements BeforeEachCallback, AfterEachCallback {

    @Override
    public void beforeEach(ExtensionContext context) {
        UserTokenAuditWriter.setHalted(false);
    }

    @Override
    public void afterEach(ExtensionContext context) {
        UserTokenAuditWriter.awaitIdle(2000L);
        UserTokenAuditWriter.setHalted(true);
    }
}
