package org.example.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * 存储可写性校验的测试。
 *
 * <p>对应一次真实的线上翻车：{@code data} 目录属主是 root、容器以 uid 999 运行，
 * 导致审计写不进去，但 API 仍返回 {@code success:true}。
 * 功能"看起来正常"，实际留痕全是空的。
 *
 * <p><b>关于平台差异</b>：把目录设成只读需要 POSIX 权限位，Windows 上不支持。
 * 所以那几个用例用 {@link org.junit.jupiter.api.Assumptions#assumeTrue} 跳过，
 * 而不是让它报错 —— <b>"跑不了"和"跑失败"必须区分开</b>，
 * 否则在 Windows 上开发时会看到一片红，久而久之就没人看测试结果了。
 */
class StorageGuardTest {

    /** 能不能用 POSIX 权限位（Linux/Mac 可以，Windows 不行） */
    private static final boolean POSIX =
            FileSystems.getDefault().supportedFileAttributeViews().contains("posix");

    private static StorageGuard newGuard(String dirs, boolean enforce) {
        StorageGuard g = new StorageGuard();
        ReflectionTestUtils.setField(g, "writableDirsRaw", dirs);
        ReflectionTestUtils.setField(g, "enforceWritable", enforce);
        return g;
    }

    @Test
    @DisplayName("可写目录：正常通过")
    void writableDirPasses(@TempDir Path tmp) {
        StorageGuard g = newGuard(tmp.toString(), true);
        assertDoesNotThrow(g::verify);
    }

    @Test
    @DisplayName("目录不存在：自动创建（首次启动的情况）")
    void missingDirIsCreated(@TempDir Path tmp) {
        Path nested = tmp.resolve("data").resolve("sub");
        StorageGuard g = newGuard(nested.toString(), true);
        assertDoesNotThrow(g::verify);
        assertTrue(Files.isDirectory(nested), "应当自动创建目录");
    }

    @Test
    @DisplayName("不可写目录 + enforce=true：拒绝启动（这是本次修复的核心行为）")
    void readOnlyDirFailsClosed(@TempDir Path tmp) throws IOException {
        assumeTrue(POSIX, "需要 POSIX 权限位，Windows 上跳过");
        assumeTrue(!"root".equals(System.getProperty("user.name")), "root 不受权限位限制");

        Path ro = tmp.resolve("readonly");
        Files.createDirectories(ro);
        Files.setPosixFilePermissions(ro, PosixFilePermissions.fromString("r-xr-xr-x"));

        StorageGuard g = newGuard(ro.toString(), true);
        IllegalStateException ex = assertThrows(IllegalStateException.class, g::verify);
        assertTrue(ex.getMessage().contains("存储目录不可写"),
                "报错信息应当明确指出问题，实际: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("全部留痕"),
                "报错信息应当解释为什么这是致命的（而不是只说一句不可写）");
    }

    @Test
    @DisplayName("不可写目录 + enforce=false：只告警不阻止启动（本地开发用）")
    void readOnlyDirWarnsWhenNotEnforced(@TempDir Path tmp) throws IOException {
        assumeTrue(POSIX, "需要 POSIX 权限位，Windows 上跳过");
        assumeTrue(!"root".equals(System.getProperty("user.name")), "root 不受权限位限制");

        Path ro = tmp.resolve("readonly2");
        Files.createDirectories(ro);
        Files.setPosixFilePermissions(ro, PosixFilePermissions.fromString("r-xr-xr-x"));

        StorageGuard g = newGuard(ro.toString(), false);
        assertDoesNotThrow(g::verify, "enforce=false 时不应拒绝启动");
    }

    @Test
    @DisplayName("多个目录：只要有一个不可写就报出来（且点名是哪一个）")
    void reportsWhichDirFailed(@TempDir Path tmp) throws IOException {
        assumeTrue(POSIX, "需要 POSIX 权限位，Windows 上跳过");
        assumeTrue(!"root".equals(System.getProperty("user.name")), "root 不受权限位限制");

        Path ok = tmp.resolve("ok");
        Path bad = tmp.resolve("bad");
        Files.createDirectories(ok);
        Files.createDirectories(bad);
        Files.setPosixFilePermissions(bad, PosixFilePermissions.fromString("r-xr-xr-x"));

        StorageGuard g = newGuard(ok + "," + bad, true);
        IllegalStateException ex = assertThrows(IllegalStateException.class, g::verify);
        // 报错应当点名是哪个目录，否则排查时还得猜
        assertTrue(ex.getMessage().contains("bad"), "报错应当指出具体是哪个目录");
    }

    @Test
    @DisplayName("探针文件用完会删掉（不在数据目录留垃圾）")
    void probeFileIsCleanedUp(@TempDir Path tmp) {
        StorageGuard g = newGuard(tmp.toString(), true);
        assertDoesNotThrow(g::verify);
        assertTrue(!Files.exists(tmp.resolve(".storage-probe")),
                "探针文件应当被清理，不能留在数据目录里");
    }

    @Test
    @DisplayName("空配置不炸")
    void emptyConfigIsSafe() {
        assertDoesNotThrow(() -> newGuard("", true).verify());
        assertDoesNotThrow(() -> newGuard("  ,  ", true).verify());
    }
}
