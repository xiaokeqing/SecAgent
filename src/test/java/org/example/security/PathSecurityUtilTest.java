package org.example.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 路径穿越防护工具的单元测试。
 * 覆盖正常文件名、../、绝对路径、Windows 盘符、空字节、双扩展名、保留名等绕过尝试。
 */
class PathSecurityUtilTest {

    private static final Set<String> ALLOWED = Set.of("txt", "md");

    @Test
    void shouldAcceptNormalFileNames() {
        assertEquals("notes.txt", PathSecurityUtil.sanitizeFileName("notes.txt", ALLOWED));
        assertEquals("安全文档.md", PathSecurityUtil.sanitizeFileName("安全文档.md", ALLOWED));
        assertEquals("a-b_c (1).md", PathSecurityUtil.sanitizeFileName("a-b_c (1).md", ALLOWED));
    }

    @Test
    void shouldRejectTraversalWithDotDot() {
        String[] payloads = {
                "../../../etc/passwd",
                "..\\..\\..\\Windows\\win.ini",
                "..%2f..%2fetc%2fpasswd",
                "....//....//tmp/x.txt",
                "..",
                ".."
        };
        for (String p : payloads) {
            assertThrows(PathSecurityUtil.InvalidFileNameException.class,
                    () -> PathSecurityUtil.sanitizeFileName(p, ALLOWED),
                    "应当拒绝穿越载荷: " + p);
        }
    }

    @Test
    void shouldRejectAbsolutePathAndDriveLetter() {
        assertThrows(PathSecurityUtil.InvalidFileNameException.class,
                () -> PathSecurityUtil.sanitizeFileName("/etc/passwd", ALLOWED));
        assertThrows(PathSecurityUtil.InvalidFileNameException.class,
                () -> PathSecurityUtil.sanitizeFileName("C:\\Windows\\win.ini", ALLOWED));
        // 冒号（Windows 盘符 / ADS）
        assertThrows(PathSecurityUtil.InvalidFileNameException.class,
                () -> PathSecurityUtil.sanitizeFileName("a.txt:evil", ALLOWED));
        // 空字节
        assertThrows(PathSecurityUtil.InvalidFileNameException.class,
                () -> PathSecurityUtil.sanitizeFileName("a.txt\0.jsp", ALLOWED));
    }

    @Test
    void shouldRejectDisallowedOrSpoofedExtension() {
        // 非白名单扩展名
        assertThrows(PathSecurityUtil.InvalidFileNameException.class,
                () -> PathSecurityUtil.sanitizeFileName("shell.jsp", ALLOWED));
        // 双扩展名（取最后一个点，jsp 不在白名单）
        assertThrows(PathSecurityUtil.InvalidFileNameException.class,
                () -> PathSecurityUtil.sanitizeFileName("shell.php.jpg.jsp", ALLOWED));
        // 无扩展名
        assertThrows(PathSecurityUtil.InvalidFileNameException.class,
                () -> PathSecurityUtil.sanitizeFileName("readme", ALLOWED));
    }

    @Test
    void shouldRejectWindowsReservedNames() {
        for (String name : new String[]{"NUL.txt", "con.md", "COM1.txt", "lpt9.md"}) {
            assertThrows(PathSecurityUtil.InvalidFileNameException.class,
                    () -> PathSecurityUtil.sanitizeFileName(name, ALLOWED),
                    "应拒绝 Windows 保留名: " + name);
        }
    }

    @Test
    void resolveWithinShouldKeepFileInsideBase(@TempDir Path tempDir) {
        Path target = PathSecurityUtil.resolveWithin(tempDir, "notes.md");
        assertTrue(target.normalize().startsWith(tempDir.toAbsolutePath().normalize()));
        assertEquals("notes.md", target.getFileName().toString());
    }

    @Test
    void shouldRejectEmptyAndIllegalCharacters() {
        assertThrows(PathSecurityUtil.InvalidFileNameException.class,
                () -> PathSecurityUtil.sanitizeFileName("", ALLOWED));
        assertThrows(PathSecurityUtil.InvalidFileNameException.class,
                () -> PathSecurityUtil.sanitizeFileName(null, ALLOWED));
        // 分号（IIS 解析漏洞 x.asp;.jpg）
        assertThrows(PathSecurityUtil.InvalidFileNameException.class,
                () -> PathSecurityUtil.sanitizeFileName("x.asp;.jpg", ALLOWED));
    }
}
