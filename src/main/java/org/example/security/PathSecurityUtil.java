package org.example.security;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 文件上传安全工具：防御路径穿越（Path Traversal, CWE-22）。
 *
 * <p>原始实现直接用 {@code uploadDir.resolve(原始文件名)}，当文件名包含
 * {@code ../../etc/passwd}、绝对路径或 Windows 盘符时，文件会被写到上传目录之外。
 * 本工具对文件名做白名单净化，并对最终落盘路径做“规范化后必须位于根目录内”的强校验。
 */
public final class PathSecurityUtil {

    /** 单段文件名允许字符：中英文、数字、点、下划线、连字符、空格、括号 */
    private static final Pattern SAFE_NAME = Pattern.compile("^[\\u4e00-\\u9fa5A-Za-z0-9._() -]+$");

    /** Windows 保留设备名（不区分大小写） */
    private static final Set<String> WINDOWS_RESERVED = new HashSet<>(Arrays.asList(
            "nul", "con", "aux", "prn",
            "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
            "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9"));

    private static final int MAX_NAME_LENGTH = 200;

    private PathSecurityUtil() {
    }

    /**
     * 净化并返回一个安全的单段文件名（不含任何目录分隔符）。
     *
     * @param rawName        上传携带的原始文件名
     * @param allowedExts    允许的扩展名（小写、不含点，如 {"txt","md"}）
     * @return 安全文件名
     * @throws InvalidFileNameException 文件名非法、含穿越特征或扩展名不允许时抛出
     */
    public static String sanitizeFileName(String rawName, Set<String> allowedExts) {
        if (rawName == null || rawName.trim().isEmpty()) {
            throw new InvalidFileNameException("文件名不能为空");
        }

        // 1. 拒绝空字节、路径分隔符、冒号等危险字符（穿越 / Windows 盘符 / ADS）
        //    合法的 multipart 文件名只应是单段文件名，不应包含 / 或 \
        if (rawName.indexOf('\0') >= 0 || rawName.indexOf('/') >= 0
                || rawName.indexOf('\\') >= 0 || rawName.indexOf(':') >= 0) {
            throw new InvalidFileNameException("文件名包含非法字符或路径");
        }

        String name = rawName;

        // 2. 显式拒绝 . 与 .. 以及含连续点的穿越特征
        if (name.equals(".") || name.equals("..") || name.contains("..")) {
            throw new InvalidFileNameException("文件名包含路径穿越特征");
        }

        // 3. 拒绝以 ~ 开头的特殊引用
        if (name.startsWith("~")) {
            throw new InvalidFileNameException("文件名非法");
        }

        // 4. 白名单字符校验（也会拦截 % 等编码符号，避免 %2e%2e、%2f 绕过）
        if (!SAFE_NAME.matcher(name).matches()) {
            throw new InvalidFileNameException("文件名包含不允许的字符");
        }

        // 5. 长度限制
        if (name.length() > MAX_NAME_LENGTH) {
            throw new InvalidFileNameException("文件名过长");
        }

        // 6. Windows 保留名
        String base = name;
        int dot = name.indexOf('.');
        if (dot > 0) {
            base = name.substring(0, dot);
        }
        if (WINDOWS_RESERVED.contains(base.toLowerCase())) {
            throw new InvalidFileNameException("文件名命中系统保留名");
        }

        // 7. 扩展名白名单（取最后一个点之后的扩展名，纯小写比较）
        String ext = "";
        int lastDot = name.lastIndexOf('.');
        if (lastDot >= 0 && lastDot < name.length() - 1) {
            ext = name.substring(lastDot + 1).toLowerCase();
        }
        if (allowedExts == null || !allowedExts.contains(ext)) {
            throw new InvalidFileNameException("不支持的文件类型");
        }

        return name;
    }

    /**
     * 把安全文件名解析到根目录下，并做最终的“目录逃逸”校验。
     *
     * @param baseDir      上传根目录（已规范化）
     * @param safeFileName 已经过 {@link #sanitizeFileName} 净化的文件名
     * @return 保证位于根目录内的目标路径
     * @throws InvalidFileNameException 解析结果逃逸出根目录时抛出
     */
    public static Path resolveWithin(Path baseDir, String safeFileName) {
        Path base = baseDir.toAbsolutePath().normalize();
        Path target = base.resolve(safeFileName).normalize();
        if (!target.startsWith(base)) {
            throw new InvalidFileNameException("非法的文件路径：已拒绝目录穿越");
        }
        return target;
    }

    /** 文件名非法异常，统一由全局异常处理器转换为 400。 */
    public static class InvalidFileNameException extends RuntimeException {
        public InvalidFileNameException(String message) {
            super(message);
        }
    }
}
