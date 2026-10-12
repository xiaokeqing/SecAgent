package org.example.response;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * 处置/封禁留痕的<b>原子落盘</b>工具。
 *
 * <h3>为什么必须是 tmp + ATOMIC_MOVE</h3>
 * 留痕文件是"整份覆盖写"（JSON 数组）。原来是直接 {@code Files.write(目标)}：
 * 写到一半进程被杀/磁盘满，目标文件就变成<b>被截断的半份 JSON</b>——
 * 下次启动解析失败、审计记录整体丢失，而调用方只看到"写回失败"一行日志。
 * 先写同目录临时文件、再原子替换，保证任何时刻读到的要么是旧版本、要么是新版本。
 *
 * <p>另外，序列化刻意<b>不放在业务锁里</b>做（见 {@link AuditService} /
 * {@link BlockRecordStore}）：那条锁要保护的只是"内存状态不许丢更新"，
 * 序列化与磁盘 I/O 放进去会让并发 append 的尾延迟变成"整份文件的写盘时间"。
 */
final class AtomicJsonFile {

    private AtomicJsonFile() {
    }

    /**
     * 把 {@code snapshot} 序列化后原子写入 {@code path}。
     *
     * <p><b>调用约定</b>：{@code snapshot} 必须是调用方在<b>状态锁内</b>取好的快照 ——
     * 这样"锁内只改内存 + 锁外落盘"仍然是顺序一致的结果，
     * 不会出现"后写的快照比先写的旧、把新记录覆盖掉"。
     */
    static void write(ObjectMapper mapper, String path, Object snapshot) throws IOException {
        Path target = Path.of(path).toAbsolutePath();
        Path dir = target.getParent();
        if (dir != null) {
            Files.createDirectories(dir);
        }
        byte[] bytes = mapper.writeValueAsBytes(snapshot);

        Path tmp = Files.createTempFile(dir, target.getFileName().toString() + ".", ".tmp");
        try {
            Files.write(tmp, bytes);
            try {
                Files.move(tmp, target,
                        StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                // 少数文件系统（部分网络盘/容器 overlay）不支持原子移动：
                // 退化为普通替换，但至少保证"先写全、再替换"
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}
