package org.example.publicapi;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileTime;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

/**
 * 音频缓存：{@code sha256(voiceId + "\n" + text)} → {@code <cacheDir>/<hash>.mp3}。
 *
 * <h3>为什么按"内容"做键（而不是按 phraseId / 请求）</h3>
 * 同一句话用同一个音色合成出来的字节是一样的，键里带上 {@code voiceId}
 * 保证"换了音色不会命中旧音色的文件"。命中时<b>连上游都不调</b>：
 * 既省上游额度（这本就是花钱的那一步），也把最坏延迟从"上游决定"变成"读一个文件"。
 *
 * <h3>为什么按最旧淘汰，而不是拒绝写入</h3>
 * 磁盘是 2C2G 小机上最容易失控的资源。超限时若"拒绝写新缓存"，缓存会退化成
 * "第一批文件永久占位、新内容永远不缓存"；所以按修改时间淘汰最旧的，
 * 保证缓存始终覆盖<b>最近</b>用过的内容。最近写入的那一个永不被淘汰（见 {@link #evict}），
 * 否则刚算出来的音频会在同一个请求里被自己删掉。
 *
 * <h3>为什么淘汰是"每次写入时算一遍"</h3>
 * 缓存条目量级是"每天几百个文件"，一次目录列举 + 求和远比引入定时任务简单可靠
 * （本项目不喜欢在请求路径上做重活，但这里的量级是毫秒级，且发生在"要调上游"的
 * 冷路径上 —— 有缓存命中时一次 IO 都不做）。
 */
public class TtsCache {

    private static final Logger logger = LoggerFactory.getLogger(TtsCache.class);

    private static final String SUFFIX = ".mp3";

    private final Path dir;
    private final long maxBytes;

    public TtsCache(Path dir, int maxCacheMb) {
        this.dir = (dir == null ? Path.of("data/tts-cache") : dir).toAbsolutePath();
        this.maxBytes = Math.max(0, maxCacheMb) * 1024L * 1024L;
    }

    /** 缓存键：{@code sha256(voiceId + "\n" + text)} 的十六进制（小写，64 字符，可安全做文件名） */
    public static String keyOf(String voiceId, String text) {
        String material = (voiceId == null ? "" : voiceId) + "\n" + (text == null ? "" : text);
        return sha256Hex(material);
    }

    /** 命中返回字节，未命中返回 null；命中时顺带刷新 mtime（LRU 语义，淘汰时不会被误杀） */
    public byte[] get(String key) {
        Path p = pathOf(key);
        try {
            if (!Files.isReadable(p)) {
                return null;
            }
            byte[] bytes = Files.readAllBytes(p);
            try {
                Files.setLastModifiedTime(p, FileTime.fromMillis(System.currentTimeMillis()));
            } catch (IOException ignored) {
                // 刷 mtime 失败不影响"命中"这件事本身
            }
            return bytes;
        } catch (IOException | RuntimeException e) {
            // 单条缓存读坏（半截文件/权限变化）：当成未命中，让它重新去上游取，
            // 绝不把损坏的字节当音频发给前端。
            logger.warn("TTS 缓存读取失败（{}）：{} —— 按未命中处理", p, e.getMessage());
            return null;
        }
    }

    /** 写入缓存并做一次上限淘汰；写失败只告警，不影响本次响应（音频已经在内存里了） */
    public void put(String key, byte[] audio) {
        if (audio == null || audio.length == 0) {
            return;
        }
        Path target = pathOf(key);
        try {
            Files.createDirectories(dir);
            Path tmp = Files.createTempFile(dir, key, ".tmp");
            Files.write(tmp, audio);
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException | RuntimeException e) {
            logger.warn("TTS 缓存写入失败（{}）：{} —— 本次仍正常返回，仅少一条缓存", target, e.getMessage());
            return;
        }
        evict();
    }

    /** 缓存目录当前字节数（供启动自检/测试断言） */
    public long totalBytes() {
        long total = 0;
        for (Path p : listEntries()) {
            try {
                total += Files.size(p);
            } catch (IOException ignored) {
                // 刚好被删掉：不计入
            }
        }
        return total;
    }

    /** 缓存条目数（供启动自检/测试断言） */
    public int fileCount() {
        return listEntries().size();
    }

    /** 缓存目录（绝对路径） */
    public Path directory() {
        return dir;
    }

    /** 已用的上限（字节） */
    public long maxBytes() {
        return maxBytes;
    }

    private Path pathOf(String key) {
        return dir.resolve(key + SUFFIX);
    }

    private List<Path> listEntries() {
        if (!Files.isDirectory(dir)) {
            return List.of();
        }
        List<Path> out = new ArrayList<>();
        try (Stream<Path> files = Files.list(dir)) {
            files.filter(p -> p.getFileName().toString().endsWith(SUFFIX)).forEach(out::add);
        } catch (IOException e) {
            logger.warn("TTS 缓存目录列举失败（{}）：{}", dir, e.getMessage());
            return List.of();
        }
        return out;
    }

    /** 按修改时间从旧到新淘汰，直到总量落在上限内；至少保留一个文件（刚写进去的那个） */
    private void evict() {
        List<Path> entries = listEntries();
        if (entries.isEmpty()) {
            return;
        }
        entries.sort(Comparator.comparingLong(TtsCache::lastModifiedMillis)
                .thenComparing(p -> p.getFileName().toString()));

        long total = 0;
        for (Path p : entries) {
            try {
                total += Files.size(p);
            } catch (IOException ignored) {
                // 不计入
            }
        }
        if (total <= maxBytes) {
            return;
        }
        int index = 0;
        while (total > maxBytes && entries.size() - index > 1) {
            Path victim = entries.get(index++);
            try {
                long size = Files.size(victim);
                Files.deleteIfExists(victim);
                total -= size;
                logger.info("TTS 缓存超限（上限 {} MB），淘汰最旧的一条：{}", maxBytes / 1024 / 1024,
                        victim.getFileName());
            } catch (IOException e) {
                logger.warn("TTS 缓存淘汰失败（{}）：{}", victim, e.getMessage());
                break;
            }
        }
    }

    private static long lastModifiedMillis(Path p) {
        try {
            return Files.getLastModifiedTime(p).toMillis();
        } catch (IOException e) {
            return Long.MAX_VALUE;
        }
    }

    private static String sha256Hex(String text) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(text.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 是 JDK 必备算法，这里不可能发生；真发生了就当没缓存（fail-closed）
            throw new IllegalStateException("SHA-256 不可用：无法计算 TTS 缓存键", e);
        }
    }
}
