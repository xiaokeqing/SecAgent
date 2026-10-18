package org.example.publicapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 攻击者口令字典的<b>只读索引</b>：只存 SHA-256 与计数，<b>绝不存明文</b>。
 *
 * <h3>为什么不是"运行时去读 Cowrie 日志"</h3>
 * 蜜罐日志在 srv2 上（{@code /opt/secagent/logs}），量级是每天几十万行——把这个读取放进
 * 请求路径既不可能（毫秒级响应）也不该做（明文口令会因此进入应用内存与日志上下文）。
 * 所以拆成两步：
 * <ol>
 *   <li><b>离线</b>：{@code scripts/password-dict-build.py} 在日志所在机器上把
 *       {@code password} 字段就地 SHA-256、按前 5 位十六进制分桶、写出本类要读的索引文件。
 *       明文只在那一次进程的内存里出现，不落盘、不进任何响应；</li>
 *   <li><b>运行时</b>：本类只加载那个<b>只含 hash 与次数</b>的索引文件（默认
 *       {@code data/password-hashes.json}，配置项 {@code app.public.password-dict-file}）。</li>
 * </ol>
 *
 * <h3>索引文件格式（本类即契约）</h3>
 * <pre>
 * {
 *   "generatedAt": "2026-10-18T09:00:00+08:00",   // 可选：字典生成时间（原样透出，供页面自证新鲜度）
 *   "totalAttempts": 128934,                       // 可选：所有桶的次数合计
 *   "unique": 41234,                               // 可选：不同 hash 的个数
 *   "buckets": {
 *     "a1b2c": {                                   // 键 = 完整 SHA-256 的**前 5 位**小写 hex
 *       "count": 37,                               // 该桶内所有口令的合计尝试次数
 *       "lastSeen": "2026-10-18T09:00:00+08:00",   // 可选：桶内最后一次被尝试的时间
 *       "hashes": ["<剩余 59 位 hex>", ...],       // 可选：桶内 hash 的<b>后 59 位</b>（蜜罐里真实出现过）
 *       "listed": ["<剩余 59 位 hex>", ...]        // 可选：只在公开弱口令榜里的（蜜罐没抓到过）
 *     }
 *   }
 * }
 * </pre>
 * 键与值都经过严格校验：前缀非 {@code ^[0-9a-f]{5}$}、后缀非 {@code ^[0-9a-f]{59}$}、
 * {@code count} 缺失/为负 —— 整份文件按"格式错"处理（{@code available:false}），
 * <b>绝不跳过坏条目继续用</b>：半份字典会让"没查到"变成假阴性，而假阴性正是这个功能最坏的失败方式。
 *
 * <h3>为什么只给 5 位前缀 + 桶内 hash 清单，而不是整桶计数</h3>
 * 只给 {@code count} 的话前端<b>没法判断</b>：那个数是"同前缀所有口令的合计"，
 * 你的口令在不在桶里它并不知道（1,048,576 个桶里撞前缀时 count 会虚高）。
 * 所以像公开的 k-匿名查询一样，把桶内 hash 的<b>后 59 位</b>发出去让前端自己比对 ——
 * 后端<b>永远拿不到</b>用户的口令与前 5 位以外的信息，也就无法记录"谁查了哪个口令"。
 * 代价是"知道前缀的人能拿到该桶的全部 suffix"，但那需要先猜到口令的 SHA-256 前缀，
 * 与直接猜口令等价；且每桶最多下发 {@value #MAX_SUFFIXES_PER_BUCKET} 条（超出 {@code truncated:true}）。
 */
@Component
public class PasswordDictionaryService {

    private static final Logger logger = LoggerFactory.getLogger(PasswordDictionaryService.class);

    /** SHA-256 的十六进制长度：前 {@value #PREFIX_HEX_CHARS} 位进桶，其余 {@value #SUFFIX_HEX_CHARS} 位用于精确比对 */
    public static final int PREFIX_HEX_CHARS = 5;
    public static final int SUFFIX_HEX_CHARS = 59;

    /** 单桶最多下发多少条 suffix（HIBP 同口径量级；防止一个超大桶把响应撑成几 MB） */
    public static final int MAX_SUFFIXES_PER_BUCKET = 200;

    /** 索引文件大小上限：超过按"读不到"处理，<b>不截断</b>（截断会发出半个真相） */
    private static final long MAX_FILE_BYTES = 64L * 1024 * 1024;

    /** 两次"看文件变没变"之间的最短间隔：字典由离线脚本每天重建，不必每请求 stat */
    private static final long RECHECK_INTERVAL_MS = 30_000L;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** 配置项：只含 hash 与计数的索引文件（缺失/格式错 ⇒ available:false，服务照常启动） */
    @Value("${app.public.password-dict-file:data/password-hashes.json}")
    private String dictFile = "data/password-hashes.json";

    private volatile Snapshot snapshot;

    /**
     * 一个 5 位前缀桶：合计次数 + 最后出现时间 + 桶内 hash 的后 59 位。
     *
     * <p>{@code suffixes} 与 {@code listed} <b>刻意分开</b>：前者是蜜罐里真的被尝试过的口令，
     * 后者只出现在公开弱口令榜里（蜜罐还没见过它被真人尝试）。两者的文案必须不同 ——
     * 把"榜上有名"写成"被攻击者试过 N 次"就是撒谎。
     */
    public record Bucket(long count, String lastSeen, List<String> suffixes, List<String> listed) {
    }

    /**
     * 一次加载的结果。{@code available=false} 时 {@code reason} 非空、{@code buckets} 为空 ——
     * 端点据此如实回答"读不到（原因）—— 不补数"，而不是回一个空桶冒充"没查到"。
     */
    public record Snapshot(boolean available, String reason, String file, long fileBytes,
                           String generatedAt, long totalAttempts, long unique,
                           Map<String, Bucket> buckets, long checkedAtMs, long mtimeMs) {

        public Bucket bucket(String prefix) {
            return buckets.get(prefix);
        }
    }

    /** 当前快照：文件变了（且距上次检查 ≥{@value #RECHECK_INTERVAL_MS} 毫秒）就重读一次 */
    public Snapshot snapshot() {
        Snapshot s = snapshot;
        long now = System.currentTimeMillis();
        if (s != null && now - s.checkedAtMs() < RECHECK_INTERVAL_MS) {
            return s;
        }
        synchronized (this) {
            s = snapshot;
            if (s != null && System.currentTimeMillis() - s.checkedAtMs() < RECHECK_INTERVAL_MS) {
                return s;
            }
            snapshot = load();
            return snapshot;
        }
    }

    /** 丢掉缓存、立刻重读（运维在字典更新后不想等 30 秒时用；单测也用它） */
    public Snapshot reload() {
        synchronized (this) {
            snapshot = load();
            return snapshot;
        }
    }

    /** 读不到时的统一快照（本类不声明它"存在"：hashing 不猜） */
    public static Snapshot unavailable(String reason) {
        return new Snapshot(false, reason, null, 0L, null, 0L, 0L,
                Collections.emptyMap(), System.currentTimeMillis(), -1L);
    }

    private Snapshot load() {
        long checkedAt = System.currentTimeMillis();
        Path path = null;
        try {
            path = Path.of(dictFile);
        } catch (RuntimeException e) {
            return new Snapshot(false, "DICT_PATH_INVALID: " + e.getMessage(), dictFile, 0L,
                    null, 0L, 0L, Collections.emptyMap(), checkedAt, -1L);
        }

        if (!Files.isRegularFile(path)) {
            logger.warn("密码字典索引不存在（app.public.password-dict-file={}）：端点回 available:false，不补数", dictFile);
            return new Snapshot(false, "DICT_FILE_MISSING", dictFile, 0L,
                    null, 0L, 0L, Collections.emptyMap(), checkedAt, -1L);
        }

        long size;
        long mtime;
        byte[] raw;
        try {
            size = Files.size(path);
            FileTime ft = Files.getLastModifiedTime(path);
            mtime = ft.toMillis();
            if (size > MAX_FILE_BYTES) {
                logger.warn("密码字典索引过大（{} 字节 > {}）：按读不到处理，不截断", size, MAX_FILE_BYTES);
                return new Snapshot(false, "DICT_FILE_TOO_LARGE", dictFile, size,
                        null, 0L, 0L, Collections.emptyMap(), checkedAt, mtime);
            }
            raw = Files.readAllBytes(path);
        } catch (Exception e) {
            logger.warn("密码字典索引读失败（{}）：{}", dictFile, e.toString());
            return new Snapshot(false, "DICT_UNREADABLE", dictFile, 0L,
                    null, 0L, 0L, Collections.emptyMap(), checkedAt, -1L);
        }

        try {
            return parse(raw, size, mtime, checkedAt);
        } catch (InvalidDictException e) {
            logger.warn("密码字典索引格式不合法（{}）：{} —— 端点回 available:false，不跳过坏条目", dictFile, e.getMessage());
            return new Snapshot(false, "DICT_INVALID_FORMAT: " + e.getMessage(), dictFile, size,
                    null, 0L, 0L, Collections.emptyMap(), checkedAt, mtime);
        } catch (Exception e) {
            logger.warn("密码字典索引解析异常（{}）：{}", dictFile, e.toString());
            return new Snapshot(false, "DICT_INVALID_FORMAT", dictFile, size,
                    null, 0L, 0L, Collections.emptyMap(), checkedAt, mtime);
        }
    }

    private Snapshot parse(byte[] raw, long size, long mtime, long checkedAt) throws Exception {
        JsonNode root = MAPPER.readTree(new String(raw, StandardCharsets.UTF_8));
        if (root == null || !root.isObject()) {
            throw new InvalidDictException("根节点不是对象");
        }
        JsonNode bucketsNode = root.get("buckets");
        if (bucketsNode == null || !bucketsNode.isObject()) {
            throw new InvalidDictException("缺 buckets 对象");
        }
        long totalAttempts = nonNegativeLong(root.get("totalAttempts"), "totalAttempts");
        long unique = nonNegativeLong(root.get("unique"), "unique");
        String generatedAt = root.hasNonNull("generatedAt") ? text(root.get("generatedAt"), "generatedAt") : null;

        Map<String, Bucket> buckets = new LinkedHashMap<>();
        var it = bucketsNode.fields();
        while (it.hasNext()) {
            var entry = it.next();
            String prefix = entry.getKey();
            if (!isLowerHex(prefix, PREFIX_HEX_CHARS)) {
                throw new InvalidDictException("桶键不是 " + PREFIX_HEX_CHARS + " 位小写 hex：" + prefix);
            }
            JsonNode b = entry.getValue();
            if (b == null || !b.isObject()) {
                throw new InvalidDictException("桶 " + prefix + " 不是对象");
            }
            long count = nonNegativeLong(b.get("count"), "buckets." + prefix + ".count");
            String lastSeen = b.hasNonNull("lastSeen") ? text(b.get("lastSeen"), "lastSeen") : null;
            List<String> suffixes = Collections.emptyList();
            JsonNode hashes = b.get("hashes");
            if (hashes != null && !hashes.isNull()) {
                if (!hashes.isArray()) {
                    throw new InvalidDictException("桶 " + prefix + " 的 hashes 不是数组");
                }
                List<String> tmp = new ArrayList<>(hashes.size());
                for (JsonNode h : hashes) {
                    String s = h.isTextual() ? h.asText() : null;
                    if (s == null || !isLowerHex(s, SUFFIX_HEX_CHARS)) {
                        throw new InvalidDictException("桶 " + prefix + " 有非 " + SUFFIX_HEX_CHARS + " 位小写 hex 的 suffix");
                    }
                    tmp.add(s);
                }
                suffixes = Collections.unmodifiableList(tmp);
            }
            List<String> listed = Collections.emptyList();
            JsonNode listedNode = b.get("listed");
            if (listedNode != null && !listedNode.isNull()) {
                if (!listedNode.isArray()) {
                    throw new InvalidDictException("桶 " + prefix + " 的 listed 不是数组");
                }
                List<String> tmp = new ArrayList<>(listedNode.size());
                for (JsonNode h : listedNode) {
                    String s = h.isTextual() ? h.asText() : null;
                    if (s == null || !isLowerHex(s, SUFFIX_HEX_CHARS)) {
                        throw new InvalidDictException("桶 " + prefix + " 的 listed 有非 "
                                + SUFFIX_HEX_CHARS + " 位小写 hex 的 suffix");
                    }
                    tmp.add(s);
                }
                listed = Collections.unmodifiableList(tmp);
            }
            buckets.put(prefix, new Bucket(count, lastSeen, suffixes, listed));
        }

        logger.info("密码字典索引已加载：{} 个桶、{} 个 hash、{} 次尝试（{}）",
                buckets.size(), unique, totalAttempts, dictFile);
        return new Snapshot(true, null, dictFile, size, generatedAt, totalAttempts, unique,
                Collections.unmodifiableMap(buckets), checkedAt, mtime);
    }

    private static long nonNegativeLong(JsonNode n, String what) throws InvalidDictException {
        if (n == null || n.isNull()) {
            return 0L;
        }
        if (!n.isIntegralNumber() || n.asLong() < 0L) {
            throw new InvalidDictException(what + " 不是非负整数");
        }
        return n.asLong();
    }

    private static String text(JsonNode n, String what) throws InvalidDictException {
        if (n == null || !n.isTextual() || n.asText().isBlank()) {
            throw new InvalidDictException(what + " 不是非空字符串");
        }
        return n.asText();
    }

    static boolean isLowerHex(String s, int len) {
        if (s == null || s.length() != len) {
            return false;
        }
        for (int i = 0; i < len; i++) {
            char c = s.charAt(i);
            boolean ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    /** 离线脚本与测试共用的 hash 口径（避免两处各写一遍 hex 转换） */
    static String sha256Hex(String plain) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] d = md.digest(plain.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder(64);
        for (byte b : d) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    /** 格式错的内部信号：只在 {@link #parse} 里抛，外面统一转成 available:false */
    private static final class InvalidDictException extends Exception {
        InvalidDictException(String message) {
            super(message);
        }
    }
}
