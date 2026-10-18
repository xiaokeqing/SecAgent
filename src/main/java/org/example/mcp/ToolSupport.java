package org.example.mcp;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 工具共用的口径：信封字段、参数读取、时间解析、口令脱敏。
 *
 * <p>这些方法集中在一个类里，是为了让"每个工具输出都带 generatedAt/source、取不到就 available:false、
 * 口令永不出现在输出里"这三条只有一处实现 —— 六个工具各抄一遍必然会有一两个抄漏。
 */
public final class ToolSupport {

    /** 输出时间戳：带偏移的 ISO-8601（客户端好排序、好比时区）。 */
    public static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX");

    /** 平台内部时间口径（PublicApiController 的 FMT 同款），口径必须与上游一致才能正确比较窗口。 */
    public static final DateTimeFormatter PLATFORM_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /** 口令「结构串」的合法形状：{@code 6 位·纯数字·弱口令} / {@code 12 位·字母+数字·非弱口令}。 */
    private static final Pattern CRED_STRUCTURE = Pattern.compile("^\\d+\\s*位·.+·(弱口令|非弱口令)$");

    /** 名字像"凭据"的键（精确匹配，避免把 credStructure 这类结构字段一起打成隐藏）。 */
    private static final Set<String> SECRET_KEYS = new HashSet<>(Arrays.asList(
            "password", "passwd", "pass", "pwd", "secret", "token", "accesstoken", "refreshtoken",
            "apikey", "api_key", "authorization", "auth", "privatekey", "private_key", "key",
            "passwordhash", "credential", "creds"));

    private ToolSupport() {
    }

    // ==================== 信封 ====================

    public static String generatedAt() {
        return OffsetDateTime.now().format(TS);
    }

    /** 所有工具输出的公共三件套：generatedAt / source / available。 */
    public static Map<String, Object> base(String source, boolean available) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("generatedAt", generatedAt());
        m.put("source", source);
        m.put("available", available);
        return m;
    }

    /** 取不到数据时的标准形状：不留半截数字，只给原因。 */
    public static Map<String, Object> unavailable(String source, String reason) {
        Map<String, Object> m = base(source, false);
        m.put("reason", reason == null || reason.isBlank() ? "DATA_SOURCE_UNAVAILABLE" : reason);
        m.put("note", "取不到就报不可用：不补数、不猜、不用样本冒充真实数据。");
        return m;
    }

    // ==================== 协议输入 Schema ====================

    public static Map<String, Object> schema(Map<String, Object> properties, List<String> required) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("type", "object");
        s.put("properties", properties);
        s.put("required", required == null ? List.of() : required);
        s.put("additionalProperties", false);
        return s;
    }

    public static Map<String, Object> prop(String type, String description) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("type", type);
        p.put("description", description);
        return p;
    }

    public static Map<String, Object> prop(String type, String description, Object defaultValue) {
        Map<String, Object> p = prop(type, description);
        p.put("default", defaultValue);
        return p;
    }

    // ==================== 参数 ====================

    public static int intArg(Map<String, Object> args, String key, int def, int min, int max) {
        Object v = args == null ? null : args.get(key);
        int n = def;
        if (v instanceof Number number) {
            n = number.intValue();
        } else if (v instanceof String s && !s.isBlank()) {
            try {
                n = Integer.parseInt(s.trim());
            } catch (NumberFormatException ignored) {
                n = def;
            }
        }
        return Math.max(min, Math.min(max, n));
    }

    public static String strArg(Map<String, Object> args, String key) {
        Object v = args == null ? null : args.get(key);
        if (v == null) {
            return null;
        }
        String s = String.valueOf(v).trim();
        return s.isEmpty() ? null : s;
    }

    public static boolean boolArg(Map<String, Object> args, String key) {
        Object v = args == null ? null : args.get(key);
        if (v instanceof Boolean b) {
            return b;
        }
        return v != null && "true".equalsIgnoreCase(String.valueOf(v).trim());
    }

    // ==================== 形状转换 ====================

    public static String text(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> map(Object o) {
        if (o instanceof Map<?, ?> m) {
            Map<String, Object> out = new LinkedHashMap<>();
            m.forEach((k, v) -> out.put(String.valueOf(k), v));
            return out;
        }
        return new LinkedHashMap<>();
    }

    public static List<Object> list(Object o) {
        if (o instanceof List<?> l) {
            return new ArrayList<>(l);
        }
        return new ArrayList<>();
    }

    /** 平台时间串 → LocalDateTime；解析不了返回 null（调用方必须当"未知"处理，不许猜成 now）。 */
    public static LocalDateTime parseTime(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String v = raw.trim();
        try {
            return LocalDateTime.parse(v, PLATFORM_FMT);
        } catch (DateTimeParseException ignored) {
            // 继续试其它口径
        }
        try {
            return LocalDateTime.parse(v, DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        } catch (DateTimeParseException ignored) {
            // 继续
        }
        try {
            return OffsetDateTime.parse(v, DateTimeFormatter.ISO_OFFSET_DATE_TIME)
                    .atZoneSameInstant(ZoneId.systemDefault()).toLocalDateTime();
        } catch (DateTimeParseException ignored) {
            return null;
        }
    }

    // ==================== 口令保护 ====================

    /**
     * 凭据串 → 只说结构、不说口令。
     *
     * <p>平台 {@code credentialShapes} 的输出是 {@code 用户名 / 6 位·纯数字·弱口令}。
     * 这里<b>不信任上游一定已经脱敏</b>（防御性）：只有右半边真的长得像结构串才保留，
     * 否则整段替换成 {@code [口令已隐藏]}。这样即使上游哪天把原文透出来，MCP 这一层也不会转发出去。
     */
    public static String redactCredential(String raw) {
        if (raw == null) {
            return null;
        }
        String v = raw.trim();
        int slash = v.indexOf(" / ");
        String user = slash >= 0 ? v.substring(0, slash) : null;
        String shape = slash >= 0 ? v.substring(slash + 3) : v;
        if ("无法判定".equals(shape) || CRED_STRUCTURE.matcher(shape).matches()) {
            return slash >= 0 ? user + " / " + shape : shape;
        }
        return (slash >= 0 ? user + " / " : "") + "[口令已隐藏]";
    }

    /**
     * 凭据列表（蜜罐 topCredentials 那种）逐条只留结构。
     *
     * <p>为什么这里"宁可错杀"：这是唯一一处可能装着口令的字段，
     * 只要一条不像结构串就整段打掉 —— 少显示一个用户名，比漏一个口令便宜得多。
     */
    public static List<Object> credentialList(Object value) {
        List<Object> out = new ArrayList<>();
        if (value instanceof List<?> l) {
            for (Object o : l) {
                out.add(o instanceof String s ? redactCredential(s) : deepRedact(o));
            }
        } else if (value instanceof String s) {
            out.add(redactCredential(s));
        }
        return out;
    }

    /**
     * 递归脱敏：键名像凭据的整段打成 {@code [已隐藏]}；带 {@code 用户名 / 结构} 形状的串只留结构。
     *
     * <p>只对"值"动手、键名精确匹配，所以 {@code credStructure} 这种结构字段不会被误杀；
     * 也不碰普通字符串（否则 {@code 45.205.1.230} 这种来源地址会被当成口令一起藏掉）。
     */
    public static Object deepRedact(Object value) {
        if (value instanceof Map<?, ?> m) {
            Map<String, Object> out = new LinkedHashMap<>();
            m.forEach((k, v) -> {
                String key = String.valueOf(k);
                if (SECRET_KEYS.contains(key.toLowerCase(Locale.ROOT))) {
                    out.put(key, "[已隐藏]");
                } else {
                    out.put(key, deepRedact(v));
                }
            });
            return out;
        }
        if (value instanceof List<?> l) {
            List<Object> out = new ArrayList<>();
            for (Object o : l) {
                out.add(deepRedact(o));
            }
            return out;
        }
        if (value instanceof String s) {
            return s.contains(" / ") ? redactCredential(s) : s;
        }
        return value;
    }
}
