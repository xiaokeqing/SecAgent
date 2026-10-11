package org.example.integration.wazuh;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Wazuh 时间戳 → 本地时区字符串。
 *
 * <h3>为什么单独抽一个类</h3>
 * 这里出过一个「格式完全正确、值差 8 小时」的错：
 * Wazuh 写进 indexer 的 {@code @timestamp} 是 <b>UTC</b>
 * （实测 {@code 2026-10-11T13:57:40.279Z}），原实现把 {@code T} 换成空格、
 * 删掉 {@code Z} 和毫秒，然后<b>按本地时间解析</b> ——
 * 21:57（北京时间）的告警在页面上显示成 13:57。
 * <p>
 * 这类错的特征是：字符串合法、排序也正确（相对顺序不变），
 * 只有拿它跟墙上时钟对照才会露馅。而告警时间是安全运营最不能错的东西
 * （判断「是不是正在被打」全靠它）。
 * <p>
 * 抽成类是为了<b>能用固定的时区做断言</b>：如果它依赖 JVM 默认时区，
 * 测试就会在 CI 机器上飘 —— 而一条会飘的测试最终一定会被忽略。
 */
public final class WazuhTime {

    private static final DateTimeFormatter LOCAL = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final DateTimeFormatter BARE = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private WazuhTime() {
    }

    /** 用 JVM 默认时区转换（业务代码走这个入口） */
    public static String toLocal(String iso) {
        return toLocal(iso, ZoneId.systemDefault());
    }

    /**
     * 把 Wazuh 时间戳转成目标时区的 {@code yyyy-MM-dd HH:mm:ss}。
     *
     * @param iso  Wazuh 的时间字段，形态可能是
     *             {@code 2026-10-11T13:57:40.279Z}、
     *             {@code 2026-10-11T13:57:40.279+0000}（偏移量没有冒号），
     *             也可能是不带时区的裸时间
     * @param zone 目标时区（生产环境是 Asia/Shanghai）
     * @return 本地时间字符串；完全解析不了时原样返回（不编造时间）
     */
    public static String toLocal(String iso, ZoneId zone) {
        if (iso == null || iso.isBlank()) {
            return LocalDateTime.now(zone).format(LOCAL);
        }
        String s = iso.trim();

        // 1) 标准 ISO8601：带 Z 或 +08:00 —— 这条是线上真实形态
        try {
            return OffsetDateTime.parse(s).atZoneSameInstant(zone).format(LOCAL);
        } catch (Exception ignored) {
            // 继续尝试其它形态
        }

        // 2) Wazuh 的 timestamp 字段：2026-10-11T13:57:40.279+0000（偏移量缺冒号）
        try {
            String t = s.replaceAll("([+-]\\d{2})(\\d{2})$", "$1:$2");
            return OffsetDateTime.parse(t).atZoneSameInstant(zone).format(LOCAL);
        } catch (Exception ignored) {
            // 继续
        }

        // 3) 不带时区的裸时间：按目标时区解释（不假装它带时区），保留旧行为兜底
        try {
            String t = s.contains("T") ? s.replace('T', ' ') : s;
            int dot = t.indexOf('.');
            if (dot > 0) {
                t = t.substring(0, dot);
            }
            t = t.replaceAll("[Zz]\\s*$", "").trim();
            if (t.length() > 19) {
                t = t.substring(0, 19);
            }
            return LocalDateTime.parse(t, BARE).format(LOCAL);
        } catch (Exception e) {
            return iso;
        }
    }
}
