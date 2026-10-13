package org.example.publicapi;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 蜜罐抓到的口令 → <b>只给结构，不给原文</b>（"永不公开"清单第 ① 条的执行点）。
 *
 * <h3>为什么这条与开关无关，永远不给</h3>
 * 站主明确：公开面可以显示观测到的真实来源 IP，但<b>蜜罐抓到的完整口令/凭据永远不给公网</b>。
 * 这不是"敏感度问题"，是<b>硬伤害</b>：公开一个真实口令等于替攻击者完成了撞库验证，
 * 对任何碰巧复用该口令的第三方站点都是直接伤害 —— 与"我们被不被投诉"无关。
 * 所以本类不读任何开关：{@code app.public.mask-ips} 无论真false，口令都只出结构。
 *
 * <h3>给什么（站主定的白名单）</h3>
 * <ul>
 *   <li>用户名：可以给（攻击者试的账号名本身就是战报信息）；</li>
 *   <li>口令<b>长度</b>、<b>字符类</b>（大写/小写/数字/特殊字符）、<b>是否弱口令</b>标记；</li>
 *   <li>绝不给出原文字符、绝不给出前几位/后几位、绝不给出哈希（哈希对小口令空间可爆破）。</li>
 * </ul>
 *
 * <h3>弱口令标记是"粗判"，不是强度评估</h3>
 * 判据只有三条，全部可复现：命中内置常见弱口令表、长度 ≤ 8 且只用单一字符类、长度 ≤ 6。
 * 页面若要展示它，必须按"粗判"措辞 —— 把启发式说成"密码强度评分"是不诚实的。
 */
public final class CredentialStructure {

    private CredentialStructure() {
    }

    /** 口令原文被隐去后的写法（自由文本里出现 {@code 口令=xxx} 时用） */
    public static final String PASSWORD_HIDDEN = "[口令已隐藏]";

    /**
     * 自由文本里的"口令字段"：{@code 口令=xxx} / {@code password: xxx} / {@code 密码=xxx}。
     *
     * <p>为什么必须有它：蜜罐规则的 {@code rule.description} 原文形如
     * {@code 蜜罐: 攻击者"登录成功" 用户=root 口令=123456 来源=1.2.3.4}，
     * 而时间线正是把这段描述直接放进出参的（只掩了 IP）—— 也就是说
     * <b>完整口令本来就随 timeline.detail 出过公网</b>。这类文本必须整段过一遍本规则。
     *
     * <p>刻意宽松（只要出现关键词 + 分隔符，右边一律隐藏）：宁可把一个无关字段打成占位符，
     * 也不能漏掉一个真口令。
     */
    private static final Pattern PASSWORD_IN_TEXT = Pattern.compile(
            "(?i)(口令|密码|password|passwd|pwd)\\s*[:=：]\\s*(\\S+)");

    /** {@code username=xxx} / {@code 用户=xxx}（用户名可以给，这里只负责抽出来供结构化输出） */
    private static final Pattern USER_IN_TEXT = Pattern.compile(
            "(?i)(用户名|用户|user|username)\\s*[:=：]\\s*(\\S+)");

    /**
     * 内置常见弱口令表（小写比较）。
     *
     * <p>刻意只收"全世界都在试的那几十个"，不做百科：这张表的作用是给页面一个
     * "这个口令属于最常被撞库的那一类"的标记，而不是给出密码强度结论。
     */
    private static final java.util.Set<String> COMMON_WEAK = java.util.Set.of(
            "123456", "1234567", "12345678", "123456789", "1234567890", "12345", "1234",
            "111111", "000000", "666666", "888888", "123123", "123321", "654321",
            "password", "passwd", "admin", "administrator", "root", "toor", "test", "guest",
            "qwerty", "qwerty123", "abc123", "a123456", "123qwe", "1qaz2wsx", "qazwsx",
            "iloveyou", "letmein", "welcome", "monkey", "dragon", "master", "shadow",
            "p@ssw0rd", "passw0rd", "changeme", "default", "temp", "oracle", "mysql");

    /**
     * 从一个 {@code 用户 / 口令} 形式的原始 key 里<b>只出结构</b>。
     *
     * <p>入参形状来自 {@code WazuhService.honeypotSummary}：{@code mCred.group(1) + " / " + mCred.group(2)}。
     * 兜底方向是 fail-closed：<b>没有分隔符时，把整串都当作口令</b>（用户名留空），
     * 宁可少给一个用户名，也不能因为形状不符就把可能的明文口令原样输出。
     *
     * @param rawKey 形如 {@code root / 123456} 的原始串
     * @return {@code {key, count 由调用方补；username, passwordLength, passwordCharClasses, weakPassword}}
     */
    public static Map<String, Object> describe(String rawKey) {
        String username = null;
        String password = null;
        if (rawKey != null) {
            int sep = rawKey.indexOf(" / ");
            if (sep >= 0) {
                username = rawKey.substring(0, sep).trim();
                password = rawKey.substring(sep + 3).trim();
            } else {
                password = rawKey.trim();
            }
        }

        Map<String, Object> m = new LinkedHashMap<>();
        m.put("username", (username == null || username.isEmpty()) ? null : username);
        m.put("passwordLength", password == null ? 0 : password.length());
        m.put("passwordCharClasses", charClassesLabel(password));
        m.put("weakPassword", isWeak(password));
        m.put("key", structureKey(username, password));
        return m;
    }

    /**
     * 结构摘要（人读，给 {@code key} 字段用）。
     *
     * <p>为什么 {@code key} 要改内容：改造前它是 {@code root / 123456}（<b>含完整口令</b>），
     * 这是本次必须修掉的泄露点。字段名与字段位置都不动（契约"只许新增字段"），
     * 只把值换成结构。形如：{@code root / 6 位·小写字母+数字·弱口令}。
     */
    public static String structureKey(String username, String password) {
        String structure = structureLabel(password);
        String user = (username == null || username.isBlank()) ? "（用户名未知）" : username;
        return user + " / " + structure;
    }

    /** 形如 {@code 6 位·小写字母+数字·弱口令} 的结构摘要（不含口令任何字符） */
    public static String structureLabel(String password) {
        int len = password == null ? 0 : password.length();
        return len + " 位·" + charClassesLabel(password) + (isWeak(password) ? "·弱口令" : "·非弱口令");
    }

    /** 字符类中文标签（固定枚举顺序：大写→小写→数字→特殊字符） */
    public static String charClassesLabel(String password) {
        if (password == null || password.isEmpty()) {
            return "无法判定";
        }
        boolean upper = false;
        boolean lower = false;
        boolean digit = false;
        boolean special = false;
        boolean nonAscii = false;
        for (int i = 0; i < password.length(); i++) {
            char c = password.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                upper = true;
            } else if (c >= 'a' && c <= 'z') {
                lower = true;
            } else if (c >= '0' && c <= '9') {
                digit = true;
            } else if (c <= 0x7f) {
                special = true;
            } else {
                nonAscii = true;
            }
        }
        StringBuilder sb = new StringBuilder();
        if (upper) {
            sb.append("大写字母+");
        }
        if (lower) {
            sb.append("小写字母+");
        }
        if (digit) {
            sb.append("数字+");
        }
        if (special) {
            sb.append("特殊字符+");
        }
        if (nonAscii) {
            sb.append("非ASCII+");
        }
        if (sb.length() == 0) {
            return "无法判定";
        }
        return sb.substring(0, sb.length() - 1);
    }

    /** 粗判弱口令（判据见类注释；确定性、无随机、无外部依赖） */
    public static boolean isWeak(String password) {
        if (password == null || password.isEmpty()) {
            return false;
        }
        if (COMMON_WEAK.contains(password.toLowerCase(Locale.ROOT))) {
            return true;
        }
        if (password.length() <= 6) {
            return true;
        }
        // 长度 ≤ 8 且只有一个字符类（纯数字 / 纯小写 / 纯大写）也算弱
        if (password.length() <= 8) {
            boolean upper = false;
            boolean lower = false;
            boolean digit = false;
            boolean other = false;
            for (int i = 0; i < password.length(); i++) {
                char c = password.charAt(i);
                if (c >= 'A' && c <= 'Z') {
                    upper = true;
                } else if (c >= 'a' && c <= 'z') {
                    lower = true;
                } else if (c >= '0' && c <= '9') {
                    digit = true;
                } else {
                    other = true;
                }
            }
            int classes = (upper ? 1 : 0) + (lower ? 1 : 0) + (digit ? 1 : 0) + (other ? 1 : 0);
            return classes <= 1;
        }
        return false;
    }

    /**
     * 把自由文本里的口令字段整体隐去，用户名保留。
     *
     * @param text 任意文本（可为 null）
     * @return 形如 {@code 用户=root 口令=[口令已隐藏] 来源=...} 的文本
     */
    public static String hidePasswords(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        Matcher m = PASSWORD_IN_TEXT.matcher(text);
        StringBuilder sb = new StringBuilder();
        boolean hit = false;
        while (m.find()) {
            hit = true;
            m.appendReplacement(sb, Matcher.quoteReplacement(m.group(1) + "=" + PASSWORD_HIDDEN));
        }
        if (!hit) {
            return text;
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * 从自由文本里抽用户名（用户名可以公开，但页面上通常已经能看到，这里是给结构化字段兜底）。
     *
     * @return 抽到的用户名；抽不到返回 {@code null}
     */
    public static String usernameIn(String text) {
        if (text == null || text.isEmpty()) {
            return null;
        }
        Matcher m = USER_IN_TEXT.matcher(text);
        return m.find() ? m.group(2) : null;
    }
}
