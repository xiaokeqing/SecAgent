package org.example.notify;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 通用 webhook 载荷模板渲染：把 {@code {{变量}}} 替换成实际值，并给常见 IM 做转义。
 *
 * <h3>为什么是"模板 + 变量"而不是内置 Telegram/飞书/钉钉三种实现</h3>
 * 这三家（以及自建 n8n / Bark / 企业微信机器人）的共同点只有一个：
 * <b>HTTP POST 一个 JSON</b>。差异全在"JSON 长什么样"。
 * 因此内置三套代码意味着三份要跟着对方改格式的维护负担，
 * 而做成一行的模板就能覆盖：默认
 * <pre>{"text":"{{title}}\n{{body}}"}</pre>
 * 换 Telegram 是 {@code {"chat_id":"...","text":"{{title}}\n{{body}}"}}，
 * 换飞书是 {@code {"msg_type":"text","content":{"text":"{{title}}\n{{body}}"}}}。
 *
 * <h3>渲染后的 JSON 必须仍然合法 —— 这是本类最容易出错的地方</h3>
 * 告警标题里会带 IP、规则名，甚至可能带引号。朴素替换会把引号直接插进 JSON 字符串里，
 * 拼出一份非法 JSON：对端返回 400，而日志里只看到"通知发送失败"——
 * 完全看不出是<b>转义</b>的问题。
 * <p>
 * 所以这里分两步：
 * <ol>
 *   <li>先按 <b>JSON 字符串</b>的口径转义每个变量值（{@code " \ \n \r \t 控制字符}）；</li>
 *   <li>再替换，并在替换后 {@link ObjectMapper#readTree} 校验一次。
 *       非法就抛异常、由调用方如实记审计 —— <b>绝不"发出去试试"</b>。</li>
 * </ol>
 */
public final class NotificationTemplate {

    /** 变量占位：{{name}}，允许变量名里有字母数字下划线点 */
    private static final Pattern VAR = Pattern.compile("\\{\\{\\s*([A-Za-z0-9_.]+)\\s*}}");

    /** 默认模板：通用 JSON，{@code text} 字段是绝大多数 IM 机器人的共同约定 */
    public static final String DEFAULT_TEMPLATE = "{\"text\":\"{{title}}\\n{{body}}\"}";

    private NotificationTemplate() {
    }

    /**
     * 渲染模板为最终 JSON 字符串。
     *
     * @param template 模板（null/空 → {@link #DEFAULT_TEMPLATE}）
     * @param vars     变量表（来自 {@link NotifyEvent#variables(int)}）
     * @return 渲染后的 JSON
     * @throws IllegalArgumentException 模板里出现未知变量，或渲染结果不是合法 JSON
     */
    public static String render(String template, Map<String, String> vars) {
        String tpl = (template == null || template.isBlank()) ? DEFAULT_TEMPLATE : template;

        StringBuilder out = new StringBuilder();
        Matcher m = VAR.matcher(tpl);
        int last = 0;
        while (m.find()) {
            out.append(tpl, last, m.start());
            String name = m.group(1);
            String raw = find(vars, name);
            if (raw == null) {
                // 未知变量必须报错，不能替换成空串：写错 {{titel}} 的通知会"看起来发出去了"，
                // 只是每次正文里少一截 —— 这种问题在手机上只会被当成"对端渲染怪怪的"。
                throw new IllegalArgumentException("通知模板里的变量 {{" + name + "}} 不存在（可用变量："
                        + (vars == null ? "无" : vars.keySet()) + "）");
            }
            out.append(escapeJson(raw));
            last = m.end();
        }
        out.append(tpl.substring(last));

        String json = out.toString();
        validate(json);
        return json;
    }

    /** 大小写不敏感地取变量（模板由人手写，{{Title}} 和 {{title}} 不该是两种行为） */
    private static String find(Map<String, String> vars, String name) {
        if (vars == null) {
            return null;
        }
        if (vars.containsKey(name)) {
            return vars.get(name);
        }
        for (Map.Entry<String, String> e : vars.entrySet()) {
            if (e.getKey().equalsIgnoreCase(name)) {
                return e.getValue();
            }
        }
        return null;
    }

    /**
     * 按 JSON 字符串的口径转义。
     *
     * <p>必须把 {@code \n} 转成字面量两字符 {@code \n}（反斜杠 + n），
     * 而不是真实换行：模板里写的 {@code "{{title}}\n{{body}}"} 中那个 {@code \n}
     * 本来就是 JSON 的换行转义，替换进来的值如果是真实换行，JSON 就断了。
     */
    public static String escapeJson(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder b = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                case '\b' -> b.append("\\b");
                case '\f' -> b.append("\\f");
                default -> {
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
                }
            }
        }
        return b.toString();
    }

    /** 渲染结果必须是合法 JSON —— 否则宁可失败（fail-closed），也不要发一份对端看不懂的载荷 */
    public static void validate(String json) {
        try {
            JsonNode n = new ObjectMapper().readTree(json);
            if (n == null) {
                throw new IllegalArgumentException("通知模板渲染结果为空 JSON");
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("通知模板渲染结果不是合法 JSON：" + e.getMessage()
                    + "（模板要保证替换后仍是 JSON；值里的引号由本类转义）", e);
        }
    }
}
