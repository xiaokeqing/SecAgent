package org.example.mcp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 自写检测规则清单（读<b>站点仓库</b>里的两个规则文件，只读、只解析 sid 与 msg）。
 *
 * <p>为什么不走平台 HTTP 端点：这两份规则是"我们写了什么检测"的自述文件，
 * 平台本身不解析它们（Suricata/Wazuh 才解析）。MCP 直接读文件是唯一能回答
 * "我们的检测规则有哪些"的来源；文件不存在就 {@code available:false}，不去猜。
 *
 * <p>路径口径：{@code <site>/detections/suricata/xk-lab.rules} 与
 * {@code <site>/detections/wazuh/xk-lab_rules.xml}（{@code <site>} 默认 {@code F:/7AAA/AI/blog}，
 * 可用 {@code XK_MCP_SITE_DIR} 覆盖）。
 */
public final class DetectionCatalog {

    public static final String SURICATA_REL = "detections/suricata/xk-lab.rules";
    public static final String WAZUH_REL = "detections/wazuh/xk-lab_rules.xml";

    /**
     * Suricata 规则头：{@code action proto src_addr src_port (->|<>|<-) dst_addr dst_port (}。
     * 一共 7 个 token —— 少写一个端口就会整条规则都匹配不上（真实规则是
     * {@code alert ssh $EXTERNAL_NET any -> $HOME_NET 2222 ( \}），所以这里显式把
     * 两个端口和方向都单列出来，而不是凑够 5 个 token 就当成头。
     */
    private static final Pattern SURICATA_HEAD = Pattern.compile(
            "^\\s*(alert|drop|reject|pass)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(->|<>|<-)\\s+(\\S+)\\s+(\\S+)\\s*\\(");
    private static final Pattern SID = Pattern.compile("\\bsid:\\s*(\\d+)\\s*;");
    private static final Pattern MSG = Pattern.compile("\\bmsg:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
    private static final Pattern CLASSTYPE = Pattern.compile("\\bclasstype:\\s*([^;]+);");
    private static final Pattern REV = Pattern.compile("\\brev:\\s*(\\d+)");
    private static final Pattern WAZUH_RULE =
            Pattern.compile("<rule\\b([^>]*)>(.*?)</rule>", Pattern.DOTALL);
    private static final Pattern XML_ID = Pattern.compile("\\bid=\"([^\"]+)\"");
    private static final Pattern XML_LEVEL = Pattern.compile("\\blevel=\"([^\"]+)\"");
    private static final Pattern XML_DESC =
            Pattern.compile("<description>(.*?)</description>", Pattern.DOTALL);
    private static final Pattern XML_IF_SID = Pattern.compile("<if_sid>(.*?)</if_sid>", Pattern.DOTALL);
    private static final Pattern XML_GROUP = Pattern.compile("\\bgroup=\"([^\"]+)\"");

    private DetectionCatalog() {
    }

    /** 解析结果（字段公开：这是个纯数据载体，不需要 getter 噪音）。 */
    public static final class Result {
        public boolean available;
        public String reason;
        public String siteDir;
        public List<Map<String, Object>> files = new ArrayList<>();
        public List<Map<String, Object>> suricata = new ArrayList<>();
        public List<Map<String, Object>> wazuh = new ArrayList<>();
        public List<String> notes = new ArrayList<>();

        public int total() {
            return suricata.size() + wazuh.size();
        }
    }

    public static Result load(Path siteDir) {
        Result r = new Result();
        r.siteDir = siteDir == null ? null : siteDir.toAbsolutePath().normalize().toString();
        if (siteDir == null) {
            r.reason = "SITE_DIR_NOT_CONFIGURED";
            return r;
        }
        Path suricata = siteDir.resolve(SURICATA_REL);
        Path wazuh = siteDir.resolve(WAZUH_REL);

        boolean anyReadable = false;
        String suricataText = readRuleFile(suricata, SURICATA_REL, r, true);
        if (suricataText != null) {
            anyReadable = true;
            parseSuricata(suricataText, r);
        }
        String wazuhText = readRuleFile(wazuh, WAZUH_REL, r, false);
        if (wazuhText != null) {
            anyReadable = true;
            parseWazuh(wazuhText, r);
        }

        r.available = anyReadable;
        if (!anyReadable) {
            r.reason = "DETECTION_FILES_NOT_FOUND: " + suricata + " 与 " + wazuh + " 都读不到";
        } else if (r.total() == 0) {
            r.notes.add("规则文件读得到但没解析出任何 sid/id（文件格式变了？）—— 这里不猜规则条数。");
        }
        return r;
    }

    private static String readRuleFile(Path file, String rel, Result r, boolean suricataFlavor) {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("path", file.toAbsolutePath().normalize().toString());
        meta.put("role", suricataFlavor ? "suricata" : "wazuh");
        meta.put("rel", rel);
        boolean exists = Files.isRegularFile(file);
        meta.put("exists", exists);
        try {
            meta.put("bytes", exists ? Files.size(file) : 0L);
        } catch (IOException e) {
            meta.put("bytes", null);
        }
        r.files.add(meta);
        if (!exists) {
            return null;
        }
        try {
            String text = Files.readString(file, StandardCharsets.UTF_8);
            meta.put("readable", true);
            return text;
        } catch (IOException e) {
            meta.put("readable", false);
            r.notes.add("读 " + rel + " 失败：" + e.getMessage());
            return null;
        }
    }

    /** Suricata 的多行规则用行尾 {@code \} 续行：先拼成逻辑行，再从中抽 sid/msg。 */
    private static void parseSuricata(String text, Result r) {
        StringBuilder logical = new StringBuilder();
        for (String rawLine : text.split("\r?\n")) {
            String line = rawLine.stripTrailing();
            if (logical.length() == 0 && (line.isBlank() || line.stripLeading().startsWith("#"))) {
                continue;
            }
            String trimmed = line.strip();
            if (trimmed.endsWith("\\")) {
                logical.append(trimmed, 0, trimmed.length() - 1).append(' ');
                continue;
            }
            if (logical.length() > 0) {
                logical.append(trimmed);
                addSuricataRule(logical.toString(), r);
                logical.setLength(0);
            } else if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                addSuricataRule(trimmed, r);
            }
        }
        if (logical.length() > 0) {
            addSuricataRule(logical.toString(), r);
        }
    }

    private static void addSuricataRule(String logicalLine, Result r) {
        Matcher head = SURICATA_HEAD.matcher(logicalLine);
        Matcher sid = SID.matcher(logicalLine);
        if (!head.find() || !sid.find()) {
            return;
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("kind", "suricata");
        m.put("sid", parseIntOrNull(sid.group(1)));
        m.put("action", head.group(1));
        m.put("protocol", head.group(2));
        m.put("src", head.group(3) + " " + head.group(4));
        m.put("direction", head.group(5));
        m.put("dst", head.group(6) + " " + head.group(7));
        Matcher msg = MSG.matcher(logicalLine);
        m.put("msg", msg.find() ? unescape(msg.group(1)) : null);
        Matcher cls = CLASSTYPE.matcher(logicalLine);
        m.put("classtype", cls.find() ? cls.group(1).trim() : null);
        Matcher rev = REV.matcher(logicalLine);
        m.put("rev", rev.find() ? parseIntOrNull(rev.group(1)) : null);
        m.put("file", SURICATA_REL);
        r.suricata.add(m);
    }

    /** Wazuh 规则是 XML：只抽 id/level/description/if_sid/group，不做完整 XML 解析（避免引入 parser 依赖与 DTD 风险）。 */
    private static void parseWazuh(String text, Result r) {
        // 注释里的 <rule ...> 不算规则
        String cleaned = text.replaceAll("(?s)<!--.*?-->", "");
        Matcher rule = WAZUH_RULE.matcher(cleaned);
        while (rule.find()) {
            String attrs = rule.group(1);
            String body = rule.group(2);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("kind", "wazuh");
            Matcher id = XML_ID.matcher(attrs);
            m.put("id", id.find() ? parseIntOrNull(id.group(1)) : null);
            Matcher level = XML_LEVEL.matcher(attrs);
            m.put("level", level.find() ? parseIntOrNull(level.group(1)) : null);
            Matcher desc = XML_DESC.matcher(body);
            m.put("description", desc.find() ? unescape(desc.group(1).strip()) : null);
            Matcher ifSid = XML_IF_SID.matcher(body);
            m.put("ifSid", ifSid.find() ? unescape(ifSid.group(1).strip()) : null);
            Matcher group = XML_GROUP.matcher(attrs);
            m.put("group", group.find() ? unescape(group.group(1)) : null);
            m.put("file", WAZUH_REL);
            r.wazuh.add(m);
        }
    }

    private static Integer parseIntOrNull(String s) {
        try {
            return Integer.valueOf(s.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static String unescape(String s) {
        return s.replace("&lt;", "<").replace("&gt;", ">")
                .replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&");
    }
}
