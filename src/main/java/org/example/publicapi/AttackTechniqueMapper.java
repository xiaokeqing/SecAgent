package org.example.publicapi;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * 告警规则名 → MITRE ATT&amp;CK 技术编号映射。
 *
 * <p>为什么需要它：{@code /api/public/alerts} 的每条聚合项原来只有 {@code ruleName} /
 * {@code typeLabel} 这类"规则原文"，前端「威胁矩阵」要画 ATT&amp;CK 格子只能自己拿关键词
 * 去猜（口径散落在 JS 里、且没人能单测）。把映射收到服务端一张表里之后：
 * <ul>
 *   <li>口径只有一处，可单测、可评审；</li>
 *   <li>规则名匹配不上就输出 {@code null}，前端据此显示"未归类"，而不是硬塞一个格子；</li>
 *   <li>技术编号用 ATT&amp;CK 官方 ID（T1110 等），不是自造分类。</li>
 * </ul>
 *
 * <h3>为什么不拿 {@code source} / {@code typeLabel} 兜底</h3>
 * 站内已有的 {@code AlertType.guess()} 本身就是关键词粗分类（{@code "scan"}、
 * {@code "404"} 都算 SCAN），拿它给 ATT&amp;CK 兜底等于把"没把握的猜测"再包装一层，
 * 反而拉低可信度。所以本类的唯一判据是<b>规则名文本</b>；规则名说不清楚就不说。
 *
 * <h3>维护方式</h3>
 * 所有映射都在 {@link #RULES} 这一张有序表里，一行一条：正则 → 技术编号。
 * <b>顺序有意义</b>：先加入更具体的条目（例如 {@code "ET SCAN SUSPICIOUS"} 属于 T1190
 * 而不是泛化的扫描 T1046），命中第一条即返回。新增技术编号只需要在这里加行 +
 * 在 {@link Technique} 处加常量，不需要改任何 if/else。
 *
 * <p>纯函数、无状态：控制器直接静态调用，单测不需要 Spring 上下文。
 */
public final class AttackTechniqueMapper {

    /** 一条 ATT&amp;CK 技术：编号 + 中文名 + 官方英文名。字段名与公开 JSON 契约一致。 */
    public record Technique(String id, String name, String label) {

        /** 转成公开响应里的 {@code attck} 对象；键序固定为 id / name / label。 */
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("name", name);
            m.put("label", label);
            return m;
        }
    }

    private record Rule(Pattern pattern, Technique technique) {
    }

    // ==================== 支持的技术编号（只列有把握的） ====================

    private static final Technique T1110 = new Technique("T1110", "暴力破解", "Brute Force");
    private static final Technique T1190 = new Technique("T1190", "利用面向公众的应用", "Exploit Public-Facing Application");
    private static final Technique T1021 = new Technique("T1021", "远程服务", "Remote Services");
    private static final Technique T1046 = new Technique("T1046", "网络服务发现", "Network Service Discovery");
    private static final Technique T1505 = new Technique("T1505", "服务器软件组件", "Server Software Component");
    private static final Technique T1071 = new Technique("T1071", "应用层协议", "Application Layer Protocol");

    /**
     * 映射表（<b>顺序即优先级</b>，命中即返回）。
     *
     * <p>分组的理由：同一段文本可能同时命中多个技术（{@code "SSH Brute Force"} 既是远程服务
     * 又是暴力破解），按"具体 → 宽泛"排列，让更可解释的那条胜出。
     */
    private static final List<Rule> RULES = List.of(
            // ---------- T1110 暴力破解：必须出现"猜/失败/爆破"语义 ----------
            rule(T1110, "\\bbrute[-\\s]?forc(e|ing|ed)?\\b"),
            rule(T1110, "\\bbrute\\b"),
            rule(T1110, "\\b(authentication|auth|login|password)\\s+(failure|failures|failed|fail)\\b"),
            rule(T1110, "\\bfailed\\s+(password|login|authentication)\\b"),
            rule(T1110, "\\b(invalid|nonexistent|non-existent)\\s+user\\b"),
            rule(T1110, "\\bpassword\\s+guessing\\b"),
            rule(T1110, "暴力破解|口令爆破|密码爆破|暴力猜解"),
            rule(T1110, "(登录|认证|口令|密码)(失败|错误)"),
            rule(T1110, "重复(失败|登录失败)|多次(失败|尝试)"),

            // ---------- T1505 服务器软件组件：Web shell / 后门植入 ----------
            rule(T1505, "web[-\\s]*shell"),
            rule(T1505, "\\bshell\\s+upload\\b"),
            rule(T1505, "\\bupload\\b.{0,24}(\\bshell\\b|webshell|jsp|aspx?|php|\\bwar\\b)"),
            rule(T1505, "(webshell|web shell|木马|后门).{0,12}上传"),
            rule(T1505, "上传.{0,12}(webshell|web shell|木马|后门|jsp|aspx?|php)"),
            rule(T1505, "\\b(jsp|aspx?|php|war)\\s*(webshell|shell)\\b"),

            // ---------- T1071 应用层协议：可疑 UA / C2 信标 ----------
            rule(T1071, "\\buser[-\\s]?agent\\b"),
            rule(T1071, "urllib|python-requests|python/requests"),
            rule(T1071, "\\b(curl|wget)/"),
            rule(T1071, "\\b(c2|c&c|cnc)\\b"),
            rule(T1071, "\\bbeacon(ing|ed)?\\b"),
            rule(T1071, "\\bcommand[-\\s]and[-\\s]control\\b"),
            rule(T1071, "\\b(dns|http|https|smb)\\s*tunnel(ing)?\\b"),
            rule(T1071, "可疑\\s*(UA|用户代理)|应用层协议|恶意外联"),

            // ---------- T1190 利用面向公众的应用：注入 / 漏洞利用 / Web 攻击 ----------
            rule(T1190, "\\bsql\\s*injection\\b|\\bsqli\\b|union\\s+select"),
            // "ET SCAN SUSPICIOUS inbound to MSSQL" 这类签名指向具体公网服务，按 T1190 记；
            // 泛化的端口/主机扫描留给下面的 T1046。（两者都命中时，本行在前。）
            rule(T1190, "\\bscan\\s+suspicious\\b|suspicious.{0,24}\\bscan"),
            rule(T1190, "\\bexploit(s|ed|ing)?\\b"),
            rule(T1190, "\\bcve-\\d{4}-\\d{4,}\\b"),
            rule(T1190, "\\brce\\b|remote\\s+code\\s+execution"),
            rule(T1190, "\\bweb[_\\s-]?server\\b|\\bweb\\s*attack\\b"),
            rule(T1190, "\\b(path|directory)\\s+traversal|\\.\\./"),
            rule(T1190, "\\bcommand\\s+injection\\b|\\b(remote\\s+)?file\\s+inclusion\\b"),
            rule(T1190, "\\bxss\\b|cross[-\\s]?site\\s+scripting"),
            rule(T1190, "SQL\\s*注入|注入攻击|漏洞利用|利用.{0,8}漏洞|远程代码执行|反序列化|文件包含|目录遍历|跨站脚本|XSS|命令注入"),

            // ---------- T1021 远程服务：连接/登录尝试（只认"服务 + 连接"同现） ----------
            rule(T1021, "\\b(ssh|smb|rdp|vnc|telnet|winrm|rlogin)\\b.{0,24}(connect|connection|login|auth|连接|登录|认证|尝试)"),
            rule(T1021, "远程(桌面|服务|登录).{0,12}(连接|登录|认证|尝试)"),
            rule(T1021, "\\bremote\\s+(desktop|service|services)\\b.{0,24}(connection|login|attempt)"),

            // ---------- T1046 网络服务发现：端口/主机扫描、探测 ----------
            rule(T1046, "\\bport\\s*scan(ner|ning|ned|s)?\\b"),
            rule(T1046, "\\bportscan(ner|ning|ned|s)?\\b"),
            rule(T1046, "\\b(network|host|service|ip)\\s+scan(ner|ning|ned|s)?\\b"),
            rule(T1046, "\\b(nmap|masscan|zmap|unicornscan)\\b"),
            rule(T1046, "\\bprobe(s|d|ing)?\\b"),
            // Suricata 的 "ET SCAN …" 系列以扫描为主，落到这里；上面 T1190 的
            // "scan suspicious" 更具体，会先命中。
            rule(T1046, "\\bscan(s|ned|ning|ner)?\\b"),
            rule(T1046, "端口扫描|端口探测|网络扫描|主机扫描|服务扫描|扫描探测|服务发现|扫描器")
    );

    private static Rule rule(Technique technique, String regex) {
        return new Rule(Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE), technique);
    }

    private AttackTechniqueMapper() {
    }

    /**
     * 规则名 → 技术。映射不到返回 {@code null}（"未知就是未知"，不猜）。
     *
     * @param ruleName Wazuh / Suricata 的规则名原文；可空
     */
    public static Technique map(String ruleName) {
        if (ruleName == null || ruleName.isBlank()) {
            return null;
        }
        for (Rule r : RULES) {
            if (r.pattern().matcher(ruleName).find()) {
                return r.technique();
            }
        }
        return null;
    }

    /**
     * 规则名 → 公开 JSON 里的 {@code attck} 对象；未知返回 {@code null}
     * （控制器直接把它放进响应，Jackson 序列化为 JSON {@code null}）。
     */
    public static Map<String, Object> toMap(String ruleName) {
        Technique t = map(ruleName);
        return t == null ? null : t.toMap();
    }

    /** 映射表条目数（运维/文档口径用，测试也用它钉住"表没被清空"）。 */
    public static int ruleCount() {
        return RULES.size();
    }
}
