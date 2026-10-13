package org.example.accesslog;

import java.util.List;
import java.util.Locale;

/**
 * 公开端点 {@code GET /api/public/webstats} 的<b>路径维度固定类别枚举</b>。
 *
 * <h3>为什么路径只能以"类别"出现（站主 2026-10-14 拍板口径①）</h3>
 * 原始 {@code path} 是<b>攻击者完全可控的字符串</b>：扫 {@code /<script>...} 或一段垃圾，
 * 第二天就会出现在博客"被扫路径 TOP"榜上 —— 那是把外部输入搬到公网页面。
 * 固定类别枚举把这条路彻底关掉：<b>公网页面上永远不会出现任何攻击者输入</b>，
 * 也不需要靠转义/清洗兜底（兜底总有漏的那一次）。
 *
 * <p>枚举必须留兜底（口径②）：{@link #OTHER_404} / {@link #OTHER_4XX} / {@link #OTHER}
 * 保证"没被认出来的扫描路径"至少被计入总量 —— 类别枚举漏掉新路径时不会漏统计，
 * 只是少了名字（这一点写在 RUNBOOK 的"已知局限"里）。
 *
 * <p>{@link #wireName()} 是<b>公开契约</b>：改名等于改接口，只许新增枚举、不许改名。
 */
public enum WebStatsCategory {

    /** 漏洞利用/路径穿越：{@code ../}、{@code %2e%2e}、{@code /etc/passwd}、{@code win.ini} 等 */
    TRAVERSAL("traversal"),
    /** {@code /.git/config}、{@code /.git/HEAD} 这类源码仓库探测 */
    DOTGIT("dotgit"),
    /** {@code /.env}、{@code /.env.bak} 这类配置/凭据文件探测 */
    DOTENV("dotenv"),
    /** WordPress 入口（含 {@code wp-login.php}、{@code wp-admin}、{@code xmlrpc.php}） */
    WP_LOGIN("wp-login"),
    /** phpMyAdmin / Adminer / {@code /pma} 这类数据库管理入口 */
    PHPMYADMIN("phpmyadmin"),
    /** 通用后台/管理面（{@code /admin}、{@code /administrator}、Tomcat {@code manager/html}、{@code phpinfo}） */
    ADMIN_PANEL("admin-panel"),
    /** 兜底：404 且不匹配任何已知类别 */
    OTHER_404("other-404"),
    /** 兜底：其余 4xx 且不匹配任何已知类别 */
    OTHER_4XX("other-4xx"),
    /** 兜底：其它状态（2xx/3xx/5xx/1xx）且不匹配任何已知类别 */
    OTHER("other");

    private final String wireName;

    WebStatsCategory(String wireName) {
        this.wireName = wireName;
    }

    /** 公开响应里出现的类别名（稳定契约） */
    public String wireName() {
        return wireName;
    }

    /** 固定顺序（= 声明顺序）：用于按 ordinal 存放计数的定长数组 */
    public static final List<WebStatsCategory> ALL = List.of(values());

    /**
     * 归类：<b>只看 path（不含查询串）+ 状态码</b>，返回值永远是本枚举之一（永不返回 null）。
     *
     * <p>判定顺序 = 具体到笼统：穿越 > dotgit > dotenv > WordPress > phpMyAdmin > 后台面 >
     * 按状态码兜底。任一命中即停，所以同一个请求只会进一个类别。
     *
     * <p>只做小写化 + 子串匹配，<b>不引入任何正则</b>：这些字符串全部来自外部输入，
     * 正则回溯是攻击者可以拿来烧 CPU 的东西（本方法在写线程上跑）。
     */
    public static WebStatsCategory classify(String rawPath, int status) {
        String p = rawPath == null ? "" : rawPath.toLowerCase(Locale.ROOT);
        if (isTraversal(p)) {
            return TRAVERSAL;
        }
        if (p.contains(".git")) {
            return DOTGIT;
        }
        if (p.contains(".env")) {
            return DOTENV;
        }
        if (p.contains("wp-login") || p.contains("wp-admin") || p.contains("wp-content")
                || p.contains("xmlrpc.php") || p.contains("wordpress")) {
            return WP_LOGIN;
        }
        if (p.contains("phpmyadmin") || p.contains("adminer") || p.contains("/pma")) {
            return PHPMYADMIN;
        }
        if (p.contains("/admin") || p.contains("administrator") || p.contains("manager/html")
                || p.contains("/console") || p.contains("phpinfo")) {
            return ADMIN_PANEL;
        }
        if (status == 404) {
            return OTHER_404;
        }
        if (status >= 400 && status <= 499) {
            return OTHER_4XX;
        }
        return OTHER;
    }

    private static boolean isTraversal(String p) {
        return p.contains("..") || p.contains("%2e%2e") || p.contains("%252e")
                || p.contains("/etc/passwd") || p.contains("/etc/shadow") || p.contains("/etc/hosts")
                || p.contains("/proc/self") || p.contains("win.ini") || p.contains("boot.ini")
                || p.contains("c:\\windows") || p.contains("c:/windows") || p.contains("/windows/system32");
    }
}
