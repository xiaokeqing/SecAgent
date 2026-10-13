package org.example.publicapi;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 公开面「IP 显示口径」的<b>唯一开关读取点</b>（共用工具类）。
 *
 * <h3>它存在的唯一理由：口径只能有一个来源</h3>
 * 站主 2026-10-14 拍板：公开面<b>显示观测到的真实来源 IP</b>，不再硬掩码。
 * 但"要不要掩码"这件事一旦在多个端点里各写一遍，就必然出现第三种口径 ——
 * 例如 {@code /alerts} 已经是真实 IP，而 {@code /honeypot} 还在掩码，
 * 公网页面上就会出现"同一个攻击源，一个页面看得见、一个页面看不见"，
 * 而<b>这种不一致不会报错</b>，只会让"公开面到底给了什么"变得没人说得清。
 *
 * <p>所以本类是<b>所有</b>公开端点（含后加的 {@code /api/public/geo}）读取开关的
 * 唯一入口：配置项 {@code app.public.mask-ips}（默认 <b>{@code false} = 显示真实 IP</b>）
 * 只在这里被读一次；其余代码一律调 {@link #display(String)} /
 * {@link #displayText(String)} / {@link #disclosure()}。
 *
 * <h3>两种口径的精确语义</h3>
 * <table border="1">
 *   <tr><th>开关</th><th>结构化 IP 字段</th><th>自由文本里的 IP</th><th>{@code ipDisclosure.masked}</th></tr>
 *   <tr><td>{@code true}（掩码态）</td>
 *       <td>与改造前<b>逐字节一致</b>：{@code 45.205.***.***}、内网 →「内部地址」、认不出 → {@code ***}</td>
 *       <td>与改造前一致：{@link PublicIpMask#maskAll}</td><td>{@code true}</td></tr>
 *   <tr><td>{@code false}（默认，真实态）</td>
 *       <td>观测到的真实 IP；内网/保留/链路地址 →「内网/未知」；认不出 →「未知」</td>
 *       <td>公网 IP 原样保留，<b>内网/保留地址仍然换成「内网/未知」</b></td><td>{@code false}</td></tr>
 * </table>
 *
 * <h3>为什么真实态还要单独处理内网地址</h3>
 * "显示真实来源 IP"的对象是<b>攻击源</b>。{@code 127.0.0.1} / {@code 172.18.0.1} /
 * {@code 10.0.0.10} 这些是链路与内网地址，它们出现在公开响应里不叫"透明"，叫"白送内网拓扑"，
 * 而且会误导读者以为内网机器在攻击我们。所以真实态下这类值一律写成「内网/未知」——
 * 这一条与开关无关，永远不会被打开。
 *
 * <h3>缺 bean 时为什么按"掩码"兜底（fail-closed）</h3>
 * 单测里经常直接 {@code new PublicApiController()} / {@code new PublicOutputGuard()}，
 * 没有 Spring 注入。此时字段初值是 {@code maskIps = true}（掩码），
 * 也就是说<b>代码层的兜底方向是"少给"</b>，而<b>配置层的默认值是"给全"</b>
 * （{@code app.public.mask-ips} 缺省 = {@code false}）。
 * 两者不矛盾：运行中的应用一定走配置（Spring 注入），
 * 兜底只服务于"没有配置也别忘了保守"这种场景。
 */
@Component
public class PublicIpPolicy {

    /** 公开响应里统一的口径字段名（所有公开端点同一位置、同一形状） */
    public static final String DISCLOSURE_FIELD = "ipDisclosure";

    /** 口径原文（站主给定；掩码态与真实态用同一句，避免"两个口径两句话"） */
    public static final String NOTICE = "观测到的来源地址，未经验证，仅供参考";

    /** 认不出来的取值在真实态下的写法（不猜、不原样透出） */
    public static final String UNKNOWN_LABEL = "未知";

    /** 移除 / 更正入口的默认值（站主可改：真实邮箱或博客关于页 URL） */
    public static final String DEFAULT_REMOVAL_CONTACT = "https://xiaokeqing.cn/about/";

    /**
     * 是否掩码。配置为 {@code app.public.mask-ips}，默认 {@code false}（显示真实 IP）。
     *
     * <p>字段初值刻意写成 {@code true}：没有 Spring 注入（直接 new / 单测）时按掩码兜底，
     * 见类注释"缺 bean 时为什么按掩码兜底"。
     */
    @Value("${app.public.mask-ips:false}")
    private boolean maskIps = true;

    /** 口径里的"移除/更正"入口（站主给定的邮箱或关于页 URL） */
    @Value("${app.public.removal-contact:" + DEFAULT_REMOVAL_CONTACT + "}")
    private String removalContact = DEFAULT_REMOVAL_CONTACT;

    /** 掩码态（与改造前行为逐字节一致） */
    public static PublicIpPolicy masking() {
        return of(true);
    }

    /** 真实态（站主拍板的默认口径） */
    public static PublicIpPolicy revealing() {
        return of(false);
    }

    /** 显式指定口径（单测用；生产一律由 Spring 注入配置值） */
    public static PublicIpPolicy of(boolean maskIps) {
        PublicIpPolicy p = new PublicIpPolicy();
        p.maskIps = maskIps;
        p.removalContact = DEFAULT_REMOVAL_CONTACT;
        return p;
    }

    /** @return true = 掩码态 */
    public boolean masked() {
        return maskIps;
    }

    public String removalContact() {
        return (removalContact == null || removalContact.isBlank())
                ? DEFAULT_REMOVAL_CONTACT : removalContact.trim();
    }

    /**
     * 结构化 IP 字段的唯一出口。
     *
     * @param ip 原始取值（可能带端口、可能为 null/空白、可能根本不是 IP）
     * @return 掩码态：{@link PublicIpMask#mask(String)} 的结果（与改造前逐字节一致）；
     *         真实态：观测到的真实 IP（不含端口）；内网/保留/链路 →「内网/未知」；
     *         null/空白/认不出 →「未知」
     */
    public String display(String ip) {
        if (maskIps) {
            return PublicIpMask.mask(ip);
        }
        if (ip == null || ip.isBlank()) {
            return UNKNOWN_LABEL;
        }
        String host = PublicIpMask.host(ip);
        if (host == null || host.isBlank()) {
            return UNKNOWN_LABEL;
        }
        if (PublicIpMask.isInternalAddress(host)) {
            return PublicIpMask.INTERNAL_UNKNOWN_LABEL;
        }
        if (!PublicIpMask.isIpLiteral(host)) {
            // 不是 IP 就不猜：公开面上宁可写「未知」，也不把一个来路不明的字符串当来源地址展示
            return UNKNOWN_LABEL;
        }
        return host;
    }

    /**
     * 自由文本（规则描述、处置原因、知识库片段）里 IP 的唯一出口。
     *
     * @param text 任意文本（可为 null）
     * @return 掩码态：{@link PublicIpMask#maskAll}；真实态：只把内网/保留地址换成「内网/未知」
     */
    public String displayText(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        return maskIps ? PublicIpMask.maskAll(text) : PublicIpMask.maskInternalOnly(text);
    }

    /**
     * 统一口径字段 {@value #DISCLOSURE_FIELD}。
     *
     * <p>形状固定三键（页面只要读它就能渲染，不需要知道开关细节）：
     * <pre>
     *   {"masked":false,"notice":"观测到的来源地址，未经验证，仅供参考","removalContact":"https://..."}
     * </pre>
     * {@code masked=true} 时"展示的是网段掩码、不是真实地址"，页面据此换措辞。
     */
    public Map<String, Object> disclosure() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("masked", maskIps);
        m.put("notice", NOTICE);
        m.put("removalContact", removalContact());
        return m;
    }
}
