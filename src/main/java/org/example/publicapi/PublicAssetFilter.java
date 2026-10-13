package org.example.publicapi;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 公开响应的<b>内部资产名停用词过滤</b>（"永不公开"清单里第 ② 条的执行点）。
 *
 * <h3>为什么需要这一层（不是洁癖，是实测漏过）</h3>
 * 公开端点的字段白名单能把 {@code dstAsset} 这类<b>结构化</b>字段挡掉，
 * 但拦不住它们出现在<b>自由文本</b>里：
 * <ul>
 *   <li>知识库片段（F5 方案 B 会把命中的片段<b>直出到回答正文</b>）里写着
 *       {@code web-01 上发现大量登录失败}、{@code 查 auth.log}、
 *       {@code /api/order/detail 未鉴权} —— 实测这些 mock 名随引用直接出到了公网页面上；</li>
 *   <li>告警标题 / 规则名 / 蜜罐时间线 detail 里同样可能带资产名。</li>
 * </ul>
 * 字段白名单解决不了"文本里出现了什么"，所以这里再加一层词表过滤，
 * 并且做成 <b>deep-scrub</b>：{@code PublicApiController} 出海前对整棵响应树扫一遍
 * （见其 {@code ship(...)}），公开包里的每个端点自动获得这层保护，
 * 将来新增端点也不会因为"忘了调过滤"而漏。
 *
 * <h3>词表从配置读（可运维，不用改代码重部署）</h3>
 * {@code app.public.asset-blocklist}（逗号分隔，环境变量 {@code APP_PUBLIC_ASSET_BLOCKLIST}）。
 * 默认值是"实测泄露过的那些名字"，不是想象的清单。
 *
 * <p>为什么用<b>停用词替换</b>而不是"整段丢弃"：公开知识与战报的可读性也是需求，
 * 把 {@code 查 auth.log 里的失败登录} 整句删掉，读者只会以为内容丢了；
 * 换成 {@code 查 [内部标识已脱敏] 里的失败登录} 既说明"这里有意隐去"，又保留句子结构。
 */
@Component
public class PublicAssetFilter {

    /** 替换后的占位符（读起来是"这里被有意隐去"，而不是空白） */
    public static final String PLACEHOLDER = "[内部标识已脱敏]";

    /**
     * 默认词表 = <b>实测泄露过</b>的内部资产名 / 内部日志名 / 内部接口路径。
     *
     * <p>刻意<b>不</b>收 {@code srv1} / {@code srv2}：公开端点本来就靠这两个 id 说明
     * "两台服务器在线状态"（{@code /api/public/overview} 的 nodes），把它们过滤掉等于改口径，
     * 而这次改造的硬约束是"只许新增字段，不许改既有语义"。
     */
    public static final String DEFAULT_TERMS =
            "web-01,web-02,web-03,db-01,auth.log,/api/order/detail,/upload/files/";

    @Value("${app.public.asset-blocklist:" + DEFAULT_TERMS + "}")
    private String rawTerms = DEFAULT_TERMS;

    /** 词表（已去重、已排序：长的在前，避免短词先命中把长词切碎） */
    private volatile List<String> terms;

    /** 词表对应的正则（与 {@link #terms} 同一把锁下更新，避免"词表和正则不是同一份"） */
    private volatile Pattern compiled;

    /** 由显式词表构造（单测用；生产走 Spring 注入配置） */
    public static PublicAssetFilter of(String csv) {
        PublicAssetFilter f = new PublicAssetFilter();
        f.rawTerms = csv;
        return f;
    }

    /** 默认词表的实例（供没有注入的场景兜底，例如单测里直接 new 出来的护栏） */
    public static PublicAssetFilter defaults() {
        return of(DEFAULT_TERMS);
    }

    /** 当前生效的词表（只读，便于启动自检/排障时打印） */
    public List<String> terms() {
        if (terms == null) {
            synchronized (this) {
                if (terms == null) {
                    List<String> t = parse(rawTerms);
                    compiled = t.isEmpty() ? null : pattern(t);
                    terms = t;                       // 最后赋值：读线程看到非 null 时正则一定已就绪
                }
            }
        }
        return terms;
    }

    /**
     * 把文本里出现的内部资产名替换为 {@value #PLACEHOLDER}。
     *
     * @param text 任意文本（null / 空返回原值）
     * @return 过滤后的文本；没有命中时<b>原样返回同一个字符串</b>（保证"干净文本零改动"）
     */
    public String scrub(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        terms();
        Pattern p = compiled;
        if (p == null) {
            return text;
        }
        Matcher m = p.matcher(text);
        if (!m.find()) {
            return text;
        }
        return m.replaceAll(Matcher.quoteReplacement(PLACEHOLDER));
    }

    // ==================== 内部工具 ====================

    private static List<String> parse(String csv) {
        LinkedHashSet<String> set = new LinkedHashSet<>();
        if (csv != null) {
            for (String s : csv.split(",")) {
                String v = s.trim();
                // 太短的词（≤2 字符）会造成大面积误伤，直接忽略并留给配置的人自己发现
                if (v.length() >= 3) {
                    set.add(v);
                }
            }
        }
        List<String> out = new ArrayList<>(set);
        out.sort((a, b) -> Integer.compare(b.length(), a.length()));
        return List.copyOf(out);
    }

    private static Pattern pattern(List<String> terms) {
        StringBuilder sb = new StringBuilder("(?i)(");
        for (int i = 0; i < terms.size(); i++) {
            if (i > 0) {
                sb.append('|');
            }
            sb.append(Pattern.quote(terms.get(i)));
        }
        return Pattern.compile(sb.append(')').toString());
    }
}
