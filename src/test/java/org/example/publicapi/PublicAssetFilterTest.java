package org.example.publicapi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 内部资产名停用词过滤（{@link PublicAssetFilter}）的测试。
 *
 * <h3>防的是什么（实测泄露过的形状）</h3>
 * 字段白名单能挡掉结构化的 {@code dstAsset}，但挡不住资产名出现在<b>自由文本</b>里，
 * 而 F5 方案 B 会把命中的知识库引用片段<b>直出到公开回答的正文里</b> ——
 * 实测 {@code web-01} / {@code auth.log} / {@code /api/order/detail} 就是这么出去的。
 * 这一层的失效同样不报错：接口 200、内容看起来还挺专业。
 */
class PublicAssetFilterTest {

    private final PublicAssetFilter filter = PublicAssetFilter.defaults();

    @Test
    @DisplayName("默认词表命中实测泄露过的资产名/日志名/接口路径")
    void defaultTermsAreScrubbed() {
        String raw = "web-01 上发现大量失败登录，请查 auth.log，并确认 /api/order/detail 是否需要鉴权；"
                + "备份在 /upload/files/ 下。";

        String out = filter.scrub(raw);

        for (String bad : List.of("web-01", "auth.log", "/api/order/detail", "/upload/files/")) {
            assertFalse(out.contains(bad), "内部标识「" + bad + "」不得出现在公开文本里：" + out);
        }
        assertTrue(out.contains(PublicAssetFilter.PLACEHOLDER), "应替换成占位符：" + out);
        assertTrue(out.contains("上发现大量失败登录"), "句子结构要保留（不是整段删掉）：" + out);
    }

    @Test
    @DisplayName("大小写不敏感：WEB-01 / Auth.Log 同样命中")
    void caseInsensitive() {
        String out = filter.scrub("主机 WEB-01 的 Auth.Log 里有记录");
        assertFalse(out.contains("WEB-01"));
        assertFalse(out.toLowerCase().contains("auth.log"), out);
    }

    @Test
    @DisplayName("干净文本零改动（引用同一对象，便于断言「没动过」）")
    void cleanTextIsUntouched() {
        String raw = "SSH 暴力破解的防护建议：限制重试次数、启用密钥登录、封禁高频来源。";
        assertSame(raw, filter.scrub(raw), "没有命中时不应产生新字符串");
        assertEquals(raw, filter.scrub(raw));
    }

    @Test
    @DisplayName("词表从配置来（自定义词表生效；≤2 字符的词被忽略，避免大面积误伤）")
    void termsComeFromConfig() {
        PublicAssetFilter custom = PublicAssetFilter.of("internal-host, 支付网关 ,ab,,");

        assertEquals(List.of("internal-host", "支付网关"), custom.terms(), "词表应去空白、去重、忽略过短词、长的在前");
        assertFalse(custom.scrub("internal-host 的登录异常").contains("internal-host"));
        assertTrue(custom.scrub("internal-host 的登录异常").contains(PublicAssetFilter.PLACEHOLDER));
        assertEquals("web-01", custom.scrub("web-01"), "自定义词表不该夹带默认词");
    }

    @Test
    @DisplayName("空词表 = 不过滤（显式关掉是可运维的，不是静默失效）")
    void emptyBlocklistDisablesScrubbing() {
        PublicAssetFilter none = PublicAssetFilter.of("");
        assertTrue(none.terms().isEmpty());
        assertEquals("web-01 auth.log", none.scrub("web-01 auth.log"));
    }

    @Test
    @DisplayName("null / 空输入不抛异常（公开端点不该因为空字段 500）")
    void handlesNullAndEmpty() {
        assertEquals(null, filter.scrub(null));
        assertEquals("", filter.scrub(""));
    }
}
