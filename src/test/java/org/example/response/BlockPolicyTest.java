package org.example.response;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 分级 TTL 的策略单测。
 *
 * <p>这些断言是"封多久"的合同：调参可以改 {@code response.ttl.*}，
 * 但"扫描 &lt; 爆破 &lt; 利用"这个量级关系、以及"显式时长优先"的决策顺序不能被改掉，
 * 所以测试直接盯死 {@link BlockPolicy#decide} 的返回值与依据标记。
 */
class BlockPolicyTest {

    private final BlockPolicy policy = new BlockPolicy();

    @Test
    void scanReasonFallsInto30Minutes() {
        BlockPolicy.Decision d = policy.decide(null, "端口扫描 + 目录枚举", null);
        assertThat(d.getThreatClass()).isEqualTo(BlockPolicy.ThreatClass.SCAN);
        assertThat(d.getMinutes()).isEqualTo(30);
        assertThat(d.isPolicyDerived()).isTrue();
        assertThat(d.getMinutes()).isLessThan(60);
    }

    @Test
    void bruteForceReasonFallsInto24Hours() {
        BlockPolicy.Decision d = policy.decide(null, "SSH 暴力破解：failed password 次日重试", null);
        assertThat(d.getThreatClass()).isEqualTo(BlockPolicy.ThreatClass.BRUTE_FORCE);
        assertThat(d.getMinutes()).isEqualTo(1440);
        assertThat(d.isPolicyDerived()).isTrue();
    }

    @Test
    void exploitReasonFallsInto7Days() {
        BlockPolicy.Decision d = policy.decide(null, "检测到 webshell 利用 CVE-2021-44228", null);
        assertThat(d.getThreatClass()).isEqualTo(BlockPolicy.ThreatClass.EXPLOIT);
        assertThat(d.getMinutes()).isEqualTo(10080);
        assertThat(d.isPolicyDerived()).isTrue();
    }

    @Test
    void exploitOutranksBruteForceWhenBothKeywordsPresent() {
        // "扫描之后尝试注入"必须按最严重的一档处理，否则攻击者只要先扫一下就能把封禁降级
        BlockPolicy.Decision d = policy.decide(null, "先扫描后爆破，最终注入成功", null);
        assertThat(d.getThreatClass()).isEqualTo(BlockPolicy.ThreatClass.EXPLOIT);
        assertThat(d.getMinutes()).isEqualTo(10080);
    }

    @Test
    void explicitDurationWinsAndIsMarkedNotPolicyDerived() {
        BlockPolicy.Decision d = policy.decide(45, "扫描探测", null);
        assertThat(d.getMinutes()).isEqualTo(45);
        // 关键：显式时长走人工上限，不能被当成策略派生去蹭 7 天的 policy 上限
        assertThat(d.isPolicyDerived()).isFalse();
        assertThat(d.getThreatClass()).isEqualTo(BlockPolicy.ThreatClass.SCAN);
    }

    @Test
    void unclassifiedReasonWithHighRiskFallsBackTo24Hours() {
        BlockPolicy.Decision d = policy.decide(null, "异常外联流量", "HIGH");
        assertThat(d.getThreatClass()).isEqualTo(BlockPolicy.ThreatClass.OTHER);
        assertThat(d.getMinutes()).isEqualTo(1440);
        assertThat(d.isPolicyDerived()).isTrue();
    }

    @Test
    void unclassifiedLowRiskReasonFallsBackToDefault() {
        BlockPolicy.Decision d = policy.decide(null, "异常外联流量", "LOW");
        assertThat(d.getMinutes()).isEqualTo(60);
        // null / 空白原因同样走默认档，不能因此抛异常
        assertThat(policy.decide(null, null, null).getMinutes()).isEqualTo(60);
        assertThat(policy.decide(null, "  ", null).getMinutes()).isEqualTo(60);
    }

    @Test
    void timeoutSecondsConversionIsCappedAndNeverZero() {
        assertThat(BlockPolicy.toTimeoutSeconds(10080)).isEqualTo(604800);
        assertThat(BlockPolicy.toTimeoutSeconds(Integer.MAX_VALUE)).isEqualTo(31_536_000);
        // 0/负数必须至少给 1 分钟，否则 ipset 会得到 timeout=0（立即过期）
        assertThat(BlockPolicy.toTimeoutSeconds(0)).isEqualTo(60);
        assertThat(BlockPolicy.toTimeoutSeconds(-5)).isEqualTo(60);
    }

    @Test
    void threatClassTokensAreSafeForServerScript() {
        // token 会被拼进 forced command 的 reason 参数，服务端只认这个字符集；
        // 改 token 时若忘了同步脚本正则，这条会立刻失败
        for (BlockPolicy.ThreatClass c : BlockPolicy.ThreatClass.values()) {
            assertThat(BlockCommands.reasonSlug(c.getToken())).isEqualTo(c.getToken());
            assertThat(c.getToken()).matches("^[a-z0-9][a-z0-9._-]{0,31}$");
        }
    }
}
