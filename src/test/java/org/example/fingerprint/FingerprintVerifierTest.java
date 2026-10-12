package org.example.fingerprint;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 三方核对规则的矩阵测试。
 *
 * <p>重点不是"能不能判 ok"，而是<b>任何一项缺失/对不上时都不会判 ok</b> ——
 * 事故的形态恰恰是"一切看起来正常"。
 */
class FingerprintVerifierTest {

    private static final String MD5 = "0d635ec82ea214b45e9a5ab73ba69a9b";
    private static final String COMMIT = "d0a3104";

    @Test
    @DisplayName("三项一致且工作区干净 → status=ok、fingerprintMismatch=false")
    void allConsistentIsOk() {
        FingerprintVerifier.Verdict v =
                FingerprintVerifier.verify(MD5, COMMIT, Boolean.FALSE, COMMIT);

        assertThat(v.getStatus()).isEqualTo("ok");
        assertThat(v.isMismatch()).isFalse();
        assertThat(v.getIssues()).isEmpty();
    }

    @Test
    @DisplayName("全长 commit 与短号指同一提交 → 仍算一致（不因长度差异误报）")
    void fullAndShortAreSameCommit() {
        FingerprintVerifier.Verdict v = FingerprintVerifier.verify(
                MD5, "d0a3104", Boolean.FALSE, "d0a3104ced410e44fe8a717c8fc8a18487cf43f8");

        assertThat(v.getStatus()).isEqualTo("ok");
        assertThat(v.isMismatch()).isFalse();
    }

    @Test
    @DisplayName("B≠C（部署的 jar 不是目标 commit）→ mismatch=true 且 degraded")
    void commitMismatchIsCaught() {
        FingerprintVerifier.Verdict v =
                FingerprintVerifier.verify(MD5, "6203642", Boolean.FALSE, COMMIT);

        assertThat(v.isMismatch()).isTrue();
        assertThat(v.getStatus()).isEqualTo("degraded");
        assertThat(v.getMismatchReason()).contains("6203642").contains(COMMIT);
    }

    @Test
    @DisplayName("B=unknown（jar 里没有 git.properties）→ mismatch=true 且 degraded")
    void unknownEmbeddedCommitIsCaught() {
        FingerprintVerifier.Verdict v =
                FingerprintVerifier.verify(MD5, "unknown", Boolean.FALSE, COMMIT);

        assertThat(v.isMismatch()).isTrue();
        assertThat(v.getStatus()).isEqualTo("degraded");
        assertThat(v.getMismatchReason()).contains("无法证明");
    }

    @Test
    @DisplayName("C 未注入（没有对照基准）→ 不许判 ok")
    void missingExpectedCommitIsCaught() {
        FingerprintVerifier.Verdict v =
                FingerprintVerifier.verify(MD5, COMMIT, Boolean.FALSE, "unknown");

        assertThat(v.isMismatch()).isTrue();
        assertThat(v.getStatus()).isEqualTo("degraded");
    }

    @Test
    @DisplayName("dirty=true（jar 里混了未提交改动）→ degraded")
    void dirtyBuildIsDegraded() {
        FingerprintVerifier.Verdict v =
                FingerprintVerifier.verify(MD5, COMMIT, Boolean.TRUE, COMMIT);

        assertThat(v.getStatus()).isEqualTo("degraded");
        assertThat(v.getIssues()).anySatisfy(s -> assertThat(s).contains("dirty"));
    }

    @Test
    @DisplayName("A 缺失（artifactMd5=unknown）→ 三方核对不成立，degraded")
    void missingArtifactMd5IsDegraded() {
        FingerprintVerifier.Verdict v =
                FingerprintVerifier.verify("unknown", COMMIT, Boolean.FALSE, COMMIT);

        assertThat(v.getStatus()).isEqualTo("degraded");
        assertThat(v.getIssues()).anySatisfy(s -> assertThat(s).contains("artifactMd5"));
    }

    @Test
    @DisplayName("A 形状不对（不是 32 位 hex）→ 不当证据用，degraded")
    void malformedArtifactMd5IsDegraded() {
        FingerprintVerifier.Verdict v =
                FingerprintVerifier.verify("not-a-md5", COMMIT, Boolean.FALSE, COMMIT);

        assertThat(v.getStatus()).isEqualTo("degraded");
        assertThat(v.getIssues()).anySatisfy(s -> assertThat(s).contains("32 位十六进制"));
    }

    @Test
    @DisplayName("dirty 未知（读不到 git.dirty）→ 也不能判 ok")
    void unknownDirtyIsDegraded() {
        FingerprintVerifier.Verdict v =
                FingerprintVerifier.verify(MD5, COMMIT, null, COMMIT);

        assertThat(v.getStatus()).isEqualTo("degraded");
        assertThat(v.getIssues()).anySatisfy(s -> assertThat(s).contains("embeddedGitDirty=unknown"));
    }

    @Test
    @DisplayName("sameCommit：unknown 与 unknown 不算一致；短于 7 位的前缀不算一致")
    void sameCommitRejectsWeakMatches() {
        assertThat(FingerprintVerifier.sameCommit("unknown", "unknown")).isFalse();
        assertThat(FingerprintVerifier.sameCommit(null, "d0a3104")).isFalse();
        assertThat(FingerprintVerifier.sameCommit("", "d0a3104")).isFalse();
        assertThat(FingerprintVerifier.sameCommit("d0", "d0a3104")).isFalse();
        assertThat(FingerprintVerifier.sameCommit("d0a3104", "d0a3104")).isTrue();
        assertThat(FingerprintVerifier.sameCommit("D0A3104", "d0a3104")).isTrue();
    }
}
