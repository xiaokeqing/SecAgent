package org.example.fingerprint;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 断言「jar 内固化 git 信息」这条链真的成立。
 *
 * <p>第一条测试是关键：它在<b>构建产物</b>的 classpath 上直接找 {@code git.properties}。
 * 如果哪天有人把 pom 里的 git-commit-id 插件删了、或把 generateGitPropertiesFile 关了，
 * 这条测试会红 —— 而不是等到线上 health 显示 unknown 才发现（那时候已经发布了）。
 */
class BuildFingerprintTest {

    @Test
    @DisplayName("git.properties 必须随 classes 一起产出，且 commit 短号可用")
    void gitPropertiesIsReadableFromClasspath() {
        BuildFingerprint fp = BuildFingerprint.load(BuildFingerprintTest.class.getClassLoader());

        assertThat(fp.isPresent())
                .as("classpath 上找不到 git.properties —— jar 就失去了『是哪个 commit 编的』这个证据")
                .isTrue();
        assertThat(fp.getCommitShort())
                .as("embeddedGitCommit 必须是真实的短号，不能是 unknown")
                .isNotEqualTo(BuildFingerprint.UNKNOWN)
                .matches("[0-9a-f]{7,40}");
        assertThat(fp.getCommitFull())
                .as("全长 commit 也应可用（用于和全号对照）")
                .matches("[0-9a-f]{7,40}");
        assertThat(fp.getCommitShort()).startsWith(fp.getCommitFull().substring(0, 7));
        assertThat(fp.getBuildTime()).isNotEqualTo(BuildFingerprint.UNKNOWN);
        assertThat(fp.getDirty())
                .as("git.dirty 必须能解析成布尔值（true/false 都合法，但不能是 unknown）")
                .isNotNull();
    }

    @Test
    @DisplayName("短号缺失时用全长截断，不把 unknown 当结论")
    void abbrevFallsBackToFullId() {
        Properties props = new Properties();
        props.setProperty("git.commit.id", "0123456789abcdef0123456789abcdef01234567");
        props.setProperty("git.dirty", "false");
        props.setProperty("git.branch", "main");

        BuildFingerprint fp = BuildFingerprint.fromProperties(props);

        assertThat(fp.getCommitShort()).isEqualTo("0123456");
        assertThat(fp.getDirty()).isFalse();
        assertThat(fp.getBranch()).isEqualTo("main");
        assertThat(fp.isPresent()).isTrue();
    }

    @Test
    @DisplayName("git.properties 缺失/损坏时退化为 unknown（present=false），而不是抛异常")
    void absentIsHonestUnknown() {
        BuildFingerprint fp = BuildFingerprint.absent();

        assertThat(fp.isPresent()).isFalse();
        assertThat(fp.getCommitShort()).isEqualTo(BuildFingerprint.UNKNOWN);
        assertThat(fp.getDirty()).isNull();
        assertThat(fp.getBranch()).isEqualTo(BuildFingerprint.UNKNOWN);
    }
}
