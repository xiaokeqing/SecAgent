package org.example.fingerprint;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * health 的「三方核对」逻辑（纯函数，方便单测，不依赖 Spring 上下文）。
 *
 * <h3>三方是哪三方</h3>
 * <ul>
 *   <li><b>A</b> = {@code artifactMd5}：镜像内产物指纹（来自部署脚本注入，将来来自镜像 label）。
 *       它证明「跑的就是上传的那个 jar」。</li>
 *   <li><b>B</b> = {@code embeddedGitCommit}：jar 内 git.properties 固化的 commit。
 *       它证明「这个 jar 是哪个 commit 编出来的」。</li>
 *   <li><b>C</b> = 期望的 release commit（环境变量 {@code app.build.sha} / {@code BUILD_SHA}）。
 *       它是「本次应该发布哪个版本」的对照基准。</li>
 * </ul>
 *
 * <p>A 单独存在时只能说明「产物没被换」，B/C 一起才能说明「版本对不对」。三者都成立才判 ok。
 *
 * <h3>为什么要 fail-closed（宁可疑，不许错觉）</h3>
 * 事故的形状就是「一切看起来正常」：服务健康、接口正常，只有代码是旧的。
 * 所以这里的原则是：<b>任何一项查不了（unknown / 缺失），都算不通过</b>，
 * 而不是「没证据就算默认没问题」。status 因此不再无条件 ok。
 */
public final class FingerprintVerifier {

    public static final String UNKNOWN = "unknown";

    private FingerprintVerifier() {
    }

    /**
     * @param artifactMd5    A：镜像内 jar MD5（未知传 null / "" / "unknown"）
     * @param embeddedCommit B：jar 内固化的 commit 短号（未知传 null / "" / "unknown"）
     * @param embeddedDirty  构建时工作区是否 dirty；未知传 null
     * @param expectedCommit C：期望 release commit（未注入传 null / "" / "unknown"）
     */
    public static Verdict verify(String artifactMd5, String embeddedCommit, Boolean embeddedDirty,
                                 String expectedCommit) {
        List<String> issues = new ArrayList<>();
        boolean mismatch = false;
        String mismatchReason = "";

        boolean bKnown = isKnown(embeddedCommit);
        boolean cKnown = isKnown(expectedCommit);

        if (!bKnown) {
            mismatch = true;
            mismatchReason = "jar 内没有可用的 commit 指纹（embeddedGitCommit="
                    + orUnknown(embeddedCommit) + "）—— 无法证明这个 jar 是哪个 commit 编出来的";
        } else if (!cKnown) {
            mismatch = true;
            mismatchReason = "期望 release commit 未注入（BUILD_SHA=" + orUnknown(expectedCommit)
                    + "）—— 没有对照基准，不能判定版本一致";
        } else if (!sameCommit(embeddedCommit, expectedCommit)) {
            mismatch = true;
            mismatchReason = "jar 内固化的 commit（" + embeddedCommit.trim()
                    + "）≠ 期望 release commit（" + expectedCommit.trim()
                    + "）—— 部署的产物与目标版本不是同一个 commit";
        }
        if (mismatch) {
            issues.add(mismatchReason);
        }

        // 只有拿得到 git.properties 时才谈 dirty；拿不到已由上面的 mismatch 覆盖
        if (bKnown) {
            if (embeddedDirty == null) {
                issues.add("embeddedGitDirty=unknown —— 无法确认构建时工作区是否干净");
            } else if (embeddedDirty) {
                issues.add("构建时工作区是 dirty 的（embeddedGitDirty=true）——"
                        + " jar 里含未提交改动，不能等价于任何一个 commit");
            }
        }

        if (!isKnown(artifactMd5)) {
            issues.add("artifactMd5（A）缺失 —— 无法核对镜像内产物与上传 jar，三方核对不成立");
        } else if (!artifactMd5.trim().toLowerCase().matches("[0-9a-f]{32}")) {
            issues.add("artifactMd5（A）不是 32 位十六进制（" + artifactMd5.trim()
                    + "）—— 产物指纹形状不对，不能当作证据");
        }

        return new Verdict(mismatch, mismatchReason, Collections.unmodifiableList(issues));
    }

    /** 是否是一个「已知」的值（null / 空 / unknown 都算未知） */
    public static boolean isKnown(String v) {
        return v != null && !v.trim().isEmpty() && !UNKNOWN.equalsIgnoreCase(v.trim());
    }

    /**
     * 两个 commit 是否指同一个提交。
     * 允许「全号 vs 短号」这种长度差异（短号至少 7 位，避免 "d0" 之类的巧合前缀）。
     */
    public static boolean sameCommit(String a, String b) {
        if (!isKnown(a) || !isKnown(b)) {
            return false;
        }
        String x = a.trim().toLowerCase();
        String y = b.trim().toLowerCase();
        if (x.equals(y)) {
            return true;
        }
        return (x.length() >= 7 && y.startsWith(x)) || (y.length() >= 7 && x.startsWith(y));
    }

    private static String orUnknown(String v) {
        return isKnown(v) ? v.trim() : UNKNOWN;
    }

    /** 核对结果：status / mismatch / 原因；issues 为空才允许 status=ok。 */
    public static final class Verdict {

        private final boolean mismatch;
        private final String mismatchReason;
        private final List<String> issues;

        Verdict(boolean mismatch, String mismatchReason, List<String> issues) {
            this.mismatch = mismatch;
            this.mismatchReason = mismatchReason;
            this.issues = issues;
        }

        public boolean isMismatch() {
            return mismatch;
        }

        public String getMismatchReason() {
            return mismatchReason;
        }

        public List<String> getIssues() {
            return issues;
        }

        public boolean isDegraded() {
            return !issues.isEmpty();
        }

        /** "ok" 只在三项全部成立时出现；否则 "degraded"。 */
        public String getStatus() {
            return issues.isEmpty() ? "ok" : "degraded";
        }
    }
}
