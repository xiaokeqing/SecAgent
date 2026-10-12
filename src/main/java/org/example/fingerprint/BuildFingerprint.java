package org.example.fingerprint;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

/**
 * jar 内固化的「构建来源」指纹 —— 从 classpath 上的 {@code git.properties} 读取。
 *
 * <h3>它解决什么问题（真实事故）</h3>
 * 本项目发生过「部署显示新版本、容器里跑的是旧代码」：老的 Dockerfile 是多阶段构建，
 * 在镜像内用<b>服务器上的旧 src</b> 编译；而 health 的 {@code buildSha} 只是容器里
 * 一个环境变量，属于<b>自述</b> —— 谁都可以把它写成新版本号，它证明不了任何事。
 *
 * <p>现在由 {@code git-commit-id-maven-plugin} 在<b>打包时</b>把 git 信息写进
 * {@code classes/git.properties}，随 jar 一起发布。于是「这个 jar 是哪个 commit 的产物」
 * 变成了 jar 自带的、可以当场读出来的证据：想改它就得改 jar，而 jar 的 MD5 又被
 * 部署脚本硬校验过（镜像内 app.jar == 上传 jar）。
 *
 * <h3>失败时的行为</h3>
 * {@code git.properties} 缺失/损坏时<b>不抛异常</b>（健康接口不该因此 500），
 * 而是返回 {@link #absent()}：所有字段为 {@code unknown}、{@link #isPresent()} 为 false。
 * 调用方（{@link FingerprintVerifier}）会据此把 health 标成 degraded ——
 * 也就是说「拿不到证据」等价于「不通过」，而不是「默认没问题」。
 */
public final class BuildFingerprint {

    /** 读取不到信息时统一用这个字面量（避免 null 在 JSON 里变成缺失字段） */
    public static final String UNKNOWN = "unknown";

    /** plugin 生成的属性文件名（放在 classes 根目录，随 jar 发布） */
    public static final String RESOURCE_NAME = "git.properties";

    private final boolean present;
    private final String commitId;
    private final String commitIdAbbrev;
    private final String branch;
    private final Boolean dirty;
    private final String buildTime;
    private final String commitTime;
    private final String commitMessageShort;
    private final String totalCommitCount;

    private BuildFingerprint(boolean present, String commitId, String commitIdAbbrev, String branch,
                             Boolean dirty, String buildTime, String commitTime,
                             String commitMessageShort, String totalCommitCount) {
        this.present = present;
        this.commitId = commitId;
        this.commitIdAbbrev = commitIdAbbrev;
        this.branch = branch;
        this.dirty = dirty;
        this.buildTime = buildTime;
        this.commitTime = commitTime;
        this.commitMessageShort = commitMessageShort;
        this.totalCommitCount = totalCommitCount;
    }

    /** 从 classpath 读取 git.properties；读不到就返回 absent()，绝不抛异常。 */
    public static BuildFingerprint load(ClassLoader classLoader) {
        ClassLoader cl = classLoader != null ? classLoader : BuildFingerprint.class.getClassLoader();
        try (InputStream in = cl.getResourceAsStream(RESOURCE_NAME)) {
            if (in == null) {
                return absent();
            }
            Properties props = new Properties();
            props.load(new InputStreamReader(in, StandardCharsets.UTF_8));
            return fromProperties(props);
        } catch (IOException | RuntimeException e) {
            // 读不了就当没有：会被上层标成 degraded，而不是假装 ok
            return absent();
        }
    }

    /** 供测试直接构造（不依赖 jar）。 */
    public static BuildFingerprint fromProperties(Properties props) {
        String full = clean(props.getProperty("git.commit.id"));
        String abbrev = clean(props.getProperty("git.commit.id.abbrev"));
        String dirtyRaw = clean(props.getProperty("git.dirty"));
        Boolean dirty = null;
        if ("true".equalsIgnoreCase(dirtyRaw)) {
            dirty = Boolean.TRUE;
        } else if ("false".equalsIgnoreCase(dirtyRaw)) {
            dirty = Boolean.FALSE;
        }
        // 短号缺失时从全长截断（宁可退化，也不要报 unknown 掩盖真实 commit）
        if (abbrev == null && full != null) {
            abbrev = full.length() > 7 ? full.substring(0, 7) : full;
        }
        return new BuildFingerprint(true, full, abbrev, clean(props.getProperty("git.branch")), dirty,
                clean(props.getProperty("git.build.time")), clean(props.getProperty("git.commit.time")),
                clean(props.getProperty("git.commit.message.short")),
                clean(props.getProperty("git.total.commit.count")));
    }

    /** jar 里没有 git.properties（或读不了）时的取值：全 unknown + present=false。 */
    public static BuildFingerprint absent() {
        return new BuildFingerprint(false, null, null, null, null, null, null, null, null);
    }

    private static String clean(String v) {
        if (v == null) {
            return null;
        }
        String t = v.trim();
        return t.isEmpty() ? null : t;
    }

    private static String orUnknown(String v) {
        return v != null ? v : UNKNOWN;
    }

    /** git.properties 是否真的读到了（false = 这个 jar 没有可用的来源证据） */
    public boolean isPresent() {
        return present;
    }

    /** 短号（git.commit.id.abbrev）—— health 里的 embeddedGitCommit */
    public String getCommitShort() {
        return orUnknown(commitIdAbbrev);
    }

    /** 全长 commit（git.commit.id） */
    public String getCommitFull() {
        return orUnknown(commitId);
    }

    public String getBranch() {
        return orUnknown(branch);
    }

    /** true/false；拿不到时为 null（health 里显示 "unknown"） */
    public Boolean getDirty() {
        return dirty;
    }

    public String getBuildTime() {
        return orUnknown(buildTime);
    }

    public String getCommitTime() {
        return orUnknown(commitTime);
    }

    public String getCommitMessageShort() {
        return orUnknown(commitMessageShort);
    }

    public String getTotalCommitCount() {
        return orUnknown(totalCommitCount);
    }
}
