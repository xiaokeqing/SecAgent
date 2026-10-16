package org.example.controller;

import org.example.fingerprint.BuildFingerprint;
import org.example.fingerprint.FingerprintVerifier;
import org.example.vector.VectorStoreGateway;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.lang.management.ManagementFactory;
import java.util.HashMap;
import java.util.Map;

/**
 * 通用健康检查接口（内存 / Milvus 两种模式均可用）。
 * 用于启动后确认服务、向量库后端与知识库文档数量是否正常。
 *
 * <h3>为什么健康接口要返回构建版本号</h3>
 * 这个项目真实发生过一次「部署漂移」：代码改完、测试跑过、提交也推了，
 * 但<b>忘了部署</b> —— 线上跑的还是有已知缺陷的旧镜像。
 * 更麻烦的是从外部完全看不出来：服务健康、接口正常、演示也正常，
 * 只是那些修复根本没生效。
 * <p>
 * 靠"我记得要部署"解决不了这件事（那次就是以为已经部署了）。
 * 正确做法是<b>让漂移变得可见</b>：把构建时的 commit 号注入镜像、
 * 健康接口返回它、整体检查脚本拿它跟仓库 HEAD 比对 ——
 * 不一致就直接报出来，不依赖任何人记得。
 *
 * <h3>为什么后来又要加「三方核对」</h3>
 * 上面那套只解决了「忘了部署」，解决不了更阴的一种：<b>部署了，但部署的是旧代码</b>。
 * 实测发生过 —— 老 Dockerfile 是多阶段构建，在镜像内用<b>服务器上的旧 src</b> 编译，
 * 而 {@code buildSha} 只是容器里的环境变量（自述），于是"新版本号 + 旧代码"同时成立，
 * 从外部看一切正常。
 * <p>
 * 所以现在分工明确：
 * <ul>
 *   <li>{@code buildSha}（env）= <b>自述</b>，只用于展示与对照，明确标注"非证据"；</li>
 *   <li>{@code embeddedGitCommit}（jar 内 git.properties）= <b>证据</b>，
 *       指明这个 jar 是哪个 commit 编出来的；</li>
 *   <li>{@code artifactMd5}（部署脚本注入，将来来自镜像 label）= 产物指纹；
 *       它证明跑的就是上传的那个 jar。</li>
 * </ul>
 * 三者对不上（或任何一项是 unknown）就把 {@code status} 降级为 {@code degraded}
 * 并给出 {@code fingerprintMismatchReason} —— 健康接口不再无条件说 ok。
 *
 * <h3>为什么可以放在免鉴权的健康接口里</h3>
 * 只暴露 commit 短号与构建时间，<b>不含任何敏感信息</b>。
 * 实际上"代码版本不敏感"本身就是一个判断：这套代码是开源的，
 * 提交号在 GitHub 上人人可见。
 */
@RestController
@RequestMapping("/api")
public class HealthController {

    @Autowired
    private VectorStoreGateway vectorStore;

    /** 构建镜像时的 commit 短号（由 compose 通过 BUILD_SHA 注入）—— 自述，非证据 */
    @Value("${app.build.sha:unknown}")
    private String buildSha;

    /**
     * 服务器源码树的 revision（由部署脚本注入）。
     *
     * <p>为什么要与 buildSha 分开暴露：实测出现过「buildSha 显示新版本、容器里跑的是旧代码」——
     * 因为多阶段 Dockerfile 在镜像内用**服务器上的旧 src** 编译。
     * 把"声称的版本"与"真实产物/源码指纹"分开，这类漂移才看得出来。
     */
    @Value("${app.build.source-sha:unknown}")
    private String sourceSha;

    /** 构建进镜像的 jar 的 MD5（部署脚本在服务器侧构建时算出并注入）—— 最硬的产物指纹 */
    @Value("${app.build.artifact-md5:unknown}")
    private String artifactMd5;

    /** 构建时间（由 compose 通过 BUILD_TIME 注入） */
    @Value("${app.build.time:unknown}")
    private String buildTime;

    /**
     * jar 内固化的构建来源指纹（classpath 上的 git.properties）。
     *
     * <p>只在 bean 构造时读<b>一次</b>：这东西跟着 jar 走，运行期不会变；
     * 每次请求都读盘属于无意义的 IO。
     *
     * <p>读不到时返回 absent（各字段 unknown）—— 于是 health 会自报 degraded，
     * 而不是像以前那样无条件 ok。
     */
    private final BuildFingerprint embeddedGit = BuildFingerprint.load(HealthController.class.getClassLoader());

    @GetMapping("/health")
    public Map<String, Object> health() {
        // 三方核对（纯函数）：A=artifactMd5  B=embeddedGitCommit  C=期望 release commit(BUILD_SHA)
        FingerprintVerifier.Verdict verdict =
                FingerprintVerifier.verify(artifactMd5, embeddedGit.getCommitShort(),
                        embeddedGit.getDirty(), buildSha);

        Map<String, Object> result = new HashMap<>();
        // status 不再无条件 ok：任何一项查不了/对不上，就是 degraded
        result.put("status", verdict.getStatus());
        result.put("fingerprintMismatch", verdict.isMismatch());
        if (verdict.isMismatch()) {
            result.put("fingerprintMismatchReason", verdict.getMismatchReason());
        }
        result.put("fingerprintIssues", verdict.getIssues());
        result.put("application", "SecAgent");

        // buildSha 保留，但【降级为展示用】：它是环境变量自述，谁都能写，证明不了任何事
        result.put("buildSha", buildSha);
        result.put("expectedReleaseCommit", buildSha);
        result.put("buildTime", buildTime);

        // 硬证据：来自 jar 内 git.properties（构建时固化，改不动除非改 jar）
        result.put("embeddedGitCommit", embeddedGit.getCommitShort());
        result.put("embeddedGitBranch", embeddedGit.getBranch());
        result.put("embeddedGitDirty", embeddedGit.getDirty() == null ? "unknown" : embeddedGit.getDirty());
        result.put("embeddedGitBuildTime", embeddedGit.getBuildTime());
        result.put("embeddedGitCommitTime", embeddedGit.getCommitTime());
        // 【U5 部分收口，2026-10-16】这里原本还返回 embeddedGitCommitMessage（提交标题）。
        // 它是这个端点上【最脏】的一项：提交标题里写的是内部 RUNBOOK 章节号、待办描述与
        // "别再回显口令"这类修复细节，等于把内部工程叙事挂到公网匿名端点上。
        // 为什么只删这一项、其余指纹字段保留：embeddedGitCommit / artifactMd5 /
        // fingerprintMismatch 是【部署与回滚门禁的硬校验输入】——
        // scripts/srv1-redeploy.sh 与 scripts/srv1-rollback.sh 靠它们判定"这次部署是否成功"，
        // srv1-health-watchdog.sh 读 commit，docker-compose 的 healthcheck 也打这个端点。
        // 收口成 {"status":"ok"} 会让重建后的校验直接失败并自动回滚 ⇒ 完整收口必须与
        // 这些脚本（以及站点侧的 /api/health 消费端）同批改，属独立批次。
        // 本项之所以能单独删：全仓库 + 站点侧都没有任何消费端读 embeddedGitCommitMessage。
        // （这也正是 U5 里"提交信息"那一半；"mock 开关 / documentVectors"那一半见待办 U5 备注。）
        result.put("embeddedGitPropertiesPresent", embeddedGit.isPresent());

        // 双指纹（P0-4）：不再只靠 buildSha 自述，能看出"跑的是哪个产物、哪份源码"
        result.put("sourceSha", sourceSha);
        result.put("artifactMd5", artifactMd5);
        // 【U5 收口第 2 段，2026-10-16】原本这里还有两项，均已从**匿名**端点移除：
        //   · "fingerprint"      = 一段解释"哪个字段是硬证据"的长文案（内部运行手册口径）；
        //   · "logsMockEnabled" / "alertsMockEnabled" = `${cls,prometheus}.mock-enabled`，
        //     它们是**AI 工具层的能力开关**（QueryMetricsTools/QueryLogsTools 为 true 时返回模拟
        //     数据、OutboundSelfCheck 为 true 时不发出站请求），跟"公开监控页的数据真假"无关
        //     （公开页读的是 Wazuh 真实链路，响应头 X-Data-Source=WAZUH_REAL）。
        //   但字段名会被任何看到 health 的人读成"线上在混 mock 数据" —— 这正是要收口的原因：
        //   想核这两项的人请看容器启动日志（QueryMetricsTools/QueryLogsTools 的 "Mock模式: …" 行）。
        //   为什么不加"带令牌才返回"的隐藏分支：health 是匿名端点且**没有任何限速**，
        //   那样等于给令牌校验开了一个不限速的爆破口 —— 收口不能以扩大攻击面为代价。
        result.put("vectorStore", vectorStore.backend());
        result.put("documentVectors", vectorStore.count());
        result.put("uptimeMs", ManagementFactory.getRuntimeMXBean().getUptime());
        return result;
    }
}
