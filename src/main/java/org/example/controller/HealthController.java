package org.example.controller;

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

    @Value("${cls.mock-enabled:false}")
    private boolean clsMock;

    @Value("${prometheus.mock-enabled:false}")
    private boolean prometheusMock;

    /** 构建镜像时的 commit 短号（由 compose 通过 BUILD_SHA 注入），用于检测部署漂移 */
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

    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> result = new HashMap<>();
        result.put("status", "ok");
        result.put("application", "SecAgent");
        result.put("buildSha", buildSha);
        result.put("buildTime", buildTime);
        // 双指纹（P0-4）：不再只靠 buildSha 自述，能看出"跑的是哪个产物、哪份源码"
        result.put("sourceSha", sourceSha);
        result.put("artifactMd5", artifactMd5);
        result.put("fingerprint",
                "buildSha=声称版本(env)｜sourceSha=服务器源码｜artifactMd5=镜像内 jar MD5(最硬)");
        if (!"unknown".equals(buildSha) && "unknown".equals(artifactMd5)) {
            result.put("fingerprintWarning",
                    "缺少 artifactMd5 —— 不是服务器侧构建（或脚本未注入），无法验证产物与源码是否一致");
        }
        result.put("vectorStore", vectorStore.backend());
        result.put("documentVectors", vectorStore.count());
        result.put("logsMockEnabled", clsMock);
        result.put("alertsMockEnabled", prometheusMock);
        result.put("uptimeMs", ManagementFactory.getRuntimeMXBean().getUptime());
        return result;
    }
}
