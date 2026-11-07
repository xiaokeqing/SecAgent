package org.example.publicapi;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.example.core.model.AlertSeverity;
import org.example.core.model.AlertSource;
import org.example.core.model.AlertType;
import org.example.core.model.SecurityAlert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

/**
 * 首屏聚合与部署可追溯域：/home、/deploy。
 *
 * <p>本类是原 {@code PublicApiController}（已删除的委托门面）拆分出的按域 controller 之一：只做搬移，路径、参数、
 * 响应字段、状态码、缓存头与限流口径与原 god controller 逐字一致。
 * 共享状态与通用工具（快照缓存、出关脱敏、信封/缓存头）在 {@link PublicApiSupport} 里，
 * 由构造器注入；历史门面 {@code PublicApiController} 已删除，测试改为直接装配这些 controller。
 */
@RestController
@RequestMapping("/api/public")
public class PublicHomeController {

    private static final Logger logger = LoggerFactory.getLogger(PublicHomeController.class);

    private final PublicApiSupport support;
    private final PublicAlertController alertController;
    private final PublicGeoController geoController;


    public PublicHomeController(PublicApiSupport support, PublicAlertController alertController, PublicGeoController geoController) {
        this.support = support;
        this.alertController = alertController;
        this.geoController = geoController;
    }

    // ==================== ① 聚合端点：一次请求拿三块（弱网收益最大的一处） ====================

    /**
     * <b>内容页聚合端点</b>：一次请求拿回 {@code alerts + geo + honeypot + audit + health} 五块。
     *
     * <h3>为什么要有它（2026-10-16 站主弱网实测的直接产物）</h3>
     * 手机热点（无代理）下首屏 TTFB ≈ 6s，而首屏要发 3 个公开请求
     * （{@code /api/public/alerts.js} + {@code geo.js} + {@code honeypot.js}）——
     * 每个请求各自付一次"客户端 → CF → 源站"的路程，三段路程串起来就是访客感知的"取数慢"。
     * 三合一后：**访客只付一次路程**，且**只消耗一份限流额度**（原来 3 个请求 = 3 次额度，
     * 20 次/分的上限被三个端点分掉）。
     *
     * <h3>口径：与单端点<b>逐字段一致</b>（不新增、不改名、不丢字段）</h3>
     * 每个子块单独过一次 {@link #ship(Map)}（因此各自带自己的 {@code ipDisclosure}），
     * 再嵌进 {@code data.alerts / data.geo / data.honeypot}。于是：
     * <pre>home.data.alerts ≡ alerts.data（逐字段相同）</pre>
     * 这条由 {@code PublicApiHomeEndpointTest} 用真实响应体断言，不靠人眼。
     *
     * <p>新鲜度三件套（{@code snapshotAt / cacheAgeSeconds / snapshotTtlSeconds}）仍在**信封层**，
     * 由 {@link #stampSnapshotFreshness(Map)} 统一盖 —— 它的值来自本端点自带快照的装载时刻
     * （{@link Snapshot#load} 在 loader 返回后打点），所以"这份聚合数据有多旧"是如实值。
     *
     * <p>缓存 / ETag / 429 / CORS 与其它端点走**同一条通路**：同一个 {@code ok(...)}、
     * 同一个别名口径（{@code max-age=45, stale-while-revalidate=300} + 按数据内容算的稳定 ETag）。
     *
     * <h3>2026-10-18 扩到五块的原因（站主实测）</h3>
     * 首屏英雄数字里最有说服力的两个数（「累计封禁」「护栏拦截」）来自 {@code /audit}，
     * {@code /status/} 页要的构建 SHA / 运行时长来自 {@code /health} —— 这两块原先都不在聚合里，
     * 于是弱网下首屏仍然要多付两次「客户端 → CF → 源站」的路程（实测每次 0.9~8 秒）。
     * 并进来后首屏只剩「HTML + 一个聚合请求」，且仍只消耗一份限流额度。
     * {@code audit} 与单端点 {@code /audit} 的 data **逐字段相同**（同一个 Snapshot、同一个 ship）；
     * {@code health} 是本控制器内可自证的那部分（构建自述 + 运行时长），不跨控制器取数。
     */
    @GetMapping({"/home", "/home.js"})
    public ResponseEntity<Map<String, Object>> home(HttpServletRequest req, HttpServletResponse res) {
        if (!support.rateLimiter.allow(support.clientIp(req))) {
            return support.tooMany(res);
        }
        return support.ok(support.homeCache.get(support.cacheSeconds, this::buildHome), res);
    }

    /**
     * 组装聚合块：三个子块各走自己的快照缓存（各自 TTL / 各自后台预聚合 / 各自失败兜底），
     * 并各自 {@link #ship(Map)} 一次 —— 这一步是"逐字段一致"的关键：
     * 单端点的 {@code ok(...)} 会给 data 补 {@code ipDisclosure}，所以子块也必须补，
     * 否则聚合里的子块会少一个字段（而少字段不会报错，只会让前端的一个字段永远读不到）。
     */
    Map<String, Object> buildHome() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("alerts", support.ship(support.alertsCache.get(support.cacheSeconds, alertController::buildAlerts)));
        out.put("geo", support.ship(support.geoCache.get(support.cacheSeconds, geoController::buildGeo)));
        out.put("honeypot", support.ship(support.honeypotCache.get(support.cacheSeconds, alertController::buildHoneypot)));
        /* audit 是**可选块**：它的上游是处置审计日志，坏了也只该少这一块。
           理由（2026-10-18 实测）：聚合端点的全部价值是"一次请求把首屏填满"，
           所以任何单个子块失败都**不许**把整次请求变成 500——否则一个封禁库读不到，
           连告警列表和地图一起黑屏，比没有聚合更糟。取不到就不放这个键，
           前端发现 `home.data.audit` 缺失会自己补拉一次 /api/public/audit（它有自己的错误态文案）。 */
        try {
            out.put("audit", support.ship(support.auditCache.get(support.cacheSeconds, alertController::buildAudit)));
        } catch (RuntimeException e) {
            logger.warn("聚合里的 audit 块取不到（首屏降级为四块，前端会补拉 /audit）：{}", e.getMessage());
        }
        out.put("health", buildHealthBlock());
        return out;
    }

    /**
     * 聚合里的 {@code health} 块：只放**本控制器能自证**的事实，不跨控制器调 {@code /api/health}。
     *
     * <p>口径与 {@code /api/health}、{@code /api/public/deploy} 一致：{@code build.*} 是
     * <b>容器自述</b>（{@code selfReported=true}），不是独立证据；{@code runtime.*} 来自进程内
     * {@code STARTED_AT_MS}，是真实的进程启动时刻。这样首屏/状态页不必再为一个版本号多打一次请求。
     */
    Map<String, Object> buildHealthBlock() {
        Map<String, Object> h = new LinkedHashMap<>();
        h.put("status", support.source.available() ? "ok" : "degraded");
        h.put("buildSha", support.buildSha);
        h.put("sourceSha", support.buildSourceSha);
        h.put("artifactMd5", support.buildArtifactMd5);
        h.put("buildTime", support.buildTime);
        h.put("selfReported", true);
        Map<String, Object> rt = new LinkedHashMap<>();
        rt.put("startedAt", Instant.ofEpochMilli(PublicApiSupport.STARTED_AT_MS)
                .atZone(ZoneId.systemDefault()).truncatedTo(ChronoUnit.SECONDS)
                .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
        rt.put("uptimeSeconds", Math.max(0, (System.currentTimeMillis() - PublicApiSupport.STARTED_AT_MS) / 1000));
        h.put("runtime", rt);
        h.put("dataSource", support.source.available() ? "WAZUH_REAL" : "UNAVAILABLE");
        return h;
    }

    // ==================== ①b 给 C2 面板线的两个只读端点 ====================

    /**
     * <b>部署可追溯</b>（C2 面板要的）：当前构建 + 容器启动时刻 + 可选的"发布信息"文件。
     *
     * <h3>为什么这些字段可信度分级写</h3>
     * {@code build.*} 来自容器环境变量与 {@code git.properties}（**自述**，health 端点已有同样口径：
     * 实测出现过"版本号是新的、容器里跑的是旧代码"，所以自述必须与证据分开写）；
     * 而 {@code release.*}（发布号/文件数/切换时刻）**在另一台机器上**（srv2 的 releases 目录），
     * 本进程读不到 ⇒ 只有在运维链把一份 JSON 落到 {@code app.public-api.deploy-file}
     * 指向的路径时才给值，否则如实 {@code available=false} + 原因，**绝不编造发布号与文件数**。
     */
    @GetMapping({"/deploy", "/deploy.js"})
    public ResponseEntity<Map<String, Object>> deploy(HttpServletRequest req, HttpServletResponse res) {
        if (!support.rateLimiter.allow(support.clientIp(req))) {
            return support.tooMany(res);
        }
        return support.ok(support.deployCache.get(support.cacheSeconds, this::buildDeploy), res);
    }

    Map<String, Object> buildDeploy() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("generatedAt", support.generatedAt());

        Map<String, Object> build = new LinkedHashMap<>();
        build.put("sha", support.buildSha);
        build.put("sourceSha", support.buildSourceSha);
        build.put("artifactMd5", support.buildArtifactMd5);
        build.put("buildTime", support.buildTime);
        build.put("selfReported", true);   // 明确标注：这几个值是"容器自述"，不是独立证据
        out.put("build", build);

        Map<String, Object> runtime = new LinkedHashMap<>();
        runtime.put("startedAt", Instant.ofEpochMilli(PublicApiSupport.STARTED_AT_MS)
                .atZone(ZoneId.systemDefault()).truncatedTo(ChronoUnit.SECONDS)
                .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
        runtime.put("uptimeSeconds", Math.max(0, (System.currentTimeMillis() - PublicApiSupport.STARTED_AT_MS) / 1000));
        out.put("runtime", runtime);

        out.put("release", readDeployFile());
        out.put("available", true);   // 构建信息恒可得；release 的可得性由 release.available 单列
        out.put("note", "build.* 是容器自述（与 /api/health 同源）；release.* 来自 app.public-api.deploy-file，"
                + "取不到就写 available=false —— 不用 0 或猜测值冒充发布信息。");
        return out;
    }

    /** 发布信息文件（可选）：只透传白名单键，未配置/缺失/坏 JSON 一律如实说不可得 */
    Map<String, Object> readDeployFile() {
        Map<String, Object> rel = new LinkedHashMap<>();
        if (support.deployFile == null || support.deployFile.isBlank()) {
            rel.put("available", false);
            rel.put("reason", "RELEASE_INFO_NOT_CONFIGURED");
            rel.put("note", "未配置 app.public-api.deploy-file（发布号在 srv2 的 releases 目录，本进程读不到）");
            return rel;
        }
        Object parsed = support.readJsonOrNull(support.deployFile);
        if (parsed == null) {
            rel.put("available", false);
            rel.put("reason", "RELEASE_INFO_UNREADABLE");
            rel.put("note", "发布信息文件不存在或不是合法 JSON：" + support.deployFile + "（不用旧值冒充新发布）");
            return rel;
        }
        if (!(parsed instanceof Map<?, ?> m)) {
            rel.put("available", false);
            rel.put("reason", "RELEASE_INFO_SHAPE");
            rel.put("note", "发布信息文件顶层必须是 JSON 对象");
            return rel;
        }
        rel.put("available", true);
        for (String k : PublicApiSupport.DEPLOY_FILE_KEYS) {
            if (m.containsKey(k)) {
                rel.put(k, m.get(k));
            }
        }
        rel.put("source", "app.public-api.deploy-file");
        return rel;
    }
}
