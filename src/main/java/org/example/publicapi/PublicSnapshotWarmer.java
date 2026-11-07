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
import org.springframework.stereotype.Component;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * 公网快照的定时预聚合（原 {@code PublicApiController#warmPublicSnapshots} 的独立组件形态）。
 *
 * <p>拆分后仍然只有<b>一个</b> {@code @Scheduled} 方法：五个按域 controller 若各自带一个定时器，
 * 同一轮会重复查上游、且 {@code /home} 的最后刷新顺序会失效。
 */
@Component
public class PublicSnapshotWarmer {

    private static final Logger logger = LoggerFactory.getLogger(PublicSnapshotWarmer.class);

    private final PublicApiSupport support;
    private final PublicAlertController alertController;
    private final PublicHomeController homeController;
    private final PublicGeoController geoController;
    private final PublicMiscController miscController;

    public PublicSnapshotWarmer(PublicApiSupport support,
                                PublicAlertController alertController,
                                PublicHomeController homeController,
                                PublicGeoController geoController,
                                PublicMiscController miscController) {
        this.support = support;
        this.alertController = alertController;
        this.homeController = homeController;
        this.geoController = geoController;
        this.miscController = miscController;
    }

    /**
     * 定时预聚合：把"读 indexer + 聚合"的现算成本**从访客请求路径搬到后台**。
     *
     * <h3>它解决什么</h3>
     * 站主实测："页面打开很快，但取数慢（约 10s 才出数据）"。根因之一就是
     * <b>冷快照要现算</b>：{@code alerts} 冷 3.7s / {@code webstats} 冷 4.1s / {@code honeypot} 冷 3.8s
     * （暖态 3~5ms）。快照一旦过期，第一个到达的访客就要替所有人付这笔钱。
     * 后台每 {@code warm-interval-ms}（默认 30s）检查一遍：只要某个快照的年龄超过
     * {@code TTL × warm-threshold-ratio}（默认 45s × 0.5 = 22.5s）就主动刷新 ⇒
     * 访客侧几乎永远命中热快照（目标：源站响应 ≤50ms，无论冷暖）。
     *
     * <h3>三个刻意的设计</h3>
     * <ol>
     *   <li><b>不比原来更频繁地查上游</b>：阈值取 TTL 的一半，而不是"每 30 秒无条件重算" ——
     *       后者会把上游查询量抬到"有访客才算"的几十倍；</li>
     *   <li><b>绝不阻塞、绝不抛</b>：任何端点刷新失败只记一条 WARN，保留旧快照
     *       （{@link Snapshot#refreshIfOlderThan} 内部已兜底）；整个方法再包一层 try/catch，
     *       保证"预聚合坏掉"不会影响任何请求、也不会让定时线程崩掉；</li>
     *   <li><b>与请求侧共用同一个 Snapshot 与同一把"刷新权"</b>：后台正在刷时，请求侧立刻拿旧值，
     *       两边不会同时打上游（也天然防击穿）。</li>
     * </ol>
     *
     * <p>拆分后快照实例下沉到 {@link PublicApiSupport}、各端点 builder 分到五个按域 controller，
     * 因此定时任务单独收敛到本类：注入同一份 {@code PublicApiSupport} 与各域 controller，
     * 仍然复用同一批 Snapshot 实例（不会出现"两份缓存"）。
     */
    @Scheduled(fixedDelayString = "${app.public-api.warm-interval-ms:30000}",
            initialDelayString = "${app.public-api.warm-initial-delay-ms:10000}")
    public void warmPublicSnapshots() {
        long maxAge = Math.max(1000L, (long) (Math.max(1, support.cacheSeconds) * 1000L * Math.max(0.1d, support.warmThresholdRatio)));
        int refreshed = 0;
        refreshed += warmOne(support.overviewCache, "overview", maxAge, alertController::buildOverview);
        refreshed += warmOne(support.alertsCache, "alerts", maxAge, alertController::buildAlerts);
        refreshed += warmOne(support.honeypotCache, "honeypot", maxAge, alertController::buildHoneypot);
        refreshed += warmOne(support.auditCache, "audit", maxAge, alertController::buildAudit);
        refreshed += warmOne(support.latestCache, "latest", maxAge, alertController::buildLatest);
        refreshed += warmOne(support.geoCache, "geo", maxAge, geoController::buildGeo);
        refreshed += warmOne(support.webStatsCache, "webstats", maxAge, miscController::buildWebStats);
        /* ★2026-10-16 补：**聚合端点也必须进预聚合**。
           漏了它的后果是线上实测出来的：`/api/public/home.js` 的 P50 = **29.9 秒**（min 868ms）——
           45 秒 TTL 一过，第一个访客就要替所有人现算三块（alerts+geo+honeypot），
           而单端点那些早就被后台刷热了 ⇒ 聚合反而比单端点慢 20 倍，与本端点"省一次路程"的初衷相反。
           **顺序有讲究**：放在三个子快照之后 —— 这样 buildHome() 只是"组合三份已热快照"（毫秒级），
           若放前面，它会触发三个子快照的冷现算，把后台这一轮拖成十几秒。 */
        refreshed += warmOne(support.homeCache, "home", maxAge, homeController::buildHome);
        if (refreshed > 0) {
            logger.debug("公网快照预聚合：本轮刷新 {} 个端点（年龄阈值 {}ms）", refreshed, maxAge);
        }
    }

    /** 单个端点的预聚合：任何异常都吞掉并记 WARN —— 预聚合坏掉不许影响请求或定时线程 */
    private int warmOne(PublicApiSupport.Snapshot snapshot, String name, long maxAgeMillis, Supplier<Map<String, Object>> loader) {
        try {
            return snapshot.refreshIfOlderThan(maxAgeMillis, support.cacheSeconds, loader) ? 1 : 0;
        } catch (Exception e) {
            logger.warn("公网快照预聚合失败（{}，保留旧快照）：{}", name, e.getMessage());
            return 0;
        }
    }
}
