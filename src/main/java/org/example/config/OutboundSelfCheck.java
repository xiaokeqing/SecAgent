package org.example.config;

import org.example.integration.wazuh.SshBlockExecutor;
import org.example.integration.wazuh.WazuhService;
import org.example.service.VectorEmbeddingService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * 出站依赖的<b>启动自检</b>：应用启动完成后，用<b>一行</b>结构化日志打印
 * 每个出站依赖的实际生效值（依赖名 / connect / read / callTimeout / 熔断冷却）。
 *
 * <h3>为什么要有它（不是日志洁癖）</h3>
 * 这个项目真实踩过的坑是"代码看着对、运行起来不生效"，而排障方式是
 * "改一处 → 部署 → 失败"循环，每次 5 分钟。根因是当时没人能回答
 * "这条链路现在实际的超时是几秒、有没有熔断" —— 只能逐个翻配置与代码。
 * <p>
 * 所以把"实际生效值"变成启动时的一行可核对日志：
 * <ul>
 *   <li>值取自真正构造客户端的对象（{@code OutboundTimeouts} / {@code DashScopeConfig}
 *       / 各客户端自己的 getter），不是"再读一遍配置"——后者在
 *       "配置改了但客户端没拿到"时会打印骗人的值；</li>
 *   <li>没配的项显式打印 {@code MISSING}，<b>绝不静默</b>：缺项本身就是需要被看见的信息
 *       （例如 DashScope SDK 的 embedding 客户端本身没有显式 connect/read 配置，只有调用层预算）。</li>
 * </ul>
 *
 * <p>做成 {@link ApplicationReadyEvent} 而不是 {@code @PostConstruct}：
 * 后者会因为 Bean 创建顺序而在部分客户端尚未构造完时打印（打印出来的是半成品值）。
 */
@Component
public class OutboundSelfCheck {

    private static final Logger logger = LoggerFactory.getLogger(OutboundSelfCheck.class);

    /** 单行日志里的标记，便于 grep/告警按它抽取 */
    public static final String MARKER = "OUTBOUND-TIMEOUTS-SELFCHECK";

    /** 缺项标记：不允许留空，缺什么就写什么 */
    public static final String MISSING = "MISSING";

    /**
     * 一个出站依赖的生效值。
     *
     * @param name           依赖名（与 OutboundGuard 的冷却 key 对齐）
     * @param connect        建连超时（含单位），缺项时以 {@link #MISSING} 开头
     * @param read           读/等待超时（含单位）
     * @param callTimeout    单次调用总预算（含单位）——必须小于入口预算
     * @param circuitBreaker 熔断/冷却：启用的写实现（OutboundGuard + 冷却时长），否则写 NONE/DISABLED
     * @param note           这条链路的用途与边界
     */
    public record Dependency(String name, String connect, String read, String callTimeout,
                            String circuitBreaker, String note) {
    }

    private final OutboundTimeouts timeouts;
    private final DashScopeConfig dashScopeConfig;
    private final VectorEmbeddingService embeddingService;
    private final SshBlockExecutor sshExecutor;
    private final WazuhService wazuhService;

    @Value("${vector.store:memory}")
    private String vectorStore;

    @Value("${milvus.timeout:10000}")
    private long milvusConnectMs;

    @Value("${prometheus.mock-enabled:true}")
    private boolean prometheusMock;

    @Value("${prometheus.timeout:10}")
    private int prometheusTimeoutSeconds;

    @Value("${app.outbound.default-cooldown-ms:60000}")
    private long cooldownMs;

    @Value("${app.outbound.max-inflight-per-dependency:2}")
    private int maxInflight;

    public OutboundSelfCheck(OutboundTimeouts timeouts,
                             DashScopeConfig dashScopeConfig,
                             VectorEmbeddingService embeddingService,
                             SshBlockExecutor sshExecutor,
                             WazuhService wazuhService) {
        this.timeouts = timeouts;
        this.dashScopeConfig = dashScopeConfig;
        this.embeddingService = embeddingService;
        this.sshExecutor = sshExecutor;
        this.wazuhService = wazuhService;
    }

    /** 启动完成即打印一次 —— 一行，可被日志采集直接抽取 */
    @EventListener(ApplicationReadyEvent.class)
    public void logEffectiveValues() {
        logger.info("{}", buildLine());
    }

    public String buildLine() {
        return render(dependencies());
    }

    /** 收集每个出站依赖的实际生效值 */
    public List<Dependency> dependencies() {
        List<Dependency> rows = new ArrayList<>();

        // ---- 1) LLM chat（DashScope）：值取自真正建 OkHttpClient 的 DashScopeConfig ----
        String chatCircuit = "cooldown(" + cooldownMs + "ms,自建)";
        rows.add(new Dependency("dashscope-chat",
                dashScopeConfig == null ? MISSING : dashScopeConfig.getEffectiveConnectTimeoutMs() + "ms",
                dashScopeConfig == null ? MISSING : dashScopeConfig.getEffectiveReadTimeoutMs() + "ms",
                dashScopeConfig == null ? MISSING : dashScopeConfig.getEffectiveCallTimeoutMs() + "ms",
                chatCircuit,
                "spring.ai.dashscope.chat.options.* → DashScopeConfig 的 OkHttp"));

        // ---- 2) LLM embedding：SDK 自身没有显式 connect/read，只有调用层预算（如实标 MISSING）----
        String embeddingCall = (embeddingService == null)
                ? MISSING : embeddingService.effectiveCallTimeoutMs() + "ms";
        rows.add(new Dependency("dashscope-embedding",
                MISSING + "(sdk默认)",
                MISSING + "(sdk默认)",
                embeddingCall,
                guardCircuit(),
                "TextEmbedding.call 的调用层有界（SDK 无显式 connect/read 配置）"));

        // ---- 3) Wazuh 管理 API / indexer：统一超时 + OutboundGuard ----
        OutboundTimeouts wazuhTimeouts = (wazuhService != null)
                ? wazuhService.effectiveOutboundTimeouts() : timeouts;
        String wazuhCircuit = (wazuhService == null)
                ? MISSING + "(Wazuh 未启用/未构造客户端)"
                : (wazuhService.outboundGuardEnabled() ? guardCircuit() : MISSING + "(守卫未接入)");
        rows.add(new Dependency("wazuh-api",
                wazuhTimeouts.getConnectTimeoutMs() + "ms",
                wazuhTimeouts.getReadTimeoutMs() + "ms",
                wazuhTimeouts.getCallTimeoutMs() + "ms",
                wazuhCircuit,
                "管理 API（JWT 登录 / active-response / manager 日志）"));
        rows.add(new Dependency("wazuh-indexer",
                wazuhTimeouts.getConnectTimeoutMs() + "ms",
                wazuhTimeouts.getReadTimeoutMs() + "ms",
                wazuhTimeouts.getCallTimeoutMs() + "ms",
                wazuhCircuit,
                "OpenSearch 告警/聚合/蜜罐查询（独立 9200 端口与凭据）"));

        // ---- 4) 公众端点里调 indexer 的那条链路：复用同一个客户端，故值相同 ----
        rows.add(new Dependency("public-indexer",
                wazuhTimeouts.getConnectTimeoutMs() + "ms",
                wazuhTimeouts.getReadTimeoutMs() + "ms",
                wazuhTimeouts.getCallTimeoutMs() + "ms",
                wazuhCircuit,
                "PublicApiController→PublicAlertSource→WazuhGateway→WazuhClient（复用 wazuh-indexer 客户端与冷却）"));

        // ---- 5) SSH 直连处置 ----
        OutboundTimeouts sshTimeouts = (sshExecutor != null) ? sshExecutor.effectiveTimeouts() : timeouts;
        String sshCircuit = (sshExecutor == null)
                ? MISSING + "(SSH 执行器缺失)"
                : (sshExecutor.guardEnabled() ? guardCircuit() : MISSING + "(守卫未接入)");
        rows.add(new Dependency("ssh-block",
                sshTimeouts.getConnectTimeoutMs() + "ms(ssh ConnectTimeout)",
                sshTimeouts.getReadTimeoutMs() + "ms(进程等待上限)",
                sshTimeouts.getCallTimeoutMs() + "ms",
                sshCircuit,
                "SSH forced command 封禁/解封（处置路径）"));

        // ---- 6) Prometheus/Alertmanager：本次部署是 mock，显式标注（不静默）----
        if (prometheusMock) {
            rows.add(new Dependency("prometheus",
                    "DISABLED(mock)",
                    "DISABLED(mock)",
                    "DISABLED(mock)",
                    "NONE",
                    "prometheus.mock-enabled=true：不发出站请求"));
        } else {
            String p = (prometheusTimeoutSeconds * 1000L) + "ms";
            rows.add(new Dependency("prometheus",
                    p, p, MISSING + "(未设 callTimeout)",
                    "NONE",
                    "真出站时只有 connect/read，无总预算封顶"));
        }

        // ---- 7) Milvus：仅 vector.store=milvus 时装配 ----
        boolean milvus = vectorStore != null && "milvus".equalsIgnoreCase(vectorStore.trim());
        if (milvus) {
            rows.add(new Dependency("milvus",
                    milvusConnectMs + "ms",
                    MISSING + "(gRPC 未显式设 read)",
                    MISSING + "(未设 callTimeout)",
                    "NONE",
                    "vector.store=milvus：gRPC 客户端，仅设了 connect 超时"));
        } else {
            rows.add(new Dependency("milvus",
                    "DISABLED(vector.store=" + vectorStore + ")",
                    "DISABLED",
                    "DISABLED",
                    "NONE",
                    "未启用 Milvus（默认 memory 向量库）"));
        }

        return rows;
    }

    private String guardCircuit() {
        return "OutboundGuard(cooldown=" + cooldownMs + "ms,halfOpen,maxInflight=" + maxInflight + ")";
    }

    /** 渲染成<b>一行</b>（不换行，避免被日志采集拆成多条） */
    public static String render(List<Dependency> deps) {
        StringBuilder sb = new StringBuilder(MARKER);
        sb.append(" deps=").append(deps.size());
        for (Dependency d : deps) {
            sb.append(" | ").append(d.name())
                    .append("{connect=").append(d.connect())
                    .append(",read=").append(d.read())
                    .append(",callTimeout=").append(d.callTimeout())
                    .append(",circuit=").append(d.circuitBreaker())
                    .append(",note=").append(d.note())
                    .append('}');
        }
        return sb.toString();
    }
}
