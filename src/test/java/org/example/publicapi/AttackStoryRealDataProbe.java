package org.example.publicapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.aggregation.AlertAggregationService;
import org.example.config.OutboundTimeouts;
import org.example.integration.wazuh.WazuhClient;
import org.example.integration.wazuh.WazuhService;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 一次性工具：<b>用真实索引器（只读）跑一遍两个故事线端点</b>，把原始响应打到 stdout。
 *
 * <p>类名不以 Test 结尾 → surefire 默认不会扫到它。运行方式（凭据只在环境变量里，不进仓库）：
 * <pre>
 *   STORY_IDX_URL=https://127.0.0.1:19200 STORY_IDX_USER=... STORY_IDX_PASS=... \
 *   STORY_AUDIT_DIR=/tmp/audit mvn -B test -Dtest=AttackStoryRealDataProbe -DfailIfNoTests=false
 * </pre>
 * 这不是 CI 测试：它依赖一份真实索引器 + 一条只读隧道，CI 里没有这些东西。
 * 它存在的意义是让"这个端点到底能不能串起真实数据"这句话有可复现的证据（见 RUNBOOK §32）。
 */
class AttackStoryRealDataProbe {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void probe() throws Exception {
        String indexerUrl = System.getenv("STORY_IDX_URL");
        if (indexerUrl == null || indexerUrl.isBlank()) {
            System.out.println("PROBE SKIPPED：未设置 STORY_IDX_URL（这是预期行为，CI 里不跑）");
            return;
        }
        String user = System.getenv().getOrDefault("STORY_IDX_USER", "admin");
        String pass = System.getenv().getOrDefault("STORY_IDX_PASS", "");
        String auditDir = System.getenv().getOrDefault("STORY_AUDIT_DIR", "data");

        // 只读客户端：管理 API 的地址给个占位（本探测只用 indexer 的 _search）
        WazuhClient client = new WazuhClient("https://localhost:55000", "probe", "probe", false,
                OutboundTimeouts.defaults(), null, indexerUrl, user, pass);
        WazuhService gateway = new WazuhService();
        ReflectionTestUtils.setField(gateway, "client", client);
        ReflectionTestUtils.setField(gateway, "available", true);
        ReflectionTestUtils.setField(gateway, "enabled", true);
        // ⚠️ 必须显式补上这一条：没有 Spring 容器时 @Value 不会注入，srcIpFields() 会退回单字段
        // "data.srcip" —— 于是 Suricata/蜜罐那一半来源（data.src_ip）整个消失，
        // 而且【不会报错】：故事线上只看到主机侧那几条。这正是本项目反复踩的"少了一半还不报错"。
        ReflectionTestUtils.setField(gateway, "srcIpFieldsConfig",
                System.getenv().getOrDefault("STORY_SRC_IP_FIELDS", "data.srcip,data.src_ip"));

        PublicAlertSource source = new PublicAlertSource();
        ReflectionTestUtils.setField(source, "wazuhGateway", gateway);
        ReflectionTestUtils.setField(source, "aggregator", new AlertAggregationService());

        PublicAuditReader audit = new PublicAuditReader();
        ReflectionTestUtils.setField(audit, "dataDir", Path.of(auditDir).toAbsolutePath().toString());
        System.out.println("PROBE auditStatus = " + audit.status());
        System.out.println("PROBE indexer = " + indexerUrl + "  auditDir = " + Path.of(auditDir).toAbsolutePath());

        AttackStoryService story = new AttackStoryService();
        ReflectionTestUtils.setField(story, "source", source);
        ReflectionTestUtils.setField(story, "auditReader", audit);
        ReflectionTestUtils.setField(story, "ipPolicy", PublicIpPolicy.revealing());
        ReflectionTestUtils.setField(story, "cacheSeconds", 15);
        ReflectionTestUtils.setField(story, "topSources", 50);
        ReflectionTestUtils.setField(story, "maxEventsPerStage", 20);
        ReflectionTestUtils.setField(story, "maxLimit", 20);
        ReflectionTestUtils.setField(story, "selfIps", System.getenv().getOrDefault("STORY_SELF_IPS", ""));

        PublicApiController c = new PublicApiController();
        PublicRateLimiter limiter = new PublicRateLimiter();
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 200);
        ReflectionTestUtils.setField(c, "rateLimiter", limiter);
        ReflectionTestUtils.setField(c, "cacheSeconds", 15);
        ReflectionTestUtils.setField(c, "exposeBuildSha", false);
        ReflectionTestUtils.setField(c, "buildSha", "probe");
        ReflectionTestUtils.setField(c, "ipPolicy", PublicIpPolicy.revealing());
        ReflectionTestUtils.setField(c, "source", source);
        ReflectionTestUtils.setField(c, "auditReader", audit);
        ReflectionTestUtils.setField(c, "attackStoryService", story);

        MockMvc mvc = MockMvcBuilders.standaloneSetup(c).build();

        String stories = call(mvc, "/api/public/stories?limit=5&window=24h");
        System.out.println("=== GET /api/public/stories?limit=5&window=24h ===");
        System.out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(mapper.readTree(stories)));

        JsonNode list = mapper.readTree(stories).path("data").path("sources");
        if (list.size() > 0) {
            String top = list.get(0).path("srcIp").asText();
            String detail = call(mvc, "/api/public/story?src=" + top + "&window=24h");
            System.out.println("=== GET /api/public/story?src=" + top + "&window=24h ===");
            System.out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(mapper.readTree(detail)));
        } else {
            System.out.println("=== /story 未跑：窗口内没有可公开的候选来源 ===");
        }
    }

    private String call(MockMvc mvc, String url) throws Exception {
        MvcResult r = mvc.perform(get(url)).andExpect(status().isOk()).andReturn();
        return r.getResponse().getContentAsString(StandardCharsets.UTF_8);
    }
}
