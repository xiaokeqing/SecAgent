package org.example.publicapi;

import org.example.aggregation.AlertAggregationService;
import org.example.integration.WazuhGateway;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 一次性工具：重新生成掩码态冻结串（{@code src/test/resources/publicapi/masked-golden-*.json}）。
 *
 * <p>类名<b>不以 Test 结尾</b>，所以不会被 surefire 的默认 include 扫到；
 * 只有在显式指定时才运行：
 * <pre>
 *   mvn -B test -Dtest=AttackStoryGoldenGenerator -DfailIfNoTests=false
 * </pre>
 * 冻结串是"以后有人动了掩码态的任何一处就立刻变红"的证据，
 * <b>不要</b>为了让测试变绿而随手重跑它 —— 先想清楚"这次改动是不是有意的"。
 */
class AttackStoryGoldenGenerator {

    @Test
    void generate() throws Exception {
        Path dir = Files.createTempDirectory("story-golden");
        AttackStoryFixtures.writeEmptyAudit(dir);

        PublicIpPolicy policy = PublicIpPolicy.masking();
        PublicAuditReader reader = new PublicAuditReader();
        ReflectionTestUtils.setField(reader, "dataDir", dir.toString());
        ReflectionTestUtils.setField(reader, "ipPolicy", policy);

        WazuhGateway gateway = AttackStoryFixtures.gateway("REAL", true);
        PublicAlertSource source = new PublicAlertSource();
        ReflectionTestUtils.setField(source, "wazuhGateway", gateway);
        ReflectionTestUtils.setField(source, "aggregator", new AlertAggregationService());

        AttackStoryService svc = new AttackStoryService();
        ReflectionTestUtils.setField(svc, "source", source);
        ReflectionTestUtils.setField(svc, "auditReader", reader);
        ReflectionTestUtils.setField(svc, "ipPolicy", policy);
        ReflectionTestUtils.setField(svc, "cacheSeconds", 15);
        ReflectionTestUtils.setField(svc, "topSources", 50);
        ReflectionTestUtils.setField(svc, "maxEventsPerStage", 40);
        ReflectionTestUtils.setField(svc, "maxLimit", 20);
        ReflectionTestUtils.setField(svc, "selfIps", AttackStoryFixtures.IP_SELF);

        PublicApiController c = new PublicApiController();
        PublicRateLimiter limiter = new PublicRateLimiter();
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 20);
        ReflectionTestUtils.setField(c, "rateLimiter", limiter);
        ReflectionTestUtils.setField(c, "cacheSeconds", 15);
        ReflectionTestUtils.setField(c, "exposeBuildSha", false);
        ReflectionTestUtils.setField(c, "buildSha", "test");
        ReflectionTestUtils.setField(c, "ipPolicy", policy);
        ReflectionTestUtils.setField(c, "source", source);
        ReflectionTestUtils.setField(c, "auditReader", reader);
        ReflectionTestUtils.setField(c, "attackStoryService", svc);

        MockMvc mvc = MockMvcBuilders.standaloneSetup(c).build();
        Path out = Path.of("src/test/resources/publicapi");
        Files.createDirectories(out);

        String stories = body(mvc, "/api/public/stories");
        write(out.resolve("masked-golden-stories.json"), stories);
        String story = body(mvc, "/api/public/story?src=" + AttackStoryFixtures.IP_DECOY);
        write(out.resolve("masked-golden-story.json"), story);
        System.out.println("WROTE golden files to " + out.toAbsolutePath());
    }

    private static String body(MockMvc mvc, String url) throws Exception {
        String json = mvc.perform(get(url)).andExpect(status().isOk()).andReturn()
                .getResponse().getContentAsString(StandardCharsets.UTF_8);
        return json.replaceAll("\"generatedAt\":\"[^\"]*\"", "\"generatedAt\":\"<TS>\"");
    }

    private static void write(Path p, String content) throws Exception {
        Files.writeString(p, content, StandardCharsets.UTF_8);
    }
}
