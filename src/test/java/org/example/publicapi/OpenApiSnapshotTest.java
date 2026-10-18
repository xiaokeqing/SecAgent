package org.example.publicapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.controller.HealthController;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.util.pattern.PathPatternParser;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * <b>公开面清单与真实 mapping 的对照</b>：{@code OpenApiSpec} 里写了 34 个 path，就必须真有 34 个
 * 注册到 Spring MVC 上的 handler，一个不多、一个不少。
 *
 * <h3>为什么值得单开一个测试</h3>
 * <p>手写清单最大的风险不是"写错一个字段"，而是<b>悄悄漂移</b>：有人加了个端点忘了写清单，或者删了端点
 * 清单里还留着一条 —— 两种都不会让编译失败，也不会让页面报错，只会让"机器可读的契约"变成谎言。
 * 所以这里不比较源码文本，而是让 Spring 自己把注册的 mapping 交出来，与清单做集合比较。
 *
 * <h3>为什么不写 {@code @SpringBootTest}</h3>
 * <p>本仓库<b>没有任何</b> {@code @SpringBootTest}（全量上下文要一堆外部依赖，见
 * {@code GlobalCorsExposeHeaderTest} / {@code TtsConfigContractTest} 的注释），与
 * {@code PublicApiHomeEndpointTest} 同一启法：{@code MockMvcBuilders.standaloneSetup(...)}。
 * standalone 的 {@code StandaloneMockMvcBuilder} 会把填好的 handler mapping 以
 * {@code requestMappingHandlerMapping} 注册进 {@code StubWebApplicationContext}，
 * 所以拿到的就是"已注册的 mapping"本身，成本却只有毫秒级。
 *
 * <h3>这里只装两个控制器</h3>
 * <p>只注册 {@code PublicApiController} 与 {@code HealthController} —— 公开面就是这两者的并集，
 * 别的控制器（受保护面）不该出现在这份清单里，也不该被这个测试枚举到。
 */
class OpenApiSnapshotTest {

    private static final ObjectMapper M = new ObjectMapper();

    /** 清单口径：20 个基础端点（含控制器里未被最初清单列出的 tts/say）+ 15 个 .js 别名。 */
    private static final Set<String> EXPECTED = expectedPaths();

    /**
     * 需求里点名要登记的 19 条（不含 {@code /api/public/tts/say}）。
     *
     * <p>把这 19 条单独钉一遍：清单可以比它**多**（多了真实存在的 tts/say），但不能比它**少** ——
     * 少了就是契约缺页，而"多出来的那条"必须在 {@code info.description} 里说清来路。
     */
    private static final List<String> REQUIRED_BASE_PATHS = List.of(
            "/api/health",
            "/api/public/ask",
            "/api/public/kb",
            "/api/public/overview",
            "/api/public/alerts",
            "/api/public/alerts/{aggId}",
            "/api/public/latest",
            "/api/public/honeypot",
            "/api/public/audit",
            "/api/public/geo",
            "/api/public/webstats",
            "/api/public/stories",
            "/api/public/story",
            "/api/public/tts",
            "/api/public/deploy",
            "/api/public/eval",
            "/api/public/home",
            "/api/public/ip",
            "/api/public/password");

    // ==================== ① mapping 枚举 ====================

    @Test
    @DisplayName("MockMvc 枚举出的 mapping = 清单声明的 35 个 path（20 基础 + 15 别名）")
    void mappingEnumerationMatchesDeclaredList() {
        Set<String> registered = registeredPaths();

        assertEquals(OpenApiSpec.PATH_COUNT, registered.size(),
                "公开面应有 35 个 path（20 基础 + 15 别名），实际枚举到 " + registered.size() + " 个：" + registered);
        assertEquals(EXPECTED, registered, "枚举结果与声明清单不一致");

        // 基础端点：需求点名的 19 条一条都不能少；控制器里真实存在的 tts/say 也要在
        assertEquals(20, OpenApiSpec.BASE_PATHS.size(), "基础端点清单应为 20 条（19 条点名 + tts/say）");
        for (String required : REQUIRED_BASE_PATHS) {
            assertTrue(registered.contains(required), "缺基础端点：" + required);
        }
        assertTrue(registered.contains("/api/public/tts/say"),
                "/api/public/tts/say 是控制器里真实存在的公开 POST，漏写清单就是漏页");

        // 15 个别名一个都不能少，且 /alerts/{aggId} 确实没有别名
        assertEquals(15, OpenApiSpec.ALIASED_PATHS.size(), "带 .js 别名的 GET 应为 15 条");
        for (String base : OpenApiSpec.ALIASED_PATHS) {
            assertTrue(registered.contains(base + ".js"), "缺 .js 别名：" + base + ".js");
        }
        assertFalse(registered.contains("/api/public/alerts/{aggId}.js"),
                "带路径参数的详情端点没有 .js 别名（清单与控制器都不该有）");
        assertFalse(registered.contains("/api/openapi.json"),
                "清单自身不进 openapi.json 的 paths，也不该被这个批次当成业务端点");
    }

    // ==================== ② spec 的结构 ====================

    @Test
    @DisplayName("openapi.json 合法：3.0.x、paths 数量 35、每个 path 有 get 或 post")
    void specHasOpenApiShape() {
        Map<String, Object> doc = OpenApiSpec.spec();

        assertEquals(OpenApiSpec.SPEC_VERSION, doc.get("openapi"));
        assertTrue(String.valueOf(doc.get("openapi")).startsWith("3."), "openapi 必须以 3. 开头");

        Map<?, ?> info = (Map<?, ?>) doc.get("info");
        assertNotNull(info, "缺 info");
        String description = String.valueOf(info.get("description"));
        assertTrue(description.contains("只读"), "info.description 必须写明只读");
        assertTrue(description.contains("脱敏"), "info.description 必须写明公开面脱敏");
        assertTrue(description.contains(".js"), "info.description 必须写明 .js 别名");
        assertTrue(description.contains("不编造"), "info.description 必须写明失败不编造");

        Map<?, ?> paths = (Map<?, ?>) doc.get("paths");
        assertNotNull(paths, "缺 paths");
        assertEquals(OpenApiSpec.PATH_COUNT, paths.size(), "paths 数量应等于 35");
        assertEquals(EXPECTED, new TreeSet<>(paths.keySet()), "paths 的键集合应与声明清单一致");

        for (Map.Entry<?, ?> entry : paths.entrySet()) {
            String path = String.valueOf(entry.getKey());
            Map<?, ?> item = (Map<?, ?>) entry.getValue();
            boolean hasGet = item.containsKey("get");
            boolean hasPost = item.containsKey("post");
            assertTrue(hasGet || hasPost, "path 缺少 get/post：" + path);
            assertFalse(hasGet && hasPost, "一个 path 不该同时有 get 与 post：" + path);

            Map<?, ?> op = (Map<?, ?>) item.get(hasGet ? "get" : "post");
            assertOperationShape(path, hasGet ? "get" : "post", op);
        }

        // 三个 POST 必须真的是 POST
        assertTrue(((Map<?, ?>) paths.get("/api/public/ask")).containsKey("post"), "/ask 必须是 POST");
        assertTrue(((Map<?, ?>) paths.get("/api/public/tts")).containsKey("post"), "/tts 必须是 POST");
        assertTrue(((Map<?, ?>) paths.get("/api/public/tts/say")).containsKey("post"),
                "/tts/say 必须是 POST —— 它是真实存在的公开端点，不是读接口");
        // /alerts/{aggId} 是唯一的路径参数端点，参数必须 in=path 且 required=true
        Map<?, ?> aggOp = (Map<?, ?>) ((Map<?, ?>) paths.get("/api/public/alerts/{aggId}")).get("get");
        Map<?, ?> aggIdParam = ((List<?>) aggOp.get("parameters")).stream()
                .map(p -> (Map<?, ?>) p)
                .filter(p -> "aggId".equals(p.get("name")))
                .findFirst()
                .orElseThrow(() -> new AssertionError("/alerts/{aggId} 缺 aggId 参数"));
        assertEquals("path", aggIdParam.get("in"));
        assertEquals(Boolean.TRUE, aggIdParam.get("required"));

        // 别名口径：摘要点名 `.js`、正文说明与主路径完全一致、operationId 可区分
        for (String base : OpenApiSpec.ALIASED_PATHS) {
            Map<?, ?> alias = (Map<?, ?>) paths.get(base + ".js");
            Map<?, ?> op = (Map<?, ?>) alias.get("get");
            String summary = String.valueOf(op.get("summary"));
            String desc = String.valueOf(op.get("description"));
            String opId = String.valueOf(op.get("operationId"));
            assertTrue(summary.contains(".js"), "别名 summary 要点名 .js：" + base);
            assertTrue(desc.contains("与 `" + base + "` 的响应体完全一致"), "别名正文要声明与主路径一致：" + base);
            assertTrue(opId.endsWith("Alias"), "别名 operationId 要可与主路径区分：" + opId);
        }
    }

    @Test
    @DisplayName("GET /api/openapi.json 真的返回可解析的 3.0 文档（与 spec() 同一份）")
    void endpointServesParseableJson() throws Exception {
        MockMvc specMvc = MockMvcBuilders.standaloneSetup(new OpenApiSpec()).build();
        String body = specMvc.perform(get(OpenApiSpec.PATH))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

        JsonNode served = M.readTree(body);
        assertTrue(served.path("openapi").asText().startsWith("3."), "响应里的 openapi 字段必须以 3. 开头");
        assertEquals(OpenApiSpec.PATH_COUNT, served.path("paths").size(), "响应里的 paths 数量应为 34");

        // 线上取到的必须与进程内装配的是同一份（防止"序列化层改了形状"这类漂移）
        JsonNode expected = M.readTree(M.writeValueAsString(OpenApiSpec.spec()));
        assertEquals(expected, served, "HTTP 响应与 OpenApiSpec.spec() 不是同一份文档");
    }

    // ==================== 辅助 ====================

    /**
     * 从 standalone MockMvc 的处理器映射里把已注册的 path 全展开。
     *
     * <p>一个方法可能带多个 pattern（如 {@code @GetMapping({"/story","/story.js"})}），
     * 所以按 handler 逐个展开而不是假设"一方法一路径"；同时兼容 PathPattern 与 Ant 两套条件
     * （standalone 默认用 {@link PathPatternParser}，但显式 setUseTrailingSlashMatch 之类的定制会让另一套生效）。
     */
    private static Set<String> registeredPaths() {
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new PublicApiController(), new HealthController()).build();
        RequestMappingHandlerMapping mapping = mvc.getDispatcherServlet()
                .getWebApplicationContext()
                .getBean(RequestMappingHandlerMapping.class);
        assertNotNull(mapping, "standalone 上下文里应有 requestMappingHandlerMapping");

        Set<String> paths = new TreeSet<>();
        for (Map.Entry<RequestMappingInfo, HandlerMethod> entry : mapping.getHandlerMethods().entrySet()) {
            RequestMappingInfo info = entry.getKey();
            if (info.getPathPatternsCondition() != null) {
                paths.addAll(info.getPathPatternsCondition().getPatternValues());
            } else if (info.getPatternsCondition() != null) {
                paths.addAll(info.getPatternsCondition().getPatterns());
            } else {
                throw new AssertionError("mapping 没有任何路径条件：" + info);
            }
        }
        return paths;
    }

    private static Set<String> expectedPaths() {
        Set<String> paths = new LinkedHashSet<>(OpenApiSpec.BASE_PATHS);
        for (String base : OpenApiSpec.ALIASED_PATHS) {
            paths.add(base + ".js");
        }
        return paths;
    }

    /** 每个操作都必须写清 summary/description/operationId/parameters 与 200/400/429 三种响应。 */
    private static void assertOperationShape(String path, String method, Map<?, ?> op) {
        String where = method.toUpperCase() + " " + path + " ";
        for (String field : List.of("summary", "description", "operationId")) {
            Object value = op.get(field);
            assertNotNull(value, where + "缺 " + field);
            assertFalse(String.valueOf(value).isBlank(), where + field + " 不能为空");
        }
        assertTrue(op.containsKey("parameters"), where + "缺 parameters（没有也要给空数组）");
        List<?> parameters = (List<?>) op.get("parameters");
        for (Object raw : parameters) {
            Map<?, ?> param = (Map<?, ?>) raw;
            String name = String.valueOf(param.get("name"));
            String in = String.valueOf(param.get("in"));
            assertNotNull(param.get("schema"), where + "参数 " + name + " 缺 schema");
            assertNotNull(param.get("description"), where + "参数 " + name + " 缺 description");
            if ("path".equals(in)) {
                assertTrue(path.contains("{" + name + "}"), where + "路径参数 " + name + " 不在 path 模板里");
                assertEquals(Boolean.TRUE, param.get("required"), where + "路径参数 " + name + " 必须 required=true");
            } else {
                assertEquals("query", in, where + "参数 " + name + " 只支持 query/path");
            }
        }

        Map<?, ?> responses = (Map<?, ?>) op.get("responses");
        assertNotNull(responses, where + "缺 responses");
        for (String code : List.of("200", "400", "429")) {
            Map<?, ?> response = (Map<?, ?>) responses.get(code);
            assertNotNull(response, where + "缺 " + code + " 响应");
            assertFalse(String.valueOf(response.get("description")).isBlank(), where + code + " 响应缺 description");
        }
    }
}
