package org.example.publicapi;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * <b>公开面的机器可读清单</b>：{@code GET /api/openapi.json} 返回一份手写的 OpenAPI 3.0 文档。
 *
 * <h3>为什么手写，而不是引 springdoc</h3>
 * <p>公开面一共 19 个基础端点 + 15 个 {@code .js} 别名，形状各不相同，且每个端点都有一批
 * <b>「这台机器上的真实口径」</b>要对读者说清（{@code total} 是上限哨兵、{@code rawTotal} 与
 * {@code aggregated} 不是一回事、费率按 IP 算是多少、读不到时给 {@code available=false} 而不是 0）。
 * 注解扫描能推出参数名和返回值类型，但推不出这些；而"推不出来就先空着"的清单，
 * 恰恰是本项目最不能要的东西。所以这里<b>逐端点手写</b>，改端点时必须同步改这里 ——
 * 代价是几十行重复，换来的是"清单里每句话都有人负责"。
 *
 * <h3>这份清单不包含什么</h3>
 * <ul>
 *   <li>不包含自己：{@code /api/openapi.json} 描述的是公开面契约，清单本身不在契约里；</li>
 *   <li>不包含受保护面：{@code /api/user/**}、处置与控制类端点一个都不出现，
 *       所以就算这份清单被原样贴到站上，也不构成攻击面说明书；</li>
 *   <li>不包含内部资产名、内网地址、口令原文 —— 与公开面响应的脱敏口径一致。</li>
 * </ul>
 *
 * <p>路径白名单：没有令牌的人也能取到它，所以它必须待在
 * {@code app.api-token.white-list} 里（{@code src/main/resources/application.yml}）；
 * 漏登记的话线上会是 401 —— 这是"文档端点不是业务端点"最容易被忽略的一步。
 */
@RestController
public class OpenApiSpec {

    /** 清单自己的路径；不写进 {@code paths}（见类注释）。 */
    public static final String PATH = "/api/openapi.json";

    /** OpenAPI 小版本：3.0.x 的形状（不带 3.1 的 {@code webhooks}/{@code jsonSchemaDialect}）。 */
    public static final String SPEC_VERSION = "3.0.3";

    /** 公开面唯一入口；站点表格、curl 示例与这里保持同一个基址。 */
    public static final String PUBLIC_ORIGIN = "https://demo.xiaokeqing.cn";

    /** 清单里应有的 path 条数：20 个基础 + 15 个 {@code .js} 别名。测试拿它当契约。 */
    public static final int PATH_COUNT = 35;

    /**
     * 20 个基础端点（含 3 个 POST 与 1 个带路径参数的 GET）。
     *
     * <p>注意有一条<b>不在最初那张 19 条清单里</b>：{@code /api/public/tts/say}。它是控制器里实打实的
     * 第 20 个公开端点（自由文本语音，见 {@code PublicApiController#ttsSay}），清单漏写它会让
     * "机器可读的公开面"少一条 —— 正是这个端点让人以为"公开面没有吃自由文本的地方"。
     * 所以按真实 mapping 收录，并在 {@code info.description} 里写明这个差异。
     */
    public static final List<String> BASE_PATHS = List.of(
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
            "/api/public/tts/say",
            "/api/public/deploy",
            "/api/public/eval",
            "/api/public/home",
            "/api/public/ip",
            "/api/public/password");

    /** 有 {@code .js} 别名的 15 个 GET（{@code /alerts/{aggId}} 与两个 POST 没有别名）。 */
    public static final List<String> ALIASED_PATHS = List.of(
            "/api/public/kb",
            "/api/public/overview",
            "/api/public/alerts",
            "/api/public/latest",
            "/api/public/honeypot",
            "/api/public/audit",
            "/api/public/geo",
            "/api/public/webstats",
            "/api/public/stories",
            "/api/public/story",
            "/api/public/deploy",
            "/api/public/eval",
            "/api/public/home",
            "/api/public/ip",
            "/api/public/password");

    @GetMapping(value = PATH, produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> document() {
        return spec();
    }

    /**
     * 纯函数式的文档装配：不碰 Spring 上下文、不读文件、不查库。
     * 这样单测既能直接断言结构，也能确认"同一份对象被反复取用"不会漂。
     */
    public static Map<String, Object> spec() {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("openapi", SPEC_VERSION);
        doc.put("info", info());
        doc.put("servers", List.of(Map.of(
                "url", PUBLIC_ORIGIN,
                "description", "公开面唯一入口（Cloudflare 后面的只读出口）；本地演示时把前缀换成 http://127.0.0.1:8080 即可")));
        doc.put("tags", List.of(Map.of(
                "name", "public",
                "description", "匿名可读的只读端点；无鉴权、无写操作、不常驻连接")));
        doc.put("paths", paths());
        return doc;
    }

    // ==================== info ====================

    private static Map<String, Object> info() {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("title", "XK-LAB 公开面 · 只读接口清单");
        info.put("version", "1.0.0");
        info.put("description", String.join("\n",
                "这份清单由后端手写维护（`org.example.publicapi.OpenApiSpec`，不引 springdoc、不做运行时注解扫描），",
                "页面上那张表是给人读的手写说明；两边若不一致，**以这份 json 为准**。",
                "",
                "## 四条口径",
                "- **只读**：所有端点都不写库、不改状态、不触发任何处置动作。两个 POST 的语义分别是「问一句」与「合成一段」，",
                "  请求体只描述输入形状；要处置（封禁 / 审批）得走受保护的自用面，不在这里。",
                "- **公开面脱敏**：响应里不含原始 IP、内网地址、口令原文、内部规则原文；`geo` / `webstats` 里零 IP，",
                "  `alerts` / `story` 里的地址在展示层统一掩成 `1.2.3.x`，蜜罐口令只给长度与字符类别。需要原文才能算出来的东西，宁可缺。",
                "- **`.js` 是给浏览器直连的别名**：15 个 GET 端点各有一个同名 `<path>.js`，响应体与不带后缀的地址**完全一致**，",
                "  存在理由只是让浏览器/边缘缓存按扩展名缓存（命中缓存的请求到不了源站，也就不吃限流）；它不是脚本，",
                "  仍按 `application/json` 解析。`/api/public/alerts/{aggId}` 与两个 POST 没有别名。",
                "- **失败不编造**：取不到就 `available=false` + `reason`（或 400/429/503 + `code`/`message`），不补 0、不补样例值、",
                "  不拿启动时刻冒充数据时间。本清单只描述接口形状，**不代表线上此刻一定 available**；要判「现在通不通」请看 `/status/`。",
                "",
                "## 计数",
                "- 基础端点 **20** = `/api/health` + 19 个 `/api/public/*`（含 3 个 POST、1 个带路径参数的 GET）",
                "- `.js` 别名 **15** = 除 `/api/public/alerts/{aggId}` 外，每个 GET 各一个",
                "- 合计 **35** 个 path；本清单自身是 `GET /api/openapi.json`，不列在里面",
                "- 与原清单的差异：`/api/public/tts/say`（自由文本语音）是控制器里已有的第 20 个公开端点，",
                "  最初那张 19 条清单漏了它。这里按**真实 mapping** 收录 —— 漏写比多写更糟：读者会以为公开面没有吃自由文本的地方。",
                "",
                "## 共同约定",
                "- 成功统一 `200` + `application/json`（TTS 例外：成功时是音频字节流，`audio/mpeg`）",
                "- 参数或请求体形状不对 → `400` + `code`/`message`；限流 → `429` + `Retry-After`",
                "- 公开面按 IP 限流；具体额度在各端点的 `description` 里写明，`quota` 字段会回报剩余量",
                "- 一次性返回，没有 SSE / WebSocket；别名带 `ETag` 与 `Age`，别加随机 cache-buster"));
        return info;
    }

    // ==================== paths ====================

    private static Map<String, Object> paths() {
        Map<String, Object> paths = new LinkedHashMap<>();

        // ---- 1. health ----
        base(paths, "get", "/api/health", "publicHealth", "健康探针",
                "进程活着、线上跑的是哪个版本。返回 `buildSha` / `embeddedGitCommit` / `vectorStore` / "
                        + "`documentVectors` / `uptimeMs` / `status`。它是公开面唯一端出构建指纹的端点："
                        + "与 `/api/public/deploy` 的 `release` 对不上，就说明页面与进程不是同一次发布。"
                        + "无缓存（`cf-cache-status: DYNAMIC`），每次都要回源 3–4s，别塞进首屏必等路径。",
                List.of(), null, null, false);

        // ---- 2. ask (POST) ----
        base(paths, "post", "/api/public/ask", "publicAsk", "公开问答（检索 + 引用 + 六态标注）",
                "整个公开面唯一会触发一次模型调用的端点。请求体给 `question`（或等价的 `q`），可选 `speakJa=true` "
                        + "让回答顺带合成一段日语音频（走公开池额度）。响应给 `answer`、六态机读值 `state`/`stateLabel`、"
                        + "`citations[]`、`quota{pool, limit, used, remaining}`、`clientIpMasked`、`outputFindings`、`ttsTextHash`。"
                        + "限流：**6 次/分/IP + 公开池 30 次/日 + 同 IP 并发 1**；`429` 与「读不到」是两件事，别混着写。"
                        + "它只解释、不做任何处置；`clientIpMasked` 已经是打码后的值，别当原始 IP 用。",
                List.of(), jsonBody(
                        "可省略请求体（字段名都取不到时会按空问题处理并如实回 400 语义）。只认 `question` / `q` 两个问题键，"
                                + "其余键忽略；`speakJa` 只认显式 opt-in。",
                        props(
                                "question", prop("string", "待提问的自由文本；与 `q` 等价，二者取其一即可"),
                                "q", prop("string", "`question` 的短写别名"),
                                "speakJa", prop("boolean", "显式 opt-in：`true` 时顺带合成日语音频（额外消耗公开池额度）"))),
                null, false);

        // ---- 3. kb ----
        base(paths, "get", "/api/public/kb", "publicKb", "知识库只读检索",
                "在公开白名单里做一次检索：根目录 `security-docs` / `data/kb-approved`、来源类型 `community`、top-k=3、摘要 300 字。"
                        + "不带 `q` **不报错**：返回空 `results` + `note`「未提供查询词（q）」，别把这句当检索失败。"
                        + "响应里的 `rule` 就是白名单口径本身（`allowedRoots` / `allowedSourceTypes`），可自查。"
                        + "每次都有 embedding 成本 ⇒ **禁止轮询**，20 次/分钟按 IP 算。检索不到是真没有，不是接口坏了。",
                List.of(queryParam("q", "可选；检索词。缺失时返回空 `results` 与说明性 `note`，不算错误")),
                null, null, true);

        // ---- 4. overview ----
        base(paths, "get", "/api/public/overview", "publicOverview", "主机与链路在线 + 告警窗口分布 + 数据源模式",
                "`nodes[]{id, label, online}` 给主机/链路在线状态，`alerts{windowSize, windowCount, bySeverity[], bySource[]}` "
                        + "给窗口内分布，`dataSource{wazuhMode, degraded}` 说明数据源模式 —— 只有 `wazuhMode == \"REAL\"` 才是真 Wazuh 在供数。"
                        + "注意 `nodes[].detail` 里带构建提交号（形如 `build da9d1dba…`）：渲染只取 `id`/`label`/`online`，"
                        + "别把 detail 整块吐到页面上。",
                List.of(), null, null, true);

        // ---- 5. alerts ----
        base(paths, "get", "/api/public/alerts", "publicAlerts", "告警聚合（窗口内告警 + 来源 + severity）",
                "给的是**聚合**，不是原始日志：同一份响应里 `rawTotal` 是原始条数、`aggregated` 才是聚合成几条"
                        + "（实测 200 → 26），行数对不上不是 bug。`list[]` 每条给 "
                        + "`aggId, count, startTime, endTime, title, ruleName, srcIp, srcGeo, severity, status, hitCount`，"
                        + "`stats24h.trend[]` 给 24h 趋势。`srcIp` 在接口里可能仍是原文，展示层统一掩码。",
                List.of(), null, null, true);

        // ---- 6. alerts/{aggId} ----
        base(paths, "get", "/api/public/alerts/{aggId}", "publicAlertDetail", "单条告警详情",
                "路径里是**聚合 id（aggId），不是 IP**：想「按 IP 查告警」这个端点做不到，请用 `/api/public/ip?q=`。"
                        + "不存在的 id 直接 `404`（`code`/`message` 里说明），不给空壳 200。"
                        + "响应是该 aggId 那一条的完整结构，与 `/alerts` 的 `list[]` 元素同形。",
                List.of(pathParam("aggId", "聚合 id（来自 `/api/public/alerts` 的 `list[].aggId`），不是 IP")),
                null, extraResponses("404", "该 aggId 在当前窗口里不存在"), false);

        // ---- 7. latest ----
        base(paths, "get", "/api/public/latest", "publicLatest", "窗口聚合（只给一个窗口的量）",
                "`windowSize` 与 `windowAlertCount`：只回答「这个窗口里有多少条」。窗口会随时间滚动，"
                        + "别拿它和 `/api/public/geo` 的 `coverage.totalAlerts` 直接比 —— 两个数可能不是同一个窗口。"
                        + "旧版本文档记的 `latestEvent` / `latestBlock` 键已不存在，字段以实际响应为准。",
                List.of(), null, null, true);

        // ---- 8. honeypot ----
        base(paths, "get", "/api/public/honeypot", "publicHoneypot", "蜜罐战报（连接 / 登录 / 来源 Top / 口令结构 / 时间线）",
                "`total` **恒为 10000**，那是统计上限哨兵，不是真实累计 —— 真实计数看 `connections`（其次 `logins`）。"
                        + "这两个数随窗口滚动，同一晚两次读数就可能不同，对比要取同一时刻。"
                        + "口令只给 `username` + `passwordLength` + `passwordCharClasses` + `weakPassword`，**永不出现原文**。"
                        + "`commandsAvailable=false` 表示「命令序列这段没接数据源」，不是编出来的空。",
                List.of(), null, null, true);

        // ---- 9. audit ----
        base(paths, "get", "/api/public/audit", "publicAudit", "处置审计（护栏拦截 / 封禁留痕 / 理由）",
                "`summary{blockTotal, blockActive, blockedByGuard, executedActions}` 里四个数**都是累计**，不是本周/本日；"
                        + "`blockedByGuard` 是被护栏拦下的**动作**数，不是「封了几个」，与 `blockTotal` 比大小没有意义。"
                        + "`blocks[]` / `actions[]` 里的地址与理由可能带 IP 或内网线索，展示前一律过掩码。"
                        + "顶层 `readOnly` 恒为真：这个端点是审计回放，不接受任何写操作。",
                List.of(), null, null, true);

        // ---- 10. geo ----
        base(paths, "get", "/api/public/geo", "publicGeo", "来源地理聚合（国家 / 省 / ASN + 24h 趋势）",
                "**必须连 `coverage` 一起看**：只有带源 IP 的告警才进地理统计，别把子集画成「全量攻击」"
                        + "（实测 78,130 条里 75,127 带 IP、30,263 定位成功）。响应里**零 IP**。"
                        + "`byCountry[]` 给 `count` / `uniqueIps` / `sharePercent`，`byAsnTop[]` 给 ASN Top，`trend[]` 给 24h 趋势。"
                        + "地理库是 DB-IP Lite（CC BY 4.0），署名必须带响应里的 `geoAttribution` 那行。",
                List.of(), null, null, true);

        // ---- 11. webstats ----
        base(paths, "get", "/api/public/webstats", "publicWebstats", "Web 访问统计（访问量 / 来源）",
                "**一个 IP 都不给**，连打码都不给；访问路径只给固定类别、不给原文。"
                        + "`totals{requests, statusClass{}}`、`topCategories[]`、`topUas[]`、`heatmap[]`（日期×小时）、`coverage{}`、`note`。"
                        + "不同版本文档对「日桶 / 状态码」说法不一（一份列了 `byDay[]` 与 `statusClass`，另一份实测说还没上），"
                        + "渲染前先取一次实际响应，缺的格子如实写「读不到」。",
                List.of(), null, null, true);

        // ---- 12. stories ----
        base(paths, "get", "/api/public/stories", "publicStories", "攻击故事线候选池",
                "`sources[]{srcIp, stages{}, stagesWithData, firstSeen, lastSeen, severityMax, gaps[]}` 给候选来源与四段覆盖，"
                        + "`coverage{stageStatus, stageNotes, audit{...}}` 逐段说明接没接上，`limits{defaultLimit, maxLimit, topSources}`。"
                        + "`auditActions` 多轮实测全 0：**不是「没有处置动作」，是这一段没读到数据**，真要看翻 `coverage.audit`。"
                        + "`/api/public/stories/1` 是 `404`，它没有子资源；`sources[]` 默认 10 条、最多 20，不是全量。",
                List.of(
                        queryParam("window", "可选；时间窗标签，不支持的取值 → `400 WINDOW_NOT_SUPPORTED`"),
                        queryParam("limit", "可选；候选来源条数上限，默认 10、最大 20（超出按下限截断，不报错）")),
                null, null, true);

        // ---- 13. story ----
        base(paths, "get", "/api/public/story", "publicStory", "单源事件时间线（点了才拉，页面不预取）",
                "**只服务 `/stories` 候选池里的来源**：允许任意 `src` 就等于把端点变成「随便给个 IP 就能问'他有没有打过我们'」的查询器，"
                        + "那本身就是情报泄露。`events[]{ts, stage, stageLabel, kind, severity, outcome, summary}` 按时间升序合并四段，"
                        + "每段最多 40 条，被截断时 `truncated=true` 如实标 —— 别把截断后的时间线当完整攻击过程。"
                        + "缺 `src` → `400 MISSING_SRC`；形状不是公网字面量 → `400 INVALID_SRC`；不在池里 → `404 SOURCE_NOT_IN_WINDOW`。"
                        + "脱敏要连 `events[].summary` 里的内嵌 IP 一起盖。",
                List.of(
                        queryParam("src", "被测来源：必须是 IPv4/IPv6 公网字面量（内网/保留地址不接受），且要填 `/stories` 返回的真实来源"),
                        queryParam("window", "可选；时间窗标签，不支持的取值 → `400 WINDOW_NOT_SUPPORTED`")),
                null, null, true);

        // ---- 14. tts (POST) ----
        base(paths, "post", "/api/public/tts", "publicTts", "在线语音合成代理（转发字节流）",
                "**默认关闭**（等语音 Key）：`ttsService` 没装配时一律 `503 TTS_DISABLED`，这是配置状态的真话，不是故障。"
                        + "开启后也只收白名单内的 **`phraseId` / `textHash`** 两种键 —— 塞自由文本 → `400 TEXT_NOT_ALLOWED`，"
                        + "请求体里不出现待朗读文本本身。成功时响应是音频字节流（`audio/mpeg`），不是 JSON。"
                        + "另有 `/api/public/tts/say` 的额度（每 IP 30 次/日、全局 300 次/日）不在此清单范围。",
                List.of(), jsonBody(
                        "只描述输入形状：`phraseId` / `textHash` 用于引用服务端已缓存的音频，`speakJa` 沿用问答端点那个开关。",
                        props(
                                "phraseId", prop("string", "服务端已知的短语 id（白名单内），与 `textHash` 二选一"),
                                "textHash", prop("string", "服务端已记录回答对应的文本 hash（由 `/api/public/ask` 的 `ttsTextHash` 给出）"),
                                "speakJa", prop("boolean", "是否生成日语语音（与 `/api/public/ask` 同一开关语义）"))),
                extraResponses(
                        "400", "请求体形状不对，或试图合成自由文本（`TEXT_NOT_ALLOWED`）",
                        "503", "TTS 未启用（`TTS_DISABLED`）：配置状态如实上报，不是临时故障"),
                false);

        // ---- 15. tts/say (POST) ----
        base(paths, "post", "/api/public/tts/say", "publicTtsSay", "自由文本语音（把一句话念出来）",
                "短语表那条线（`/api/public/tts`）只认服务端给过的文本，而「把 AI 回答念出来」的回答每次都不同 —— "
                        + "所以有这么一个吃自由文本的出口，它靠<b>把滥用者想要的东西逐项拿掉</b>来保持安全："
                        + "长度 ≤60 字、字符集限日语（平假名/片假名/汉字/数字/标点，连英文都念不出来，当不了通用朗读 API）、"
                        + "每 IP 30 次/日 + 全局 300 次/日（与短语表共用同一本落盘额度账）、同一句磁盘缓存只合成一次（内容寻址）、"
                        + "上游失败归一成 `502` 且**不打印上游响应体**。与 `/tts` 是同一条管线的两个入口，不是放宽。"
                        + "成功时响应是音频字节流（`audio/mpeg`），不是 JSON。",
                List.of(), jsonBody(
                        "只收一个 `text`：要合成的日语短句，≤60 字、限日语字符集；超限/字符集不符 → `400`。",
                        props(
                                "text", prop("string", "要朗读的日语短句（≤60 字；平假名/片假名/汉字/数字/标点）"))),
                extraResponses(
                        "502", "上游合成失败（`TTS_UPSTREAM_FAILED` 一类归一化原因）：不把上游原文透出来",
                        "503", "TTS 未启用（`TTS_DISABLED`）"),
                false);

        // ---- 15. deploy ----
        base(paths, "get", "/api/public/deploy", "publicDeploy", "构建与发布信息（可追溯）",
                "**嵌套结构，不是平铺的**：`build{}` / `runtime{}` / `release{release, totalBytes, source}`；"
                        + "**没有 `files` / `history` 两个键**，别按它们写代码。发布文件没配好时给 `available:false` + "
                        + "`RELEASE_INFO_NOT_CONFIGURED`（实测线上常见这个状态），不拿启动时刻冒充发布时刻。"
                        + "与 `/api/health` 的 `buildSha` 交叉看，才能判断前端与进程是不是同一次发布。",
                List.of(), null, null, true);

        // ---- 16. eval ----
        base(paths, "get", "/api/public/eval", "publicEval", "评测报告（AI 质量那几格）",
                "`sampleSize` / `keyPointHitRate` / `refusalRate` / `strictRate` / `citationRate` / "
                        + "`personaCatchphraseRate` / `tabooRate` / `generatedAt` + `note`/`caveats`。"
                        + "**比率必须连 `sampleSize` 一起读**：96 份与 4 份不是一个可信度。报告没配好时 `available:false` + "
                        + "`EVAL_REPORT_NOT_CONFIGURED`，这是如实报告，不是接口坏了。",
                List.of(), null, null, true);

        // ---- 17. home ----
        base(paths, "get", "/api/public/home", "publicHome", "首屏聚合：alerts + geo + honeypot 三合一",
                "一个请求拿回 `alerts` / `geo` / `honeypot`（并带 `audit` / `health` 的可用性块）+ "
                        + "`ipDisclosure{notice, removalContact}`；各块与独立端点**逐字段一致**。缓存 45s、"
                        + "`stale-while-revalidate`；**快 ≠ 新**：真实年龄 = `cacheAgeSeconds` + 响应头 `Age`。"
                        + "体量随 24h 数据长，实测 23–27 KB，别当固定大小的小接口。",
                List.of(), null, null, true);

        // ---- 18. ip ----
        base(paths, "get", "/api/public/ip", "publicIpProfile", "「这个 IP 干过什么」：单来源画像",
                "跨三个源聚合：索引里的告警 + 蜜罐会话 + 应用侧处置留痕 + GeoIP。字段 "
                        + "`firstSeen/lastSeen/events/byKind/ports/credStructure/geo/banned`，外加 `sources` 说明每个源接没接上、"
                        + "`notes[]` 逐项说明为什么是 null（「读不到」与「没有数据」必须能分开读）。"
                        + "只按 `q` 这一个字面量查，不按网段、不按 ASN 扩张；只收 IPv4 字面量，内网/保留地址 → `400 NOT_PUBLIC_IP`。"
                        + "口令只给结构（`root / 6 位·纯数字·弱口令`），原文字符不出现。",
                List.of(queryParam("q", "必填：要画像的 IPv4 字面量（四段十进制）。缺失 → `400 MISSING_Q`，非法 → `400 INVALID_IP`")),
                null, null, true);

        // ---- 19. password ----
        base(paths, "get", "/api/public/password", "publicPassword", "「你的密码在攻击者字典里吗」k-匿名自查",
                "`p` = 口令 SHA-256 的**前 5 位**小写 hex（不收原文、不收大写、不收更长前缀）。后端按前缀把桶内 hash 的"
                        + "**后 59 位**发出去，判定命中由页面用 `crypto.subtle` 自己算完整 hash 后比对 —— 后端全程拿不到口令。"
                        + "`match` 恒为 `null`（谁判定始终是前端）；`bucketCount` 是这 5 位前缀下**所有**口令的尝试次数合计，"
                        + "不是「你这一个」的次数。字典读不到时给 `available:false` + `notes` 写原因（不 500、不补数、"
                        + "不把「读不到」渲染成「没查到」）；`truncated:true` 表示桶内超出下发上限，可能只是被截断、"
                        + "不代表不在字典里。",
                List.of(queryParam("p", "必填：口令 SHA-256 的前 5 位小写十六进制（例如 `a1b2c`）；非法 → `400 INVALID_PREFIX`")),
                null, null, true);

        return paths;
    }

    // ==================== 结构装配 ====================

    /**
     * 登记一个端点；{@code withJsAlias=true} 时顺手登记同名 {@code .js} 别名。
     *
     * <p>别名为什么用"生成"而不是再抄一遍：两边必须<b>永远同形</b>，抄两遍迟早会漂；这里只把摘要改一下、
     * 正文前置一句「与主路径完全一致」，参数与响应原样复用。
     */
    private static void base(Map<String, Object> paths, String method, String path, String operationId,
                             String summary, String description,
                             List<Map<String, Object>> parameters,
                             Map<String, Object> requestBody,
                             Map<String, Object> extraResponses,
                             boolean withJsAlias) {
        paths.put(path, Map.of(method, operation(operationId, summary, description, parameters, requestBody, extraResponses)));
        if (withJsAlias) {
            String aliasPath = path + ".js";
            paths.put(aliasPath, Map.of("get", operation(
                    operationId + "Alias",
                    summary + "（`.js` 直连别名）",
                    "**别名**：与 `" + path + "` 的响应体完全一致，唯一差别是路径带 `.js` 后缀 —— "
                            + "给浏览器/边缘按扩展名缓存用，不改内容、不额外取数，也不是脚本（`application/json`）。\n\n"
                            + description,
                    parameters, null, extraResponses)));
        }
    }

    private static Map<String, Object> operation(String operationId, String summary, String description,
                                                 List<Map<String, Object>> parameters,
                                                 Map<String, Object> requestBody,
                                                 Map<String, Object> extraResponses) {
        Map<String, Object> op = new LinkedHashMap<>();
        op.put("tags", List.of("public"));
        op.put("operationId", operationId);
        op.put("summary", summary);
        op.put("description", description);
        op.put("parameters", parameters == null ? List.of() : parameters);
        if (requestBody != null) {
            op.put("requestBody", requestBody);
        }
        op.put("responses", responses(extraResponses));
        return op;
    }

    private static Map<String, Object> responses(Map<String, Object> extraResponses) {
        Map<String, Object> responses = new LinkedHashMap<>();
        responses.put("200", response("成功。响应体为 `application/json`；取不到的字段如实给 `available=false` 与 `reason`，不给样例值。"));
        responses.put("400", response("请求参数或请求体形状不合法（含必填查询参数缺失）。响应体带 `code` 与 `message`。"));
        responses.put("429", response("触发公开面限流（按 IP 计数）。响应头带 `Retry-After`；额度类端点另给剩余量 `quota`。"));
        if (extraResponses != null) {
            responses.putAll(extraResponses);
        }
        return responses;
    }

    private static Map<String, Object> response(String description) {
        return Map.of(
                "description", description,
                "content", Map.of("application/json", Map.of("schema", Map.of("type", "object"))));
    }

    /** 「额外状态码 → 说明」成对给出，避免在调用点写一次性的 Map 字面量。 */
    private static Map<String, Object> extraResponses(String... codeAndDescription) {
        Map<String, Object> extras = new LinkedHashMap<>();
        for (int i = 0; i + 1 < codeAndDescription.length; i += 2) {
            extras.put(codeAndDescription[i], response(codeAndDescription[i + 1]));
        }
        return extras;
    }

    private static Map<String, Object> queryParam(String name, String description) {
        Map<String, Object> param = new LinkedHashMap<>();
        param.put("name", name);
        param.put("in", "query");
        param.put("required", false);
        param.put("schema", Map.of("type", "string"));
        param.put("description", description);
        return param;
    }

    private static Map<String, Object> pathParam(String name, String description) {
        Map<String, Object> param = new LinkedHashMap<>();
        param.put("name", name);
        param.put("in", "path");
        param.put("required", true);
        param.put("schema", Map.of("type", "string"));
        param.put("description", description);
        return param;
    }

    private static Map<String, Object> jsonBody(String description, Map<String, Object> properties) {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", properties);
        schema.put("additionalProperties", false);
        Map<String, Object> body = new LinkedHashMap<>();
        // 请求体不是必填：缺体/空体时端点按"空问题"处理并如实返回，而不是在框架层 400 掉
        body.put("required", false);
        body.put("description", description);
        body.put("content", Map.of("application/json", Map.of("schema", schema)));
        return body;
    }

    /** {@code properties}：按「名字, Schema」成对给出（Schema 里不再重复名字）。 */
    private static Map<String, Object> props(Object... nameAndSchema) {
        Map<String, Object> props = new LinkedHashMap<>();
        for (int i = 0; i + 1 < nameAndSchema.length; i += 2) {
            props.put(String.valueOf(nameAndSchema[i]), nameAndSchema[i + 1]);
        }
        return props;
    }

    /** 一个 JSON Schema 的属性（OpenAPI 3.0 的 Schema Object 形状：`type` + `description`）。 */
    private static Map<String, Object> prop(String type, String description) {
        Map<String, Object> prop = new LinkedHashMap<>();
        prop.put("type", type);
        prop.put("description", description);
        return prop;
    }
}
