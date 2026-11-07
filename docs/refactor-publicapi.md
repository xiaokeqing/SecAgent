# 拆分 `PublicApiController` 为按域 controller —— 最终形态与迁移清单

> 状态：**已收尾**（2026-11-07）。两阶段完成：先拆出五个按域 controller + 委托门面，再把门面
> `PublicApiController` 整体删除 —— 现在测试直接组装五个域 controller（测试源新增 `PublicApiTestAssembly`），
> 生产代码里**不存在**任何门面或兼容壳，`legacy-facade-bean` 开关也随之移除。
> 路径、参数名、响应 JSON 字段、状态码、缓存头、限流注解全部不变。
> 最终 `mvn.cmd -o -q clean test` → `Tests run: 903, Failures: 0, Errors: 0, Skipped: 4`（899 是更早基线；HEAD 上 `2b6ea1c` 新增 `/indices`、`/conn` 两个公共端点的 4 条测试，故当前总数为 903）。
> 未做任何 git commit。

## 1. 实测事实（与任务描述不一致处以实测为准）

| 项 | 任务描述 | 实测 |
|---|---|---|
| 文件行数 | 约 2310 行 | 拆分前 **3063 行**（`git show HEAD:` 为 3057 行，工作区还有并行子任务的 `hours` 别名改动） |
| mapping 数 | 19 | **20**（`GET /story` 带 `?src=` 与 `params="id"` 两条） |
| `/daily*` | 建议建 `PublicDailyController` | **本文件没有 `/daily`**；`/daily` 在 `src/main/java/org/example/report/DailyReportController.java:73/132/184`，**不在本次范围**，故不建 `PublicDailyController` |
| 额外 `/api/public` 端点 | — | `src/main/java/org/example/controller/PublicStreamController.java`（`/stream`）不在本文件，**本次未动** |

## 2. 最终结构（括号内为当前行数）

```
org.example.publicapi
├── PublicApiSupport        (869) @Component   共享状态（字段/常量/Snapshot/工具）+ 唯一一处缓存实现
├── PublicAlertController   (729) @RestController  /overview /alerts /alerts/{aggId} /honeypot /audit /latest
├── PublicHomeController    (239) @RestController  /home /deploy
├── PublicKbController      (430) @RestController  /ask /kb /tts /tts/say
├── PublicGeoController     (258) @RestController  /geo /ip
├── PublicMiscController    (864) @RestController  /eval /password /webstats /stories /story(2 条)
└── PublicSnapshotWarmer    (136) @Component   唯一的 @Scheduled 预聚合
```

拆分前：单文件 3063 行。收尾后：端点实现全部在五个按域 controller 里，共享状态与工具全部在
`PublicApiSupport` 里；**门面 `PublicApiController` 已删除**，生产 `main` 下不再有任何"注释 + 一行转发"的壳。
测试源另有一个装配器 `src/test/java/org/example/publicapi/PublicApiTestAssembly.java`（55 行），
是五个 controller 在单测里的唯一组装点。

## 3. 门面的来龙去脉（已删除；这一节留作复盘）

拆分第一步曾在 `PublicApiController` 里保留一层"注解 + 一行转发"的委托门面，原因只有一个：**历史单测**。
本仓库**没有任何 `@SpringBootTest`**（`DeepSeekWiringTest`、`GlobalCorsExposeHeaderTest`、`TtsConfigContractTest`
的注释都明确写了这一点）。当时约 19 个测试类都是这个形态：

```java
PublicApiController c = new PublicApiController();
ReflectionTestUtils.setField(c, "rateLimiter", limiter);
ReflectionTestUtils.setField(c, "cacheSeconds", 15);
MockMvcBuilders.standaloneSetup(c).build();
```

`standaloneSetup(c)` **只注册 `c` 这个对象自己声明的 `@RequestMapping` 方法**。所以门面当时必须
`extends PublicApiSupport` 并保留全部 20 个带原注解的 handler（方法体一行转发），测试才能零改动继续跑。

### 3.1 当时踩到的坑（记录价值）

- 第一版门面**只留 `@RequestMapping("/api/public")`、去掉 `@RestController`** → 全量测试 **120 个用例报 404**
  （`Status expected:<200> but was:<404>`）。`standaloneSetup` 的 handler 检测要求类上有
  `@Controller`/`@RestController`，仅类级 `@RequestMapping` 不够。
- 但把 `@RestController` 加回去，门面就会被组件扫描成 Bean，和五个域 controller 注册**同一批 20 条路径** →
  生产启动 `Ambiguous mapping`。当时的解法是 `@ConditionalOnProperty(prefix="app.public-api", name="legacy-facade-bean")`
  默认关闭；该条件已随门面一起删除（`application*.yml` 里从未出现过这个属性）。

### 3.2 收尾：测试改为直接组装域 controller（当前形态）

门面删除后，测试源新增 `PublicApiTestAssembly` 承担原来的组装职责：

```java
final PublicApiSupport support = new PublicApiSupport();
final PublicAlertController alertController = new PublicAlertController(support);
final PublicGeoController geoController = new PublicGeoController(support);
final PublicHomeController homeController = new PublicHomeController(support, alertController, geoController);
final PublicKbController kbController = new PublicKbController(support);
final PublicMiscController miscController = new PublicMiscController(support);
final PublicSnapshotWarmer snapshotWarmer =
        new PublicSnapshotWarmer(support, alertController, homeController, geoController, miscController);

MockMvc mvc() {
    return MockMvcBuilders
            .standaloneSetup(alertController, homeController, kbController, geoController, miscController)
            .build();
}
```

**构造顺序不可换**：`PublicHomeController` 依赖 `PublicAlertController` 与 `PublicGeoController`，
必须 alert → geo → home → kb → misc。各测试类的改法：`new PublicApiController()` → `new PublicApiTestAssembly()`，
`ReflectionTestUtils.setField(c, …)` → `setField(assembly.support, …)`，`standaloneSetup(x)` → `x.mvc()`
（需要额外 filter/interceptor 的用 `x.builder().addFilters(...)/.addInterceptors(...)`）。

当初那次"打包后真实启动 + 20 端点冒烟"验证的是拆分后的生产形态本身，与门面无关，结论仍然成立：
`Started Main in 6.241 seconds`，无 `Ambiguous mapping`，
（`/overview`…`/webstats` 200、`/story`（缺 src）400、`/alerts/xyz` 404、`/tts` 503（未配 key）、`/story?id=` 200）。

## 4. 20 条 mapping → 目标 controller（逐条）

| # | 路径 | HTTP | 目标 controller | 返回体要点 | 缓存/ETag |
|---|---|---|---|---|---|
| 1 | `/ask` | POST | Kb | `{code,message,data:{answer,…}}`，`no-store`；429 限流 / 429 并发闸门（`X-Public-Concurrency`）；`X-Data-Source: PUBLIC_ASK`、`X-RateLimit-*`、owner 时 `X-Owner-Ask` | 无 ETag |
| 2 | `/kb`、`/kb.js` | GET | Kb | 知识库检索（`q` 可空），`note` 文案随 `policy().masked()` 分叉 | kb 限流，`no-store` |
| 3 | `/tts` | POST | Kb | 音频字节（`audio/mpeg`/`audio/wav`）或错误信封 | 成功 `public,max-age=cacheSeconds` + `X-Tts-Cache`；失败 `no-store` |
| 4 | `/tts/say` | POST | Kb | 同上（每 IP + 全局日配额） | 同上 |
| 5 | `/overview`、`/overview.js` | GET | Alert | `{generatedAt,cacheSeconds,alerts{…},nodes[],dataSource{}}` | 别名 ETag + 陈旧标记 |
| 6 | `/alerts`、`/alerts.js` | GET | Alert | `list` + `stats` + `stats24h(-State/-Reason)` | 别名 ETag |
| 7 | `/alerts/{aggId}` | GET | Alert | 单条聚合；未命中 → **404** 信封 `{code,message}` | 无 ETag |
| 8 | `/honeypot`、`/honeypot.js` | GET | Alert | `source.honeypotSummary(800)` 的公开口径 | 别名 ETag |
| 9 | `/audit`、`/audit.js` | GET | Alert | `auditReader.summary() + blocks(20) + actions(30)` | 别名 ETag |
| 10 | `/latest`、`/latest.js` | GET | Alert | `buildLatest(...)`：最新事件 + 严重度/来源分布 | 别名 ETag |
| 11 | `/home`、`/home.js` | GET | Home | `{generatedAt,cacheSeconds,health{…},data:{alerts,geo,honeypot,audit}}` | 别名 ETag |
| 12 | `/deploy`、`/deploy.js` | GET | Home | `build{sha,sourceSha,artifactMd5,buildTime}` + `runtime{startedAt,uptimeSeconds}` + `release{available,…}` | 别名 ETag |
| 13 | `/eval`、`/eval.js` | GET | Misc | 评测报告白名单字段；无配置/坏 JSON → `available=false + reason` | 别名 ETag |
| 14 | `/geo`、`/geo.js` | GET | Geo | `thresholds/totals/topCountries/topProvinces/topAsns/topIps`；不可用 → `available=false + reason` | 别名 ETag |
| 15 | `/stories`、`/stories.js` | GET | Misc | 故事列表（`window`、`limit`）；坏窗口 → 400 `WINDOW_NOT_SUPPORTED` | 别名 ETag |
| 16 | `/story`、`/story.js`（`?src=`） | GET | Misc | 单源故事；`MISSING_SRC`/`INVALID_SRC`/404 `SOURCE_NOT_IN_WINDOW` | 别名 ETag |
| 17 | `/story`、`/story.js`（`params="id"`） | GET | Misc | 攻击链时间线；数据源不可用 → `available=false` + `数据源不可用` | 别名 ETag |
| 18 | `/ip`、`/ip.js` | GET | Geo | IP 画像；`MISSING_Q`/`INVALID_IP`/`NOT_PUBLIC_IP` → 400 | 普通缓存头 |
| 19 | `/password`、`/password.js` | GET | Misc | `{available,masked,count,bucket,truncated,notes,limits}` | `public,max-age=passwordCacheSeconds` + `X-Data-Source: PASSWORD_DICT*` + `X-RateLimit-*` |
| 20 | `/webstats`、`/webstats.js` | GET | Misc | `thresholds/totals/statusClasses/topCategories/topUas/coverage` | 别名 ETag |

> 与建议映射的差异：`/overview`、`/honeypot`、`/audit`、`/latest` 归入 `PublicAlertController`（与 `/alerts`
> 共用 `PublicAlertSource`/`PublicAuditReader` 和同一批 Snapshot），否则 `PublicMiscController` 会有 10 个端点、
> 变成新的 god controller。`/story` 与 `/stories` 跟 `attackStoryService` 一起放 Misc。

## 5. 字段归属：**全部**下沉到 `PublicApiSupport`

所有字段（含 Geo / WebStats / 密码域）都留在 `PublicApiSupport`，原因有三：

1. `ReflectionTestUtils.setField(assembly.support, "geoMinCount", 3)` 直接打在 `PublicApiSupport` 实例上，
   不再需要"靠门面继承在父类找字段"；
2. `/home` 必须读到与 `/alerts`、`/geo`、`/honeypot`、`/audit` **同一个** `Snapshot` 实例
   （`PublicApiHomeEndpointTest.aggregateBlocksAreFieldForFieldIdentical` 逐字段比较），
   所以 10 个 Snapshot 只能在一个地方；
3. `PublicSnapshotWarmer` 注入同一份 support，才不会出现"两份缓存"。

字段分组（均在 `PublicApiSupport` 内，注解与默认值原样搬）：

- **共享**：`source`、`rateLimiter`、`cacheSeconds(45)`、`warmThresholdRatio(0.5)`、`exposeBuildSha`、
  `buildSha/buildSourceSha/buildArtifactMd5/buildTime`、`deployFile`、`evalReportFile`、
  `ipPolicy`、`assetFilter`、`auditReader`；10 个 `Snapshot`
  （`overviewCache/alertsCache/honeypotCache/auditCache/latestCache/homeCache/deployCache/evalCache/geoCache/webStatsCache`）；
  常量 `FMT/HOUR_FMT/CACHE_ALIAS_SWR_SECONDS/TTS_AUDIO/TTS_AUDIO_WAV/ETAG_MAPPER/STARTED_AT_MS/JSON_FILE_MAX_BYTES/
  DEPLOY_FILE_KEYS/EVAL_REPORT_KEYS/TIMELINE_MAX_EVENTS/TIMELINE_REASON_UNAVAILABLE/FAIL_CLOSED_POLICY/DEFAULT_ASSET_FILTER`。
- **Kb 域**：`publicAskService`、`publicAskRateLimiter`（`@Qualifier("publicAskRateLimiter")`）、`publicKbService`、
  `publicKbRateLimiter`、`publicConcurrencyGuard`、`ownerTokenService`、`ttsService`、
  `ttsSayPerIpDaily(30)`、`ttsSayGlobalDaily(300)`、`maxBodyChars(4000)`。
- **Geo 域**：`geoIpService`、`geoMinCount(3)`、`geoMinSharePercent(1.0)`、`geoTopIps(1000)`、
  `geoTopCountries(20)`、`geoTopProvinces(10)`、`geoTopAsns(10)`、`geoSelfIps("")`；`ipProfileService`。
- **Misc 域**：`passwordDict`、`passwordRateLimiter`、`passwordRequestsPerMinute(30)`、`passwordCacheSeconds(300)`、
  `passwordMaxHashes(200)`、`fallbackPasswordRateLimiter`、`webStatsService`、`webStatsMinCount(5)`、
  `webStatsTopCategories(10)`、`webStatsTopUas(5)`、`attackStoryService`。

## 6. 曾被反射/静态引用的成员：门面删除后各自归位

`ReflectionTestUtils.invokeMethod` 走 `ReflectionUtils.findMethod`（**会向上找父类**），但
`getClass().getDeclaredMethod(...)` **只找本类声明** —— 这正是当初门面留转发壳的原因。
收尾时逐个改指真实归属，现在每个成员只在自己所在的类上声明一次：

| 成员 | 原引用点 | 收尾后 |
|---|---|---|
| `ship(Map)` | `PublicMaskedRegressionTest` | `PublicApiSupport.class.getDeclaredMethod("ship", Map.class)`，再 `invoke(assembly.support, …)` |
| `buildHoneypot()` | `PublicMaskedRegressionTest` | 反射打在 `assembly.alertController`（方法本就在 `PublicAlertController`） |
| `buildAudit()` | `PublicMaskedRegressionTest` | 同上，`assembly.alertController` |
| `warmPublicSnapshots()` | `PublicSnapshotWarmerTest`（调两次，断言不抛） | `assembly.snapshotWarmer.warmPublicSnapshots()` |
| `Snapshot` 嵌套类 | `PublicSnapshotWarmerTest`、`PublicFreeTextIpGateTest` 等 | `PublicApiSupport.Snapshot` |
| `static parseSelfIps` | `PublicApiGeoEndpointTest`；主代码 `AttackStoryService.java:298` | `PublicGeoController.parseSelfIps` |
| `static buildLatest`（7 参与 8 参） | `PublicApiLatestTest` | `PublicAlertController.buildLatest` |
| `static buildWebStatsAvailable/Unavailable`、`webStatsSharePercent` | `PublicApiWebstatsEndpointTest` | `PublicMiscController.*` |
| `static credentialShapes` | 主代码 `PublicIpProfileService.java:203` | `PublicAlertController.credentialShapes` |
| `scrubText(String)` | `PublicFreeTextIpGateTest`（`invokeMethod`，可继承） | 继承自 `PublicApiSupport`，未额外声明 |

## 7. 定时预聚合收敛为一处

原 `@Scheduled warmPublicSnapshots()` 搬到 `PublicSnapshotWarmer`（`@Component`，注入 `PublicApiSupport` +
Alert/Home/Geo/Misc 四个 controller，kb 不参与预热），**全仓只剩一个 `@Scheduled`**：
`fixedDelayString="${app.public-api.warm-interval-ms:30000}"`、`initialDelayString="${app.public-api.warm-initial-delay-ms:10000}"`。

预热顺序保持原样：`overview → alerts → honeypot → audit → latest → geo → webstats → home`，
**home 必须最后**（它只组合已热快照；放前面会把后台一轮拖成十几秒，原注释记录了 P50 29.9 秒的线上事故）。

## 8. 如何保证"只是搬移"（不变量核对）

- **注解零丢失**：用脚本把 `HEAD` 版全文的注解行与拆分后 7 个文件的注解行做 multiset 对比 ——
  差异只有 `@RestController`(1→5)、`@RequestMapping("/api/public")`(1→5)、`@Component`×2（Support/Warmer），
  以及并行子任务新增的 `@RequestParam hours` 一行；**没有丢任何 `@Value/@Autowired/@Qualifier/@GetMapping/@PostMapping/params`**。
- **代码行零丢失**：同样的行级对比（归一化 `support.`/`PublicApiSupport.` 前缀、去掉 `private`）差异仅限：
  `this::buildX` → `alertController::buildX`（跨域 lambda）、构造器/import/类声明行、
  以及并行子任务的 `windowSpec`。没有任何一条业务语句只存在于拆分前。
- 路径、`@RequestParam`/`@PathVariable` 参数名、响应字段名、状态码、缓存头、ETag、限流注解**一律未改**。
- 中文类注释与关键注释（含原 god controller 的"为什么"段落、`/home` P50 事故注释）随成员一起搬走，未改写。
- 验证：拆分完成时 `mvn.cmd -o clean test` → 893 tests / 0 failures / 0 errors / 4 skipped，并打包后真实启动 + 20 端点冒烟；
  门面收尾后（测试改为直连域 controller）`mvn.cmd -o -q clean test` → **903 tests / 0 failures / 0 errors / 4 skipped**。

## 9. 已收尾：门面已删除，测试直连域 controller

- **没有任何兼容壳**：`PublicApiController.java`（695 行）整文件删除，20 个一行转发 handler、10 个静态转发、
  `ship`/`buildHoneypot`/`buildAudit`/`warmPublicSnapshots` 四个壳、以及 `legacy-facade-bean` 条件
  全部消失；`application*.yml` 从未定义过该属性，无需清理配置。
- **装配顺序是硬约束**：`PublicApiTestAssembly` 必须 alert → geo → home → kb → misc
  （`PublicHomeController` 构造依赖 alert 与 geo）。新增域 controller 时只改装配器一处即可，
  但别忘了 `PublicSnapshotWarmer` 的构造参数也要同步。
- **`/home` 的逐字段一致**依赖"同一 Snapshot + 同一 `ship`"：`homeCache` 里的 alerts/geo/honeypot/audit 块
  必须来自 `alertController`/`geoController` 的同一批缓存，别改成各建缓存。
- **ETag/缓存头逐字不变**：`Cache-Control: public, max-age=45, stale-while-revalidate=300`、
  `snapshotAt/cacheAgeSeconds/snapshotTtlSeconds/freshnessNote`、`X-Data-Source`、`X-RateLimit-*`、
  `Retry-After: 60` 都有测试断言。
- **限流桶唯一**：`PublicRateLimiter` / `PublicAskRateLimiter` / `PublicConcurrencyGuard` 仍是原来的 Bean，
  没有因为拆分多建实例（否则计数翻倍、限流口径漂移）。
- **`/story` 双映射**：`?src=` 与 `params="id"` 两条 mapping 的 `params` 条件原样保留，否则路由歧义。
- **`/daily` 不在本文件**：不要为它新建 controller，也不要移动 `report/DailyReportController`。
- **`PublicApiSupport` 现在 869 行**（字段 + 工具 + Snapshot），体量仍偏大；后续若要再拆字段组，
  必须先解决 `ReflectionTestUtils.setField` 按字段名注入的耦合（风险高于收益，本次不做）。

## 10. 收尾改动统计（相对拆分完成时）

| 项 | 数值 |
|---|---|
| 删除的类 | `PublicApiController.java` **695 行**（类注释 + 5 个 controller 字段 + 构造器 + 20 个一行转发 handler + 10 个静态转发 + 4 个兼容壳） |
| `PublicApiSupport` | 882 → **869 行**（改 logger 类名、删 14 个不再使用的 import、重写类注释，逻辑零改动） |
| 迁移的测试类 | **22 个**（19 个 `new PublicApiController()` 的直接使用者 + 同批引用者），另 2 个探针 `AttackStoryRealDataProbe`/`AttackStoryGoldenGenerator` |
| 测试源新增 | `PublicApiTestAssembly.java`（55 行，五个 controller 的唯一组装点） |
| 主代码静态调用改指 | `AttackStoryService.java:298` → `PublicGeoController.parseSelfIps`；`PublicIpProfileService.java:203` → `PublicAlertController.credentialShapes` |
| 文档/注释 | 5 个域 controller 类注释 + 15 处 javadoc `{@link}` 改指真实类 |
| 最终验证 | `mvn.cmd -o -q clean test` → `Tests run: 903, Failures: 0, Errors: 0, Skipped: 4`（未新增/删减测试方法：`@Test`/`@ParameterizedTest` 注解数 HEAD 与收尾后同为 897） |
