# 拆分 `PublicApiController` 为按域 controller —— 最终形态与迁移清单

> 状态：**已完成**（2026-11-07）。路径、参数名、响应 JSON 字段、状态码、缓存头、限流注解全部不变；
> `mvn.cmd -o clean test` → `Tests run: 893, Failures: 0, Errors: 0, Skipped: 4`（基线 892 + 1 条并行的 `/story?id=` 测试）。
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
├── PublicApiSupport        (883) @Component   共享状态（字段/常量/Snapshot/工具）+ 唯一一处缓存实现
├── PublicAlertController   (730) @RestController  /overview /alerts /alerts/{aggId} /honeypot /audit /latest
├── PublicHomeController    (240) @RestController  /home /deploy
├── PublicKbController      (431) @RestController  /ask /kb /tts /tts/say
├── PublicGeoController     (259) @RestController  /geo /ip
├── PublicMiscController    (799) @RestController  /eval /password /webstats /stories /story(2 条)
├── PublicSnapshotWarmer    (137) @Component   唯一的 @Scheduled 预聚合
└── PublicApiController     (696) @RestController + @ConditionalOnProperty（默认关）  委托门面，专供历史单测
```

拆分前：单文件 3063 行。拆分后：门面 696 行（其中 20 个方法各只有一行 `return xxxController.yyy(...)`），
端点实现全部在五个按域 controller 里，共享状态与工具全部在 `PublicApiSupport` 里。

## 3. 为什么旧类必须保留"委托门面"（这是本次拆分最反直觉的地方，必读）

本仓库**没有任何 `@SpringBootTest`**（`DeepSeekWiringTest`、`GlobalCorsExposeHeaderTest`、`TtsConfigContractTest`
的注释都明确写了这一点）。约 19 个测试类全部是这个形态：

```java
PublicApiController c = new PublicApiController();
ReflectionTestUtils.setField(c, "rateLimiter", limiter);
ReflectionTestUtils.setField(c, "cacheSeconds", 15);
MockMvcBuilders.standaloneSetup(c).build();
```

`standaloneSetup(c)` **只注册 `c` 这个对象自己声明的 `@RequestMapping` 方法**，域 controller 在测试里根本不会被注册。
所以门面必须：

1. `extends PublicApiSupport` —— 40+ 私有字段、`Snapshot`、静态工具都在同一实例上，
   `ReflectionTestUtils.setField` 会沿父类逐级查找字段，**测试零改动**；
2. 保留全部 **20 个带原注解**的 handler 方法，方法体只有一行转发；
3. 构造函数里 `new` 五个域 controller 并传 `this`（同一个 support 实例，共享同一批 `Snapshot`）；
4. 保留测试用 `getDeclaredMethod` 反身引用的私有壳（见 §6）。

### 3.1 实测踩坑：`@RestController` 不能省，但也不能"真正生效"

- 第一版门面**只留 `@RequestMapping("/api/public")`、去掉 `@RestController`** → 全量测试 **120 个用例报 404**
  （`Status expected:<200> but was:<404>`）。`standaloneSetup` 的 handler 检测要求类上有
  `@Controller`/`@RestController`，仅类级 `@RequestMapping` 不够。
- 但把 `@RestController` 加回去，门面就会被组件扫描成 Bean，和五个域 controller 注册**同一批 20 条路径** →
  生产启动 `Ambiguous mapping`。

### 3.2 最终解法：条件化的门面 Bean

```java
@RestController
@RequestMapping("/api/public")
@ConditionalOnProperty(prefix = "app.public-api", name = "legacy-facade-bean", havingValue = "true")
public class PublicApiController extends PublicApiSupport { ... }
```

- `app.public-api.legacy-facade-bean` **默认不存在** ⇒ 组件扫描跳过门面 ⇒ 生产里只有五个域 controller 是 Bean，
  路径不冲突；
- 单测是手工 `new PublicApiController()`，条件注解只在 Spring 容器里生效，**完全不影响** `standaloneSetup`；
- 条件开启（设为 `true`）时门面会被注册 —— 仅在"临时回退到单类形态"时才这么做，且必须同时让五个域 controller 下线，
  否则路径重复。

**实测生产启动**（打包后 `java -jar target/sec-agent-1.0-SNAPSHOT.jar --server.port=18082`）：
`Started Main in 6.241 seconds`，日志**没有** `Ambiguous mapping`；20 条路径冒烟全部返回预期状态码
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

1. `ReflectionTestUtils.setField(controller, "geoMinCount", 3)` 打的是 `new PublicApiController()`，
   靠继承在父类找到字段；
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

## 6. 被反射/静态引用、因此必须声明在旧类自身上的成员

`ReflectionTestUtils.invokeMethod` 走 `ReflectionUtils.findMethod`（**会向上找父类**），但
`getClass().getDeclaredMethod(...)` / `PublicApiController.class.getDeclaredMethod(...)` **只找本类声明**。

| 成员 | 引用点 | 处理 |
|---|---|---|
| `private ship(Map)` | `PublicMaskedRegressionTest.java:213` | 门面保留一行 `return super.ship(data);` |
| `private buildHoneypot()` | `PublicMaskedRegressionTest.java:150-154/180/210` | 门面保留转发壳 |
| `private buildAudit()` | `PublicMaskedRegressionTest.java:190` | 门面保留转发壳 |
| `public warmPublicSnapshots()` | `PublicSnapshotWarmerTest.java:139-143`（调两次，断言不抛） | 门面保留一行转发到 `snapshotWarmer` |
| `Snapshot` 嵌套类 | `PublicSnapshotWarmerTest.java:32/33` `new PublicApiController.Snapshot()` | 门面保留 `static final class Snapshot extends PublicApiSupport.Snapshot` |
| `static parseSelfIps` | `PublicApiGeoEndpointTest.java:344-346`；主代码 `AttackStoryService.java:298` | 门面 static 转发 |
| `static buildLatest`（7 参与 8 参） | `PublicApiLatestTest` | 门面 static 转发 |
| `static buildWebStatsAvailable/Unavailable`、`webStatsSharePercent` | `PublicApiWebstatsEndpointTest.java:368-391` | 门面 static 转发 |
| `static credentialShapes` | 主代码 `PublicIpProfileService.java:203` | 门面 static 转发 |
| `scrubText(String)` | `PublicFreeTextIpGateTest.java:298-316`（`invokeMethod`，可继承） | 继承自 Support，未额外声明 |

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
- 验证：`mvn.cmd -o clean test` → 893 tests / 0 failures / 0 errors / 4 skipped；打包后真实启动 + 20 端点冒烟。

## 9. 保留未动 / 风险点

- **门面是"测试专用"的**：改它的方法名、参数名或注解会直接打挂 ~19 个测试类；它不是生产 Bean，
  但没有它 `standaloneSetup` 就覆盖不到域 controller。
- **条件属性不要随手打开**：`app.public-api.legacy-facade-bean=true` 会与五个域 controller 重复注册
  同一批路径（`Ambiguous mapping`）。
- **`/home` 的逐字段一致**依赖"同一 Snapshot + 同一 `ship`"：`homeCache` 里的 alerts/geo/honeypot/audit 块
  必须来自 `alertController`/`geoController` 的同一批缓存，别改成各建缓存。
- **ETag/缓存头逐字不变**：`Cache-Control: public, max-age=45, stale-while-revalidate=300`、
  `snapshotAt/cacheAgeSeconds/snapshotTtlSeconds/freshnessNote`、`X-Data-Source`、`X-RateLimit-*`、
  `Retry-After: 60` 都有测试断言。
- **限流桶唯一**：`PublicRateLimiter` / `PublicAskRateLimiter` / `PublicConcurrencyGuard` 仍是原来的 Bean，
  没有因为拆分多建实例（否则计数翻倍、限流口径漂移）。
- **`/story` 双映射**：`?src=` 与 `params="id"` 两条 mapping 的 `params` 条件原样保留，否则路由歧义。
- **`/daily` 不在本文件**：不要为它新建 controller，也不要移动 `report/DailyReportController`。
- **Support 现在 883 行**（字段 + 工具 + Snapshot），体量偏大；后续若要再拆字段组，必须先解决
  `ReflectionTestUtils.setField` 按字段名注入的耦合（风险高于收益，本次不做）。
