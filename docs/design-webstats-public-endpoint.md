# 设计说明：`GET /api/public/webstats`（**待口径确认，暂未实现**）

> 状态：**只写设计，不实现**。等站主确认口径后再动手（本文末尾第 6 节是需要拍板的 6 个问题）。
> 关联：RUNBOOK §24（应用侧访问日志）、§10（公开端点运维要点）、§4.5（`/api/public/ask` 与 `kb`）。

## 1. 目标与非目标

**目标**：让博客"监测中心"能展示三样东西 —— **Top 被扫路径 / 状态码分布 / Top UA**。

**非目标（明确不做）**：
- 不做"攻击者来源排行"：**不返回任何 IP，连掩码 IP 都不给**。
  理由：公开"攻击者来自哪些网段/有多少个来源"本身就是情报泄露，
  而且会暴露我们的监测覆盖规模（被打得多狠、有没有人一直在打）。
- 不做逐条事件流（那是取证，属于内部面）。
- 不新增内部数据面：数据只能来自**已经落地的访问日志**的聚合。

## 2. 口径（建议值，待确认）

```jsonc
GET /api/public/webstats
{
  "code": 200, "message": "success",
  "data": {
    "generatedAt": "2026-10-13 20:50:00",
    "cacheSeconds": 15,
    "available": true,              // 数据源不可用/未开启时 false + note（fail-closed，绝不用 0 冒充"太平"）
    "windowMinutes": 1440,          // 聚合窗口：最近 24 小时
    "total": 18342,                 // 窗口内请求总数
    "statusClasses": { "2xx": 17102, "3xx": 88, "4xx": 1102, "5xx": 50 },  // 只到"类"，不到具体码
    "topPaths": [                   // ≤10 条；见第 3 节的"必须用固定枚举"方案
      { "path": "/wp-login.php", "count": 214 },
      { "path": "/.env",         "count": 96 }
    ],
    "topUas": [                     // ≤5 条；UA 是攻击者可控字符串，必须清洗+限量
      { "ua": "curl/8.0.1", "count": 421 }
    ],
    "note": "仅聚合口径；不含任何来源 IP"
  }
}
```

字段白名单（**新增字段默认不出现**，与本项目其余公开端点同一条纪律）：
`generatedAt / cacheSeconds / available / windowMinutes / total / statusClasses / topPaths / topUas / note`。

## 3. 三个必须先解决的安全问题（这是本文的重点）

1. **Top 路径 = 把攻击者可控字符串搬到公网页面上**（反射/存储型内容的入口）。
   攻击者扫 `/<script>…` 或 `/<一段垃圾>`，第二天就出现在"被扫路径"榜上。
   - 方案 A（推荐）：**只展示固定枚举的"扫描类别"**，不展示原始 path：
     `wp-login / dotenv / dotgit / phpmyadmin / traversal / admin-panel / other-4xx`，
     每个类别给计数。这样公网页面上**永远不出现任何攻击者输入**，也不需要靠转义兜底。
   - 方案 B：展示原始 path，但**服务端强制清洗**（字符白名单 `[A-Za-z0-9._~/%:-]`、长度 ≤64、
     非白名单字符替换为 `?`）+ **计数门槛 ≥5** + 只取 Top10。
     风险仍高于 A（例如能构造出很像我们自己的路径来误导读者）。
   - 我的建议：**A 为主体，B 作为可选开关**（默认关）。
2. **Top UA 同理**（UA 是更脏的字段）：长度 ≤64、控制字符替换、
   **剔除我方自有 UA**（`secagent-*`、健康检查、内部脚本），并把计数门槛设 ≥5。
3. **不返回 IP，也不要"间接指纹"**：不返回"不同来源数"、不返回"某路径的来源分布"，
   不返回 `clientIp` 的任何派生量。测试里用正则断言出参**不含任何 IP 形态字符串**。

## 4. 数据来源与成本（决定实现形态）

**不能**在请求里读 `data/access.jsonl`：① 那是**内部数据面**（本项目公开面的纪律是"只解释、不取证"）；
② 一天一个 64MB 的文件按请求解析 = 把 §23 那条"请求路径上做 I/O"的教训再犯一次。

⇒ **在进程内做聚合**：新增 `org.example.accesslog.WebStatsAggregator`，
   由**写线程**在落盘同一批记录时顺手累加（请求线程仍然零成本、零 I/O）：

```
写入路径（现状）：  请求线程 --offer()--> 有界队列 --写线程--> access.jsonl
改造后：            请求线程 --offer()--> 有界队列 --写线程--> access.jsonl
                                                  └-----------> WebStatsAggregator（内存计数）
计数器：总数 / status 类 / 路径类别 Top-N / UA Top-N
窗口：  两层滚动桶（当前小时 + 上一小时）或 24×5min 桶，二选一（见第 6 节问题 3）
内存：  上限固定（例如 32 个 UA 槽 + 16 个路径类别计数），攻击者刷不出内存增长
关闭：  app.accesslog.enabled=false 时聚合器也不工作 → 端点返回 available=false + note
```

**复用既有的公开面机制，一个都不新增**：

| 机制 | 复用方式 |
|---|---|
| 限流 | 同一个 `PublicRateLimiter`（20 次/分钟，304 也计入） |
| CORS | 同一个 `PublicCorsInterceptor`（`app.public-api.allowed-origins` 白名单） |
| ETag / 304 | 同一个 `PublicEtagFilter`（无需改动，只要走 `ok(...)` 那条通路） |
| 缓存 | 同一个 `Snapshot`（`app.public-api.cache-seconds`，15 秒） |
| 出参外壳 | 同一个 `ok(...)`（`code/message/data` + `Cache-Control` + `X-Data-Source`） |
| 代码隔离 | 控制器放在 `publicapi` 包（`PublicApiIsolationTest` 的禁用符号清单不用动），聚合器放在 `accesslog` 包，只暴露不可变 DTO |

## 5. 验收标准（实现时必须一起交付）

1. `PublicApiIsolationTest`、`SpringBeanConstructorTest` 全绿（新 bean 若多构造器必须显式 `@Autowired`）。
2. 新增测试：
   - `WebStatsNoIpLeakTest`：对多种输入（含带 IP 形态的 UA/路径）断言出参**正则级不含 IP**；
   - `WebStatsAggregatorTest`：滚动窗口、Top-N 截断、计数门槛、UA 清洗/剔除自有 UA、内存上限；
   - `PublicApiWebstatsTest`：`available=false` + `reason` 的 fail-closed 分支（对照 `/latest` 的写法）；
   - 复用 `PublicEtagFilterTest` 的口径断言 304 语义不变。
3. 公开面文档：RUNBOOK §10 追加"`/api/public/webstats` 的口径与**为什么不给 IP**"。
4. 端到端：`curl` 出参与第 2 节字段白名单逐字对比（多一个字段就是不合格）。

## 6. 需要站主拍板的 6 个问题

1. **Top 路径**：用方案 A（固定类别枚举，公网页面上永不出现攻击者输入）还是方案 B（原始 path + 强清洗）？
   我建议 A。
2. **窗口**：24 小时（推荐，够看出"最近有没有人打"）还是 7 天（更容易看出趋势，但聚合状态要常驻内存/Flink 级复杂度）？
3. **滚动实现**：24×5 分钟桶（精确但状态多一点）还是"当前小时+上一小时"两桶（最省，口径粗）？
4. **计数门槛**：Top 榜的入榜门槛（建议 ≥5 次，避免"单人一次探测就上公网页面"）。
5. **状态码分布**：只给 2xx/3xx/4xx/5xx 四类（推荐）还是给到具体码（如 404/403）？
6. **要不要顺带暴露"疑似扫描占比"**（例：4xx 里属于已知扫描类别的比例）？
   有情报价值，但也等于公开我们的检测能力边界 —— 我倾向**不给**。

> 结论：这件事**技术上可行且成本很低**（复用既有四个机制 + 一个内存聚合器），
> **唯一的真风险是"把攻击者可控字符串搬到公网页面"**。所以我把"固定类别枚举"作为推荐口径 ——
> 它同时满足了"能展示 Top 被扫路径"和"公开面不引入任何外部输入"这两个互相拉扯的要求。
