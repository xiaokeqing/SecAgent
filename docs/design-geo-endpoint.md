# 设计说明：`GET /api/public/geo`（攻击来源地理分布，只给聚合）

> 状态：**已实现**（2026-10-13，代码：`org.example.geoip.*` + `PublicApiController#geo`）。
> 本文是交给博客大屏实施方的对接文档：字段表 + 示例响应 + 前端怎么画 + 不许做什么。
> 关联：RUNBOOK §26（库/更新/内存/降级/署名/如何关闭）、§10（公开端点运维要点）。

## 0. 一句话

匿名可访问的**只读聚合**端点：把 24 小时内的攻击来源 IP 变成
**国家 / 省份 / ASN + 计数 + 独立 IP 数 + 时间桶**，由离线库（DB-IP Lite）在地图上着色。
**响应里没有任何 IP（连掩码 IP 都没有）、没有单条告警、没有内网资产。**

```
GET /api/public/geo
```

## 1. 端点行为（先看这张表再写前端）

| 维度 | 口径 |
|---|---|
| 方法 / 路径 | `GET /api/public/geo` |
| 认证 | **匿名**（公开面） |
| 限流 | 每 IP **20 次/分钟**（与 `/overview`、`/alerts` 同一个桶）；超限 `429` + `Retry-After: 60` |
| 缓存 | 服务端快照 **15 秒**（`app.public-api.cache-seconds`）；响应头 `Cache-Control: public, max-age=15` |
| 条件请求 | 支持 `ETag` / `If-None-Match` → `304`（**304 也计入限流**） |
| CORS | 只有白名单来源收到 `Access-Control-Allow-Origin`（`app.public-api.allowed-origins`） |
| 信封 | 与其余公开端点一致：`{"code":200,"message":"success","data":{...}}` |
| 附加字段 | 公开面统一注入 `data.ipDisclosure`（IP 显示口径与申诉入口），见 §5 |
| 时间窗 | **固定 24 小时**（`now-24h`），趋势按**本地时间**（Asia/Shanghai）小时分桶，共 24 点 |
| 数据源 | Wazuh indexer 的 `wazuh-alerts-*`，做**一次 terms 聚合查询**（不是把原始日志取回来本地数） |

## 2. 字段表（新增字段默认不出现；这一份就是白名单）

| 字段 | 类型 | 说明 |
|---|---|---|
| `generatedAt` | string | 本次载荷生成时间 `yyyy-MM-dd HH:mm:ss`（本地时区）。15 秒内不变 |
| `cacheSeconds` | int | 应用内快照 TTL，同时是 `Cache-Control: max-age` |
| `available` | bool | **唯一的可用性开关**。`false` 时下面所有分布字段都是空数组，且必给 `reason` |
| `reason` | string | 机读原因：`OK` / `NO_DATA_IN_WINDOW` / `GEO_DB_MISSING` / `GEO_DB_UNUSABLE` / `GEO_DB_LOADING` / `GEO_DISABLED` / `DATA_SOURCE_UNAVAILABLE` / `QUERY_FAILED` |
| `geoSource` | string \| null | 用的是哪一版库，例：`"DB-IP Lite City 2026-10 + DB-IP Lite ASN 2026-10"`。**页面上要显示它** |
| `geoAttribution` | string | 署名文案（CC BY 4.0 要求）：`"IP 地理位置数据由 DB-IP (https://db-ip.com) 提供，CC BY 4.0"` |
| `window` | string | 固定 `"24h"` |
| `thresholds` | object | 本次生效的入榜门槛：`minCount` / `minSharePercent` / `topCountries` / `topProvincesPerCountry` / `topAsns` |
| `coverage` | object | **分母**：见 §3。页面必须用它说明"这张图覆盖了多少" |
| `countryCount` | int | 入榜国家数（= `byCountry.length`） |
| `provinceCountCN` | int | 入榜的国内省份数（= `byProvinceCN.length`） |
| `knownProvinceCount` | int | 窗口内出现过的省份总数（含未入榜的） |
| `byCountry` | array | 国家榜，按 `count` 降序；见下 |
| `byProvinceCN` | array | **只含 CN** 的省份榜，供中国地图直接着色（不必自己从 `byCountry` 里翻） |
| `byAsnTop` | array | ASN 榜（机构名已截断到 60 字符） |
| `trend` | array | 24 个时间桶 `{ts:"2026-10-13T20:00", count:7}`（本地时间、整点） |
| `note` | string | 人读口径说明 + **署名**（与 `geoAttribution` 同一句） |

`byCountry[]`：

| 字段 | 类型 | 说明 |
|---|---|---|
| `country` | string | ISO-3166-1 alpha-2（**聚合键**，判定"是不是国内"只看它） |
| `countryName` | string | 中文展示名（未收录的国家回落成 ISO2 原码，例如 `SG`） |
| `count` | int | 该国的告警条数 |
| `uniqueIps` | int | 该国涉及的**独立来源 IP 数**（抗"一个吵闹 IP 点亮整张图"） |
| `sharePercent` | number | 占 `coverage.geocoded` 的百分比（两位小数） |
| `byProvince[]` | array | 该国的一级行政区：`{province, count, uniqueIps}`（`province` 是 DB-IP 英文原文，如 `Zhejiang`） |

`byProvinceCN[]`：`{province, count, uniqueIps, sharePercent}`。
`byAsnTop[]`：`{asn, org, count, uniqueIps}`。

## 3. `coverage`：为什么它是这张图"可信不可信"的关键

实测（2026-10-13，srv1 线上 indexer）：

```
24 小时告警总数            111,031
带来源 IP 字段的告警        ~107,000   ← 其中 Suricata 的 data.src_ip 占绝大多数
真正能归属到国家的          见 geocoded（内网/保留/我方会被排除）
```

**只有一部分告警带来源 IP**（主机侧/蜜罐写 `data.srcip`，Suricata 写 `data.src_ip`；两种字段都查，分别聚合后按 IP 合并）。
所以页面**必须**如实写"有来源 IP 的 N 条 / 总 M 条"，**不许把这几百条画成"全量攻击分布"**。

| 字段 | 含义 |
|---|---|
| `totalAlerts` | 窗口内告警总数（分母的分子） |
| `withSourceIp` | 其中**带来源 IP 字段**的条数（真正参与地图的候选集） |
| `geocoded` | 成功归属到国家/省份的条数（**所有占比都以它为分母**） |
| `excludedSelf` | 我方公网/内网出口 IP 的条数（配置 `APP_GEOIP_SELF_IPS`） |
| `excludedInternal` | 内网/环回/链路本地/CGNAT 条数（`10/8`、`172.16/12`、`192.168/16`、`127/8`、`169.254/16`、`100.64/10`、`fc00::/7`、`fe80::/10`） |
| `excludedReserved` | 保留/文档网段条数（`0/8`、`192.0.2/24`、`198.51.100/24`、`203.0.113/24`、`198.18/15`、`224/4`、`240/4`、`2001:db8::/32`、`ff00::/8`） |
| `unlocated` | 公网但库中没有归属（含 `ZZ` 未分配段） |
| `invalid` | 字段存在但解析不出 IP（脏数据） |
| `sourceBuckets` | 参与聚合的 IP 桶数（≤ `top-ips` × 字段数） |
| `sourceBucketsTruncated` | `true` = TOP N 之外还有长尾被截断（**不是完整分布**，页面要标注） |

## 4. 示例响应（可用态，字段已按真实形状给出）

```jsonc
{
  "code": 200,
  "message": "success",
  "data": {
    "generatedAt": "2026-10-13 21:30:00",
    "cacheSeconds": 15,
    "available": true,
    "reason": "OK",
    "geoSource": "DB-IP Lite City 2026-10 + DB-IP Lite ASN 2026-10",
    "geoAttribution": "IP 地理位置数据由 DB-IP (https://db-ip.com) 提供，CC BY 4.0",
    "window": "24h",
    "thresholds": { "minCount": 3, "minSharePercent": 1.0,
                    "topCountries": 20, "topProvincesPerCountry": 10, "topAsns": 10 },
    "coverage": {
      "totalAlerts": 111031, "withSourceIp": 107342, "geocoded": 106900,
      "excludedSelf": 195, "excludedInternal": 43285, "excludedReserved": 12,
      "unlocated": 0, "invalid": 0,
      "sourceBuckets": 42, "sourceBucketsTruncated": true
    },
    "countryCount": 3, "provinceCountCN": 2, "knownProvinceCount": 18,
    "byCountry": [
      { "country": "CN", "countryName": "中国", "count": 61200, "uniqueIps": 21, "sharePercent": 57.25,
        "byProvince": [ { "province": "Zhejiang", "count": 40100, "uniqueIps": 9 },
                        { "province": "Fujian",   "count": 11200, "uniqueIps": 6 } ] },
      { "country": "US", "countryName": "美国", "count": 2140, "uniqueIps": 12, "sharePercent": 2.0,
        "byProvince": [ { "province": "California", "count": 1500, "uniqueIps": 7 } ] }
    ],
    "byProvinceCN": [
      { "province": "Zhejiang", "count": 40100, "uniqueIps": 9, "sharePercent": 37.5 },
      { "province": "Fujian",   "count": 11200, "uniqueIps": 6, "sharePercent": 10.48 }
    ],
    "byAsnTop": [
      { "asn": 4134, "org": "CHINANET-BACKBONE", "count": 51300, "uniqueIps": 15 },
      { "asn": 15169, "org": "Google LLC", "count": 2140, "uniqueIps": 12 }
    ],
    "trend": [
      { "ts": "2026-10-12T21:00", "count": 4210 },
      { "ts": "2026-10-12T22:00", "count": 3988 }
    ],
    "note": "只给聚合：响应里不含任何 IP（连掩码 IP 都没有）、不含单条告警、不含内网资产。分母以 coverage 为准… IP 地理位置数据由 DB-IP (https://db-ip.com) 提供，CC BY 4.0",
    "ipDisclosure": { "mode": "real", "removalContact": "https://xiaokeqing.cn/about/", "note": "…" }
  }
}
```

不可用示例（**不要**把它渲染成"风平浪静"）：

```jsonc
{
  "code": 200, "message": "success",
  "data": {
    "generatedAt": "2026-10-13 21:30:00", "cacheSeconds": 15,
    "available": false, "reason": "GEO_DB_MISSING",
    "geoSource": null,
    "geoAttribution": "IP 地理位置数据由 DB-IP (https://db-ip.com) 提供，CC BY 4.0",
    "window": "24h",
    "coverage": { "totalAlerts": 0, "withSourceIp": 0, "geocoded": 0, "excludedSelf": 0,
                  "excludedInternal": 0, "excludedReserved": 0, "unlocated": 0, "invalid": 0,
                  "sourceBuckets": 0, "sourceBucketsTruncated": false },
    "byCountry": [], "byProvinceCN": [], "byAsnTop": [], "trend": [],
    "note": "离线地理库不存在（app.geoip.city-db 指向的文件/目录里没有 dbip-city-lite-*.csv.gz）：请先跑 scripts/srv1-geoip-update.sh 落地 DB-IP Lite 库；本端点不返回任何数字。 IP 地理位置数据由 DB-IP (https://db-ip.com) 提供，CC BY 4.0"
  }
}
```

`reason` 与页面文案的建议映射（**照抄，别自己发明**）：

| `reason` | 页面文案 |
|---|---|
| `OK` | 正常渲染地图 |
| `NO_DATA_IN_WINDOW` | "最近 24 小时没有带来源 IP 的告警"（不是故障） |
| `GEO_DB_MISSING` / `GEO_DB_LOADING` / `GEO_DB_UNUSABLE` / `GEO_DISABLED` | "地理库未就绪（<原因>），本次不展示分布" |
| `DATA_SOURCE_UNAVAILABLE` / `QUERY_FAILED` | "数据源暂不可用，稍后重试" |

## 5. 前端怎么画（自绘 SVG 中国地图，不引地图库）

### 5.1 数据到颜色的映射（推荐口径）

```js
// 1) 取国内省份榜；用 count 做强度着色，但【必须】同时显示 uniqueIps
const cn = data.byProvinceCN;                       // [{province, count, uniqueIps, sharePercent}]
const max = Math.max(1, ...cn.map(p => p.count));

// 2) 分级着色（等比 sqrt 比线性好：一个省独占 90% 时线性会让其余省份全变浅色）
const bucket = p => Math.min(5, Math.floor(Math.sqrt(p.count / max) * 5));
const FILL = ['#eef3f8', '#cfe3f5', '#9cc7ea', '#5fa4d8', '#2f7cb8', '#155e93'];

// 3) 省份路径匹配：几何数据用【英文名/Zhejiang】做 id，与 province 字段同名，
//    不要用中文名匹配 —— DB-IP 给的是英文原文，翻译表只用于鼠标提示。
```

- **地图几何从哪来**：自己仓库里放一份简化版中国省界 SVG（`viewBox="0 0 1000 800"`，
  每省一个 `<path id="Zhejiang">`）。**不要**在运行时从外部 CDN 拉 GeoJSON：
  公开页面不该有第三方依赖，而且那份数据可能被改。
- **着色注意**：DOM 只有 34 个省，直接改 `path.setAttribute('fill', …)` 即可，
  不需要虚拟 DOM；鼠标悬停显示"Zhejiang · 40100 条 / 9 个独立 IP / 37.5%"。
- **Top 省份榜**：取 `byProvinceCN.slice(0,5)` 横向条形图，条宽按 `count / max`。
- **时间趋势**：`trend` 是 24 个整点，直接画折线/柱状即可（x 轴就是 `ts`，已经是本地时间）。
  注意 `trend` 是"带来源 IP 的告警"的口径，和 `coverage.withSourceIp` 同一批数据 ——
  别把它和 `/api/public/alerts` 的 `stats24h.trend`（全量告警）画在同一条轴上。
- **世界视图**：`byCountry` 的 `country` 是 ISO2，可直接对接任何 ISO2-keyed 的世界地图路径
  （同样建议自绘/内置）。国内单独用 `byProvinceCN`。
- **`sourceBucketsTruncated === true`**：地图角上写一句"仅显示来源最集中的 N 个 IP 桶"，
  否则读者会以为这是完整分布。

### 5.2 必须显示的三行字（合规 + 诚实）

1. `coverage`：**"有来源 IP 的 107,342 条 / 总 111,031 条"**（数字来自响应，别写死）
2. `geoSource`：**"DB-IP Lite City 2026-10 + DB-IP Lite ASN 2026-10"**
3. 署名（CC BY 4.0 的硬要求）：**"IP 地理位置数据由 DB-IP (https://db-ip.com) 提供，CC BY 4.0"**
   —— 直接用 `note` 或 `geoAttribution` 字段的值，不要自己翻译/改写。

## 6. 前端**不许**做的事（这几条是红线）

1. **不许把 `count` 当 IP 展示**：`count` 是"告警条数"，不是"多少个 IP"。要体现独立来源请用 `uniqueIps`。
   （典型错误：把 `count: 40100` 渲染成"40100 个攻击 IP"。）
2. **不许从聚合里反推攻击者位置**：不要用 `byProvince` 的计数去猜具体城市/机房，
   也不要把 `byCountry` + `byAsnTop` 交叉比对当作"定位某个攻击者"。地理库是**国家级/省级**精度，
   写"某省某市某个 IP"是超出数据能力的断言，属于误导。
3. **不许在页面上显示任何 IP**：本端点不返回 IP，页面也不要从别的端点（例如 `/alerts` 的明细）
   把 IP 拼到这张地图旁边当作"解释"。
4. **不许把 `available=false` 渲染成"没有攻击"**：见 §4 的文案映射表。
5. **不许自己拼 URL 参数调别的地理/情报 API**（红线：项目不调任何在线第三方地理/情报 API）。
6. **不许把 `data.note` 里的署名删掉或换成 "地图数据"** 这类模糊说法 —— CC BY 4.0 要求署名。

## 7. 后端实现对应关系（给评审看的）

| 层 | 类 | 职责 |
|---|---|---|
| 库装载 | `org.example.geoip.GeoIpDatabase` | 流式读 gz CSV → 排序区间数组 + 去重记录池 |
| 查询 | `org.example.geoip.IpRangeTable` | 二分查找（IPv4/IPv6 各一套；连续且到末端才省终点数组） |
| 地址性质 | `org.example.geoip.IpAddresses` | 解析 + `GLOBAL / INTERNAL / RESERVED / INVALID` |
| 服务 | `org.example.geoip.GeoIpService` | 后台装载、状态机（`MISSING/LOADING/OK/UNUSABLE/DISABLED`）、署名常量 |
| 取数 | `WazuhService#geoWindow24h` → `PublicAlertSource#geoWindow24h` | indexer terms 聚合（两个来源字段）+ 小时桶 |
| 聚合 | `org.example.geoip.GeoAggregator` | 纯函数：排除→归属→门槛→排序→载荷（**IP 不出这里**） |
| 端点 | `PublicApiController#geo` | 限流/CORS/ETag/15s 快照/`ok(...)` 信封 + 降级分支 |
| 富化 | `WazuhService#mapRealAlerts` | 只补 `SecurityAlert.srcGeo`（内部形状 `国家\|省\|城市\|ASN\|机构`），**公开面不输出** |

测试：`GeoIpDatabaseTest`（区间边界/连续与缺口/IPv6/坏库）、`IpAddressesTest`、`GeoIpServiceTest`（四种降级）、
`GeoAggregatorTest`（门槛/排除/uniqueIps/无 IP/确定性）、`WazuhGeoWindowParseTest`（两字段合并/UTC→本地/截断）、
`PublicApiGeoEndpointTest`（路由/信封/降级头）、`PublicApiGeoLeakTest`（`/alerts`、`/alerts/{aggId}`、`/latest` 不泄露 `srcGeo`）。
