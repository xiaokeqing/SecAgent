# 设计说明：攻击故事线 `GET /api/public/stories` + `GET /api/public/story`（**2026-10-14 已实现**）

> ## ⚠️ 状态（2026-10-14）：**已实现并跑过真实索引器**
>
> 口径、字段表、实测响应、已知局限全部见 **RUNBOOK §32**（运维口径）。
> 本文是给**博客对接方**看的：字段怎么读、页面该怎么画、哪一段"没有数据"必须显式画出来。
>
> 关联：RUNBOOK §27（公开面 IP 口径与"永不公开"两条）、§26（`/api/public/geo`，同样是"四段之一"的
> 另一条聚合面）、§29（`/api/public/webstats`，同样是"只给聚合"的写法范例）、
> §31（Dionaea 诱饵端口上线 —— 本端点的 `decoyPorts` 段就是它的数据）。
>
> **⚠️ 编号说明**：任务书里这一节写的是 §31，但并行的另一位实施方先提交了
> `RUNBOOK §31 = Dionaea 上线`（commit `c07fd27`）。为了不覆盖别人的章节，本节落在 **§32**；
> 代码/配置/测试里的引用已同步改成 §32。

## 1. 一句话说明它是什么

把**同一个来源**在四个阶段的记录串成一条时间线：

```
告警(alerts) ──▶ 诱饵端口(decoyPorts) ──▶ 蜜罐登录(honeypotLogins) ──▶ 处置审计(auditActions)
```

- `GET /api/public/stories?limit=10&window=24h` —— **有哪些来源值得看**（一个来源一行）。
- `GET /api/public/story?src=<IP>&window=24h` —— **那一个来源的完整事件流**。

两个端点都复用既有公开面外壳：同一个限流器（20 次/分钟）、同一个 CORS 白名单、
同一个 ETag 过滤器（304）、同一个 15 秒快照、同一个 `ok(...)` 信封 ——
所以它们**自动**带上 `ipDisclosure` 与内部资产名过滤，一个新增机制都没有。

**非目标（明确不做）**：
- 不做"全网攻击态势"：只有**窗口内已观测到的**来源，且只服务候选池里的来源。
- 不做取证下钻：不给原始日志、不给 payload、不给内网目的地址与资产名。
- 不做命令录制：蜜罐命令时间线**没有数据源**，一律 `commandsAvailable=false`（见第 5 节）。

## 2. 四段的数据源（**这一段是本文最重要的部分**）

| 阶段（公开键名） | 中文 | 真实数据源 | 取数方式 |
|---|---|---|---|
| `alerts` | 告警 | Wazuh indexer `wazuh-alerts-*`，`rule.groups` **不含** `cowrie`/`dionaea` | terms 聚合 + 明细查询 |
| `decoyPorts` | 诱饵端口 | 同上，`rule.groups=dionaea`（规则 100300/100301/100302/100310） | 同上 |
| `honeypotLogins` | 蜜罐登录 | 同上，Cowrie 登录规则 `100101`/`100102` | 同上 |
| `auditActions` | 处置审计 | **应用侧留痕文件** `data/response-audit.json` —— **不在 indexer 里** | 本地文件读取 |

三件事必须说清楚，否则页面一定画错：

1. **前三段和后一段不是一条链路**。前三段是"被攻击的痕迹"，第四段是"我们的动作"。
   处置审计只存在于服务机（srv1）的留痕文件里，indexer 里查不到它。
2. **同一来源在同一个阶段可能来自两个字段**。实测同一索引里既有 `data.srcip`（主机侧/蜜罐）
   也有 `data.src_ip`（Suricata 经 Wazuh agent 进来）。两个字段分别聚合后**按 IP 合并**；
   只查一个字段会安静地丢掉一大半来源（本端点的取数参数是 `app.geoip.src-ip-fields`，与 `/geo` 同一个键）。
3. **"这段没有数据" ≠ "这段没接入"**。见第 4 节。

## 3. 字段表

### 3.1 `GET /api/public/stories`

查询参数：

| 参数 | 取值 | 默认 | 说明 |
|---|---|---|---|
| `limit` | 1–`max-limit`（默认 20） | 10 | 返回几条来源；**候选总数不受它影响**（见 `candidates`） |
| `window` | `1h` / `6h` / `24h` / `72h` | `24h` | 只实现了这四种；别的值返回 **400 `WINDOW_NOT_SUPPORTED`**（不悄悄按 24h 处理） |

响应（`data`，字段白名单 —— **只许新增，不许改名/删除**）：

```jsonc
{
  "generatedAt": "2026-10-14 01:34:20",
  "cacheSeconds": 15,
  "window": "24h", "windowHours": 24,
  "available": true,                 // 数据源可用吗（false 时看 reason/note）
  "reason": "OK",                    // OK / NO_DATA_IN_WINDOW / DATA_SOURCE_UNAVAILABLE / QUERY_FAILED / STORY_DISABLED / INTERNAL_ERROR
  "limit": 10,
  "candidates": 131,                 // 窗口内的候选来源总数（去内网/去我方 IP 之后）
  "sourceCount": 5,                  // 本次真正返回了几条（= min(limit, candidates)）
  "stageLabels": { "alerts": "告警", "decoyPorts": "诱饵端口",
                   "honeypotLogins": "蜜罐登录", "auditActions": "处置审计" },
  "sources": [
    {
      "srcIp": "77.90.185.30",       // 按 ipDisclosure 口径显示（真实态=观测到的地址；掩码态=网段）
      "stages": { "alerts": 21, "decoyPorts": 54, "honeypotLogins": 0, "auditActions": 0 },
      "stagesWithData": 2,           // 四段里有几段真的有数据（排序第一关键字）
      "stageCount": 4,               // 恒为 4（阶段总数）——给页面算进度条用
      "firstSeen": "2026-10-13 18:29:25",
      "lastSeen":  "2026-10-14 01:08:25",
      "severityMax": "CRITICAL", "severityMaxLabel": "严重",
      "gaps": ["honeypotLogins", "auditActions"],        // ★ 哪几段【没有数据】
      "gapLabels": ["蜜罐登录", "处置审计"],
      "honeypotEvents": 0            // 全量 Cowrie 事件数（旁证：连上过蜜罐但没登录）
    }
  ],
  "coverage": {
    "windowHours": 24,
    "indexerTotalAlerts": 112956,    // 窗口内告警总数（分母，必须展示）
    "withSourceIp": 106980,          // 其中带来源 IP 的条数（分子，必须展示）
    "topSources": 50,
    "stageStatus": { "alerts": "OK", "decoyPorts": "OK",
                     "honeypotLogins": "OK", "auditActions": "OK" },   // ★ 已接入/未接入
    "stageNotes": { "alerts": "Wazuh indexer：rule.groups 不含 cowrie/dionaea 的告警", "…": "…" },
    "excludedSelf": 2,               // 被排除的我方 IP 个数（配置 app.geoip.self-ips）
    "excludedInternal": 3,           // 被排除的内网/保留来源个数
    "audit": { "actionsReadable": true, "blocksReadable": true, "actionRecords": 46,
               "blockRecords": 10, "evalFiltered": 0, "actionsWithoutTime": 0 }
  },
  "limits": { "defaultLimit": 10, "maxLimit": 20, "topSources": 50,
              "maxEventsPerStage": 40, "supportedWindows": ["1h","6h","24h","72h"] },
  "note": "…（读法说明，含 limit 截断的自证）…",
  "ipDisclosure": { "masked": false, "notice": "观测到的来源地址，未经验证，仅供参考",
                    "removalContact": "https://xiaokeqing.cn/about/" }
}
```

**排序规则**（页面可以直接依赖它，测试已钉住）：
① `stagesWithData` 多者在前 → ② `severityMax` 高者在前 → ③ 三段事件条数多者在前 →
④ `lastSeen` 新者在前 → ⑤ `srcIp` 升序（保证同输入同输出，ETag/304 的前提）。

### 3.2 `GET /api/public/story`

查询参数：`src`（必填）、`window`（同 `/stories`）。

| 情况 | 响应 |
|---|---|
| `src` 缺失/空白 | **400** `MISSING_SRC` |
| `src` 不是公网 IP 字面量（内网/保留/乱值） | **400** `INVALID_SRC` |
| `src` 是公网 IP，但不在候选池里 | **404** `SOURCE_NOT_IN_WINDOW` |
| `window` 不认识 | **400** `WINDOW_NOT_SUPPORTED` |
| 正常 | **200** + 下面的 `data` |

> **为什么只服务候选池里的来源**：如果任意 `src` 都查，这个端点就变成
> "随便给个 IP 就能问'他有没有打过我们'"的查询器 —— 那本身就是情报泄露，
> 而且与"给榜上的攻击源画时间线"是两件不同的事。候选池 = 同一窗口内 `/stories` 用的那份聚合
> （最多 `top-sources` 个来源），所以**池外的来源一律 404**。

响应（`data`，字段白名单）：

```jsonc
{
  "generatedAt": "2026-10-14 01:34:21",
  "cacheSeconds": 15, "window": "24h", "windowHours": 24,
  "available": true, "reason": "OK",
  "srcIp": "77.90.185.30",
  "firstSeen": "2026-10-13 18:29:25", "lastSeen": "2026-10-14 01:08:25",
  "severityMax": "CRITICAL", "severityMaxLabel": "严重",
  "gaps": ["honeypotLogins", "auditActions"],
  "stages": { "alerts": 21, "decoyPorts": 54, "honeypotLogins": 0, "auditActions": 0 },
  "events": [                                  // ★ 四段合并后按时间【升序】
    { "ts": "2026-10-13 18:29:25", "stage": "alerts", "stageLabel": "告警",
      "kind": "SQL注入",
      "summary": "Suricata: Alert - ET SCAN Suspicious inbound to mySQL port 3306",
      "severity": "LOW", "severityLabel": "低危", "outcome": null },
    { "ts": "2026-10-14 01:08:05", "stage": "decoyPorts", "stageLabel": "诱饵端口",
      "kind": "诱饵端口 MySQL（3306/tcp）",
      "summary": "蜜罐(Dionaea): MySQL 连接尝试 来源=77.90.185.30:42100",
      "severity": "MEDIUM", "severityLabel": "中危", "outcome": "ACCEPT" },
    { "ts": "2026-10-14 01:08:05", "stage": "decoyPorts", "stageLabel": "诱饵端口",
      "kind": "诱饵端口 MySQL（3306/tcp）",
      "summary": "蜜罐(Dionaea): 同一来源 60 秒内多次协议连接（扫描/爆破）来源=77.90.185.30",
      "severity": "CRITICAL", "severityLabel": "严重", "outcome": "ACCEPT" }
    // …（每段各自限量，超出时 truncated=true）
  ],
  "eventCount": 40,
  "truncated": true,                           // 任一段被限量过就为 true
  "coverage": {                                // ★ 每段：查到多少条 / 读不到或未接入 + 原因
    "alerts":       { "status": "OK",  "reason": "OK", "note": "告警这一段窗口内查到 21 条",
                      "queried": 21, "returned": 20, "truncated": true,
                      "source": "Wazuh indexer（wazuh-alerts-*）" },
    "decoyPorts":   { "status": "OK",  "reason": "OK", "note": "诱饵端口这一段窗口内查到 54 条",
                      "queried": 54, "returned": 20, "truncated": true,
                      "source": "Wazuh indexer（wazuh-alerts-*）" },
    "honeypotLogins": { "status": "OK", "reason": "OK",
                      "note": "蜜罐登录这一段窗口内该来源没有记录（数据源可用）",
                      "queried": 0, "returned": 0, "truncated": false,
                      "source": "Wazuh indexer（wazuh-alerts-*）" },
    "auditActions": { "status": "OK", "reason": "OK",
                      "note": "留痕文件可读，但窗口内该来源没有任何处置记录（不是故障，也不是被隐藏）",
                      "queried": 0, "returned": 0, "truncated": false,
                      "source": "应用侧处置留痕 data/response-audit.json",
                      "actionRecords": 46, "blockRecords": 10, "actionsWithoutTime": 0 },
    "windowHours": 24, "maxEventsPerStage": 40
  },
  "commandsAvailable": false,                  // ★ 蜜罐命令时间线：没有数据源，不编
  "commandsNote": "蜜罐命令时间线的数据源尚未接入（Wazuh 侧没有命令执行规则），所以 commandsAvailable=false —— 不编造命令序列。",
  "limits": { "…": "同上" },
  "note": "…",
  "ipDisclosure": { "…": "同上" }
}
```

`kind` / `outcome` 的口径：

| stage | `kind` 怎么来 | `outcome` |
|---|---|---|
| `alerts` | 既有 `AlertType.guess(规则描述)` 的中文标签（扫描探测/暴力破解/SQL注入/…） | `null`（用 `severity`） |
| `decoyPorts` | `诱饵端口 <协议>（<目的端口>/tcp）`，协议取自 `data.connection.protocol`（smbd→SMB、mysqld→MySQL、mssqld→MSSQL…） | `ACCEPT` |
| `honeypotLogins` | `蜜罐 SSH 登录成功` / `蜜罐 SSH 登录失败` | `SUCCESS` / `FAILED` |
| `auditActions` | `封禁 IP` / `解封 IP` / 原始动作名 | `SUCCESS` / `FAILED` / `BLOCKED_BY_GUARD` |

`ts` / `firstSeen` / `lastSeen` 全部是**服务机本地时间**（`yyyy-MM-dd HH:mm:ss`，indexer 的 UTC
时间戳由 `WazuhTime` 换算；留痕文件本来就是本地时间）。**字符串可直接按字典序排序**。

## 4. `gaps[]` 与 `coverage.stageStatus`：**这两个字段不能混着读**

这是本端点最容易被画错的地方：

| 现象 | `stages[x] == 0` | `gapLabels` 里出现 x | `coverage.stageStatus[x]` |
|---|---|---|---|
| 这段接入了，但这个来源这段时间没做这一步 | ✔ | ✔ | `OK` |
| 这段**根本没接入**（索引里没有这类规则/日志，或留痕文件读不到） | ✔ | ✔ | `NOT_WIRED` |
| 能不能查到还没确认（接入判定查询失败） | ✔ | ✔ | `UNKNOWN` |
| 数据源整体不可用 | 全 0 | 全部 | 降级载荷里给 `UNKNOWN` / `NOT_WIRED` |

**页面必须把三件事分开写**：
1. 时间轴上那一段**画成"没有数据"**（不要省略、不要用直线连过去）；
2. 旁边写清"**是这一段没接入**"还是"**这个来源没做这一步**"（读 `stageStatus`）；
3. 顶部展示 `coverage.indexerTotalAlerts` / `withSourceIp` **分母**（实测 24h 有 11 万条告警，
   而带来源 IP 的只有约 10.7 万条；候选池上限 `topSources`，长尾来源不在榜上 —— 不写这个，
   读者会把"榜上 50 个来源"当成"全部攻击者"）。

## 5. 蜜罐命令时间线：**没有数据源，所以 `commandsAvailable=false`**

蜜罐（Cowrie）只把"新连接 / 客户端版本 / 登录成功 / 登录失败"写进 Wazuh，
**没有命令执行规则**（Dionaea 的 `dionaea.json` 也没有命令 handler）。所以：

- `commandsAvailable` 恒为 `false`，`commandsNote` 说明原因；
- 页面**不许**用"登录成功后接……"之类的推测把命令序列画出来；
- 要让这一段真的有数据，见第 8 节"还缺什么"。

## 6. 页面怎么画（给博客的建议）

**主体：横向时间轴 + 四条色带**（每条一个阶段）：

```
攻击过程（来源 77.90.185.30 · 最近 24 小时）
                   18:29        01:07 01:08            01:08:25
告警      ██████────────────────●────●──●──●─────────────●       21 条 · 最高 低危
诱饵端口  ───────────────────── ●●●●●●●●●●●●●●●●●●●●●●●●       54 条 · 最高 严重
蜜罐登录  ░░░░░░ 未接入/无数据（该来源没有登录记录；该阶段已接入）░░░░
处置审计  ░░░░░░ 无处置记录（留痕文件可读，窗口内没有它的记录）░░░░
                    └─ 至少一段没有数据时【必须显示这条灰带】，不要留空
```

- 色带里的点是 `events[]`；点的大小/颜色可以用 `severity`（`CRITICAL` 用最重的颜色）。
- **灰带必须显式画**：文案按上面的三档区分（无数据 / 未接入 / 未确认）。
- 顶部 KPI 只放**可自证**的数字：`stagesWithData/4`、`eventCount`、`severityMax`，
  以及 `coverage.indexerTotalAlerts` / `withSourceIp`。
- "同一来源的动作"这类叙述只能引用 `events[]` 里真实存在的事件，**不许写推测**。

**列表页（`/stories`）**：一行一个来源，四格小色块（有数据=实色，没数据=灰），
`srcIp` + `severityMaxLabel` + 首末时间；点进详情用 `srcIp` 调 `/story`。
注意：`/stories` 只给前 `limit` 条，但 `candidates` 会告诉你有多少条被截断。

## 7. "只给摘要与结论"：脱敏口径（发布前已用正则扫描钉住）

| 东西 | 处理 |
|---|---|
| 完整口令 | **永不公开**（与开关无关）：文本里 `口令=xxx` / `密码=xxx` / `password=xxx` 整段替换成 `口令=[口令已隐藏]`；**用户名可以给** |
| 明文口令的另一条路径 | indexer 查询本身就带 `_source` **字段白名单**：`data.password` / `data.message`（形如 `login attempt [root/Abcd@123] succeeded`）/ `full_log` / `previous_output` **根本不进入进程** |
| 来源 IP | 走 `PublicIpPolicy`（`app.public.mask-ips`）：默认显示观测到的真实地址；掩码态显示网段；内网/保留地址在**任何**口径下都写 `内网/未知`（掩码态写 `内部地址`） |
| 内部资产名 | 出海前整棵响应树过 `PublicAssetFilter`（`web-01` 等 → `[内部标识已脱敏]`） |
| 内网目的地址 / 资产 | **不输出**（字段白名单里就没有 `data.dst_ip` / `agent.name`） |
| 规则正则原文 | **不输出**：只输出 `rule.description`（与 `/alerts` 已经在公开的 `title`/`ruleName` 同类），规则体/正则在索引里根本没取 |
| 处置审计的 `reason`/`detail` | **不输出**（那两段可能含内网信息；要看细节用 `/api/public/audit` 的既有口径），故事线只给"操作者/模式/结果" |
| 超长规则描述 | 截断到 200 字符并加 `…` |

## 8. 实测：真实数据里四段各是什么状态（2026-10-14 01:34，srv1 真实索引器只读）

用真实索引器（只读隧道 + 真实留痕文件的副本）跑两个端点，得到：

- `candidates = 131`，`coverage.indexerTotalAlerts = 112956`，`withSourceIp = 106980`，
  `excludedSelf = 2`（srv1/srv2 自己的公网出口），`excludedInternal = 3`。
- 榜单前 5（真实数据）：

| srcIp | alerts | decoyPorts | honeypotLogins | auditActions | severityMax | gaps |
|---|---|---|---|---|---|---|
| 77.90.185.30 | 21 | 54 | 0 | 0 | CRITICAL | honeypotLogins, auditActions |
| 77.90.185.21 | 7 | 58 | 0 | 0 | CRITICAL | honeypotLogins, auditActions |
| 58.19.99.193 | 1195 | 0 | 24 | 0 | HIGH | decoyPorts, auditActions |
| 195.178.110.218 | 271 | 0 | 475 | 0 | HIGH | decoyPorts, auditActions |
| 8.215.69.55 | 8 | 0 | 453 | 0 | HIGH | decoyPorts, auditActions |

- `77.90.185.30` 的 `/story`：40 条事件（告警 20 / 诱饵端口 20，每段各自限量），
  **时间上真的连起来了** —— 18:29 起 Suricata 报 "ET SCAN Suspicious inbound to mySQL port 3306"，
  01:08 该来源开始连 3306 诱饵端口，Dionaea 连续 accept 并在 60 秒内触发
  "同一来源 60 秒内多次协议连接（扫描/爆破）"（level 12 → 严重）。

**所以今天这四段的真实状态是**：

| 阶段 | 接得上了吗 | 今天窗口内有数据吗 |
|---|---|---|
| `alerts` | ✅ 接上了 | ✅ 有（11.3 万条里约 10.7 万条带来源 IP） |
| `decoyPorts` | ✅ 接上了（Dionaea 规则 100300/100301/100302/100310，2026-10-14 上线） | ✅ 有（实测 159 条，来源 77.90.185.21 / .30 / 3.131.220.121 等真实扫描器） |
| `honeypotLogins` | ✅ 接上了（Cowrie 100101/100102） | ✅ 有（实测 24h 约 2 万条登录事件） |
| `auditActions` | ✅ **读取链路接上了**（`actionsReadable=true`，留痕里有 46 条处置记录） | ❌ **窗口内没有记录**：srv1 上 `response-audit.json` 最新一条是 `2026-10-12 15:18`（约 34 小时前）。所以**当前每一个来源的 `gaps[]` 里都有 `auditActions`** —— 而 `coverage.stageStatus.auditActions = "OK"` 明确告诉页面"这是没有记录，不是没接入" |

也就是说：**今天还没有任何来源能凑齐 4/4 段**。最常见的组合是
"告警 + 诱饵端口"（真实扫描器打进来）或"告警 + 蜜罐登录"（撞库 + 探测）。
这是真实数据的如实结果，不是端点的缺陷。

### 要让"故事线完整"还缺什么

| 缺的东西 | 需要做什么 | 归属 |
|---|---|---|
| 窗口内要有处置记录 | 让处置动作真的在窗口内发生一次（人工封一次、或策略自动封）。**不许**为了页面好看往留痕里塞测试记录：`response-audit.json` 是生产留痕，评测记录已有 `evalRunId`/`eval-` 隔离 | 站主 |
| 蜜罐命令时间线 | 需要在 Cowrie/Dionaea 侧把命令执行事件接出来（Cowrie 的 `cowrie.command.input` 事件目前**没有对应 Wazuh 规则**），再加一条 `rule.groups` 可识别的规则 | 下一步（srv2 侧） |
| "同一个来源"跨蜜罐实例的关联 | 目前 Cowrie（2222）与 Dionaea（445/1433/3306）是两个传感器，靠**来源 IP**关联；如果攻击者换 IP 就断链（这是如实的限制，不是 bug） | 口径上接受 |
| 诱饵端口的"下载样本"事件 | Dionaea 的 `download.*` 只写文本日志 `dionaea.log`，**没有 JSON handler** → 现在**看不到**（不要画成"下载了样本"） | 下一步 |

## 9. 运维开关（详见 RUNBOOK §32）

| 键 | 默认 | 说明 |
|---|---|---|
| `app.public-api.story.top-sources`（`APP_PUBLIC_STORY_TOP_SOURCES`） | 50 | 候选来源上限 = `/story` 的可查询来源池大小 |
| `app.public-api.story.max-events-per-stage`（`APP_PUBLIC_STORY_MAX_EVENTS_PER_STAGE`） | 40 | 单来源单阶段事件上限（每段独立） |
| `app.public-api.story.max-limit`（`APP_PUBLIC_STORY_MAX_LIMIT`） | 20 | `/stories` 的 `limit` 上限 |
| `app.geoip.self-ips`（`APP_GEOIP_SELF_IPS`） | 空 | 我方出口 IP；**不配就会把自己服务器排上"值得看的攻击来源"**（与 `/geo` 同一个键、同一份配置） |
| `app.public.mask-ips`（`APP_PUBLIC_MASK_IPS`） | false | 统一 IP 口径（唯一读取点：`PublicIpPolicy`） |

三个 `APP_PUBLIC_STORY_*` 必须在 `application.yml` / `.env.example` / `docker-compose.yml`
三处一致（`AttackStoryConfigTest` 钉住）—— 少一处就是"改了不生效且不报错"。

## 10. 已知局限（如实列出，别把它读得比实际更准）

1. **同一条文档若同时带两个来源字段且值相同，会被计两次**。响应里同时给了
   `withSourceIp`，读者可以核对"各来源之和 vs 带来源 IP 的文档数"。实测未见这种情况。
2. **候选池是 TOP N（默认 50）**，长尾来源不在榜上、也**不能**用 `/story` 查（404）。
   被截断这件事由 `candidates` 与 `limits.topSources` 自证。
3. **`kind` 是粗分类**：`alerts` 段的中文标签来自项目既有的 `AlertType.guess(规则描述)`
   关键字匹配（例如 MySQL 端口的 Suricata 签名会被归到"SQL注入"）。它与自用界面**同一套**口径，
   本次没有新增分类器 —— 页面上不要把 `kind` 当成精确的攻击手法判定。
4. **时间来自两种源**：indexer 的 UTC → 本地时区换算；留痕文件本来就是本地时间（无时区）。
   服务器时区若变更，跨源排序会短暂不一致（与 webstats 的同类局限一致）。
5. **`severityMax` 对审计段用 `riskLevel`**：留痕里没有 `riskLevel` 的记录**不参与**排序
   （不把"没有等级"猜成"中危"）。
6. **不是实时**：15 秒快照 + 每段各自一条 indexer 查询（最多 3 条）+ 两个阶段接入判定查询
   （只在窗口内该段为 0 时发）。极端情况下一次请求可能触发 5 条只读查询。
7. **不做跨窗口记忆**：`/story` 只反映**当前窗口**，窗口滚动后同一个来源的故事会变短
   （历史留痕不入库）。

## 11. 博客侧联动（**必须做，否则新端点会被构建检查判为"未授权端点"**）

```
【提醒站主】加了这两个端点之后，博客仓库 scripts/assert-build.sh 的 ALLOWED 白名单需要加：
    stories
    story
（本站代码只负责把端点做好；白名单在博客侧，由站主统一处理。）
```
