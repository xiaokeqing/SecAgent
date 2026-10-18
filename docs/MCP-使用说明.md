# MCP 使用说明（xk-lab）

把本机平台已有的**只读**安全观测数据封装成一个 MCP Server：任何支持 MCP 的客户端
（Claude Desktop / Cursor / Cline / 自写 agent）都能通过 stdio 直接查询这台机器的
告警、IP 画像、封禁留痕、蜜罐与检测规则清单。

## 1. 边界（先读这一段）

| 项目 | 结论 |
| --- | --- |
| 读写 | **只读**。六个工具全部只发 GET，没有任何写/删除/执行入口。 |
| 部署形态 | **独立进程**，stdio 传输。不监听端口，不并入 9900 的 Web 服务。 |
| 数据来源 | 本机 `http://127.0.0.1:9900` 的公开面只读端点（可改 `XK_MCP_BASE_URL`，**只允许回环地址**）。 |
| 明文 | 口令/密钥一律不出现在输出里：只给"长度位·字符类·弱/非弱"这种结构；遇到疑似秘密字段直接 `[已隐藏]`。 |
| IP | `xk_audit_blocks` 默认打码（`45.205.***.***`），只有显式 `"rawIp": true` 才给原值。 |
| 取不到数据 | 返回 `{"available": false, "reason": "..."}`，**不编造数字**。 |

MCP 进程不是数据权威：平台公开面已经做过的脱敏与口径（`PublicIpPolicy`、`PublicIpMask`、
`CredentialStructure`）被原样继承下来，避免两套口径打架。

**上游是包着外壳的。** 平台公开面统一返回 `{"code":200,"message":"success","data":{…}}`，
MCP 端负责拆壳。拆壳规则（`HttpPlatformClient.unwrap`）有两条硬判定，都是为了"取不到就说取不到"：

- 外壳 `code` 不是 200/0 → `available:false`，`reason` 带业务码；
- `data` 缺失、不是对象、或是空对象 `{}` → `available:false`（`UPSTREAM_EMPTY_BODY`）。
  **"上游什么都没说"不等于"上游说没有数据"** —— 否则工具会拿空壳冒充"窗口内没有告警"。

## 2. 构建

```bat
cd /d F:\7AAA\AI\SecAgent\sec-agent
mvn -o -DskipTests package
```

产物（`pom.xml` 里加了 classifier 为 `mcp` 的 repackage 执行，**不新增任何依赖**）：

```
F:\7AAA\AI\SecAgent\sec-agent\target\sec-agent-1.0-SNAPSHOT-mcp.jar
```

这个 jar 是 Spring Boot 的 fat jar（自带 Jackson 等运行时依赖），`java -jar` 直接跑，不需要额外 classpath。
手动调试：

```bat
java -jar F:\7AAA\AI\SecAgent\sec-agent\target\sec-agent-1.0-SNAPSHOT-mcp.jar
```

启动后它只认 stdin 的 JSON-RPC，stdout 只放协议报文，所有日志走 stderr（启动时会打一行
`[xk-lab-mcp] 启动 pid=… upstream=… siteDir=… tools=6 timeoutMs=…`）。

### 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `XK_MCP_BASE_URL` | `http://127.0.0.1:9900` | 平台只读端点。**非回环地址直接拒绝启动（exit 2）**。 |
| `XK_MCP_SITE_DIR` | `F:\7AAA\AI\blog` | 站点仓库根目录，`xk_detections` 读 `detections/` 用。 |
| `XK_MCP_TIMEOUT_MS` | `5000` | 单次 HTTP 超时。在慢机器上 `/api/health`、`/api/public/ip` 可能超过 5s（实测这台机器上健康检查曾 >12s 无响应），需要时调到 `15000`。 |

平台没起时不会崩：每个工具都会返回 `available:false` 并在 `reason` 里写明原因。

## 3. 客户端配置

Claude Desktop（`claude_desktop_config.json`）/ Cursor（`mcp.json`）用同一段：

```json
{
  "mcpServers": {
    "xk-lab": {
      "command": "java",
      "args": ["-jar", "F:\\7AAA\\AI\\SecAgent\\sec-agent\\target\\sec-agent-1.0-SNAPSHOT-mcp.jar"],
      "env": {
        "XK_MCP_BASE_URL": "http://127.0.0.1:9900",
        "XK_MCP_SITE_DIR": "F:\\7AAA\\AI\\blog"
      }
    }
  }
}
```

`command` 写 `java` 依赖 PATH；客户端里 java 不在 PATH 就换绝对路径，例如
`"C:\\Program Files\\Java\\jdk-21\\bin\\java.exe"`。

## 4. 六个工具

所有输出都带 `generatedAt`（工具生成时刻，ISO-8601 带时区）与 `source`（数据来源说明），并带 `available`。
**工具名的参数在 `tools/list` 的 `inputSchema` 里**，下面是实测的字段形状。

### 4.1 `xk_health` —— 进程/构建指纹

无参数。GET `/api/health`。

```json
{
  "generatedAt": "2026-10-18T15:56:10+08:00",
  "source": "platform GET /api/health（本机回环只读）",
  "available": true,
  "status": "ok",
  "degraded": false,
  "buildSha": "b5cd0ab…",
  "artifactMd5": "3f2a…",
  "uptimeMs": 98765,
  "application": "SecAgent",
  "buildTime": "2026-10-18 15:56:09",
  "embeddedGitCommit": "…", "embeddedGitBranch": "main", "embeddedGitDirty": false,
  "fingerprintMismatch": false,
  "sourceSha": "…",
  "vectorStore": { },
  "mcp": {"server": "xk-lab-mcp", "version": "1.0.0", "pid": 32820, "javaVersion": "25", "uptimeMs": 1211}
}
```

`mcp` 段是本进程自己的指纹（和平台无关，永远有）。平台取不到时：

```json
{"generatedAt": "...", "source": "...", "available": false,
 "reason": "UPSTREAM_UNAVAILABLE: 连不上 http://127.0.0.1:9900（request timed out）；平台没起或端口不通时就是这个结果",
 "note": "取不到就报不可用：不补数、不猜、不用样本冒充真实数据。", "mcp": { }}
```

### 4.2 `xk_alerts_recent` —— 最近窗口告警聚合

参数：`minutes`（默认 60，1..1440）、`limit`（默认 20，1..200）。GET `/api/public/alerts`。

```json
{
  "generatedAt": "...", "source": "platform GET /api/public/alerts（本机回环只读，聚合口径与公开面一致）",
  "available": true,
  "alerts": [
    {"severity": "high", "ruleName": "XK-LAB SSH brute force", "srcIp": "45.205.***.***",
     "attck": {"tactic": "TA0006", "technique": "T1110"},
     "occurredAt": "2026-10-18 15:53:09", "title": "STUB：SSH 暴力破解", "count": 3, "status": "open"}
  ],
  "summary": {"windowMinutes": 60, "windowFrom": "2026-10-18 14:56:10", "inWindow": 1, "returned": 1,
              "truncatedByLimit": 0, "olderThanWindow": 0, "unparsedTime": 0, "bySeverity": {"high": 1},
              "upstream": {"windowMinutes": 60, "windowSize": 200, "total": 1, "rawTotal": 1, "aggregated": true}},
  "dataSource": {"wazuhMode": "stub", "degraded": false, "note": "…"},
  "note": "窗口内条目即上游返回的全部分组，按 occurredAt 新→旧排列。"
}
```

- 时间字段沿用平台口径 `yyyy-MM-dd HH:mm:ss`（不是 ISO）；
- `inWindow` 是窗口内条数，`olderThanWindow` 是上游给了但落在窗口外的条数，`unparsedTime` 是时间解析不出来的条数
  —— 写清楚是为了让你知道"少"是窗口/解析问题，不是没数据；
- Wazuh 降级时整条工具输出 `available:false`，`reason` 形如
  `WAZUH_DEGRADED: 告警数据源不可达，本页不展示任何告警（不以内置样本代替）`（本机实测就是这种状态：`wazuhMode=MOCK`）。

### 4.3 `xk_ip_profile` —— 单个 IP 的画像

参数：`ip`（必填，公网 IPv4 字面量）。GET `/api/public/ip?q=<ip>`。

```json
{
  "generatedAt": "...", "source": "platform GET /api/public/ip?q=<ip>（本机回环只读，口径与公开面同源）",
  "available": true,
  "query": "45.205.***.***", "ipVersion": "IPv4", "window": "168h", "windowHours": 168,
  "firstSeen": "2026-10-15 15:56:09", "lastSeen": "2026-10-18 15:53:09",
  "events": 42,
  "byKind": {"ssh_login": 30, "honeypot": 12},
  "ports": [22, 2222],
  "credStructure": ["root / 6 位·纯数字·弱口令"],
  "geo": {"country": "…"},
  "banned": {"count": 1, "active": true},
  "sources": {"indexer": {"status": "OK"}, "audit": {"status": "OK"}, "geoip": {"status": "OK"}},
  "limits": {"windowHours": 168, "topKinds": 10, "ipv4Only": true},
  "notes": [],
  "note": "只读、只回答「这个 IP 在我们这里干过什么」…",
  "upstreamGeneratedAt": "2026-10-18 15:56:09"
}
```

本地先校验，不合规不会打到上游：

| 输入 | 返回 |
| --- | --- |
| 缺 `ip` | `{"available": false, "reason": "MISSING_IP"}` |
| 非 IPv4 字面量 | `{"available": false, "reason": "INVALID_IP"}` |
| 内网/保留地址 | `{"available": false, "reason": "NOT_PUBLIC_IP"}` |

上游 `available:false`（索引不可达）时，MCP 也报 `available:false` 并沿用上游 `reason`。

### 4.4 `xk_audit_blocks` —— 封禁/处置留痕

参数：`limit`（默认 20，1..200）、`rawIp`（默认 `false`）。GET `/api/public/audit`。

```json
{
  "generatedAt": "...", "source": "platform GET /api/public/audit（本机回环只读，读的是处置留痕文件）",
  "available": true,
  "readOnly": true,
  "ipMode": "masked",
  "blocks": [
    {"ip": "45.205.***.***", "id": 1, "durationMinutes": 60, "source": "auto", "actor": "policy",
     "auditId": "audit-stub-1", "createdAt": "2026-10-18 15:53:09",
     "expiresAt": "2026-10-18 16:53:09", "unblocked": false}
  ],
  "summary": {"returned": 1, "limit": 5, "ipMode": "masked"},
  "note": "ip 已按网段级掩码（45.205.***.***）；要上游原值传 rawIp:true。内网/保留地址显示为「内部地址」。"
}
```

⚠️ 一个诚实的限制：如果平台侧把 `app.public.mask-ips` 打开了，上游返回的就已经是打码后的 IP，
**本工具无法还原**（`rawIp:true` 也只能拿到打码值）。`ipMode` 字段会如实标明当前是 `raw` 还是 `masked`。

### 4.5 `xk_honeypot_summary` —— 蜜罐概况

无参数。GET `/api/public/honeypot`。

```json
{
  "generatedAt": "...", "source": "platform GET /api/public/honeypot（本机回环只读，蜜罐会话聚合）",
  "available": true,
  "total": 40, "connections": 25, "logins": 15, "loginFails": 14, "sampled": 40,
  "commandsAvailable": false,
  "credStructure": ["root / 6 位·纯数字·弱口令"],
  "topSources": ["45.205.***.***"],
  "topClients": ["SSH-2.0-Go"],
  "timeline": [{"hour": "09:00", "count": 7}],
  "note": "口令只给结构：长度 / 字符类 / 是否弱口令，不含明文；取不到某类数据时对应字段为 null，不补 0。"
}
```

口令只给结构（`用户名 / N 位·字符类·弱/非弱`），任何原文都进不了输出。上游 `available:false` 时
MCP 报 `HONEYPOT_DATA_UNAVAILABLE: <上游 note>`。

### 4.6 `xk_detections` —— 自写检测规则清单

参数：`kind`（`suricata` | `wazuh` | `all`，默认 `all`）。

读站点仓库的两个文件（**只解析 sid/id 与 msg/description**，不碰运行中的引擎）：

- `detections/suricata/xk-lab.rules`
- `detections/wazuh/xk-lab_rules.xml`

```json
{
  "generatedAt": "...", "source": "local files: detections/suricata/xk-lab.rules + detections/wazuh/xk-lab_rules.xml（站点仓库，只读解析）",
  "available": true,
  "siteDir": "F:\\7AAA\\AI\\blog",
  "files": [
    {"path": "F:\\7AAA\\AI\\blog\\detections\\suricata\\xk-lab.rules", "role": "suricata",
     "rel": "detections/suricata/xk-lab.rules", "exists": true, "bytes": 18722, "readable": true},
    {"path": "F:\\7AAA\\AI\\blog\\detections\\wazuh\\xk-lab_rules.xml", "role": "wazuh",
     "rel": "detections/wazuh/xk-lab_rules.xml", "exists": true, "bytes": 8572, "readable": true}
  ],
  "counts": {"suricata": 7, "wazuh": 3, "total": 10},
  "suricata": [
    {"kind": "suricata", "sid": 1000101, "action": "alert", "protocol": "ssh",
     "src": "$EXTERNAL_NET any", "direction": "->", "dst": "$HOME_NET any",
     "msg": "XK-LAB SSH client fingerprint Go SSH library (botnet/bruteforce toolchain)",
     "classtype": "attempted-recon", "rev": 1, "file": "detections/suricata/xk-lab.rules"}
  ],
  "wazuh": [
    {"kind": "wazuh", "id": 100400, "level": 10,
     "description": "XK-LAB: 同一来源 5 分钟内蜜罐 SSH 会话 >=20 次（自动化爆破/刮削）来源=$(src_ip)",
     "ifSid": null, "group": "xk_lab,ssh_burst,", "file": "detections/wazuh/xk-lab_rules.xml"}
  ],
  "notes": [],
  "note": "只列我们自己写的规则（sid/id + msg/description），不读规则文件的其它内容，不碰运行中的引擎。"
}
```

两个文件都不存在（或 `XK_MCP_SITE_DIR` 指错）：`{"available": false, "reason": "DETECTION_FILES_NOT_FOUND: …"}`。

## 5. 冒烟（自己验证一遍）

```bat
cd /d F:\7AAA\AI\SecAgent\sec-agent
python -X utf8 scripts/mcp-smoke.py --dry              :: 只打印将发送的报文，不起进程
python -X utf8 scripts/mcp-smoke.py                    :: 连真平台，起进程跑通全流程
python -X utf8 scripts/mcp-smoke.py --stub-upstream    :: 自带只读桩（返回平台外壳形状），验证 available:true
```

脚本做三件事：起 `java -jar`、按 JSON-RPC 走 `initialize` → `tools/list` → 六个工具各一次、
打印每个工具返回的 `available` 与键名。任何一步失败都会打 server 的 stderr 结尾并以非 0 退出。

默认模式下若平台没起（或 Wazuh 降级），部分工具 `available:false` —— 这是**正确行为**（不编数），
不是冒烟失败；`--stub-upstream` 是验证 `available:true` 分支的路径。

## 6. 单元测试

```bat
mvn -o test -Dtest=McpToolsTest
```

15 个用例：六个工具各覆盖「正常」与「数据源不可用」，外加协议层（`initialize`/`tools/list`/`tools/call`/
未知工具/未知方法/通知不回包）与上游外壳拆壳（`code=200` 拆 data、`code=503` 报不可用、空对象报不可用）。
用假 `PlatformClient`，不联网、不起平台。

## 7. 排错

| 现象 | 原因 |
| --- | --- |
| 客户端里工具列表为空 | jar 路径写错，或 `java` 不在客户端 PATH；看客户端日志里的 stderr。 |
| 全部 `available:false` + `UPSTREAM_UNAVAILABLE` | 平台 9900 没起。 |
| 只有 `xk_health`/`xk_ip_profile` 超时 | 这两个端点在本机可能很慢，调大 `XK_MCP_TIMEOUT_MS`。 |
| 工具报 `UPSTREAM_EMPTY_BODY` | 上游返回了空壳：要么端点挂了，要么路径写错（本工具不把空壳当"没有数据"）。 |
| `xk_alerts_recent` 报 `WAZUH_DEGRADED` | 告警数据源不可达（本机常见：`wazuhMode=MOCK`），平台自己就不展示告警。 |
| `xk_detections` 不可用 | `XK_MCP_SITE_DIR` 没指向站点仓库根目录。 |
| 客户端读不到回包 | 有人往 stdout 打了日志。协议通道只允许 JSON-RPC 一行一条。 |
