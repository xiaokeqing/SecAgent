# scripts/drill · P3 攻防演练脚本（自有资产，自打自检）

> 设计与安全护栏见 `E:\DeepSeek1\work\P3攻防演练-设计与安全护栏.md`。
> 本目录的脚本是那份设计的**可执行实现**，只允许打自己的两台服务器。

## 资产（唯一允许的目标）

| 别名 | IP | 角色 | 暴露面（实测） |
|---|---|---|---|
| secagent-srv1 | 47.96.106.187 | SecAgent（阿里云杭州） | firewalld 只放行 22；9900 绑 127.0.0.1（走 SSH 隧道） |
| secagent-srv2 | 43.143.114.79 | Wazuh manager/indexer + Suricata + Cowrie（腾讯云上海） | ufw 只放行 22（宿主 sshd）、2222（Cowrie 蜜罐）；其余全部 DROP |

监控事实（决定"预期检出"能落在哪）：Wazuh 索引里只有两个 agent ——
`wazuh.manager`（读 Suricata `eve.json` + Cowrie `cowrie.json`）与 `VM-0-10-ubuntu`（srv2 宿主 sshd/pam/sca）。
**srv1 未接入 Wazuh**，所以打 srv1 的流量在这套索引里天然不会产生告警（这一点必须在报告里说清楚）。

## 脚本清单

| 脚本 | 一句话 | 预计请求数 |
|---|---|---|
| `sim-01-ssh-probe.ps1` | 对 srv2:2222 发 10 次 TCP 连接，各带不同 `SSH-2.0-<client>` 横幅（含 runId），不认证 | 10 |
| `sim-02-ssh-auth-fail.ps1` | 对 srv2:2222 做 8 次认证尝试（4 次假口令 password + 4 次一次性 publickey），用户名=runId，不做成功爆破、不进 shell | 8 |
| `sim-03-web-path-probe.ps1` | 对 srv2 的 HTTP 端口发 6 个典型可疑路径的 GET（`.env`/`phpmyadmin`/`x.asp;.jpg` 等），URL 与 UA 带 runId | 12（6 路径 × 2 端口） |
| `sim-04-port-scan.ps1` | 对 srv2 的 8 个端口做串行 TCP 连接（500ms 间隔，不发应用层数据） | 8 |
| `sim-05-benign-control.ps1` | 良性对照：经 SSH 隧道对 srv1 的 `/api/health` 发 3 次正常请求 | 3 + 1 隧道 |
| `collect.sh` | 在 srv1 上按 runId/时间窗查 `wazuh-alerts-*`，出 JSON + 可读摘要 + 检测时延 | — |

## 每个剧本内置的护栏（逐条自查）

1. **目标白名单**：`$AllowedTargets = @('47.96.106.187','43.143.114.79')`；
   每次发包前都过 `Assert-WhitelistedTarget`，非白名单直接 `exit 90`。
   `sim-05` 额外用 `ssh -G <别名>` 解析别名，解析出的主机不在白名单同样拒绝；
   回环地址只在"已校验指向 srv1:9900 的隧道"这一处允许使用。
2. **请求数上限 ≤30**：`$MaxRequests = 30`，`Get-RequestSlot` 每次发包前计数，超限 `exit 91`；
   脚本启动时若预计请求数 > 30 直接 `exit 92`。
3. **间隔 ≥500ms**：`$MinIntervalMs = 500`，发不出间隔就 `Start-Sleep` 补齐；串行、无并发。
4. **唯一 runId**：形如 `DRILL-sim-0X-<yyyyMMddTHHmmss>`，演练前打印；
   sim-01 写进 SSH 客户端横幅、sim-02 当用户名、sim-03 写进 URL 查询串与 User-Agent，
   以便在告警里用 `full_log` 通配精确定位。
5. **非破坏性**：不发真实 webshell、不上传文件、不执行命令、不进交互 shell、
   不猜真实口令（口令是 `DrillWrong-N!` 这种明显假口令）、不做 DoS（不并发/不半开扫描）。
6. **起止时间**：演练前打印"目标 / 动作 / 预计请求数 / runId"，演练后打印 ISO 秒级起止时间与实际请求数。
7. **证据落盘**：每个脚本把本次运行的参数与逐条结果写成 UTF-8 JSON 到 `_tmp\<runId>.json`，
   并写 `_tmp\<runId>-console.txt` 控制台日志。

## 运行方式（Windows）

```powershell
# 中文输出需要 UTF-8 BOM + 放开执行策略（只影响当前进程）
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
cd E:\DeepSeek1\work\scripts\drill
.\sim-05-benign-control.ps1
.\sim-01-ssh-probe.ps1
```

```bash
# 采集（在 srv1 上）
bash collect.sh --run-id DRILL-sim-01-20261012T201500 \
  --start 2026-10-12T20:15:00+08:00 --end 2026-10-12T20:15:20+08:00 \
  --src-ip 58.19.99.193 --label sim-01 --out /tmp/drill-DRILL-sim-01-20261012T201500.json
```

## 本机环境的两个坑（脚本已处理，报告里也要写明）

1. **clash TUN**：本机开着 clash-verge（Mihomo TUN），对"被丢弃的端口"会出现**本地假连通**，
   所以脚本不把 `connect 成功` 当"端口开放"，而是再看对端是否吐 banner；
   权威端口清单以 srv2 上 `sudo ss -lntup` 为准。
2. **源 IP**：本机对外是动态公网 IP，实测 srv2 侧看到的是 `58.19.99.193`（走直连）；
   而 `api.ipify.org` 走代理会看到别的出口（50.7.250.50）。
   采集脚本默认按 `--src-ip 58.19.99.193` 过滤，每次演练前用 `ssh secagent-srv2 'echo $SSH_CLIENT'` 复核。
