# srv2 · Dionaea 蜜罐（SMB / MSSQL / MySQL 协议仿真）

> 本文件由 `scripts/srv2-dionaea-deploy.sh` 一并安装到 `/opt/dionaea/README.md`，
> unit 的 `Documentation=` 就指向它 —— 出事时按这里操作。

## 1. 谁在哪、流量怎么走

```
                      公网
                       │  tcp/445, tcp/1433, tcp/3306
                       ▼
        ┌──────────────────────────────────────────────┐
        │ 腾讯云安全组（站主在控制台维护）             │
        └──────────────────────────────────────────────┘
                       │
        ┌──────────────────────────────────────────────┐
        │ srv2  10.0.0.10 / 43.143.114.79              │
        │                                              │
        │  ① iptables INPUT（ufw）                     │
        │     必须 ufw allow 445/tcp（1433/3306 早已放行）│
        │  ② iptables FORWARD → DOCKER-USER            │
        │     ← 顺序至关重要，见第 5 节                │
        │  ③ DNAT → 172.19.0.x                        │
        │                                              │
        │  ┌────────────── cowrie_honeypot (172.19.0.0/16) ──┐
        │  │  cowrie          172.19.0.2   SSH/Telnet :2222  │
        │  │  secagent-decoy  172.19.0.3   :21 :23 :6379     │
        │  │                               :8080 :8443 :27017│
        │  │  dionaea         172.19.0.4   :445 :1433 :3306  │
        │  └─────────────────────────────────────────────────┘
        │     这个网段的 egress 被 DROP（只放行回程 + 容器 DNS）
        │
        │  Suricata（net=host，抓 eth0 的包，只看不拦）
        │  Wazuh manager / indexer / dashboard（172.18.0.0/16）
        └──────────────────────────────────────────────┘
                       │
     日志落宿主 /opt/dionaea/var/log/dionaea/
     以只读方式挂进 wazuh.manager → localfile → 规则 → alerts.json
```

- **为什么 Dionaea 只占 445/1433/3306**：站主 2026-10-14 划定 —— 只接管它真的会仿真协议的端口。
  21/23/6379/8080/8443/27017 继续由 `secagent-decoy` 承担；**9200 永不碰**（那是真 indexer）。
- **1433/3306 原本属诱饵容器**，已移交 Dionaea。移交动作是"先缩诱饵的端口映射，再起 Dionaea"，
  顺序反了会端口冲突。
- 镜像内部还会 listen 21/80/443/135/1883/11211/27017 等端口，但**没有发布**，外部摸不到。

## 2. 为什么 Dionaea 不能外连（这一节是设计前提，不是可选项）

蜜罐是"故意让人打进来"的东西，所以它随时可能被拿下。一旦拿下而它又能主动外连，
这台机器就变成攻击者的**跳板**：从我们的 IP 出去扫别人、C2 回连、往外传数据 —— 那时责任在我们。

做法是三层叠加：

1. **网络层**：Dionaea 不建自己的 bridge，而是 `networks: external: name: cowrie_honeypot`，
   和 Cowrie 共用同一个隔离网段 `172.19.0.0/16`。
2. **DOCKER-USER**：该网段 egress 只留两条，其余 DROP
   （`-m state ESTABLISHED,RELATED` 放回程、`-d 127.0.0.11` 放容器 DNS），
   最后一条 `-s 172.19.0.0/16 -j DROP` 是兜底。
3. **实测**（不是看配置）：`scripts/srv2-honeypot-egress-probe.sh` 会从蜜罐网段里起一个容器，
   逐个端口尝试主动外连，并在 eth0 上抓包数 SYN。**SYN 出现 = 隔离有洞**。

### 2026-10-13 的真洞（必须记住的教训）

`srv2-decoy-ports.sh` 当时用 `iptables -I DOCKER-USER 1 -p tcp --dport N -j ACCEPT` 放行诱饵端口。
iptables 第一条匹配就停，而这些放行规则**不看来源**，又被插到了上面那条 DROP **前面**，于是：

| | 结果 |
|---|---|
| 外部连进来 | 源不是蜜罐网段 → 不受 DROP 影响 → 正常（这是放行的本意） |
| 蜜罐主动外连这些端口 | 源是蜜罐网段，但先匹配上了 ACCEPT → **被放行（洞）** |

实测取证：从蜜罐网段连 `1.1.1.1:3306`，eth0 上出现了 SYN；连不在名单里的 `1.1.1.1:443` 则被 DROP。
**影响窗口**：诱饵容器创建于 2026-10-13 10:25(+08)，2026-10-14 01:0x 修复后关闭，约 14.5 小时。
可出网的端口：21/23/1433/3306/6379/8080/8443/27017。

**修复**：把 DROP 提到端口放行之前；此后任何脚本放行端口**只能 `-A` 追加到链尾，绝不能 `-I 1`**。
`scripts/srv2-decoy-ports.sh` 已改成 `-A` + `-C` 幂等判断。

> **有没有真实发生过外连？** 查过 Suricata `eve.json`（蜜罐网段作为源的流事件 0 条）、
> Wazuh `alerts.json`（"跳板/egress" 类告警 0 条）。**没有查到实际成功外连的记录**；
> 洞是"能力上存在"而不是"已被利用"。但这只说明没记录到，不等于绝对没发生。

## 3. 资源预算

| 项目 | 值 | 说明 |
|---|---|---|
| mem_limit | 384 MiB | 实测空载 ~33 MiB；上限是"失控时牺牲它自己"的保险丝 |
| cpus | 0.5 核 | 宿主 4 核基本闲置 |
| pids_limit | 256 | 防 fork 炸弹 |
| read_only | true | 只有 `/opt/dionaea/etc`、`/opt/dionaea/var` 可写 + `/tmp` tmpfs 16MB |
| no-new-privileges | true | 容器内无法 setuid 提权 |
| 镜像 | `dinotools/dionaea:0.11.0` | 固定 tag；digest `sha256:6f06d0a6…73893` |
| 镜像磁盘 | ~266 MB | |
| 日志上限 | daily + maxsize 32M + rotate 5 | logrotate `copytruncate`（dionaea 不会重新打开日志文件） |
| bistreams 上限 | mtime>2 天 或 总量 >1GB | `/etc/cron.d/secagent-dionaea-cleanup` 每天 04:17 |
| 样本(binaries) | 不自动删，>2GB 告警 | 攻击者投递的样本是蜜罐最有价值的产物 |

关于证书：**Dionaea 的自签 TLS 证书是在内存里按连接生成的，不落盘**
（实测：容器内 `find / -name '*.pem'` 只有系统 CA；日志里是 `connection_tls_mkcert`）。
所以没有私钥文件需要保护，仓库里也不会有。若要固定证书，可在 `dionaea.cfg` 里指定
`ssl.default.cert` / `ssl.default.key` 指向 `/opt/dionaea/etc/dionaea/ssl/`（bind mount，建议 0600）。

## 4. 常用操作

```bash
# 自检（跑态证据，退出码可直接接巡检）
sudo bash /usr/local/sbin/srv2-dionaea-check.sh

# 隔离实测探针（会数 eth0 上的 SYN）
sudo bash /usr/local/sbin/srv2-honeypot-egress-probe.sh

# 日志
sudo tail -f /opt/dionaea/var/log/dionaea/dionaea.log
sudo tail -f /opt/dionaea/var/log/dionaea/dionaea.json     # 结构化，Wazuh 吃的就是这个
sudo tail -f /opt/dionaea/var/log/dionaea/dionaea-errors.log

# 磁盘维护（先报表，再加 --apply）
sudo bash /usr/local/sbin/srv2-dionaea-cleanup.sh
sudo bash /usr/local/sbin/srv2-dionaea-cleanup.sh --apply
```

## 5. 临时关掉（kill switch）

```bash
sudo bash /usr/local/sbin/srv2-dionaea-killswitch.sh off     # 几秒内摘掉，并确认它真的不在了
sudo bash /usr/local/sbin/srv2-dionaea-killswitch.sh status
sudo bash /usr/local/sbin/srv2-dionaea-killswitch.sh on      # 拉起（隔离断言不过会自动再停掉）
```

`off` 之后 1433/3306 上就**没有监听者**了（它们已从诱饵容器移交给 Dionaea），这是有意的取舍。
要让这两个端口重新"有东西应答"，把端口还给诱饵：

```bash
sudo DECOY_PORTS="6379 8080 8443 27017 21 23 1433 3306" \
     bash /opt/secagent/scripts/srv2-decoy-ports.sh --apply     # 需先停掉 Dionaea
```

彻底关掉自启动：`sudo systemctl disable --now srv2-dionaea.service`

## 6. 回滚（一条命令）

```bash
sudo bash /usr/local/sbin/srv2-dionaea-deploy.sh --rollback
```

它读 `/opt/secagent/backup/dionaea-last/restore.sh`，做：
停并移除容器 → 恢复 `docker-compose.override.yml` / `wazuh_manager.conf` / rules 目录
→ 恢复备份时的 iptables → 摘掉 unit。
**注意**：诱饵容器的端口清单不会自动还原（脚本会把备份时的启动命令打印出来，照着重建即可）；
ufw 的 445 放行也不自动撤销（`ufw delete allow 445/tcp`）。

备份位置：`/opt/secagent/backup/dionaea-<时间戳>/`（含 `restore.sh`、`iptables.save`、
`docker-compose.override.yml`、`wazuh_manager.conf`、`rules-dir/`、诱饵容器 inspect）。

## 7. 目录速查

| 路径 | 内容 |
|---|---|
| `/opt/dionaea/docker-compose.yml` | 容器定义（资源上限、只读根、端口、隔离网络） |
| `/opt/dionaea/etc/dionaea/` | 配置（从镜像 template 播种 + 本仓库的 `log_json.yaml`） |
| `/opt/dionaea/var/log/dionaea/` | `dionaea.log` / `dionaea.json` / `dionaea-errors.log` |
| `/opt/dionaea/var/lib/dionaea/` | `bistreams/`（连接字节流）、`binaries/`（样本）、sqlite |
| `/etc/systemd/system/srv2-dionaea.service` | 开机单元（After=cowrie-egress-lock.service） |
| `/etc/logrotate.d/secagent-dionaea` | 日志轮转 |
| `/etc/cron.d/secagent-dionaea-cleanup` | 磁盘上限维护 |
| `/opt/wazuh/config/wazuh_cluster/rules/srv2_dionaea_rules.xml` | Wazuh 规则（100300~100310） |

## 8. 已知限制 / 如实记录

1. **download（样本下载）类规则没做**：`log_json.py` 只实现了 connection / ftp 命令 /
   ftp·mssql·mysql 登录凭据 / p0f 这几类 handler，**没有** `download.offer`/`download.complete`
   的 handler。挂在这份 JSON 上的"下载到样本文件"规则会是一条**永远不触发**的死规则，
   所以没写。样本下载事件只存在于文本日志 `dionaea.log` 里。
2. **容器 DNS 是放行的**（`-d 127.0.0.11`），这是上游隔离设计的既有取舍（要留反向解析）。
   它意味着理论上存在"经 DNS 出站"的窄通道。若要彻底封，需要去掉这条并接受解析失败。
3. **开机有几秒窗口**：Docker 按 `restart: unless-stopped` 拉起容器，早于
   `cowrie-egress-lock.service` 应用 egress DROP。本项目的 unit
   `srv2-dionaea.service` 用 `After=` 保证次序 + 启动后做隔离实测断言（不过就停容器），
   但这个窗口本身是既有结构决定的（Cowrie 今天同样如此）。
4. **`DOCKER-USER` 的端口放行是否会在重启后重建**：目前靠
   `/etc/iptables/rules.v4`（由 `secagent-firewall-restore.service` 在 docker 之前 restore）。
   本项目自己的 unit 注释记录过"Docker 会重建 DOCKER-USER 链、跑在它前面的规则会被覆盖"，
   所以**这条持久化路径需要一次重启演练才能确认**；没做演练之前，重启后请跑一次
   `srv2-honeypot-egress-probe.sh` 确认。egress 三件套本身由
   `cowrie-egress-lock.service`（After=docker）重建，不受影响。
