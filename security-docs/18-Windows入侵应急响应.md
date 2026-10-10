# Windows 入侵应急响应 SOP

## 一、适用场景
Windows 服务器出现异常登录、Webshell、勒索、挖矿、反弹连接等可疑事件。

## 二、初步判断（先控势）
1. 保持现场，记录时间，尽量不断电（内存证据易失）；必要时先断网隔离。
2. 查看当前登录与可疑会话：`query user`、`net session`、`qwinsta`。
3. 查看进程：任务管理器或 `tasklist`、`wmic process get name,processid,parentprocessid,commandline`，关注异常路径、高 CPU 进程、异常父子进程。
4. 查看网络连接：`netstat -ano`，找异常外连 IP/端口，用 `-o` 拿到 PID 关联进程。

## 三、持久化排查（重点）
- **开机启动**：`shell:startup` 目录、注册表 `Run/RunOnce`、`msconfig`、计划任务 `schtasks /query`、服务 `services.msc`/`sc query`。
- **账号**：`net user`、`net localgroup administrators`，检查是否被新增隐藏账号（注册表 ProfileList、用户名末尾带 `$`）。
- **后门**：Web 目录、`System32`、临时目录、远程桌面、远程管理工具（WMI、WinRM）。

## 四、日志分析
- 打开"事件查看器"，重点看：
  - **4624**（登录成功）、**4625**（登录失败）、**4672**（特权登录）、**4720**（账号创建）、**4728/4732**（加入组）；
  - 登录类型 10（RDP 远程桌面）、3（网络）需重点关注。
- 来源 IP 异常、非工作时间、大量 4625 后出现 4624（爆破成功）。

## 五、Web 与文件
- Web 目录（IIS、Tomcat、Nginx）按修改时间找 Webshell、最近写入文件：
  - `forfiles`、PowerShell 按时间筛选；
- 检查 IIS 日志（`C:\inetpub\logs\LogFiles`）中的异常请求、POST、编码内容。

## 六、处置
1. 隔离主机，断开外网连接，保留镜像/内存。
2. 清除 Webshell、计划任务、服务、启动项、异常账号。
3. 修补入口漏洞（Web 漏洞、弱口令、RDP），更新补丁。
4. 全面改密（系统、数据库、远程账号），排查横向移动。
5. 杀毒/EDR 全盘扫描，确认无残留后再恢复上线。
6. 输出应急报告（时间线、入口、IOC、处置、加固建议）。

## 七、加固
- 禁用不必要端口（RDP 不暴露公网、改默认端口或走 VPN）；
- 强密码、账户锁定、最小权限、打补丁；
- 开启审核策略、安装 HIDS/EDR、备份（3-2-1 原则）。
