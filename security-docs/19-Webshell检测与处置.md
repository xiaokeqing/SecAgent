# Webshell 检测与处置

## 一、什么是 Webshell
Webshell 是攻击者上传到 Web 目录的脚本文件（如 `.php/.jsp/.asp/.aspx`），通过浏览器或工具（如中国菜刀、蚁剑、哥斯拉）执行命令、读写文件、持久化控制。

## 二、常见入口
- 文件上传漏洞（路径穿越、无扩展名校验、解析漏洞）；
- 命令执行/RCE 直接写入；
- SQL 注入 + 数据库写文件；
- 中间件/组件漏洞、后台模板编辑、弱口令。

## 三、静态特征
- 危险函数：`eval/assert/system/exec/shell_exec`（PHP）、`Runtime.exec`（JSP）、`PowerShell/CreateObject`（ASP）；
- 强混淆：`base64_decode`、`str_rot13`、`gzinflate`、字符拼接、`request.getInputStream`；
- 一句话木马（如 `eval($_POST[cmd])`）；
- 文件名伪装（图片马、`x.jsp.jpg`、目录名怪异）、文件时间异常。

## 四、动态/行为特征
- Web 进程（www-data、tomcat、w3wp）派生系统命令（`cmd.exe /c`、`sh -c`、whoami、ipconfig、net user）；
- 异常外连（C2、4444/8080 等端口）；
- 短时间内大量文件操作、命令执行；
- 非工作时间的 POST、固定 User-Agent、异常 Content-Type。

## 五、检测方法
1. 按 Web 目录最近修改时间排查可疑文件（`find . -name "*.php" -newer ...`、PowerShell）。
2. 用静态查杀工具（D 盾、河马、findWebshell）+ 规则匹配。
3. 查 Web 访问日志：上传成功（200/204）+ 随后对同一文件的 POST、命令执行痕迹。
4. 关联进程与网络：Web 服务派生的 shell、异常外连 IP。
5. 检查内存马（无文件落地的内存马，需查 Java 进程/内存、过滤链、Agent）。

## 六、处置
1. **隔离主机**，保留 Webshell 与日志证据。
2. 定位并删除 Webshell、内存马，清除自启动后门、添加的账号。
3. **定位入口并修复**：封堵上传/RCE 漏洞（这是根因，否则会再次被传）。
4. 改密：Web 后台、数据库、系统账号、密钥。
5. 排查横向移动与其他主机。
6. 验证后恢复上线，部署 WAF、HIDS、文件监控。

## 七、与项目 mock 场景
mock 告警中"WebshellDetected"即对应：攻击者通过 Web 目录上传 Webshell，Web 进程派生系统命令并对外连接 C2；研判时需关联 Web 访问日志的上传记录、主机日志的命令执行、防火墙外连 IOC。
