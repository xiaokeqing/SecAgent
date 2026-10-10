# PHP 代码审计与安全脚本开发

> 短训课程的代码审计阶段以 Web 前后端（HTML/JS/PHP/Python）为主。本文讲 PHP 代码审计的思路、危险函数、安全编码，以及 Python 安全脚本的开发原理（仅用于授权测试与防御）。

## 一、代码审计方法
1. **确定入口**：找路由、控制器、参数接收点（`$_GET/$_POST/$_REQUEST/$_COOKIE`、PHP 框架的 Input/Request）。
2. **污点分析**：从 Source（用户输入）跟踪到 Sink（危险函数/操作），中间是否有过滤/校验。
3. **按漏洞类型过一遍**：SQL 注入、命令执行、文件包含/上传/下载、XSS、反序列化、代码执行、越权、文件写入。
4. 结合全局变量、文件包含、伪协议、框架特性、历史 CVE。
5. 工具辅助：Seay 源码审计、PHP 代码审计工具、IDE 全局搜索；动态验证用 Xdebug/Burp（授权靶场）。

## 二、PHP 常见危险函数与审计点

| 漏洞 | 危险函数/特征 | 安全写法 |
|------|----------------|----------|
| SQL 注入 | 拼接 SQL；`mysql_query`/`mysqli_query` 拼字符串 | PDO/MySQLi 预编译参数化 |
| 命令执行 | `system/exec/shell_exec/passthru/popen/反引号`、`proc_open` | 不拼命令、白名单、用库替代 |
| 代码执行 | `eval/assert/create_function/call_user_func/动态函数` | 禁止用户控制函数名与代码 |
| 文件包含 | `include/require/include_once` + 变量 | 白名单映射、不接受用户路径 |
| 文件上传 | `move_uploaded_file`、仅检查 Content-Type/前端后缀 | 白名单、取最后一个点、内容校验、目录不可执行 |
| 文件读取 | `file_get_contents/fopen/readfile` 拼路径 | 规范化 + 目录边界、白名单 |
| 文件写入 | `file_put_contents/fwrite` | 控制路径与内容、防写可执行文件 |
| 反序列化 | `unserialize` 用户数据、魔术方法 `__wakeup/__destruct` | 不反序列化不可信数据、用 JSON |
| XSS | 输出未 `htmlspecialchars`、`echo` 用户输入 | 按上下文编码、模板自动转义 |
| SSRF | `curl/file_get_contents` 请求用户 URL | 白名单、禁内网、仅 http/https |

## 三、典型污点示例（教学，说明根因）
- 命令注入：`system("ping -c 4 " . $_GET['ip']);`——`ip` 未过滤即拼入命令，可加 `;` 分隔执行其他命令；
- 文件包含：`include($_GET['page'] . '.php');`——`page` 可控，可配合伪协议/路径穿越；
- 反序列化：`unserialize($_COOKIE['data']);`——配合类中的魔术方法可形成 POP 链；
- 这些都应以"输入从哪来、到哪个危险函数、中间有无过滤"来定位。

## 四、安全编码要点（PHP）
- SQL：一律 PDO 预编译（`prepare` + `bindParam`），不拼接；
- 命令：尽量不调用 shell；必须用时用 `escapeshellarg/escapeshellcmd` 且白名单；
- 输出：按上下文做 `htmlspecialchars`（HTML 体、属性、JS、URL 分别处理）；
- 上传：服务端白名单扩展名、`pathinfo` 取最后一个点、重命名、存到非 Web 可执行目录、校验 MIME 与内容；
- 包含：用固定映射（如 `$map=['a'=>'pageA']`），不直接拼用户输入；
- 配置：关闭 `allow_url_include`、`display_errors` 关生产报错、`open_basedir` 限制目录、禁用危险函数、升级 PHP 版本；
- 反序列化：跨端传 JSON，不 `unserialize` 不可信数据；
- 认证授权：服务端校验、会话固定防护、CSRF Token、密码 `password_hash`。

## 五、Python 安全脚本开发（授权用途）
课程安全开发阶段要求会写端口扫描、弱口令、SQL 注入检测、爬虫等脚本，理解工具原理：
- **网段/端口扫描**：socket 连接、并发（线程/协程）、服务指纹识别；原理与 Nmap 一致，仅用于扫描自己的靶机或授权资产。
- **弱口令检测**：基于授权字典对靶场登录/SSH 做尝试，理解认证流程与失败锁定；用于验证弱口令风险，不做撞库。
- **SQL 注入检测**：对靶场参数注入探测特征、对比响应差异，理解布尔/报错/时间盲注的判定逻辑。
- **爬虫/信息收集**：requests、解析、限速、遵守目标范围（仅授权目标）。
- **日志分析脚本**：解析 auth.log/Nginx 日志，统计失败登录、攻击源 IP、可疑 payload——这是防御向、最值得写进简历的部分。
- 工程要点：参数化、超时控制、日志记录、异常处理、明确目标白名单、限速，避免误伤生产。

## 六、从审计到防御（与岗位关联）
- 渗透/代码审计岗：找 Source→Sink，给出最小 PoC 与修复；
- 安全开发岗：把安全编码规范、安全组件、SAST/SCA 扫描集成进 CI；
- 安全运维：把日志分析、自动化检测脚本用于日常监控；
- 报告与修复闭环：定位 → 验证 → 修复（安全函数/参数化/白名单）→ 复测。

## 七、与项目关联
SecAgent 本身是 Java/Spring Boot 项目，Java 代码审计要点见《安全编码与 Java 代码审计》；本文的 PHP 审计用于覆盖短训课程和常见 PHP 网站渗透，而 Python 安全脚本（尤其日志分析、告警研判）正是多 Agent 工具的底层能力——工具函数本质就是把"查日志、统计、匹配"的安全脚本封装为可被 Agent 调用的工具。
