# 安全编码与 Java 代码审计要点

## 一、输入校验（默认不信任外部输入）
- 所有外部输入（参数、请求头、Cookie、文件名、上传内容）都要校验。
- 优先**白名单**：明确允许什么，而不是枚举禁止什么。
- 校验类型、长度、范围、格式、字符集；服务端校验为主，前端校验只用于体验。

## 二、Java 常见审计点（按函数定位污点）

### 1. SQL 注入
- 危险：字符串拼接 SQL、`Statement`、MyBatis `${}`。
- 安全：`PreparedStatement`、MyBatis `#{}`、参数化；排序字段等不能参数化的用白名单。

### 2. 命令注入
- 危险：`Runtime.getRuntime().exec(String)`、`ProcessBuilder(String)`、拼 shell。
- 安全：`ProcessBuilder` 用数组传参（不经过 shell），不拼接输入；能不用命令就不用。

### 3. 文件上传 / 路径穿越
- 危险：`new File(dir, getOriginalFilename())`、`Paths.resolve(original)`。
- 安全：文件名白名单、扩展名取最后一个点、`normalize()` 后校验 `startsWith(base)`、上传目录不可执行、重命名、限制大小、内容扫描。

### 4. SSRF
- 危险：`URL.openConnection`、`RestTemplate`、`HttpClient` 请求用户给的 URL。
- 安全：域名白名单、解析后校验 IP 非内网段、禁危险协议、校验重定向。

### 5. 反序列化
- 危险：`ObjectInputStream.readObject`、Fastjson AutoType、Jackson defaultTyping、XStream。
- 安全：不反序列化不可信数据、JEP 290 白名单、关 AutoType、升级版本。

### 6. XSS / 模板注入
- 模板引擎默认转义；避免 `utext`、`v-html`；富文本用 HTML 净化。

### 7. 越权
- 每个接口做认证与对象级授权；不依赖前端隐藏；会话与用户绑定。

## 三、密钥与配置
- 密钥、口令、Token 不放代码、不进日志、不入库，通过环境变量/密钥管理注入。
- 知识库、日志入库前做敏感信息扫描（DLP），识别 AccessKey、私钥、JWT。
- 关闭调试、默认账号、目录列举；Actuator 等敏感端点加鉴权。

## 四、错误处理与日志
- 统一全局异常处理，对外返回通用提示和正确状态码，不回显堆栈、SQL、内部路径。
- 记录安全相关日志（登录、上传、权限变更、异常），但日志要脱敏。

## 五、审计方法（污点分析）
1. 找**源（Source）**：`@RequestParam`、`@PathVariable`、Header、Cookie、上传文件名等用户输入。
2. 找**汇（Sink）**：SQL、命令、文件路径、URL 网络、反序列化、模板渲染。
3. 沿数据流看 Source 到 Sink 之间是否有校验/净化（Validator、编码、白名单）。
4. 无净化即可能成漏洞，再结合 PoC 验证（避免误报）。
5. 工具辅助：IDEA 搜索危险函数、SpotBugs/Find Security Bugs、SCA 扫依赖 CVE。

## 六、SDL 与 CI
- 需求/设计阶段做威胁建模；代码评审看安全点；
- 静态扫描（SAST）、依赖扫描（SCA）、镜像扫描进 CI；
- 单元测试覆盖安全边界（非法输入、越权、异常），用 PoC 回归。

## 七、与项目关联
对 SecAgent 的审计就是按上述方法：从上传接口的文件名（Source）到文件路径（Sink）发现路径穿越（CWE-22），并补充 DLP、鉴权、CORS、会话治理、全局异常，同时用 JUnit 测试固化各类绕过载荷的拦截结果，形成"发现—修复—回归"闭环。
