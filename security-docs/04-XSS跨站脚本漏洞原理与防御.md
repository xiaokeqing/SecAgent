# XSS 跨站脚本漏洞（CWE-79）

## 一、原理
XSS（Cross-Site Scripting）是指应用把用户可控的输入未经转义直接输出到网页，被浏览器当作脚本执行。攻击者借此在受害者浏览器中执行任意 JavaScript。

## 二、三种类型
- **反射型 XSS**：恶意参数在请求中，服务端原样返回并执行（如搜索、错误页回显），需要诱导点击。
- **存储型 XSS**：恶意脚本被存进数据库或文件，之后被页面加载执行（如评论、昵称、日志），危害最大，影响所有访问者。
- **DOM 型 XSS**：前端 JavaScript 直接读取 URL、localStorage 等并写入 DOM，服务端不参与。

## 三、危害
- 窃取 Cookie、Token、会话，实现账号劫持；
- 劫持页面执行操作（转账、改密）、钓鱼、挂马；
- 劫持键盘输入、内网探测（结合 XSS 打 SSRF）；
- 蠕虫式传播（如评论区 XSS 蠕虫）。

## 四、常见攻击点
搜索框、评论、个人资料、富文本、错误提示、文件名、JSON 接口被前端直接 `innerHTML` 渲染、URL 参数回显。

## 五、防御
1. **输出编码**：根据上下文对 HTML、属性、JS、URL、CSS 分别做实体编码，这是最核心的手段。
2. **优先用安全 API**：用 `textContent` 而非 `innerHTML`；模板引擎（Thymeleaf 等）默认转义，避免使用 `th:utext`、`v-html`、`dangerouslySetInnerHTML` 输出不可信内容。
3. **CSP 内容安全策略**：设置 `Content-Security-Policy`，限制脚本来源、禁用内联脚本，即使存在 XSS 也难以执行。
4. **输入校验**：白名单限制富文本，对必须支持 HTML 的场景用 DOMPurify 等库做 HTML 净化。
5. **Cookie 防护**：关键 Cookie 设置 `HttpOnly`（防脚本读取）、`Secure`、`SameSite`。
6. 敏感操作要求二次验证，降低 XSS 后的危害。

## 六、区分 XSS 与其他漏洞
- XSS 是把脚本注入给**别人的浏览器**执行；SQL 注入是攻击**数据库**；命令注入是执行**系统命令**；CSRF 是**冒用用户身份发请求**，不执行脚本。

## 七、研判要点
日志中若出现大量对评论、资料接口的 `<script>`、`onerror=`、`javascript:` 等特征的请求，或 WAF 拦截到 XSS 载荷，应判断是否为存储型 XSS 探测，需检查数据是否落库、是否已被其他用户访问。
