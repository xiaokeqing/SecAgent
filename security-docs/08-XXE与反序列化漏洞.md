# XXE 与反序列化漏洞

## 一、XXE（XML 外部实体注入，CWE-611）

### 原理
XML 解析器允许定义"实体"并引用外部资源（外部实体）。攻击者在 XML 中构造恶意 DTD/实体，让解析器读取本地文件、发起请求或造成拒绝服务。

### 攻击点
- 接收 XML 格式的 SOAP、SAML、支付回调、Web 服务；
- 旧版 XML 解析库（Java DocumentBuilder、SAXReader）默认开启外部实体。

### 危害
- 任意文件读取（`file:///etc/passwd`、配置、密钥）；
- 服务端请求伪造（SSRF）、内网探测；
- 拒绝服务（ billion laughs）；
- 部分情况下 RCE（如通过 expect 协议）。

### 防御
- 禁用外部实体、DTD：`FEATURE_SECURE_PROCESSING`，设置 `disallow-doctype-decl`、`external-general-parameter-entities=false`、`external-parameter-entities=false`；
- 优先用 JSON 替代 XML；
- 升级解析库，最小化依赖。

---

## 二、不安全反序列化（CWE-502）

### 原理
应用把不可信的序列化数据直接反序列化成对象。反序列化时会触发对象构造链，攻击者构造恶意字节流，利用类库中的"gadget chain"在反序列化过程中执行任意代码。

### Java 常见点
- `ObjectInputStream.readObject()`、`XMLDecoder`、`XStream`、`SnakeYAML`、`Fastjson`、`Jackson` 的 `enableDefaultTyping`、`Shiro` RememberMe、`WebLogic`、`JBoss`。

### 危害
- 远程代码执行（RCE）、WebShell；
- 认证绕过、权限提升；
- 数据泄露、拒绝服务。

### 防御
1. **不反序列化不可信数据**：不接收用户可控的序列化对象。
2. **白名单类**：使用 JEP 290 ObjectInputFilter，只允许反序列化预期类。
3. **避免危险特性**：Fastjson/Jackson 关闭 AutoType、default typing；升级到无已知 gadget 的版本。
4. **数据格式**：跨服务传输用 JSON（且不开启多态默认类型）。
5. **升级与最小化依赖**：及时更新库版本，用 SCA 工具扫描已知 CVE。
6. **监控**：WAF 识别反序列化特征，记录异常反序列化日志。

---

## 三、研判要点
- 出现针对 XML 接口的 `<!DOCTYPE`、`ENTITY` 载荷，或反序列化接口的异常字节、`rO0AB`（Java 序列化魔钥 Base64）、`{"@type":"..."}` 等特征，应高度警惕；
- 结合历史 CVE 检查 Fastjson、Jackson、Shiro、WebLogic 等组件版本。
