# SecAgent 从零运行傻瓜手册（Windows + IDEA）

> 这份文档假设你**没有任何 Java 项目运行经验**，照做即可。每一步都写了「点哪里、看到什么算成功、出错怎么办」。
> 全程**不需要安装 Docker、不需要安装 Milvus 数据库**，默认使用内存向量库。

---

## 第 0 步：你需要准备的东西

| 东西 | 说明 | 是否已具备 |
|------|------|-----------|
| IntelliJ IDEA | 写 Java 的软件，社区版/旗舰版都行 | 你已有 |
| JDK 17 | Java 运行环境（本项目必须是 17，不能用 8/11） | 下面第 1 步用 IDEA 下载 |
| 阿里云百炼 API Key | `sk-` 开头，调大模型/向量化用 | 第 2 步获取 |
| 项目代码 | `sec-agent` 文件夹 | 已提供 |

---

## 第 1 步：用 IDEA 安装 JDK 17（最省事的方式）

1. 打开 IDEA。
2. 菜单 `File → Project Structure`（快捷键 `Ctrl + Alt + Shift + S`）。
3. 左侧选 `Project`，在 `SDK` 一栏：
   - 如果已经是 **17**，直接跳到第 3 步；
   - 如果没有，点 `Add SDK → Download JDK...`。
4. 弹窗里：
   - `Version` 选 **17**；
   - `Vendor` 选 **Eclipse Temurin**（或 Oracle、Amazon Corretto 都行）；
   - 点 `Download`，等它下载完成（几分钟）。
5. `Language level` 也选 `17`，点 `OK`。

**看到什么算成功**：Project Structure 里 SDK 显示 17，没有红色报错。

---

## 第 2 步：获取阿里云百炼 API Key

1. 浏览器打开 `https://bailian.console.aliyun.com/`，登录并完成**实名认证**。
2. 左侧菜单进入「API-KEY 管理」，点「创建我的 API-KEY」，复制 `sk-` 开头的字符串。
3. 先粘到你电脑的记事本里临时保存。
4. **安全提醒**：Key 等于你的额度密码，**不要发到任何聊天框、不要传到 GitHub**，只填在本机配置里。

> 费用：新用户有免费额度；向量化接口 text-embedding-v4 有 100 万 tokens 免费额度，对话用 qwen-plus 很便宜，整个项目跑通大约花费几毛钱。

---

## 第 3 步：用 IDEA 打开项目

1. 把 `sec-agent` 文件夹放到一个**路径里没有中文和空格**的地方，例如 `D:\projects\sec-agent`。
2. IDEA 菜单 `File → Open`，选择 `sec-agent` 文件夹（**选中里面有 pom.xml 的那一层**），点 `OK`。
3. 第一次打开，右下角会提示 `Maven projects need to be imported`，点 **`Load Maven Project` / `Import Maven changes`**（或点右侧 Maven 面板的刷新按钮）。
4. 等待 IDEA 自动下载依赖（右下角进度条），第一次可能需要 **5～15 分钟**，取决于网速。

**看到什么算成功**：
- 左侧 `src/main/java` 下的代码文件夹不标红；
- 底部 `Problems` 没有大量报错；
- 右侧 Maven 面板依赖都下载完。

> 如果下载很慢：在 IDEA `Settings → Build, Execution, Deployment → Build Tools → Maven`，把 Maven 仓库换成国内镜像（阿里云），或把 IDEA 自带 Maven 的 `settings.xml` 配成阿里云镜像。一般默认也能下完，只是慢。

---

## 第 4 步：填入 API Key（两种方式，二选一）

### 方式 A：直接改配置文件（最简单，推荐本地演示用）

1. 在左侧项目树展开 `src/main/resources`，打开 `application.yml`。
2. 找到两处 `${DASHSCOPE_API_KEY:sk-placeholder}`，把默认值 `sk-placeholder` 换成你的 Key（两处都换）：

```yaml
spring:
  ai:
    dashscope:
      api-key: ${DASHSCOPE_API_KEY:sk-在这里填你的Key}
...
dashscope:
  api:
    key: ${DASHSCOPE_API_KEY:sk-在这里填你的Key}
```

> 注意：不要把填了真实 Key 的文件上传到公开仓库。

### 方式 B：配置环境变量（更规范）

1. 菜单 `Run → Edit Configurations...`。
2. 找到/新建运行配置 `Main`（Main class 为 `org.example.Main`）。
3. 在 `Environment variables` 里加：`DASHSCOPE_API_KEY=sk-你的Key`。
4. 这样 `application.yml` 里不用写真实 Key。

---

## 第 5 步：启动项目

1. 在左侧展开 `src/main/java/org/example`，找到 `Main.java`。
2. 在 `Main` 类里 `public static void main` 左边有个绿色小三角，**点它 → Run 'Main.main()'**。
3. 第一次启动会编译，等一会儿，看底部控制台日志。

**看到什么算成功**（关键日志）：

- 出现 `Tomcat started on port(s): 9900`；
- 出现 `知识库类别目录初始化完成：CVE/CNVD漏洞库=0片 应急响应手册=135片 红日渗透笔记=46片 Web安全=109片 设备安全=28片`（向量数量以实际为准，共 318 条）；
- 出现 `安全知识库自动索引已关闭（vector.kb.auto-index=false）`（默认关闭，预置向量开箱即用）；
- 出现 `Started Main in X seconds`。

> 说明：升级版已预置 318 条向量（存于 `data/vector-store.json`），**启动时不会重新调用向量化接口**，几秒内即可完成启动。若配好真实 Key 后想重新索引，把 `application.yml` 里 `vector.kb.auto-index` 改为 `true` 再重启。

---

## 第 6 步：验证功能（建议对照截图保存）

浏览器打开 **`http://localhost:9900`**，你会看到「AI 安全智能助手」界面。

### 6.1 健康检查
浏览器新开标签页访问 `http://localhost:9900/api/health`，应看到类似：

```json
{
  "status": "ok",
  "application": "SecAgent",
  "vectorStore": "memory",
  "documentVectors": 318,
  "logsMockEnabled": true,
  "alertsMockEnabled": true
}
```

### 6.2 知识库问答（RAG）
在首页输入框问一个安全知识问题，例如：
- `什么是路径穿越，怎么防御？`
- `SSH 被暴力破解了，应急处置步骤是什么？`

应看到回答里引用了知识库的处置步骤。

### 6.3 安全事件研判（多 Agent）
点右上角「**安全研判**」按钮，系统会自动：
1. 拉取当前活跃安全告警（SSH 爆破、SQL 注入、WebShell、目录扫描）；
2. 检索主机/Web/防火墙日志做证据印证；
3. 检索安全知识库；
4. 输出一份《安全事件研判报告》（活跃告警清单、日志证据、攻击链、处置建议、IOC）。

这个过程较慢（多 Agent 多次调用大模型），可能需要 **1～3 分钟**，耐心等待。

### 6.4 上传文档
输入框左下角「⋯ → 上传文件」，选一个 `.txt` 或 `.md` 上传，会自动切片向量化入库。

---

## 第 7 步：验证安全加固（PoC，用于简历/面试演示）

Windows 自带 `curl.exe`，打开一个 **cmd 或 PowerShell**，`cd` 到项目目录，运行：

```bat
docs\poc\windows-poc.bat
```

预期：
- 正常上传返回 200；
- 文件名带 `../`、`..\`、`%2f`、`shell.jsp` 的请求都被拒绝（400 非法文件名）；
- 含 AccessKey 的文档被拦截（422 敏感信息）。

具体见 `docs/02-漏洞复现与修复说明.md`。

### 演示接口鉴权（可选加分项）
1. 鉴权**默认已开启**（`app.auth.enabled=true`），无需修改配置；接口同时支持登录会话 Token 与系统级 API Token（默认 `secagent-demo-token`）。
2. 不带 Token 访问接口会返回 `401 未授权访问`。
3. 带 Token 才允许：
   curl 示例：`curl -H "X-API-Token: secagent-demo-token" http://localhost:9900/api/health`

---

## 常见报错与解决

| 报错/现象 | 原因 | 解决 |
|-----------|------|------|
| `Invalid API-key` / `api key invalid` | Key 没填或填错 | 检查第 4 步两处 Key，去掉多余空格 |
| 启动卡在「构建安全知识库」（仅当 `vector.kb.auto-index=true` 时出现） | 首次调用向量化较慢/网络抖动 | 等待；如失败应用仍会启动，可启动后手动上传。默认 `false` 预置向量，一般不会走到这一步 |
| `Connection timed out` / 429 | 网络或限流 | 稍后重试；确认 Key 有额度 |
| 端口 9900 被占用 | 其他程序占用 | 关掉占用程序，或把 application.yml 的 server.port 改成 9901 |
| 代码全是红色、找不到符号 | Maven 依赖没下载完 | 右侧 Maven 面板点刷新（Reload All Maven Projects） |
| 运行提示 `release version 17 not supported` | 没用 JDK17 编译 | 第 1 步把 Project SDK 改成 17，Maven 的 Runner JRE 也选 17 |
| 安全研判一直转圈 | 多 Agent 调用慢 | 最多等 3 分钟；控制台能看到每个 Agent 的调用过程 |
| 内存库想清空重建 | 想重新索引 | 删除项目根目录的 `data/vector-store.json` 后重启，并把 `vector.kb.auto-index` 改为 `true`（配好真实 Key 后才会重建），或直接在界面上传重新入库 |

---

## 目录说明

```
sec-agent/
├── security-docs/          # 内置知识库源文档（33 篇，预置 318 条向量开箱即用）
├── data/                   # 向量库/事件/审计等数据文件（运行后自动生成）
├── uploads/                # 上传目录（运行后自动生成）
├── docs/                   # 文档：手册、架构、审计、PoC、面试题
├── src/main/java/org/example/
│   ├── vector/             # 向量存储抽象 + memory/milvus 两实现（新增）
│   ├── security/           # 安全加固代码（新增）
│   ├── controller/         # 接口（含健康检查、修复后的上传）
│   ├── service/            # RAG、对话、多 Agent 研判服务
│   └── agent/tool/         # 安全告警、安全日志、知识库等工具
└── src/main/resources/
    ├── application.yml     # 配置（Key、向量库、mock、安全开关都在这）
    └── static/             # 前端页面
```
