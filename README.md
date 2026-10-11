# SecAgent · 基于 Spring AI 的网络安全智能问答与辅助分析系统

基于 **Spring AI / Spring AI Alibaba** 二次开发，将 RAG（检索增强生成）与多 Agent（规划/执行/监督）能力应用于网络安全场景：

- **安全知识库问答（RAG）**：内置 33 篇成体系安全知识文档（覆盖 Web 漏洞、渗透测试、应急响应、安全运营/设备、系统加固、代码审计与 AI/固件安全），向量化后支持可溯源问答；
- **安全事件研判（多 Agent + Tool Calling）**：自动汇聚安全告警、主机/Web/防火墙日志与知识库，经 ReAct 多 Agent 协同输出《安全事件研判报告》；
- **安全加固**：修复路径穿越、无鉴权、CORS 通配、会话失控、异常信息泄露等问题，并新增入库敏感信息扫描（DLP）。

默认使用**内存向量库**，无需 Docker / Milvus，普通笔记本即可运行。

---

## 多智能体版升级（本轮新增）

在原有 RAG 问答 + 多 Agent 研判基础上，本轮把研判链路升级为**编排层 + 调度员 + 三个专职智能体**，并补齐运营闭环：

- **多智能体协同（核心）**：`agent/multi/MultiAgentCoordinatorImpl` 统一收口。PLANNER 调度员先用规则关键词路由（离线可用），配真实 Key 时切模型路由，解析失败自动回退规则路由；再派发给三个专职智能体——ANALYST 研判分析员（知识库 RAG + 时间，只依据知识库作答）、FORENSICS 取证分析员（告警指标 + 安全日志 + 时间，只输出工具事实）、RESPONDER 处置执行员（SecurityActionTools + 时间）。汇总输出「结论 + 证据 + 处置结果」，前端对话页展示协同过程时间线（`/api/chat` 返回 steps 数组）。**处置动作在 SecurityActionTools 内部强制走 ResponseActionService（ResponseGuard 白名单 + 高危审批 + 审计），不靠提示词约束。**
- **告警聚合去重**：`aggregation/AlertAggregationService` 按「同一源 IP + 5 分钟时间窗（可配）+ 同类告警」自动聚合；聚合行带 ×N 徽标、时间窗、涉及资产、双来源徽标，可下钻原始明细。`/api/alerts/list` 默认聚合（同时返回 rawTotal/aggregatedTotal），`?raw=true` 返回原始。
- **封禁到期自动解封**：封禁成功登记 `data/blocked-ips.json`（含 expiresAt、来源=手动/审批/智能体）；`UnblockScheduler` 每 60s（可配，开关 `response.unblock.enabled`）扫描到期自动调 Wazuh active-response 解封（无 Wazuh 自动 MOCK），写审计 `action=unblock-ip actor=scheduler`；`GET /api/response/blocks` 查封禁中列表。
- **红队评测误报率**：用例集 27 例（基础 19 = 攻击 11 离线 + 2 模型 + 正常流量 8 离线；绕过型 8）；summary 含 `falsePositiveRate`/`normalExecuted`/`normalMisblocked`，逐例 MISBLOCKED=误拦；前端 KPI 五卡并列（攻击成功率/绕过率/误报率/平均耗时/Token 成本）。
  - **实测数值**：拦下 15 / 绕过 4，绕过率 4/19 = 21.05%（95% CI 约 8%~44%）；8 例正常流量**未观察到误拦** —— 注意真实误报率的 95% 置信上限约 **37.5%**（三法则 3/n），样本量不足以支撑「误报率很低」的结论。
  - 修过的一个指标 bug：`attackSuccessRate` 原本用 `bypassed/executedCount`（分母 19），与 `bypassRate` 的 `bypassed/expectBlockedExecuted`（分母 11）不一致。`attackSuccess` 只在攻击用例上才可能为 true，分母只能是攻击用例数。

> 架构定位不变：智能编排、研判、护栏全部写在本仓库自有代码里；Wazuh 仅作「真实数据源 + 执行封禁/解封的手」，Suricata 仅作网络层告警来源；不引入 Shuffle 等独立 SOAR 平台。

---

## 快速开始（Windows + IDEA）

> 详细图文步骤见 **[`docs/00-从零运行傻瓜手册-Windows.md`](docs/00-从零运行傻瓜手册-Windows.md)**。

1. 安装 JDK 17（IDEA 内可直接下载）。
2. 获取阿里云百炼 API Key（`sk-` 开头）。
3. 用 IDEA 打开本目录（含 `pom.xml`），等待 Maven 导入依赖。
4. 在 `src/main/resources/application.yml` 两处填入 Key，或设置环境变量 `DASHSCOPE_API_KEY`。
5. 运行 `org.example.Main`，看到 `Started Main` 与「知识库类别目录初始化完成」后，访问 <http://localhost:9900>。

命令行方式：

```bash
export DASHSCOPE_API_KEY=sk-xxxx
mvn spring-boot:run
```

---

## 功能验证

| 功能 | 操作 |
|------|------|
| 健康检查 | GET <http://localhost:9900/api/health> |
| 知识库问答 | 首页输入「什么是路径穿越，怎么防御？」 |
| 安全研判 | 首页右上角「安全研判」按钮（多 Agent，约 1~3 分钟） |
| 上传入库 | 输入框左下「⋯ → 上传文件」（支持 .txt/.md） |
| 安全 PoC | Windows 运行 `docs/poc/windows-poc.bat`，Git Bash 运行 `docs/poc/poc.sh` |
| 单元测试 | `mvn test`（路径防护 7 例 + 敏感扫描 6 例） |

---

## 文档索引

| 文档 | 内容 |
|------|------|
| [docs/00-从零运行傻瓜手册-Windows.md](docs/00-从零运行傻瓜手册-Windows.md) | 零基础环境准备、运行、排错 |
| [docs/01-项目架构与技术讲解.md](docs/01-项目架构与技术讲解.md) | 架构图、RAG 与多 Agent 链路、包结构 |
| [docs/02-漏洞复现与修复说明.md](docs/02-漏洞复现与修复说明.md) | 6 类漏洞的 PoC、修复原理、回归测试 |
| [docs/03-安全审计报告.md](docs/03-安全审计报告.md) | 正式安全审计报告 |
| [docs/04-面试必背20问.md](docs/04-面试必背20问.md) | 项目答辩与面试问答 |
| [docs/poc/](docs/poc/) | Windows / Bash PoC 脚本 |
| [security-docs/](security-docs/) | 内置安全知识库（33 篇：Web 漏洞 / 渗透测试 / 应急响应 / 安全运营与设备 / 系统加固 / 代码审计 / AI 与固件） |

---

## 技术栈

- Spring Boot 3.2、Spring AI 1.1、Spring AI Alibaba 1.1.0.0-RC2（ReactAgent / SupervisorAgent）
- 阿里云百炼：qwen-plus（对话）、text-embedding-v4（向量化，1024 维）
- 向量存储：自研 `VectorStoreGateway` 抽象，内存实现（默认，余弦相似度 + JSON 持久化）/ Milvus 实现（可选）
- 前端：原生 HTML / CSS / JavaScript + SSE
- 测试：JUnit 5

---

## 关键配置（src/main/resources/application.yml）

| 配置 | 默认 | 说明 |
|------|------|------|
| `vector.store` | `memory` | 内存向量库，可选 `milvus` |
| `vector.memory.file` | `data/vector-store.json` | 内存向量持久化路径 |
| `vector.kb.auto-index` | `false` | 启动时自动构建安全知识库（默认关闭，未配真实 Key 时避免无效调用；预置向量开箱即用） |
| `file.kb.path` | `security-docs` | 内置知识库目录 |
| `file.allowed-extensions` | `txt,md` | 上传扩展名白名单 |
| `file.sensitive-scan` | `true` | 入库敏感信息扫描 |
| `app.auth.enabled` | `true` | 接口 Token 鉴权（默认开启；登录会话 Token 或系统级 API Token 任一通过即可） |
| `app.cors.allowed-origins` | 本机 | CORS 来源白名单 |
| `app.session.ttl-minutes` | `120` | 会话过期分钟数 |

---

## 切换到 Milvus（可选）

把 `vector.store` 改为 `milvus` 并配置 Milvus 连接即可，业务代码无需改动；设置 `spring.ai.mcp.client.enabled=true` 可启用 MCP 工具（默认关闭，零依赖运行）。

---

## 安全声明

本项目仅用于课程学习、安全研究与工程实践，请勿用于任何未授权目标。项目基于 Spring AI Alibaba 教学示例二次开发，默认 mock 数据均为虚构，不涉及真实资产与漏洞。
