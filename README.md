# SecAgent · 安全观测平台后端（Spring Boot + 部署脚本）

## 1. 一句话定位

> srv1 上唯一的只读数据出口，加规则处置与审计引擎。

本仓库 = 后端（Spring Boot 3.2 / Java 17）+ 双机部署脚本；站点侧在前端仓库 [xiaokeqing.github.io](https://github.com/xiaokeqing/xiaokeqing.github.io)。仓库里另有 RAG 问答与多智能体研判链路，但和处置链路共享同一条铁律：**模型只解释、不拍板**。

## 2. 架构图（srv2 采集 → srv1 只读 API → Cloudflare → Hugo 静态站）

```text
[真实公网攻击源] 扫描 / 爆破 / Web 攻击 / 蜜罐交互
        │
        ▼
srv2 上海 · 采集面 ───────────────────────────────────────────
  nginx 18080 隧道入口 · 443 公网直连 / Wazuh Dashboard
  Wazuh 4.9.2（manager / indexer / dashboard）
  Suricata（eve.json）· Cowrie 2222 · Dionaea 445/1433/3306
  decoy 诱饵端口 21/23/6379/8080/8443/27017
  labnet（--internal，禁出网）7 台靶场，只映射 127.0.0.1:8081-8087
        │  同机文件 / 本地 socket，只读拉取
        ▼
srv1 杭州 · 本仓库 ──────────────────────────────────────────
  Spring Boot `secagent` 容器，仅监听 127.0.0.1:9900
  publicapi/  16 个 /api/public/* 只读映射 + 应用内快照缓存（45s）
  response/   规则判定 → 处置 → 真实防火墙落盘 → audit 审计留痕
  security/   提示词注入护栏 · 脱敏 · 限流 · 三级额度池
  llm/        单一模型出口（出站边界 + 熔断）；RAG 问答只解释
        │  HTTPS：demo.xiaokeqing.cn 是唯一 API 出口
        ▼
Cloudflare Tunnel / CDN
        ├──────────────► xiaokeqing.cn       ← Hugo 静态站（前端仓库）
        └──────────────► demo.xiaokeqing.cn  ← 只读 JSON API（本仓库）
```

## 3. 五个实测数字（全部来自前端仓库 `docs/Amadeus-项目总文档-20261017.md`）

| # | 指标 | 实测值 | 出处 |
|---|---|---|---|
| 1 | 告警量级 | 24h 被分析告警 **78,130** 条（含源 IP 75,127；已定位 30,263；排除本机 44,003、内网 861） | §3 实测数字 |
| 2 | 后端单元测试 | **721** 例 / 0 失败 / 4 跳过（`mvn -o test`） | §19.2、§19.11 |
| 3 | 构建断言 | **42** 项（前端仓库 `scripts/assert-build.sh`，全过才允许发布） | §20.1 |
| 4 | 门禁 SSR 契约 | **9** 页（前端仓库 `_dev/check-ssr-contract.py`） | §20.1 |
| 5 | 隔离靶场 | **7** 台（Pikachu / DVWA / Juice Shop / WebGoat / DVNA / DSVW + WebWolf） | §19.9 |

## 4. 在线地址与只读 API

| 入口 | 地址 | 说明 |
|---|---|---|
| 主页 | <https://xiaokeqing.cn/> | 站点入口（前端仓库产物） |
| 监测中心 | <https://xiaokeqing.cn/alerts/> | 数据全部来自本仓库 `/api/public/alerts` |
| 公开端点清单 | <https://xiaokeqing.cn/api/> | 人读的端点表 + 三条 curl（不是 JSON） |
| 状态页 | <https://xiaokeqing.cn/status/> | 8 个端点逐个 PASS/FAIL、构建 SHA、耗时 |
| API 基址 | <https://demo.xiaokeqing.cn> | 本仓库唯一对外出口，只读 |

```bash
curl -s https://demo.xiaokeqing.cn/api/health | head -c 300          # 健康 + buildSha（不在 /api/public 前缀下）
curl -s https://demo.xiaokeqing.cn/api/public/home.js | head -c 400  # 首屏聚合五块：alerts+geo+honeypot+audit+health
curl -s https://demo.xiaokeqing.cn/api/public/audit | head -c 400    # 处置审计（封禁/护栏拦截/执行动作）
curl -s -o /dev/null -w '%{http_code}\n' https://lab.xiaokeqing.cn/  # 应返回 404：靶场已撤出公网，只留内网
```

口径（做不到就不写）：

- **只读**：`/api/public/*` 全部只读；高危处置要人工审批，模型不拍板。
- **靶场不对公网开放**：仅 `127.0.0.1:8081–8087` + SSH 隧道，公网域名 404。
- **取不到就如实返回**：例如蜜罐 `commandsAvailable=false`（命令数据未接入）、`app.tts.enabled` 默认 `false`（实时 TTS 默认关，不承诺在线合成）。

## 5. 本地复现（先看脚本真名，再照抄）

```bash
git clone https://github.com/xiaokeqing/SecAgent.git && cd sec-agent

# 本机（只需 JDK 17 + Maven，不需要 Docker）
mvn -o test                                    # 721 / 0 fail / 4 skip；-o 需本地依赖已缓存，否则去掉 -o
mvn -DskipTests package                        # 产出 target/*.jar
DASHSCOPE_API_KEY=sk-xxx mvn spring-boot:run    # 本机起服务，仅 127.0.0.1:9900
curl -s http://127.0.0.1:9900/api/health

# srv1（root）：先把 jar 放到 /tmp/sec-agent.jar → 构建 → 推 ACR :stable → 按 digest 指针发版
bash scripts/build-on-server.sh /tmp/sec-agent.jar <buildSha>   # 服务器侧构建 + 容器镜像 ID 硬校验，不符 exit 7
#   docker tag secagent:local <ACR>/xiaokeqing/secagent:stable && docker push <ACR>/xiaokeqing/secagent:stable
bash scripts/srv1-redeploy.sh --expect-commit <sha>             # 校验镜像 label 与 jar md5，失败自动回滚
bash scripts/deploy-chain-check.sh --json                       # 发布链体检（只读）
bash scripts/verify-public-endpoint.sh                          # 公开端点对抗性复验（只读，不触发处置）
bash scripts/healthcheck-srv1.sh                                # 必须 root
```

**不要**用 `docker compose up` 起应用，也不要走「本机构建镜像再传」那套：srv1 的 `secagent-redeploy.timer` 每 5 分钟按 ACR `:stable` 的 digest 重建，本地镜像撑不过 5 分钟就会被换回旧镜像。

## 6. 技术栈

![Java](https://img.shields.io/badge/Java-17-007396?logo=openjdk&logoColor=white)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.0-6DB33F?logo=springboot&logoColor=white)
![Spring AI](https://img.shields.io/badge/Spring%20AI-1.1.0-6DB33F)
![JUnit 5](https://img.shields.io/badge/tests-721%20passing-brightgreen)
![Docker](https://img.shields.io/badge/Docker-ACR%20digest%20deploy-2496ED?logo=docker&logoColor=white)
![Data source](https://img.shields.io/badge/data-Wazuh%20%7C%20Suricata%20%7C%20Cowrie-4B5563)
