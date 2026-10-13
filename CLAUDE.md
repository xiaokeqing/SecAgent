# CLAUDE.md — SecAgent（知微安全实验室 · 服务端）

> 给任何接手这个仓库的 AI/人看的"项目指令"。**先读完这一页再动手。**
> 运维真源是 `RUNBOOK.md`（§1–§25）；对外口径与全景见 `E:\DeepSeek1\work\知微安全实验室-项目全书-v3-终版.md`。

## 这是什么
自建的安全运营系统：**srv1（阿里云）= 应用/大脑**（Spring Boot 3.2 / Java 17，多智能体研判 + 处置 + 公开面），
**srv2（腾讯云）= 检测/蜜罐/索引器**（Suricata + Cowrie + Wazuh + OpenSearch）。
模型只做分析，**处置由代码规则决定**；判不出来宁可说"未生成"，绝不拿模板冒充模型。

## 硬规矩（违反就是返工）
```
1. 部署只走 CI→ACR→按 digest 重建（`scripts/srv1-redeploy.sh`）。**永远不要 `docker compose up` 应用**（会丢 digest 引用）。
2. 改服务器上任何配置：**备份 → 改 → 校验（退出码/T 测试）→ 失败自动回滚**。改 bind-mount 配置不许 `sed -i` 一把梭。
3. **结论必须有运行态证据**（命令 + 输出）。禁止"应该可以/理论上没问题"。取不到数据就如实说"未接入"。
4. **不造假数字**：没有的字段不要编，样本/回退必须显式标 degraded / mock。
5. 公开面（`/api/public/**`）**只解释、不取证**：不读内部日志/告警/资产，不展示内部标记名与正则原文；
   IP 一律掩码；字段白名单、CORS、限流、ETag 语义不许改（只许新增字段）。
6. 提交：**只 `git add` 你自己改/新增的文件**（绝不 `git add -A`）；提交信息写清范围与验证。
7. `mvn -B test` 必须全绿（当前 276 run / 0 fail / 3 skip）才谈部署。
```

## 环境事实（今天的血泪，别再踩）
```
· 服务器：`ssh secagent-srv1` / `secagent-srv2`；命令用 `sudo bash -s`（docker 需要 root）。
· **推送端点**：远端必须是 `ssh://git@ssh.github.com:443/...`。用 `git@github.com:` 在站主网络上 SSH 握手会被重置。
· **srv1 是 Alibaba Cloud Linux 3**（不是 Ubuntu）：认证日志在 `/var/log/secure`；SSH 单元叫 `sshd.service`。
· **不要在 srv1 启用 firewalld**：它与 docker0 冲突（ZONE_CONFLICT），会让 dockerd 起不来 → 全站宕机（10-13 事故）。
  防火墙职责交给云安全组 + docker 自身链。
· **`/opt/secagent/.env` 里不能出现 `{`**：docker compose 读 env_file 会解析失败 → 部署中止。
  JSON 形状的东西（如通知模板）交给 `scripts/notify-relay.py`（本机中继）处理。
· **应用在容器里，`127.0.0.1` 是容器自己**：要访问宿主机服务（如通知中继）必须用 docker 网桥网关（当前 `172.20.0.1`）。
· **Spring 组件的多构造器必须显式 `@Autowired`**，否则启动即 `No default constructor found`
  （CI 不会发现——单测直接 new；已加 `SpringBeanConstructorTest` 门禁）。
· **Suricata 重启的真实检测空窗 ≈ 41–42 秒**（不是 5–10s）；`docker exec suricata suricata -T` 在 512MiB cgroup 内有 OOM 风险，
  校验规则请用一次性独立容器。
· Windows 侧跑 `.ps1`：**必须存成 UTF-8 with BOM**，否则 PS5 把中文读成乱码报语法错；
  不要用 `$home`（只读自动变量）等保留名；PS5 不支持 `$x = if (...) {...}`。
```

## 目录速查
```
src/main/java/org/example/
  agent/      多智能体（PLANNER→ANALYST/FORENSICS→RESPONDER）+ 工具
  publicapi/  公开端点（ask/kb/overview/alerts/honeypot/audit/latest…），字段白名单与掩码在这里
  notify/     通知中枢（四类事件、分级/合并/冷却/夜间静默、未配置如实降级）
  llm/        LlmProvider（单一模型出口）+ OutboundGuard（有界等待/熔断/半开/bulkhead）
  response/   处置（规则解析）+ 审计；security/ 护栏（注入、DLP、路径穿越、掩码）
  knowledge/  RAG 检索与知识库（公开身份只能检索公开白名单）
scripts/      运维脚本（srv1-redeploy.sh / srv1-rollback.sh / 各探测与备份脚本 / notify-relay.py）
deploy/       systemd 单元与 fail2ban/wazuh 配置片段
.github/workflows/  ci.yml（测试 + gitleaks + Trivy 报告）｜ build-image.yml（建镜像 + 推 ACR）
```

## 常用验证（复制即用）
```
curl -s http://127.0.0.1:9900/api/health | python3 -m json.tool | head -20      # 健康 + 指纹
bash /opt/secagent/scripts/deploy-chain-check.sh --json                          # 部署链体检
systemctl is-active secagent-redeploy.timer secagent-healthwatch.timer secagent-notify-relay
docker logs --since 15m secagent 2>&1 | grep -c ERROR                            # 错误面
sudo bash /opt/secagent/scripts/srv1-redeploy.sh --force                         # 手工发布（幂等）
sudo bash /opt/secagent/scripts/srv1-rollback.sh                                 # 回滚到 last-known-good
```

## 现在不该做的事
```
· 不要开 firewalld ｜ 不要在 .env 里写 JSON ｜ 不要用 compose up 部署应用
· 不要为了"看起来能跑"而回退成模板/样本数据 ｜ 不要把内部资产名、规则原文、日志原文带进公开面
· 不要 `git add -A`（多人/多智能体并行时会把别人半成品一起提交）
```
