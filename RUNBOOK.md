# SecAgent 运维 Runbook

> 用途：让任何人（包括未来的我）照着这份文档就能完成**部署、评测、排障**，而不必重新踩一遍坑。
> 每条都来自真实事故，不是理论最佳实践。最后更新：2026-10-12。

---

## 0. 先记住三条铁律

```
① 结论必须有运行态证据 —— 不看日志/不查数据库/不抓转储，就不许下结论
② 静默降级比失败更危险 —— 宁可显式报错，也不许"看着成功其实没做"
③ 指纹不能只靠环境变量 —— 必须校验真实产物（见 §3）
```

---

## 1. 部署

### 1.1 推荐路径：服务器侧构建（本机不需要 Docker）

```powershell
# 本机只编译 jar（不需要 Docker Desktop、不吃本机镜像空间）
pwsh -File scripts/deploy-remote-build.ps1
# 等价手工步骤：
#   mvn -B package                              → target/sec-agent-1.0-SNAPSHOT.jar
#   scp jar → srv1:/tmp/sec-agent.jar
#   scp Dockerfile.runtime + scripts/build-on-server.sh → srv1:/opt/secagent/
#   ssh srv1 "bash /opt/secagent/scripts/build-on-server.sh /tmp/sec-agent.jar <sha>"
```

`build-on-server.sh` 会：把 jar 放到 `runtime/app.jar` → `docker build --network=host -f Dockerfile.runtime`
→ **MD5 硬校验**（镜像内 `/app/app.jar` 必须等于上传 jar）→ 写指纹 → `compose up -d --force-recreate` → 健康检查。

**为什么不能直接用 `Dockerfile`**：它是多阶段构建（`COPY pom.xml` + `COPY src` 后**在镜像内 mvn 编译**）。
服务器连不上 GitHub 时 `src/` 是旧的 → 构建出来是**旧代码**，而 `BUILD_SHA` 显示新版本号。
这就是"指纹是新的、代码是旧的"事故（见 §3）。

### 1.2 验证（每次部署必须做）

```bash
# ① 产物一致性
docker run --rm --network none --entrypoint md5sum secagent:local /app/app.jar
# ② 指纹
cat /opt/secagent/DEPLOY-FINGERPRINTS.txt          # BUILD_SHA / SOURCE_SHA / ORIGIN_MAIN_SHA / fetch_state
curl -s http://127.0.0.1:9900/api/health           # buildSha 与上面一致
# ③ 行为（最强证据）：新代码的回答里一定有 state= 行
#    旧代码的模板文本是「已命中内部安全知识库相关条目」——出现它说明部署了旧代码
```

### 1.3 回滚

```bash
# 容器级：重新构建上一个提交的 jar 并走 1.1；或
docker load -i /root/secagent-image.tar     # 上次上传的镜像（旧路径遗留）
cd /opt/secagent && export BUILD_SHA=<sha> && docker compose up -d --force-recreate secagent
```

### 1.4 博客发布（本机，需梯子）

```powershell
hugo --gc --minify --cleanDestinationDir
# 产物推到 gh-pages（force），注意 static/CNAME 与 hugo.toml 的 baseURL 都要入库
```
> ⚠️ `static/CNAME` 与 `baseURL=https://xiaokeqing.cn/` 曾"只在 gh-pages 生效、源码未提交"——
> 从源码重建会退回 github.io。发布前 `git status` 必须干净。

---

## 2. 评测（两张卷子）

```bash
# 服务器侧（推荐）：不依赖任何人的 PC
python3 /opt/secagent/scripts/eval-papers.py --paper safety    # 18 题
python3 /opt/secagent/scripts/eval-papers.py --paper quality   # 7 题（含随机 nonce 探针）
python3 /opt/secagent/scripts/eval-papers.py --paper auto      # 单号日 safety / 双号日 quality
# cron 已挂：/etc/cron.d/secagent-eval  每天 03:20，结果归档 /opt/secagent/eval-runs/
```

**用量（实测）**：一次提问 ≈ 2 次模型调用（Planner 路由 + 生成）。
安全卷 18 + 质量卷 7 = 25 次提问 ≈ **50 次调用 = 恰好一天配额**（`app.quota.daily-limit` 默认 50）。
→ 故 cron 用 `--paper auto` **单双日分卷**。要一次跑完就得调高上限。

**退出码**：`0` 正常 / `1` 安全卷门禁不过（护栏拦截率≠100%）/ `3` 本轮无效（配额耗尽、接口异常、用例数不完整）。

**读结果**：每条含 `route`（走了哪个智能体）、`state`（model / input-sufficient… 见 §4）、`latencyMs`、`promptHash`。
**判据纪律**：判据先经**人工抽检**校准，再用于指标；不许用另一个模型当裁判。

---

## 3. 指纹与产物校验（防"看得见的成功"）

| 指纹 | 含义 | 陷阱 |
|---|---|---|
| `BUILD_SHA` | 本次部署声称的版本（**环境变量**） | 只反映 env，不反映真实产物 —— 必须配合产物 MD5 |
| `SOURCE_SHA` | 服务器源码树的 revision | 服务器可能落后于 GitHub |
| `ORIGIN_MAIN_SHA` | `git fetch` 之后的远端 revision | **不先 fetch 就是拿两个陈旧值比较，等于没比** |
| `fetch_state` | `ok` / `failed` | `failed` 表示"源码是否同步**无法验证**"，如实标注 |

**产物校验方法（踩过两个坑）**：
```
✗ docker cp <cid>:/app/app.jar -    → 输出的是 tar 流，md5 必然不符
✗ docker run（默认网络）            → srv1 bridge 坏，建端点失败
✓ docker run --rm --network none --entrypoint md5sum secagent:local /app/app.jar
```

---

## 4. 运行状态语义（`state=` 机读标记）

| state | 含义 | 页面应如何呈现 |
|---|---|---|
| `model` | 模型真生成结论 | 「模型研判」 |
| `input-insufficient` | 输入缺事件要素（概念问答） | 「依据不足，不做定性」 |
| `no-retrieval` | 知识库无命中 | 「未检索到依据，不给结论」 |
| `retrieval-failed` | 检索/embedding 不可用 | 「检索不可用，未生成」 |
| `model-failed` | 模型不可用/输出未过校验 | 「模型不可用，未生成」 |
| `rule-based` | 处置走规则 + 护栏（不调模型） | 「规则解析」（**模型不参与处置拍板**） |

---

## 5. 排障速查（按症状）

| 症状 | 先查什么 |
|---|---|
| 页面数字不动 | `curl /api/public/overview` → 看 `degraded`；再看 indexer 是否有**最新时间戳**（不是"接口通不通"） |
| 请求挂很久 | 抓线程转储（`kill -3 1` → `docker logs`），看是 connect / read / 等锁；**先 jstack，别猜** |
| 请求秒回空 body | 查配额（`docker exec secagent cat data/model-quota.json`）；查是否 fetch 失败 |
| 部署后行为没变 | 查产物 MD5（§3）；确认用的是 `Dockerfile.runtime` 而不是多阶段 `Dockerfile` |
| 磁盘满 | srv2：`queue/vd_updater/tmp`（已禁用 VD，正常不再涨）；`du -xsh` 找最大目录 |
| docker build 失败 | srv1 的 bridge 网络坏了 → 用 `--network host` 构建、`--network none` 校验 |
| `git push` 失败 | 本机到 GitHub 需要梯子；`http.sslBackend=openssl` 只解决 TLS 报错，**不解决不可达** |

---

## 6. 已知缺陷与绕法（未根治）

```
· srv1 内置 bridge 网络损坏：docker0 DOWN + 网络库坏 ID。
  绕法：构建 --network host、校验 --network none。
  ★ 真正的修复要在【维护窗口】做（清 /var/lib/docker/network/files/local-kv.db 后重启 docker
    曾导致内置网络丢失、端口映射失效、9900 中断数分钟，用 compose down/up 才恢复）。
· 服务器 2 磁盘只增不减：已有 disk-guard（≥85% 自动清理）；ILM/日志轮转未做。
· 服务器 fetch GitHub 时好时坏：指纹里有 fetch_state 显式标注，不假装同步。
· 本机到 GitHub 依赖梯子。
```

---

## 6.5 索引保留策略（ISM，2026-10-12 落地）

```
集群：单节点 OpenSearch（Wazuh indexer），经 srv1 容器内 wazuh-tunnel:9200 访问
策略：secagent-alerts-30d     → wazuh-alerts-*            30 天后删除
      secagent-stats-14d      → wazuh-statistics-* / wazuh-monitoring-*   14 天后删除
两者都带 ism_template（priority 100）→ 新索引自动套用，无需人工挂
查看：curl -sk -u "$WAZUH_INDEXER_USER:$WAZUH_INDEXER_PASS" \
        https://wazuh-tunnel:9200/_plugins/_ism/explain/wazuh-*
```

**三个坑（都真踩过）**：
1. **不要把 PUT 回显的结构当成 GET 的结构** —— PUT 回显是 `policy.policy.{...}`，GET 是 `policy.{...}`。
   我按 PUT 的形状去解析 GET，读到空 `states`，误判成"策略体没被接受"，白折腾两轮。
   → 核对策略必须用 `_plugins/_ism/explain`（权威：policy_id + state）或直接 `head -c` 看原始 JSON。
2. **单节点集群的首个副本会永远无法分配** —— 表现是 `_cluster/health` 变 `yellow`、
   `_cluster/allocation/explain` 说 `same_shard: NO`。
   修法：`PUT /<index>/_settings {"index.number_of_replicas":0}`（本例是 `.opendistro-ism-config`）。
3. **ISIM 策略体用 JSON 文件传**（`--data-binary @/tmp/p.json`），别用命令行内联引号拼 JSON ——
   嵌套引号很容易被 shell 吃掉一层，得到"能创建但内容不对"的策略。



| 事故 | 根因 | 现在的防线 |
|---|---|---|
| 部署了旧代码而指纹显示新版本 | 多阶段 Dockerfile 在镜像内用服务器旧 `src/` 编译 | `Dockerfile.runtime` + 产物 MD5 硬校验 |
| 版本号变成 `unknown` | `BUILD_SHA` 来自 compose 的 `${BUILD_SHA:-unknown}`，`up` 时未 export | 脚本里 `export BUILD_SHA=...` |
| 磁盘满导致检测静默停写 | 未用的 VD 模块临时文件涨到 22GB | 禁用 VD + disk-guard + "看最新时间戳" |
| 模型不可用挂 180 秒 | SDK read timeout 180s，且 Planner 绕过了守卫 | 三处有界（15s/8s/流 deadline）+ 入口 25s 预算 |
| 配额用尽连护栏/处置一起失效 | 配额检查在控制器入口 | 配额下移到模型出口（只拦模型步骤） |
| 配额重启即清零 | 计数只在内存 | 持久化 `data/model-quota.json` |
| 评测把接口错误当模型质量问题 | 未区分 HTTP/配额错误 | 三道诚实性守卫 + 用例数完整性检查 |
| 清网络库导致服务中断 | 无窗口时动守护进程 | 铁律：动守护进程/网络必须排窗口 |
