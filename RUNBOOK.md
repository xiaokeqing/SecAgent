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

### 1.3.1 服务器连不上 GitHub 时，怎么把提交带过去（git bundle）

**这不是"绕路"，而是当前部署链里唯一被承认的补位手段。** 因为 §3 的校验是 fail-closed：
服务器拿不到目标 commit 时，任何"看起来成功"的构建/部署都不成立。所以当 `git fetch` 失败
（`fetch_state=failed`）时，就按下面这条把 commit 送到服务器，让校验重新有据可依。

```bash
# ===== 本机（有目标 commit 的那台机器）=====
cd /path/to/sec-agent
git rev-parse HEAD                                  # 记下来：这次要送过去的 commit
git bundle create /tmp/sec-agent.bundle main        # 只打 main 分支，体积小（历史 + 目标提交）
git bundle verify /tmp/sec-agent.bundle             # 打包成功自证：应打印 "The bundle is okay"
scp /tmp/sec-agent.bundle srv1:/tmp/sec-agent.bundle

# ===== srv1 =====
cd /opt/secagent
git bundle list-heads /tmp/sec-agent.bundle          # 应看到 main 指向目标 commit（先看，再取）
git fetch /tmp/sec-agent.bundle main:refs/remotes/origin/main
git reset --hard origin/main                         # 工作区对齐到目标 commit
git rev-parse HEAD                                   # 必须等于本机记下的那个 commit
git status --porcelain                               # 必须为空（有本地改动就先 stash，别硬 reset）
rm -f /tmp/sec-agent.bundle                          # 送完就删，别留垃圾
```

**为什么必须"先 verify、后 reset"**：bundle 是一个普通文件，损坏或送错分支时
`git fetch` 会在后面才报错；先 `bundle verify` / `list-heads` 能把"文件本身不对"
和"fetch 参数写错"这两类问题分开，否则现场会只剩一个含糊的 fetch 失败。

**它解开的是哪一个 fail-closed**：`scripts/build-on-server.sh`（回退路径）与
`srv1-redeploy.sh` 的硬校验闸门都要求"服务器侧/镜像侧能说出目标 commit 是什么"。
服务器源码树落后时，这个前提就不成立 —— 此时唯一诚实的动作是
**把 commit 真的带过来**（bundle），而不是放宽校验或改 `BUILD_SHA` 糊过去。

> **附录：实测命令与输出（2026-10-12，srv1）**
> ```bash
> # 本机
> $ git rev-parse HEAD
> dfeae413f5ecfd7593f31fb2616678230d850456
> $ git bundle create /tmp/sec-agent.bundle main
> Enumerating objects: 1, done.          ← 目标 commit 已在服务器上时，只需增量打包
> ...  /tmp/sec-agent.bundle  (大小数百 KB~数十 MB)
> $ git bundle verify /tmp/sec-agent.bundle
> The bundle contains this ref:  refs/heads/main
> The bundle records a complete history.
> /tmp/sec-agent.bundle is okay
> # srv1
> $ cd /opt/secagent && git bundle list-heads /tmp/sec-agent.bundle
> dfeae413f5ecfd7593f31fb2616678230d850456 refs/heads/main
> $ git fetch /tmp/sec-agent.bundle main:refs/remotes/origin/main
> $ git reset --hard origin/main && git rev-parse HEAD
> dfeae413f5ecfd7593f31fb2616678230d850456
> ```
> 注：bundle 只解决"源码/commit 到没到服务器"，**不改变**"生产构建不再在服务器上做"
> 这一目标 —— 新链里服务器只 pull 镜像，bundle 是给回退路径（服务器侧构建）和
> 指纹核对用的。

### 1.3.2 按发布指针部署（新链，推荐；完整说明见「1.5 CI 构建 + 发布指针部署」）

```bash
# 服务器每 5 分钟自动巡检；手动立即执行：
sudo systemctl start secagent-redeploy.service
# 只看判断、不动容器（演练/排障首选）：
sudo bash /opt/secagent/scripts/srv1-redeploy.sh --dry-run
# 一键回滚到 last-known-good：
sudo bash /opt/secagent/scripts/srv1-rollback.sh --dry-run   # 先看
sudo bash /opt/secagent/scripts/srv1-rollback.sh             # 再动
```

### 1.5 CI 构建 + 发布指针部署（新链，2026-10-12 落地）

> 说明：1.3.x / 1.5.x 的编号按"内容归类"排列，不是严格的行文顺序（1.4 是历史遗留的博客发布小节）。

```
GitHub（源码）
  │ push main / 打 tag / 手动触发
  ▼
GitHub Actions  .github/workflows/build-image.yml
  │  ① 构建前校验：工作区干净 + HEAD == 触发 commit（不符即中止）
  │  ② mvn test 全量 → mvn -DskipTests package
  │  ③ 解包校验 jar 内 git.properties（commit 必须 == 触发 commit、dirty=false）
  │  ④ docker build -f Dockerfile.runtime --label revision=<commit> --label artifact-md5=<md5>
  │  ⑤ 推 ACR 两个 tag：<commit短号>（不可变）与 stable（**发布指针**）
  ▼
阿里云 ACR（杭州，与 srv1 同地域走内网 VPC 地址）
  │  srv1 只读凭据
  ▼
srv1  systemd timer 每 5 分钟 → scripts/srv1-redeploy.sh
     flock 串行 → 读 stable 的 digest → 与当前运行 digest 比对（相同则安静退出）
     → docker pull <registry>/<repo>@<digest>（**不可变产物**）
     → 硬校验闸门：label revision 存在且与期望 commit 一致
     → compose 用 digest 重建 → /api/health 要求 status=ok + fingerprintMismatch=false
       + embeddedGitCommit == revision + artifactMd5 == label
     → 通过则写 /opt/secagent/last-known-good.json；不通过则回滚上一个镜像并报错退出
```

| 项 | 值 |
|---|---|
| workflow | `.github/workflows/build-image.yml` |
| 部署脚本 | `scripts/srv1-redeploy.sh`（`--dry-run` / `--tag` / `--self-test`） |
| 回滚脚本 | `scripts/srv1-rollback.sh`（读 `last-known-good.json`） |
| 定时器 | `deploy/secagent-redeploy.service` + `deploy/secagent-redeploy.timer` |
| 串行锁 | `/var/lock/secagent-deploy.lock`（flock，内核级，进程被杀自动释放） |
| 回滚点 | `/opt/secagent/last-known-good.json`（`{digest, commit, artifactMd5, deployedAt}`） |
| 留痕 | `/opt/secagent/releases/`（compose 备份 + `secagent-state.env`） |

**ACR 地址（两个，别用错）**：

```
GitHub Actions（公网）推送用 ：crpi-bhyvm4rwtqasz9y3.cn-hangzhou.personal.cr.aliyuncs.com
srv1（同地域，走内网上传/拉取）：crpi-bhyvm4rwtqasz9y3-vpc.cn-hangzhou.personal.cr.aliyuncs.com
命名空间/仓库                  ：xiaokeqing/secagent        （登录名 aliyun4512567175 主账号）
```

> ⚠️ **RAM 子账号 AK 登录个人版 ACR 实测不被接受** —— 个人版实例要的是
> 「账号名 + ACR Registry 登录密码」。CI 与 srv1 都用这一组，因此
> `srv1` 只应持有 **只读** 的 registry 密码，别把可推送的凭据放到线上服务器。

**装/查定时器**：

```bash
# 安装（root，srv1）
install -m 644 deploy/secagent-redeploy.service deploy/secagent-redeploy.timer /etc/systemd/system/ \
  && install -m 755 scripts/srv1-redeploy.sh scripts/srv1-rollback.sh /opt/secagent/scripts/ \
  && systemctl daemon-reload && systemctl enable --now secagent-redeploy.timer
systemctl list-timers secagent-redeploy.timer          # 下次触发时间
journalctl -u secagent-redeploy.service -n 100 --no-pager   # 部署历史（可审计）
```

**为什么 5 分钟一次不是浪费**：脚本是先读 digest、比对、不等才 pull，等价（no-op）时
只花一次远端 manifest 查询就退出 —— 因此它既是最长 5 分钟的发布延迟，也是每 5 分钟一次
的"线上是否就是发布指针所指产物"巡检。**发布延迟本身就是漂移检测频率。**

#### 1.5.1 演练记录（不换线上容器的安全验证方式）

```bash
# ① 纯函数自测（不需要 docker、不碰容器）
bash scripts/srv1-redeploy.sh --self-test
# ② 用任意 tag 当"指针"，只验证读取与比对判断
sudo bash /opt/secagent/scripts/srv1-redeploy.sh --tag civtest --dry-run
# ③ 并发互斥验证：第二个实例必须被 flock 挡住
sudo bash /opt/secagent/scripts/srv1-redeploy.sh --lock-timeout 0   # 立刻退出（exit 2）
# ④ 回滚脚本两种前置条件
sudo bash /opt/secagent/scripts/srv1-rollback.sh --dry-run          # 无 last-known-good 时应 fail-closed
sudo touch /opt/secagent/last-known-good.json                        # 用假文件验证解析与拒绝逻辑
```

**演练实测（2026-10-12，srv1，原样输出见交付报告）**：

| 项 | 结果 |
|---|---|
| 测试 tag 推送 | `civtest` / `civtest-decoy`（用已有的 `secagent-tunnel:local` 打 tag 推 ACR，未构建） |
| digest 读取 | `sha256:5cdfce96945f851b5b665063f6dda620df900d12f2e6a6e45efb2c2d06ff69e0`（VPC 与公网地址读到同一个 digest） |
| dry-run 判断 | 指针 `stable` → **拉不到**（ACR 里还没有这个 tag，CI 未跑过）→ 如实报错退出 1；指针 `civtest` → 判"需要部署"，退出 0，容器未动 |
| flock 并发 | 占用锁时 `--lock-timeout 0` → 立刻退出 2（耗时 0s）；`--lock-timeout 60` → 等了 10s 拿到锁后继续 |
| rollback | 无 `last-known-good.json` → 退出 3（fail-closed）；内容非法（digest 形状不对）→ 退出 3；合法 → dry-run 打印计划、退出 0（未动容器） |
| 线上容器 | 演练全程镜像 ID `sha256:1491753002e15cca619280c1a5ef340d85dfd08855a3cd66775474d413aadbd8` 未变，`Up (healthy)` |
| **测试 tag 清理** | **未能删除**（见下）——需要在 ACR 控制台手工删 |

> ⚠️ **ACR 个人版删 tag：registry API 的 DELETE 被拒**
> 实测 `DELETE /v2/<ns>/<repo>/manifests/<digest>` 返回
> `401 UNAUTHORIZED ... Action: delete`，即使显式申请 `pull,delete` / `pull,push,delete` scope 的
> Bearer token 也一样（`docker manifest rm` 同样只报 `No such manifest`，对单架构 manifest 无效）。
> 也就是说 **srv1 上这份 registry 凭据没有删 tag 的权限**（它能 push，但不能 delete）。
> 删除只能用**阿里云控制台**（容器镜像服务 → 实例 → 命名空间 `xiaokeqing` → 仓库 `secagent`
> → 版本列表 → 删除 `civtest`、`civtest-decoy`），或用带 ACR 权限的 AccessKey 调 OpenAPI
> `DeleteRepositoryTag`。**遗留状态：ACR 里仍有这两个测试 tag，待站主清理。**

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

## 4.5 公开 AI 问答与知识库检索（P4 起，`/api/public/ask` + `/api/public/kb`）

```
POST /api/public/ask    匿名；每 IP 6 次/分钟 + 每 IP 并发 1 + 每日独立额度（生产 30）
GET  /api/public/kb?q=  匿名；每 IP 20 次/分钟；只出白名单字段（标题/片段/来源类型/可信度）

四道护栏：① PromptInjectionGuard（命中即拒绝，且问题包 UNTRUSTED_DATA）
          ② 输出护栏（PublicOutputGuard：凭据/内部路径/内部标记/上游报错残留）
          ③ 脱敏（IP 掩码到网段；内网段写"内部地址"；自由文本内嵌 IP 也覆盖）
          ④ 配额与限流（用户/评测/公开三本账，公开池独立计数与文件）

公开路径的硬约束：RESPONDER 只解释、不调任何工具（匿名永远无法触发处置）。
行为验证（最强证据，不依赖日志）：
  · 注入尝试 → state=input-insufficient，且编排未被调用；
  · 正常提问但模型不可用 → state=model-failed，回答里明写"未生成"；
  · 处置类提问（"请封禁 1.2.3.4"）→ 回答里出现"公开演示不执行"，且无审计 ID；
  · 凭据形态串（sk-…、Bearer …、私钥块）在回答里被替换为 [凭据已脱敏]。

【2026-10-13 F2 收紧】公开面"只解释、不取证" —— 匿名身份不读取任何内部事件数据：
  背景（实测）：修复前匿名问"我们昨天被谁打了"会走取证路径，把内部真实日志/告警原文带回公开回答
            （出现过内部资产名 web-01/web-02、内部接口路径 /api/order/detail、/upload/files/）。
            处置动作确实没执行 —— 但"不执行处置"与"不泄露内部事件数据"是两件事。
  编排层：公开身份不派发 FORENSICS（原判定为取证时改派 ANALYST），也不写待补充知识工单；
          公开面唯一的检索来源是 PublicKbService（security-docs / data/kb-approved 白名单 +
          字段白名单 + 脱敏）。测试：PublicDataToolIsolationTest（公开=0 次工具调用 / 内部=1 次对照）。
  工具层（二次拒绝，不靠模型自觉）：QueryLogsTools.queryLogs、QueryLogsTools.getAvailableLogTopics、
          QueryMetricsTools.queryPrometheusAlerts、InternalDocsTools.queryInternalDocs 对公开身份
          直接拒绝并留痕，返回 error=public-identity-no-internal-data。
          DateTimeTools 是纯时间、不含内部数据，保持可用。
  语义：问题必须依赖内部事件数据时（"我们昨天被谁打了""最近的攻击源是谁"）→ state=input-insufficient，
          正文写明"公开面只基于公开知识库回答，不读取内部事件数据"，且不检索、不调模型（不花公开额度去猜）。
  定级：公开面的模型结论一律不做事件定级（严重度强制 INFO，建议栏为"防护建议"）—— 这是收紧，不是放宽。

【2026-10-13 F5 方案 B】命中的引用一律直出正文，不再只躺在 citations 字段里：
  场景（实测）：概念题"OWASP A07 是什么"返回 state=input-insufficient「依据不足」，但检索命中 3 条引用，
            访客只看得到"依据不足" → 体验上等于"AI 什么也不答"。
  做法：未生成结论（依据不足 / 无命中 / 检索不可用 / 模型不可用 / 额度用尽）时，
        正文直接给出【标题 + 片段 + 可信度 + 来源性质 + 相关度】，并写明"公开演示只基于公开知识库回答"；
        已生成结论时同样直出（口径一致）。说明文案同样过 PublicOutputGuard。
        测试：PublicAskCitationRenderingTest。
  边界：不放宽"对具体事件定性"的门槛（那是方案 C，明确不做）；不做分流问答（方案 A，明确不做）。
```

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
| 部署脚本报"拉取发布指针失败" | ACR 里还没有 `stable` tag（CI 一次都没跑过，或 push 步骤失败）→ `docker manifest inspect <registry>/xiaokeqing/secagent:stable` 复现；先让 CI 跑绿 |
| 部署脚本报"缺少 label ...revision" | 镜像不是 build-image.yml 推的（手推/旧的 tag）→ 只认带 `org.opencontainers.image.revision` 的产物，别绕过 |
| timer 跑了但线上没变 | `journalctl -u secagent-redeploy.service`：正常会打印"已是最新（no-op）"；若打印"无需变更"却版本旧，说明 digest 比对被骗（查容器引用是不是 digest） |
| 部署后 health 变 degraded | 查 `artifactMd5`/`embeddedGitCommit` 是否与镜像 label 一致（§1.5 的闸门会先拦，若没拦住就是脚本被绕过执行了） |

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
3. **ISM 策略体用 JSON 文件传**（`--data-binary @/tmp/p.json`），别用命令行内联引号拼 JSON ——
   嵌套引号很容易被 shell 吃掉一层，得到"能创建但内容不对"的策略。

---

## 6.6 配置版本化与恢复演练（2026-10-12 落地）

```
脚本：/usr/local/bin/config-snapshot.sh（仓库 scripts/config-snapshot.sh）
定时：/etc/cron.d/secagent-config-snapshot —— 每周日 04:10，两台机器都挂了
产物：/var/backups/secagent-config/<host>-<时间戳>.tar.gz（含 manifest.sha256，保留最近 10 份）
演练：config-snapshot.sh --drill <包>  → 解包到临时目录逐文件校验 sha256（不碰线上配置）
覆盖：ipset.conf / iptables rules.v4,v6 / 开机恢复 systemd 单元 / /etc/cron.d /
      Wazuh ossec.conf / Suricata suricata.yaml + 规则 / 三个 compose /
      /opt/secagent 的 compose+Dockerfile.runtime+DEPLOY-FINGERPRINTS / ISM 策略清单
```
**实测**：srv2 17 个文件、srv1 9 个文件，两机 `--drill` 均 `[OK] 全部文件校验通过`。

**演练脚本自身踩的两个坑**（都是"跑一次演练"才发现的）：
1. 清单条目相对 `<快照>/files` 生成，校验时必须 `cd` 到那一层，否则全部 `FAILED open or read`；
2. 清单文件本身在上一层，引用要用绝对路径，相对名会 `No such file or directory`。

> 教训：**"备份存在" ≠ "备份可用"**。不真跑一次恢复，你不会知道到底能不能恢复。

---

## 6.7 开发期额度覆盖 / 发布前回收清单（P4 起）

**为什么要有这一段**：开发期会把三个额度池临时调大，否则"改一行代码 → 重启 → 额度已用完"
会被误当成代码问题。但**调大的是上限，不是关掉配额** —— 计数器与持久化文件照旧存在，
所以万一出现死循环，仍有一条（更大的）保险丝。

三个池子与它们的计数文件（三本账互不影响）：

| 配置项 | 计数文件 | 生产值 | 开发期值 | 服务谁 |
|---|---|---|---|---|
| `app.quota.daily-limit`（`DAILY_QUOTA`） | `data/model-quota.json` | **50** | 300 | 站主 / 登录用户 |
| `app.quota.eval-daily-limit`（`APP_QUOTA_EVAL_DAILY_LIMIT`） | `data/model-quota-eval.json` | **60** | 200 | 评测身份（`app.eval.token`） |
| `app.quota.public-daily-limit`（`APP_QUOTA_PUBLIC_DAILY_LIMIT`） | `data/model-quota-public.json` | **30** | 300 | 匿名公开演示（`POST /api/public/ask`） |

### 覆盖方式（两处都要改，否则不生效）

```bash
# srv1: /opt/secagent/.env
APP_QUOTA_DAILY_LIMIT=300        # 开发期临时上限，发布前必须改回 50
APP_QUOTA_EVAL_DAILY_LIMIT=200   # 开发期临时上限，发布前必须改回 60
APP_QUOTA_PUBLIC_DAILY_LIMIT=300 # 开发期临时上限，发布前必须改回 30
```

```yaml
# srv1: /opt/secagent/docker-compose.yml（environment 段，已入库同款）
APP_QUOTA_DAILY_LIMIT: "${APP_QUOTA_DAILY_LIMIT:-50}"
APP_QUOTA_EVAL_DAILY_LIMIT: "${APP_QUOTA_EVAL_DAILY_LIMIT:-60}"
APP_QUOTA_PUBLIC_DAILY_LIMIT: "${APP_QUOTA_PUBLIC_DAILY_LIMIT:-30}"
```

> ⚠️ **为什么 .env 单独改不够**：compose 的 `SPRING_APPLICATION_JSON` 优先级**高于**环境变量绑定，
> 所以只有把值也写进那段 JSON 的插值里（`public-daily-limit:${APP_QUOTA_PUBLIC_DAILY_LIMIT:-30}`），
> `.env` 才会真正生效。否则表现是"改了 .env、重启了、上限没变"，而且**不报错**。

### 改完怎么验证（不要只看配置文件）

```bash
docker exec secagent cat data/model-quota.json          # 上限=50 时 used 到 50 就该拒
docker exec secagent cat data/model-quota-eval.json
docker exec secagent cat data/model-quota-public.json
docker exec secagent sh -c 'echo $APP_QUOTA_PUBLIC_DAILY_LIMIT'   # 容器内实际拿到的值
curl -s http://127.0.0.1:9900/api/public/ask -X POST \
  -H 'Content-Type: application/json' -d '{"question":"什么是SSH暴力破解"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["quota"])'
```

### 发布前回收清单（逐条核对，全部打勾才能对外）

```
[ ] /opt/secagent/.env 里三个 APP_QUOTA_* 改回 50 / 60 / 30，并删掉"开发期临时"注释
[ ] /opt/secagent/docker-compose.yml 的 environment 三个默认值与 .env 一致（还是 50/60/30）
[ ] docker exec secagent sh -c 'echo $APP_QUOTA_PUBLIC_DAILY_LIMIT' → 30
[ ] /api/public/ask 返回的 data.quota.limit == 30（页面上的"剩余次数"也会跟着变）
[ ] data/model-quota*.json 三个文件都在（配额机制没有被顺手关掉）
[ ] 公开端点仍然是"匿名 + 每 IP 每月 6 次限流 + 每 IP 并发 1"（改额度不该动限流）
```

---

## 7. 本次事故清单（写在这里，避免重犯）

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

---

## 8. 排障纪律（本会话新增，都是被自己的假故障教出来的）

```
① 空结果先怀疑"输入是否真的到位"，不要先怀疑被测对象
   实例：索引器聚合查询返回 0 字节，我判成"解析失败" → 真因是我把查询跑在 srv2，
   而 secagent 容器只在 srv1，docker cp 悄悄失败。
   做法：拷贝/生成输入后，先 ls -l 校验它确实在，再执行查询。

② 排障命令不许无条件吞 stderr（`2>/dev/null`）
   上面那次假故障的直接原因就是它 —— 报错被我自己藏了，于是看到"空结果"。
   做法：排查阶段保留 stderr；只有确认"预期会报错"时才静音。

③ 结论要用权威口径核对，不要用"我以为的结构"去解析
   实例：ISM 策略我用 PUT 回显的结构去解析 GET 响应，读到空 states，白折腾两轮。
   做法：能问 `explain` 就问 explain；否则 head -c 看原始 JSON。

④ 度量/工具本身也要被验证
   本会话里出错的是"尺子"而不是"被测对象"：引用溯源度量改了三次、
   安全卷判据依赖措辞、MD5 校验方法（docker cp 输出的是 tar 流）、演练脚本路径基准。
   做法：先用一个已知答案的小样例自测工具，再拿它去测系统。
```

---

## 9. Suricata 规则裁剪依据（2026-10-12 实测，裁剪动作排在 P3 演练之后）

```
规则规模：单文件 suricata.rules = 53,122 条 alert 规则 / 44 MB（suricata.yaml 只启用这一个文件）
运行模式：af-packet

24h 实际命中（wazuh-alerts-* 聚合，总数 128,443）：
  cowrie/honeypot  100,861  ｜ suricata/ids 26,959 ｜ syslog 338 ｜ pam 207 ｜ auth_success 189 ｜ sca 184
  Suricata 侧唯一在报的签名：ET INFO Python-urllib/ Suspicious（26,101 次 ≈ 该组 97%）
  蜜罐侧噪声大户：固定几个 IP 用 Go SSH 客户端高频连接（106.37.205.248 等，合计 10 万+）

裁剪原则（三条，缺一不可）：
  1) 只裁"既无历史命中、也不在 P3 演练覆盖集里"的规则 —— 先建"动作→告警"对照再裁
  2) 先降噪（聚合/抑制）而不是先删规则：蜜罐与 INFO 级签名是噪声，但它们是真实证据
  3) 裁剪前后各跑一次演练对照，**告警无遗漏**才算通过（这是本项的验收门禁）
```

---

## 10. 公开端点的运维要点（P4，2026-10-12 上线）

```
端点（匿名可访问，走 https://demo.xiaokeqing.cn，CORS 白名单含 https://xiaokeqing.cn 与 localhost:1313）：
  POST /api/public/ask   {"question":"..."}   question ≤600 字符、body ≤4000；一次性返回（非 SSE），服务端预算 20s
  GET  /api/public/kb?q=…                     q ≤200 字符

限额（三件事互相独立，别混为一谈）：
  · 每 IP 每分钟：ask 6 次 / kb 20 次      → 超限 429 + Retry-After: 60
  · 每 IP 并发：1                          → 超限 429 + reason=per-ip-concurrency-limit + Retry-After: 5
  · 每日额度：公开池（生产 30/天）          → 独立计数器 data/model-quota-public.json，绝不吃用户池与评测池

公开路径的硬约束（改动时必须保持）：
  · 绝不触发任何真实处置动作：RESPONDER 在公开身份下只解释、不调工具（有测试用调用记录桩证明公开=0 次、内部=1 次）
  · 绝不读取内部事件数据（2026-10-13 F2 收紧）：公开身份不派发 FORENSICS，且 QueryLogsTools /
    QueryMetricsTools / InternalDocsTools 在工具层对公开身份直接拒绝；公开面唯一检索来源是
    PublicKbService（白名单目录 security-docs + data/kb-approved）—— 测试 PublicDataToolIsolationTest
  · 命中引用必须直出正文（2026-10-13 F5 方案 B）：标题 + 片段 + 可信度 + "只基于公开知识库"口径，
    未生成结论时同样直出 —— 测试 PublicAskCitationRenderingTest
  · 不泄露：内网地址（→「内部地址」）、审计原文、密钥、系统提示词、上游报错详情（→「[上游错误详情已脱敏]」）
  · 回答带机读 state 与 stateLabel；模型不可用/额度用尽如实写 failureReason，禁止模板冒充
  · 检索不可用时 available:false + 空结果（不是 500）

常见现象速查：
  429 + 频率文案      → 正常限流，等 Retry-After
  429 + 并发文案      → 同一来源有请求在飞，等上一条返回
  generated=false     → 没有模型生成（看 state 与 failureReason，不要当成"系统坏了"）
  available=false     → 向量检索不可用（如实降级，不补假数据）
```

## 11. Suricata：扫描检测的"可见性"真相与误报抑制（2026-10-13 实测）

```
【结论】多端口端口扫描的"漏报"在本环境【不是规则缺口，而是可见性缺口】：
  从 srv1 对 srv2 扫 8 个端口（22/23/25/80/443/3306/8080/9200，间隔 600ms）：
    · eve.json 里只出现 port 22 的 flow —— 其余 7 个端口的 SYN 在【云安全组】就被丢弃
    · 传感器看不到的包，任何 Suricata 规则都检测不到
    · 把规则目的地址放宽成 any 后确实会触发，但命中的是 10.0.0.10 -> 169.254.0.x 的出站流量 = 误报
  因此：不再新增"低速多端口扫描"规则；SSH 层面的扫描是可见可检测的（ET SCAN sid 2001219）。

【已做】误报抑制（运维批量登录不再刷告警）：
  阈值文件（容器内 /etc/suricata/threshold.conf）：
    threshold gen_id 1, sig_id 2001219, type threshold, track by_src, count 3, seconds 10
  应用脚本：scripts/apply-suricata-scan-tuning.sh（在 srv2 上 root 执行）
    --check     只校验当前配置（suricata -T）+ 打印 rule-files
    --rollback  回滚到最近一次备份并校验
    无参数      备份 → 写阈值 → 行级插入 threshold-file → suricata -T 放行 → 热加载/重启 → 失败自动回滚

【这份 suricata.yaml 的三个坑（都踩过，已固化进脚本）】
  1) 它是【单文件 bind mount】：`sed -i` 会 "cannot rename ... Device or resource busy"，
     必须就地覆盖写（read → 改 → write 同一个文件）
  2) 配置【必须以 `%YAML 1.1` 与 `---` 两行开头】：把 threshold-file 插到最顶端会被 Suricata 拒绝
     （The configuration file must begin with the following two lines），要插在 `---` 之后
  3) rule-files 追加新项要插到【块末尾】，不能紧跟 `rule-files:` 头行（否则顺序变成新项在前）
  改完必须以 `suricata -T` 的【退出码】作为唯一放行条件（exit=0 才加载），失败立即回滚备份

【想扩大检测面】需要让更多端口对传感器可见 → 云安全组放行（属维护窗口 + 站主决策，见清单 U6）
```

## 12. 部署链一键体检（2026-10-13 新增）

```
bash /opt/secagent/scripts/deploy-chain-check.sh          # 人读；有告警时退出码 1
bash /opt/secagent/scripts/deploy-chain-check.sh --json    # 机器可读

它核对四件事：
  ① 线上指纹：/api/health 的 status / embeddedGitCommit / artifactMd5 / fingerprintMismatch
  ② 发布指针：ACR `stable` 的 label revision 与 artifact-md5，与线上比对
  ③ 自动发布：secagent-redeploy.timer 是否 active+enabled，服务最近一次 Result 与下次运行时间
  ④ 回滚能力：last-known-good.json 是否有效、回滚镜像是否拉得动（dry-run，不重启任何容器）

【2026-10-13 修掉的最后一处坏链】自动发布服务静默失败
  症状：timer 每 5 分钟失败一次，日志是 ACR `unauthorized: authentication required`；
        而人工在 shell 里执行同一个脚本却成功。
  根因：unit 里的 `ProtectHome=yes` 使服务看不见 /root → docker CLI 读不到 /root/.docker/config.json
        → 等于未登录。
  修法：保留 ProtectHome=yes，改用独立凭据目录：
        mkdir -p /etc/secagent/docker && cp /root/.docker/config.json /etc/secagent/docker/config.json
        chmod 700 /etc/secagent/docker && chmod 600 /etc/secagent/docker/config.json
        drop-in: /etc/systemd/system/secagent-redeploy.service.d/docker-config.conf
                 [Service]
                 Environment=DOCKER_CONFIG=/etc/secagent/docker
        systemctl daemon-reload
  实测：systemctl start secagent-redeploy.service → Result=success，服务自行完成
        读 digest → pull → 重建 → 硬校验 → 健康核对 → 写 last-known-good。
```

---

## 13. 健康看门狗与发布前体检（2026-10-13 新增）

### 13.1 健康看门狗：补上"部署后起来才不健康"的自动回滚

```
问题：srv1-redeploy.sh 只保证"部署动作成功"（拉取/重建/硬校验/一次健康核对）。
      若新版本【起来之后过一会儿才暴露问题】（内存泄漏、依赖失效、向量库损坏），发布流程已结束、无人处置
      —— 这条路径此前从未被验证过。

做法：scripts/srv1-health-watchdog.sh + deploy/secagent-healthwatch.{service,timer}（每 2 分钟）
  · 核对 /api/health 的 status 与 fingerprintMismatch（两者任一不对即"不健康"）
  · 连续 3 次（≈6 分钟）不健康才动手 —— 避免单次抖动触发回滚
  · 当前提交 == last-known-good 时不动（回滚无意义，只告警）
  · 30 分钟回滚冷却 —— 避免回滚风暴
  · 与 srv1-redeploy.sh 争用同一把 flock（/var/lock/secagent-deploy.lock）—— 避免"发布"与"回滚"并发操作容器
  · 计数状态保存在 /opt/secagent/releases/health-watchdog.state

用法：
  bash /opt/secagent/scripts/srv1-health-watchdog.sh --status     # 看状态与计数
  bash /opt/secagent/scripts/srv1-health-watchdog.sh --dry-run    # 只判断、只记录，不回滚
  bash /opt/secagent/scripts/srv1-health-watchdog.sh              # 真实检查（可能触发回滚）
  journalctl -u secagent-healthwatch.service -n 50 --no-pager

实测（三条路径都验过）：
  健康路径        → 「健康：OK commit=… vectors=318」退出码 0
  坏 URL 连击 3 次 → 正确输出「决定回滚：现状 commit=… → last-known-good commit=…」（--dry-run 不动作）
  systemd 单元    → Result=success；timer active/enabled

【踩坑·值得记住】探针第一次写成 `python3 - <<'PY'`，heredoc 抢占了 stdin，
  管道传进来的响应体根本没被读到 → **连健康的接口都被判成"响应不是 JSON"**，计数一路飙到 6/3。
  一个会误判的看门狗比没有看门狗更危险 —— 所以这类"会自己动手"的脚本必须先 `--dry-run` 验证判断逻辑，
  再启用 timer。修法：改用 `python3 -c`（stdin 留给管道）。
```

### 13.2 发布前体检：把"临时值必须回收"变成一条命令

```
bash /opt/secagent/scripts/preflight-release.sh              # 发布用：七项全绿才放行（有阻塞项退出码 1）
bash /opt/secagent/scripts/preflight-release.sh --allow-dev  # 开发期用：额度未回收只提示不阻塞

七项检查：
  1) 生产额度是否已回收（三处交叉验证：容器内环境变量 / /opt/secagent/.env / 公开端点回显的 quota.limit）
  2) 代码侧模板是否生产值（.env.example 必须是 50/60/30，且不得出现 sk- 前缀值 —— 否则 CI 的 gitleaks 会红）
  3) 线上指纹一致（status=ok 且 fingerprintMismatch=false）
  4) 发布指针与线上一致（ACR stable 的 label revision == 线上 embeddedGitCommit）
  5) 两个 timer 是否在工作（secagent-redeploy / secagent-healthwatch 都要 active+enabled）
  6) 回滚基准有效（last-known-good.json 存在且其镜像拉得动）
  7) 仓库工作区干净（避免"以为发布了、其实改动没提交"）

U2（回收开发期额度）的完整执行方法：
  1) 改 /opt/secagent/.env：DAILY_QUOTA 与 APP_QUOTA_* 三行改回 50 / 60 / 30
  2) 【必须】用 `sudo bash /opt/secagent/scripts/srv1-redeploy.sh` 重建容器
     （不要用 docker compose up —— 那会把容器引用从 digest 换成本地镜像，破坏不可变产物）
  3) `bash /opt/secagent/scripts/preflight-release.sh`（不带 --allow-dev）应全绿
```

### 13.3 服务器源码树会过期 —— 体检第 2 项因此误报过

```
症状：体检报「.env.example 额度不是 50/60/30」+「出现 sk- 前缀值」，
      但仓库里那份明明是好的。
根因：srv1 的源码树（/opt/secagent）停在 970a1c2（P4 那轮同步的提交），
      旧的 .env.example 正是"带 sk- 占位值 + 开发期额度"的版本 —— 报的是【服务器上的旧文件】。
修法：按 §1.3.1 用 git bundle 把服务器树同步到最新 main：
  git bundle create /tmp/secagent.bundle main           # 本地
  scp /tmp/secagent.bundle srv1:/tmp/
  cd /opt/secagent && git fetch /tmp/secagent.bundle main:refs/remotes/origin/main && git reset --hard refs/remotes/origin/main
  注意：部署状态文件（last-known-good.json、releases/、.ci-override.yml）在 .git/info/exclude 里，
       reset --hard 不会删它们（同步后已核对仍在）。
教训：凡是"检查仓库文件"的体检项，都要先确认【被检查的那份文件到底是哪一份】——
      本地工作区、服务器源码树、镜像内 jar，三者可能不是同一个版本。
```

---

## 14. 集群 yellow 的常见成因：ISM 每日历史索引（2026-10-13 实测）

```
症状：/_cluster/health 报 yellow 且 unassigned_shards=1，但 _cat/indices 里所有业务索引都是 green。
成因：ISM 插件每天新建一个内部历史索引，形如
      .opendistro-ism-managed-index-history-YYYY.MM.DD-N
      并且【带 1 个副本】—— 单节点集群上这个副本永远分不出去，于是集群常年 yellow。
      注意：即使已有 .opendistro-* 的 0 副本模板，ISM 仍可能以显式设置创建该索引（实测如此）。

定位：
  curl ... /_cat/shards?h=index,shard,prirep,state,unassigned.reason | grep -i unassign
修掉当前这个（一行）：
  curl -XPUT .../<该索引>/_settings -d '{"index":{"number_of_replicas":0}}'
预防（模板已扩充，覆盖 .kibana* / .opensearch-* / .plugins-* / .opendistro-*）：
  _template/secagent-single-node-internal → settings.index.number_of_replicas=0, auto_expand_replicas=false, order=100

【仍未根治】ISM 显式带副本创建时模板拦不住 —— 若明天又黄，按上面两条命令处理即可；
  彻底根治需要 ISM 侧配置或加一个"每日把 .opendistro-ism-* 副本置 0"的例行任务（未做，留作选项）。
```

## 15. 夜间整机体检快照（2026-10-13 01:2x，作为收尾基线）

```
应用：commit e950b5a ｜ health status=ok ｜ fingerprintMismatch=false ｜ 向量 318
发布链：ACR stable == 线上 == e950b5a ｜ 容器引用为 digest sha256:a0bc50ff… ｜ 发布服务 Result=success
定时器：secagent-redeploy.timer active/enabled ｜ secagent-healthwatch.timer active/enabled
看门狗：连续失败=0 ｜ 从未触发回滚 ｜ 当前探测健康
检测：Suricata 正常（sid 2001219 阈值抑制生效）｜ 索引全部 green ｜ 未分配分片 0
数据链路：REAL（degraded=false）；降级时如实显示"数据源不可用"并约 1 分钟内自愈
保留策略：ISM 策略 2 条（secagent-alerts-30d / secagent-stats-14d）｜ 单节点零副本模板已扩充
评测基线：/opt/secagent/eval-runs/eval-all-20261013-010745.json（commit=e950b5a，artifactMd5=7d2c4272…）
额度：用户池 1 ｜ 评测池 142 ｜ 公开池 69（date=2026-10-13；开发期上限仍为 300/200/300，发布前须回收）
公开端点：verify-public-endpoint.sh --full 13/13 通过
博客：本地 HEAD 7c1346b（八轮改版），相对 origin/main 13 文件 +925/−309，**未发布**（等站主确认）
```

---

## 16. srv2 封禁状态的重启持久化（2026-10-13 实测，两次重启验证）

### 16.1 为什么做
```
srv2 上 ipset 集合 secagent_block + 一条引用它的 DROP 规则负责"真的拦"。
2026-10-13 首次重启实测发现：**没有任何 iptables/ipset 恢复单元** →
重启后规则消失（iptables 124→116 条、引用 secagent_block 的规则 0 条），
而 SecAgent 侧仍记着"已封禁" —— 典型的"报告已封禁、实际不拦截"。
（对比：fail2ban 是 enabled/active，它自己会恢复；我们那套不会。）
```

### 16.2 两次踩坑（已固化进 unit，别再犯）
```
坑1：在 unit 里写死 `ipset create secagent_block hash:ip`，而重启前的集合类型是 hash:net
     → 类型冲突 → 整条 ExecStart 失败（unit 显示 failed）→ 规则没恢复。
坑2：重启后【应用自己】把集合建成了 hash:ip（与旧快照的 hash:net 不一致）。
结论：**集合的创建权归应用**；恢复单元只做三件事：确保存在（hash:ip + -exist）、恢复条目、确保 DROP 规则（幂等）。
快照只存【条目】(add 行)，不存 create 行。
```

### 16.3 结果（第二次重启的对照证据）
```
重启前：集合内 1 个测试条目（203.0.113.9）+ 1 条 DROP 规则
重启后：恢复单元 enabled + Result=success ｜ 集合存在(hash:ip) ｜ 条目数=1 ｜ 测试 IP 仍在 ✓
        DROP 规则 1 条 ✓ ｜ fail2ban active ✓ ｜ 五个容器全起（manager/indexer/suricata/cowrie/dashboard）✓
srv1 侧：数据链路约 1.5 分钟自愈回 REAL，health 全程 200/ok ✓
        期间首个采样是 REAL/degraded=true —— 正是 §4.5 那条"REAL 但查询失败必须如实 degraded"在生效
安装与验证命令见 deploy/srv2-netfilter-restore.service 顶部注释
```

### 16.4 顺带关掉的项：srv1 docker bridge
```
核实：容器跑在 secagent_default（bridge，非 host/none）；iptables -t nat POSTROUTING 有
      172.17/172.18/172.19/172.20 的 MASQUERADE 链；容器内可解析 wazuh-tunnel（172.20.0.3）且能出网。
结论：**"bridge 坏掉"这条已不成立**，不需要动它（早前那次绕开做法已被正确配置取代）。
```

### 16.5 维护窗口余项
```
仍待做：Suricata 规则裁剪（门禁 = 裁剪前后各跑一次演练，告警无遗漏才算通过）
仍待站主确认：诱饵端口清单与安全影响评估（见 E:\DeepSeek1\work\维护窗口与凭据轮换-执行方案-20261013.md §三）
仍待站主提供：srv1-puller（只读）RAM 子账号凭据 → 用于替换当前主账号拉取凭据（§四）
```
