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
          ② 输出护栏（PublicOutputGuard：凭据/内部路径/内部标记/上游报错残留/内部资产名）
          ③ 脱敏（IP 口径见 §27：默认真实来源 IP，内网/保留写"内网/未知"；
             掩码态见 §27.2 一键回退；自由文本内嵌 IP 同样覆盖）
          ④ 配额与限流（用户/评测/公开三本账，公开池独立计数与文件）

公开路径的硬约束（2026-10-14 起）：RESPONDER 只解释、不调任何工具（匿名永远无法触发处置）；
          蜜罐完整口令与内部资产名永不公开（与 IP 开关无关，见 §27.4）。
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
  GET  /api/public/overview | /api/public/alerts | /api/public/alerts/{aggId} | /api/public/honeypot | /api/public/audit
  GET  /api/public/latest                     最近一次同步/最近一条事件的聚合摘要（2026-10-13 收口，见下）

  ★ /api/public/latest 的收口（2026-10-13）：该端点此前【从未实现】，前端探测它拿到 404，
    于是页面上出现"latest 未就绪 HTTP 500 / 用 audit 替代"这类技术免责文字（那一行已从前端移走，
    但端点仍然悬空 —— 谁都可以再探一次，再造一次同样的含糊提示）。
    两条路二选一，这里选【实现】而不是删除，理由：
      · 数据全部来自既有公开白名单口径（PublicAlertSource 的掩码字段 + PublicAuditReader 的掩码记录），
        **没有新增任何内部数据面**；若将来要"最近一条的标题"，那属于扩大公开面，必须先评审再加；
      · 它省掉了以后每一次"前端想要个摘要"时的重复讨论，而删除方案要长期维护一条"不得调用"的纪律。
    出参（白名单）：generatedAt / cacheSeconds / available / reason / wazuhMode / windowSize /
      windowAlertCount / severityCounts[] / sourceCounts[] /
      latestEvent{occurredAt,severity(|Label),type(|Label),source(|Label),srcIp(掩码)} /
      latestBlock（复用 /audit 的掩码记录，只取最近 1 条）
    **刻意不含**：标题、规则名、内网目的地址与资产名、聚合 id 与成员 id、原始日志、reason 正文。
    无数据时如实 available=false + reason（machine-readable）+ note（人读）：
      · DATA_SOURCE_UNAVAILABLE —— 数据源不可达或没拿到真实数据（故障）
      · NO_DATA_IN_WINDOW      —— 数据源可用但窗口内确实没有告警（不是故障；两者混在一起会被渲染成"一切太平"）
    限流 / CORS / 掩码 / ETag / Cache-Control 与其余公开端点走同一条通路（同一个 Snapshot 缓存 + ok(...)）。
    测试：PublicApiLatestTest（字段口径 / 泄露检查 / 无数据原因）、PublicApiLatestEndpointTest（路由存在 + 信封 + 响应头）。

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
  · IP 显示口径与"永不公开"两条（2026-10-14 起，**先读 §27**）：来源 IP 按 app.public.mask-ips 显示
    （默认真实地址；内网/保留→「内网/未知」），每个响应都带 ipDisclosure；蜜罐完整口令与内部资产名
    在任何口径下都不公开 —— 改公开面之前请先看 §27.6 的"可能漏改的地方"
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
  阈值文件（容器内 /etc/suricata/threshold.conf）：  ⚠️〔2026-10-13 核实：该抑制**从未真正生效** —— threshold.conf 未被 compose 挂载且为 0 字节，详见 §17.3 未决项〕
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

---

## 17. Suricata 规则裁剪：执行与验证（2026-10-13）

### 17.1 做了什么
```
背景：单文件 suricata.rules 有 69,080 行 / 53,122 条 alert 规则（44MB），而 24h 实际只命中 1 个签名
     （ET INFO Python-urllib，约占该组 97%），加载与匹配开销白付。
动作：按 §9 的三条原则裁剪 —— 只裁"24h 无命中 + 不在演练覆盖集 + 非高危类别"的 Informational 噪声。
结果：alert 规则 42,447 条（-10,675，约 -20%）；ET INFO 类 5,341 → 1,150 条。
备份：/opt/suricata/backup/suricata.rules.bak-20261013-093222（原始 69,080 行）
候选留档：prune-candidates-*.tsv（1.1MB）/ prune-candidate-sids / prune-keep-sids
```

### 17.2 关键安全核查（我独立做的）
```
① 高危类别是否被误裁 —— 按【classtype】核（不是按消息文本搜关键词，那是错误判据，我犯过一次）：
     候选集中 classtype 分布 = bad-unknown 6553 / misc-activity 3498 / policy-violation 434 /
     external-ip-check 137 / not-suspicious 53 → 无一条属真正的 MALWARE / EXPLOIT / TROJAN / C2 规则类。
     （消息文本里出现 "Malware/Trojan/exploit" 字样的 21 条经逐条查看，全是 ET INFO/FILE_SHARING 低危规则）
② 生产唯一在响的签名是否被裁掉 —— **没有**：sid 2013031（ET INFO Python-urllib）仍在；
     另 2001219（ET SCAN SSH）/ 2002910 / 2010935 / 2001569 / 2013028 全部保留 ✓
```

### 17.3 加载与运行验证
```
2026-10-13 09:47:26 CST：重启 suricata 容器以加载裁剪后的规则（维护窗口内，已获站主批准）
  · 容器内规则 58,405 行 / alert 42,447 条 ✓
  · 解析/配置错误 0 条 ✓
  · **阳性对照**：生产里持续命中的 `ET INFO Python-urllib (sid 2013031)` 重启后照常在报
    （fast.log 01:48:51 / 01:48:56 UTC 两条，节奏与裁剪前一致）→ 裁剪未伤及在用检测 ✓
  · eve.json 持续写入 ✓
  · 实施方另做 4 次对照演练（本地轮/srv1 轮 × 旧引擎/新引擎）：基线命中集 {2228000, 2260000}
    在裁剪后**逐条复现、丢失 = 0**；indexer 侧独立复核 2013031×96｜2228000×24｜2260000×12｜2001219×1 吻合；
    裁剪后 24h 命中集合仍为 58 个且与裁剪前逐项一致。

【2026-10-13 追加·三条必须记住的事实】
  ① **真实检测空窗 ≈ 41–42 秒**（`Signal Received` → `Engine started`），不是 5–10 秒。
     本配置 console 日志关闭，`docker logs` 里看不到 "Engine started"，要以 suricata.log 时间戳为准。
     → 今后在维护窗口里重启 suricata，按 45 秒空窗规划。
  ② **不要在 512 MiB cgroup 里执行 `docker exec suricata suricata -T`**：
     那会在同一 cgroup 内再起一个 450–485 MiB 引擎，与在线引擎叠加有 OOM 风险（2026-10-13 实测侥幸未触发）。
     → 校验规则请用**一次性独立容器**（挂 rules + yaml 进去跑 `-T`），或先停在线引擎。
  ③ 09:47:15 那次"非实施方发起的 docker-API 重启"**是我做的**（为加载裁剪后的规则），非 OOM、非异常。

【未决·需站主拍板】`threshold.conf` 实际未生效：
  compose 只挂载 `etc/suricata.yaml`、`rules`、`logs` —— **threshold.conf 不在挂载之列**，
  它只是镜像层里一个 **0 字节**文件（`/etc/suricata/threshold.conf`，Oct 12 16:08）。
  也就是说 §11 记的"sid 2001219 阈值抑制"**从未真正生效**：当初只把 yaml 的 `threshold-file:` 指过去，
  没把抑制规则写进那个文件，而"文件内容"这一层当时没验（验证不完整的教训）。
  修法（若启用）：把抑制规则写到**已挂载**的目录（如 `/opt/suricata/rules/threshold.conf`），
  yaml 的 `threshold-file` 指向 `/var/lib/suricata/rules/threshold.conf`；备份 → 改 → 用**一次性容器**跑 `-T` 校验
  → 重启（按 41s 空窗）→ 确认日志 `Threshold config parsed: N rule(s) found` 的 N > 0。
  站主确认前**不动它**（与当前线上保持一致）。
```

### 17.4 代价（写清楚，别只写好的一面）
```
被裁掉的是"从不命中的 Informational 规则"，其中包含一些弱信号，例如
  · "HTTP 请求 .su TLD 常与恶意软件相关"
  · "可执行文件从 /tmp 目录提供"
  · "Windows 98/3.1 User-Agent 检出"
这些以后不再告警。取舍理由：它们 24h 从未命中，却在每次加载/匹配上都要付费；
若将来需要这类信号，可随时从 §17.1 的备份恢复（或按需只加回特定 sid）。
```

---

## 18. ⑦ 凭据轮换收口（2026-10-13，站主确认"就用这个读写的"）

### 18.1 最终状态
```
srv1 拉取凭据（两个 ACR 域名 + 服务专用凭据目录 /etc/secagent/docker/config.json）：
  用户名 = aliyun4512567175（账号名）
  密码   = ACR 控制台设的【Registry 专用固定密码】（与账号登录密码、AccessKey 都不是一回事；可单独吊销）
验证（2026-10-13 实测）：
  · 正向：docker pull stable 成功（revision 0ae03a6）
  · 部署链：systemctl start secagent-redeploy → success，health=ok，digest 指针解析正常
  · 负向：**推送成功** → 该密码是【读写】档，不是只读
回滚点：/etc/secagent/backup/docker-config-20261013-102101.json
```

### 18.2 如实记录残余风险（站主已知悉并接受）
```
· 该凭据具备 push 权限 → 若 srv1 被完全拿下，攻击者可向本仓库推送镜像（供应链风险；
  当前缓解手段是部署链的 label==commit 硬门禁 + 看门狗自动回滚，但那挡的是"跑错版本"，不挡"恶意镜像"）。
· 想彻底消除：ACR 控制台「设置固定密码」里的【只读】档，或 RAM 子账号（登录名
  srv1-puller@1770913866205593.onaliyun.com + 它自己的固定密码 + 只给 cr:GetAuthorizationToken/PullRepository）。
  2026-10-13 试过该 RAM 全名 + 站主给的密码 → 登录被拒（说明那个密码属主账号），故暂未采用。
· 另：负向测试往 ACR 推了一个测试 tag `verify-pull-only-20261013-102101`，需站主在控制台删除。
```

### 18.3 脚本加固（同批）
```
scripts/srv1-switch-acr-credential.sh：原来只在"拉取失败"时回滚；现在"推送竟然成功"也会
把服务凭据自动回滚（避免把读写凭据留在服务目录里）。教训：负向测试必须用**同名 tag**做
tag+push，否则 push 一个本地不存在的 tag 会因"tag 不存在"失败 —— 那是假失败，不是权限判定。
```

---

## 19. 通知中枢（2026-10-13 新增）

```
【它解决什么】"检测到了"和"人知道了"是两件事。告警大屏、处置护栏、看门狗自动回滚都已存在，
但人不在电脑前时这些能力等于不存在 —— 而真实攻击多数发生在没人看屏的时候。
本节的通道把四类事件推到手机，并做分级与降噪。

【触发事件（四类）】
  ① 高危告警        severity >= HIGH（CRITICAL 也走这条），由定时巡检拉取，不依赖任何页面访问
  ② 自动封禁        成功 / 失败都通知（**失败等级更高**：成功只是系统按预期工作，
                    失败意味着"该拦的没拦住"）；到期自动解封也会通知（LOW，夜间会被静默）
  ③ 系统降级        WAZUH_MODE 由 REAL 变为非 REAL（以及恢复），成对通知
  ④ 看门狗回滚      srv1-health-watchdog.sh 经本机端点触发（见下）

【通道】通用 Webhook —— Telegram / 飞书 / 钉钉 / 企业微信 / Bark / n8n 的共同点只有
  "HTTP POST 一个 JSON"，差异全在载荷形状，所以只配"地址 + 模板"，不写死某一家。

【配置（全部走 .env，见 .env.example）】
  NOTIFY_WEBHOOK_URL=            空 = 关闭。支持分流：默认=https://a|WATCHDOG_ROLLBACK=https://b
  NOTIFY_WEBHOOK_TEMPLATE=       留空 = 通用 {"text":"{{title}}\n{{body}}"}
  NOTIFY_MIN_SEVERITY=HIGH       只认英文枚举名；写错按 HIGH 处理（宁可少发，也不放宽）
  NOTIFY_COOLDOWN_SECONDS=300    同类事件冷却（按去重键，不是按标题）
  NOTIFY_NIGHT_QUIET=22:00-07:00 夜间静默，**只压 INFO/MEDIUM；HIGH/CRITICAL 照发**
  NOTIFY_SAME_IP_MERGE=600       同 IP 合并窗口；0 = 关闭合并（改由冷却去重）
  模板可用变量：{{title}} {{body}} {{severity}} {{severityLabel}} {{type}} {{typeLabel}}
                {{ip}} {{actor}} {{time}} {{count}}

【降噪规则（顺序即优先级）】
  1) 等级门槛    低于 NOTIFY_MIN_SEVERITY 的直接不发
  2) 夜间静默    窗口内只压 INFO/MEDIUM；呼救与时间无关
  3) 冷却        同一去重键 cooldown 秒内只发一次
  4) 同 IP 合并  窗口内同一来源的多类事件合成一条「聚合 N 次」；
                 **一个窗口只发一条**（否则"聚合 3 次→聚合 8 次→聚合 15 次"仍是刷屏）
  注意：带 IP 的事件先走合并（合理：同一攻击源在几分钟内刷扫描+爆破+Web 探测，对手机是"一件事"），
        不带 IP 的事件（系统降级等）才由冷却去重 —— 这也是 §19 验证里分两组演示的原因。

【未配置时的降级行为（如实，不假装）】
  · NOTIFY_WEBHOOK_URL 为空 = 功能关闭：事件<b>不出网</b>，但会
      a) 打 WARN 日志（"通知未配置…未推送"）；
      b) 往 data/notify-audit.jsonl 写一行 outcome=NOT_CONFIGURED（含事件类型/等级/掩码 IP）；
      c) 启动自检日志 OUTBOUND-TIMEOUTS-SELFCHECK 里显式打印
         notify-webhook{connect=DISABLED(通知未配置:NOTIFY_WEBHOOK_URL 为空),...}
  · 因此"手机没响"永远能在日志/审计里查到原因：未配置 / 被等级拦 / 被夜间静默 / 冷却 / 重试用尽失败。
  · 发送失败有重试（默认 3 次，指数退避），依旧失败则
      a) 审计 outcome=FAILED + attempts（谁在什么时候想通知、结果如何）；
      b) 另发一条 NOTIFY_FAILED（独立类型，**只试一次，不再重试**，避免自我放大的通知风暴）。

【出站约束（与其它链路同一套，不允许裸 OkHttp）】
  · 复用 app.outbound.* 统一超时矩阵（connect 3s / read 12s / call 15s）与 OutboundGuard
    （有界等待 + 60s 冷却 + 半开），依赖标识 notify-webhook（冷却独立，不影响 Wazuh 与处置）
  · app.notify.timeout-ms 只能把调用预算<b>收紧</b>，写大了也取统一预算（15s）
  · 启动自检里 notify-webhook 的 callTimeout 取自真正建 OkHttpClient 的传送器对象

【审计文件】
  data/notify-audit.jsonl —— 只追加的单行 JSON（通知发生在告警风暴里，写入频率高，
  用追加流水而不是"整份覆盖的 JSON 数组"）。IP 在审计里只留网段。
  文件会一直长：按需切割，例如
    logrotate 或  find /opt/secagent/data -name 'notify-audit.jsonl' -size +50M -exec truncate -s 0 {} \;
  （截断而不是删除：删掉会连"曾经通知过"的证据一起丢，而这个文件本身就是"有没有通知出去"的答案。）

【④ 看门狗回滚 → 通知（脚本侧接线）】
  端点：POST /api/notify/watchdog-rollback   body {"commitFrom":..,"commitTo":..,"reason":..,"actor":"watchdog"}
  鉴权：/api/notify/** 不在 app.auth.white-list 里 → 必须带 X-API-Token（= SECAGENT_API_TOKEN）。
        这一步不能省：若免鉴权，任何能连到 9900 的人都能伪造"系统降级/已回滚"这类高危通知。
  脚本：scripts/srv1-health-watchdog.sh 里的 notify_rollback() 已接在【三种结局】上
        （dry-run / 回滚脚本缺失 / 回滚执行后的成功与失败）；取不到 token 或没有 curl 时
        只写日志，绝不假装通知成功。dry-run 也会发，便于在不真回滚的前提下先验证链路。

【如何本地验证（不依赖真手机、不依赖公网）】
  1) 起一个本地 sink（脚本用的是标准库 http.server；用 `python3 -m http.server` 不行 ——
     它只处理 GET，收到 POST 回 501，看起来像"通知没通"，实际是 sink 选错了）：
       python3 scripts/notify-sink.py 18099
  2) 编译并运行演示程序（它把同一条链路跑一遍，逐条打印每个事件的判定结果）：
       mvn -B -o dependency:build-classpath -Dmdep.outputFile=target/cp.txt -q
       javac -encoding UTF-8 -d target/demo -cp "target/classes:$(cat target/cp.txt)" \
             src/test/resources/demo/org/example/notify/NotificationDemo.java
       java -cp "target/demo:target/classes:$(cat target/cp.txt)" \
            org.example.notify.NotificationDemo http://127.0.0.1:18099/
     （Windows 用 `;` 分隔 classpath）
  3) 实测输出（2026-10-13 本机，10 个事件）：
       第 1 组（关掉合并，单看冷却）:
         A 高危告警（HIGH，带 IP）              → SENT
         B 同一 dedupKey 第 2 次（300s 冷却内） → SUPPRESSED（reason=冷却期内）
         B 同一 dedupKey 第 3 次（300s 冷却内） → SUPPRESSED
         C 无 IP 的系统降级（HIGH）             → SENT
         D 同上降级再报一次（同键）             → SUPPRESSED
       第 2 组（同 IP 合并=600s）:
         E 同一来源第 1 条（进入合并窗口）      → MERGED
         F 同一来源第 2 条（并入）              → MERGED
         G 同一来源第 3 条（并入）              → MERGED
         （窗口汇合后实际发出 1 条："聚合 3 次 · [高危] Web 目录扫描 …"）
       第 3 组（夜间 23:30，静默 22:00-07:00）:
         H 夜间 MEDIUM 解封事件                 → SUPPRESSED（被静默）
         I 夜间 CRITICAL 看门狗回滚             → SENT（呼救不受时间影响）
       汇总：{SENT=4, SUPPRESSED=4, MERGED=3}；sink 侧实收 4 个 POST —— 4 = SENT，降噪生效。
       sink 实际收到的两个报文示例（证明发出的是合法 JSON 且变量已渲染）：
         {"text": "[高危] SSH 暴力破解尝试\n规则=5712；来源=45.83.91.12；触发=poller"}
         {"text": "聚合 3 次 · [高危] Web 目录扫描\n同一来源 198.51.100.7 在 600s 内触发 3 次：…"}
  4) 真正的告警巡检（端到端，需要真 Wazuh）：配好 URL 后看日志
       "高危告警通知：本轮提交 N 条新告警到通知中枢"  —— 且 MOCK 模式下这一轮不会推送
       （内置样本不出来发真告警：样本长得太像真的，这是本项目反复吃过的亏）。
  5) 测试门禁：mvn -B test（通知相关 6 个测试类，含"模板渲染/冷却/同 IP 合并/夜间静默/
     未配置降级/失败重试/端点契约/本地 demo 可编译"）。CI 的 unit-tests job 就是跑它。

【残余与边界（写清楚，别只写好的一面）】
  · 通知是旁路：它挂了不会让研判/处置失败（全程吞异常并记审计）。代价是"通知自己坏了"
    只体现在日志与审计里，没有第三方心跳；若要做到"通知挂了也能被发现"，
    得另做一条与主站分离的探活（未做）。
  · 巡检周期默认 60s，因此高频攻击的"第一条"通知有最多 60s 延迟；这是刻意换取的
    "不依赖页面访问"（挂在 /api/alerts/list 上会变成"没人看屏就不通知"）。
  · 同 IP 合并窗口内的第二条起不再单独发（一个窗口一条聚合）；窗口内如果攻击升级
    （MEDIUM→CRITICAL），升级信息体现在聚合正文的"最近="里，而不会另发一条。
  · 出站告警通道本身只做 HTTP POST 到运维自选的地址，应用侧不做内容加密/签名：
    webhook 的保密责任在 URL（很多 IM 把 token 写在 URL 里）与网络路径（https）上。
```
---

## 20. 外部心跳与容量告警（2026-10-13 落地，补 P0 缺口）

```
【为什么需要它（P0 缺口的准确含义）】
srv1 此前已有一套自检：secagent-redeploy.timer（发布巡检）+ secagent-healthwatch.timer（健康→回滚），
外加应用内通知中枢（§19）。但三者【都跑在 srv1 上】——
srv1 整机断电 / 云主机故障 / 内核 panic 时，它们一起死，"整机死了"这句话没有任何人能说出来。
报警者必须活在另一台机器上 → 这里用 srv2，不引第三方服务。
磁盘同理：磁盘写满是少数【必然发生且完全可预防】的故障（OpenSearch 写满会变只读、Wazuh 丢告警），
而在这之前一定有几天的高水位窗口 —— 此前没有任何东西在这个窗口里说过话。
```

### 20.1 组件与落点

```
scripts/notify.sh                      → srv1 + srv2 : /opt/secagent/scripts/
                                        服务器侧通知出口（纯 bash + curl，不依赖应用）
scripts/srv1-heartbeat.sh              → srv1         : /opt/secagent/scripts/
                                        被 srv2 SSH 过来时执行的【强制命令】，只读，输出一行 JSON 心跳
scripts/srv2-watch-srv1.sh             → srv2         : /opt/secagent/scripts/
                                        dead man switch：探 srv1 三个面，连续 3 次失败就告警
scripts/capacity-watch.sh              → srv1 + srv2  : /opt/secagent/scripts/
                                        宿主磁盘 + OpenSearch 水位 + ISM 保留期是否真的在删
scripts/srv2-gen-heartbeat-key.sh      → srv2（一次性）生成探活专用密钥
scripts/srv1-authorize-heartbeat-key.sh→ srv1（一次性）授权公钥（带 restrict + command=，含备份/校验/回滚）
deploy/secagent-srv1deadman.{service,timer}     → srv2 : 每 3 分钟跑 watch
deploy/secagent-capacity-srv{1,2}.{service,timer}→ 各自机 : 每 15 分钟跑体检

安装（unit 文件里的注释有同款命令；改配置一律备份→改→校验→失败回滚）：
  srv1: install -m 755 scripts/notify.sh scripts/srv1-heartbeat.sh scripts/capacity-watch.sh /opt/secagent/scripts/
        install -m 644 deploy/secagent-capacity-srv1.{service,timer} /etc/systemd/system/
        systemctl daemon-reload && systemctl enable --now secagent-capacity-srv1.timer
  srv2: install -m 755 scripts/notify.sh scripts/capacity-watch.sh scripts/srv2-watch-srv1.sh /opt/secagent/scripts/
        install -m 644 deploy/secagent-capacity-srv2.{service,timer} deploy/secagent-srv1deadman.{service,timer} /etc/systemd/system/
        systemctl daemon-reload && systemctl enable --now secagent-capacity-srv2.timer secagent-srv1deadman.timer
```

### 20.2 三个探测面与判定（srv2 反向盯 srv1）

```
① 应用健康：GET https://demo.xiaokeqing.cn/api/health（公网路径，等价于"外部可达性"）
             要求 HTTP 2xx 且 status=ok；顺带把 commit 记进通知正文
② SSH 连通：ssh -i /etc/secagent/heartbeat/srv1_ed25519 root@47.96.106.187:22
             私钥在 srv1 侧被 restrict,command=... 钉死为"只能读一份心跳"
③ 关键单元：从 ② 拿回的心跳 JSON 里核对
             secagent-redeploy.timer / secagent-healthwatch.timer 是否 active

判定：任一面失败 = 本轮失败；连续 3 次（timer 每 3 分钟一轮）≈ 9 分钟 → 发 HIGH。
      标题按失败面区分，【不把"单元挂了"说成"整机不可用"】：
        health+ssh 同时失败 → 「srv1 疑似整机不可用」
        只有 ssh 失败       → 「srv1 SSH 不可达」
        只有 health 失败    → 「srv1 应用健康异常（公网不可达）」
        只有 units 失败     → 「srv1 关键 systemd 单元异常」
恢复：三面皆通时发 INFO「srv1 已恢复」，正文带"不可用/降级时长"（从 down_since 算）。

状态与去重：/opt/secagent/heartbeat-state.json（state/consecutive_failures/down_since/last_alert/
failed_faces/三个面的原始 detail + 心跳原文）。一次故障只报一次；仍不恢复则每 6 小时（REALERT_SECONDS）提醒一次。
写状态用自建 JSON 转义：ssh 的 stderr 带 CR，原样写进字符串会产生【非法 JSON】（实测踩到，已修）。

【反误报的一条实测规则】部署期间 secagent-redeploy.timer 会被重启，is-active 的瞬间读到 inactive，
而它的 companion service 正在跑。这种"系统在正常工作"的瞬间若按"单元挂了"处理，每次发布都会误报整机故障。
所以：timer 非 active 时再看同名 .service；若为 active/activating/deactivating 则算 OK，
并在 detail 里写明"（部署进行中：…，timer 暂时停止，不算故障）"—— 降级可见，不隐藏。
（2026-10-13 实测到 journal 里该 timer 成对出现 Stopped/Started，因此这条不是假想。）
```

### 20.3 notify.sh 的退出码（"没发出去"必须能被区分）

```
用法：notify.sh <级别> <标题> <正文> [--key K] [--cooldown N] [--force] [--dry-run] [--config F]
  0 = 已发送            2 = 用法/模板错误（未知变量、渲染后非法 JSON → fail-closed，拒绝发送）
  3 = 未配置 NOTIFY_WEBHOOK_URL（写日志后退出，绝不假装成功）
  4 = 冷却中跳过（同键冷却期内不重复）        5 = 发送失败（curl 非 2xx/超时/连不上）
  6 = 低于最低通知级别，或被夜间静默压到阈值以下
读配置：NOTIFY_ENV_FILE → /opt/secagent/.env → /etc/secagent/notify.env → /opt/secagent/notify.env
  【解析，不 source】—— source 一个 .env 等于执行它（值里的 $(...) 会被跑），改配置不该变成执行命令。
  环境变量优先于文件（实测踩坑：默认值冒充"用户设置"把文件值挡住，导致该压制的 INFO 真发出去了，已修）。
载荷：默认模板 {"text":"{{title}}\n{{body}}"}，与 §19 应用侧同一份模板语义（一份配置可同时喂两边）。
  可用变量 title body severity severityLabel type typeLabel ip actor time count host source key level levelLabel；
  未知变量直接报错退出 2（不替换成空串）。
```

### 20.4 冷却与静默（怎么不吵、怎么彻底闭嘴）

```
冷却：notify.sh 按"键"冷却，默认 600s。键由调用方给：
  · dead man switch：srv1-down-<标题>-since-<故障起点> / srv1-recovered-since-<故障起点>
    —— 键里带"本次故障起点"是必要的：否则 10 分钟内的第二次故障会被上一次的冷却吞掉（复验实测到）。
    同一次故障内不重复告警由脚本的 last_alert_epoch 负责，不依赖 notify.sh 的冷却。
  · 容量：disk-<host>-<设备> / os-flood-<host> / os-high-<host> / os-ism-stale-<host>，冷却 21600s（6h）
夜间静默：NOTIFY_NIGHT_QUIET=22:00-07:00，NOTIFY_NIGHT_QUIET_MODE=downgrade（默认）
  downgrade = 只把级别压低一档并在正文标注［夜间静默：HIGH → MEDIUM］，消息仍发出；
  high-only = 与应用侧 NotificationService 同口径（只压制 INFO/LOW/MEDIUM，HIGH/CRITICAL 照发）；
  off = 不静默。
最低级别：NOTIFY_SERVER_MIN_SEVERITY（默认 INFO）。【刻意不复用 NOTIFY_MIN_SEVERITY】——
  应用侧默认 HIGH，若这里跟着 HIGH，"已恢复"(INFO) 这类消息会被静默吞掉。
手工静默某类告警：给它所在的 timer 停掉（systemctl disable --now secagent-capacity-srv2.timer），
  而不是清空 NOTIFY_WEBHOOK_URL —— 后者会让【所有】告警都只写日志（退出码 3）。
```

### 20.5 怎么手工触发（运维最常用的五条）

```
在 srv2 看三个面的当前结果（不改状态、不发通知）：
  bash /opt/secagent/scripts/srv2-watch-srv1.sh --status
不写状态、不改通知地查依赖与配置：
  bash /opt/secagent/scripts/srv2-watch-srv1.sh --self-test
立刻跑一轮（不等 timer）：
  systemctl start secagent-srv1deadman.service     # 退出码 0/1/2/3，看 journalctl -u secagent-srv1deadman.service
演练（不改文件就能制造失败；下列 env 会被脚本读取）：
  NOTIFY_ENV_FILE=/tmp/x.env STATE_FILE=/tmp/hb-state.json \
  SRV1_HEALTH_URL=http://127.0.0.1:9/api/health SRV1_SSH_PORT=9 FAIL_THRESHOLD=2 \
    bash /opt/secagent/scripts/srv2-watch-srv1.sh
  # 恢复：去掉上面两个 SRV1_* 覆盖，再跑一次即会发 INFO「已恢复」
看数值（不发通知）：
  bash /opt/secagent/scripts/capacity-watch.sh --no-notify      # 也可 --json
容量演练阈值（只改脚本比较，绝不改集群设置）：
  DISK_WARN_PCT=20 DISK_HIGH_PCT=90 bash .../capacity-watch.sh            # 压成 MEDIUM
  WATERMARK_FLOOD_OVERRIDE=40 bash .../capacity-watch.sh                  # 压成 flood_stage
```

### 20.6 srv2 → srv1 那把钥匙的最小权限（实测）

```
authorized_keys 条目：restrict,command="/opt/secagent/scripts/srv1-heartbeat.sh" ssh-ed25519 …
  restrict 关掉 pty/agent/X11/端口转发/~/.ssh/rc；command= 把能力钉死在"读一份只读心跳"。
  未加 from=（来源 IP）：srv2 出口 IP 一旦变动，dead man switch 会【静默失效】—— 悄悄不报警的报警器比没有更坏。
  要加就 HEARTBEAT_FROM_IP=43.143.114.79 重跑 srv1-authorize-heartbeat-key.sh（脚本会备份 + 读回校验 + 失败回滚）。
实测（2026-10-13，从 srv2 发起）：
  ssh … secagent-heartbeat → 心跳 JSON                        ✔
  ssh … id                 → 同样只得到心跳 JSON（拿不到 uid=0）✔ 强制命令生效
  ssh … 'cat /etc/shadow'  → 同样只得到心跳 JSON              ✔
  ssh … -R（远端转发）      → ssh: remote port forwarding failed（rc=255）✔
  ssh … -L 后真的往里连     → channel 1: open failed: administratively prohibited ✔
  ssh … -t（申请 pty）      → 只得到心跳 JSON                  ✔
私钥落点：/etc/secagent/heartbeat/srv1_ed25519（600，root），known_hosts 在 /var/lib/secagent/heartbeat/
  —— 因为服务以 ProtectHome=yes 跑（蜜罐机 srv2 没有理由碰 /root）。
```

### 20.7 2026-10-13 实测证据（本机与两台服务器真跑）

```
【notify.sh 十项自测】对本地 sink（scripts/notify-sink.py 18099）实跑，全部符合预期：
  未配置 URL → exit 3；正常发送 → HTTP 200；同键第二次 → exit 4；换键 → 0；
  夜间 downgrade → 发出但级别变 MEDIUM（正文带标注）；high-only 下 INFO → exit 6；
  MIN_SEVERITY=HIGH 下 INFO → exit 6；模板写错 {{titel}} → exit 2 且不发；
  正文含引号/换行/反斜杠 → 载荷仍是合法 JSON；对端不可达 → exit 5；--dry-run → 不发。
  （其中"MIN_SEVERITY=HIGH 下 INFO 却发出去了"是本次自测抓到的真 bug，已修。）

【dead man switch 制造失败→告警→恢复 全过程】sink 收到的原始 POST（节选）：
  --- srv1 疑似整机不可用（经 3 次失败触发）---
  连续 3 次探测失败（≥阈值 3，约 9 分钟），判定：整机不可用。
  失败面：health ssh units
  ① 应用健康：curl 失败(rc=7)：http://127.0.0.1:9/api/health
  ② SSH 连通：ssh rc=255 root@47.96.106.187:9 | ssh: connect to host 47.96.106.187 port 9: Connection timed out
  ③ 关键单元：SSH 不可达，无法核对单元（顺带失败）
  不可用起点：2026-10-13 11:47:02（已持续 0 分 20 秒）
  --- srv1 已恢复 ---
  srv1 三个探测面已全部恢复。不可用/降级时长：0 分 30 秒（自 2026-10-13 11:47:02）。健康详情：HTTP 200 status=ok commit=c4f3f24
  --- srv1 关键 systemd 单元异常（③ 面单独演练，标题没有错误地说成"整机不可用"）---
  失败面：units ｜ ③ 关键单元：关键单元非 active： secagent-nonexistent.timer=missing
  演练说明：三个面在演练中各失败过一次；生产节奏下 3 次之间各隔 3 分钟（≈9 分钟），
  演练里为省时间连续调用（阈值与状态机逻辑完全相同），并用 FAIL_THRESHOLD=2 复验过一次。
  【真实故障捕获（非演练）】2026-10-13 11:54:19 公网 /api/health 真的返回 HTTP 502（另一实施方改
  /opt/secagent/.env 触发 compose 重建失败，容器停在 Created）。本告警按设计触发，标题是
  「srv1 应用健康异常（公网不可达）」——【没有】误报成"整机不可用"（当时 SSH 与两个单元都正常），
  与"标题按失败面区分"的设计一致；同时它如实报告"没发出去（退出码 3）"（当时 srv2 未配 webhook）。

【容量告警四条路径 + 6 小时冷却】（srv2 真实数值上压低阈值验证，sink 实收）
  POST: 磁盘告警：VM-0-10-ubuntu 使用率 51%（MEDIUM 阈值 20%）
  POST: 磁盘告警：VM-0-10-ubuntu 使用率 51%（HIGH 阈值 20%）
  POST: OpenSearch 已达 flood_stage：VM-0-10-ubuntu 磁盘 52%（判断阈值 40%，集群现值 95%）
  POST: OpenSearch 接近水位：VM-0-10-ubuntu 磁盘 52%（判断阈值 40%，集群现值 90%；flood_stage=95%）
  再跑同一配置 → "[冷却中，未重复发送]"（21600s 内不刷屏）✔

【当前真实数值（2026-10-13 11:50，capacity-watch 原始输出）】
  srv1 宿主：/ = 31%（12.09G/40.9G，设备 /dev/vda3）；/opt/secagent = 31%【同一设备，不是独立卷】；
             /var/lib/docker = 31%。docker system df：Images 1.88GB(可回收 1.609GB)、Build Cache 1.431GB
  srv2 宿主：/ = 51%（19.8G/41.2G，设备 /dev/vda2）；/opt/secagent 与 /var/lib/docker 同为该设备
  OpenSearch（在 srv2！）：status=green，active_shards=22，unassigned=0，索引 13 个
    索引器节点 wazuh.indexer：disk.percent = 52%（disk.avail 18.6gb / disk.total 39.2gb）
    水位现值：low=85% high=90% flood_stage=95%；cluster.routing.allocation.disk.watermark.enable_for_single_data_node=false
    Top5 占用：wazuh-alerts-4.x-2026.10.12 137.2mb(211364 docs) ｜ wazuh-alerts-4.x-2026.10.13 25.2mb ｜
              wazuh-alerts-4.x-2026.10.11 24.6mb ｜ wazuh-statistics-2026.42w 1.1mb ｜
              wazuh-states-vulnerabilities-wazuh.manager 1020.6kb
    ISM 策略：secagent-alerts-30d（适用 wazuh-alerts-*，保留 30d）、
              secagent-stats-14d（适用 wazuh-statistics-*,wazuh-monitoring-*，保留 14d）
    保留期核对结果：当前没有超过保留期的索引 —— 保留策略与现状一致
    【必须知道的一条】enable_for_single_data_node=false 意味着这个单数据节点集群上磁盘水位【不生效】：
    磁盘写满时 OpenSearch 不会自动置只读/停分配，唯一的防线就是本告警。
```

### 20.8 未做 / 疑虑（如实记录，别当成已经做完）

```
1) 【最关键】srv2 上 NOTIFY_WEBHOOK_URL 尚未配置：此时 srv1 整机断电，srv2 确实会探测到并"试图报警"，
   但 notify.sh 会返回退出码 3、只把消息写进 /opt/secagent/logs/notify.log（在失联的 srv1 之外，日志是安全的），
   【手机上不会响】。所以"整机死了有人知道"这句话，在配置 webhook 之前只完成了一半。
   落地条件：在 srv2（以及 srv1）的 /opt/secagent/.env 或 /etc/secagent/notify.env 里配好
   NOTIFY_WEBHOOK_URL（0600，root），然后手工跑一次：
     bash /opt/secagent/scripts/notify.sh HIGH "通知链路自检" "看到这条说明出口通了" --force   # 期望 exit 0
2) 【与任务假设不符】OpenSearch 不在 srv1，而在 srv2 的 wazuh.indexer 容器（只监听 127.0.0.1:9200）。
   capacity-watch.sh 两台都装：srv1 上会如实打印"本机不是索引器，跳过"，真正的索引水位检查在 srv2。
   若希望在 srv1 侧也看索引水位，需要走 app 容器上的 wazuh-tunnel（本次没做，避免 exec 进应用容器）。
3) /opt/secagent 不是独立卷：srv1 上它与 / 同为 /dev/vda3，srv2 上与 / 同为 /dev/vda2。
   脚本仍单独列出（将来拆盘即自动生效），但"容器卷单独看"目前拿到的就是根盘数字，不要误以为有独立配额。
4) 检测延迟：3 次 × 3 分钟 = 最多约 9 分钟才知道 srv1 失联（外加通知出站时间）。这是刻意的抖动过滤，
   想更快就调小 timer 的 OnUnitActiveSec，代价是更容易被网络抖动触发。
5) 通知链路自身没有外部监督：只做了 srv2→srv1 一个方向。若 srv2 也整机挂了，"没人知道"的问题依旧存在
   （真正的闭环需要第三个互不相关的观测点；本次未做，也不该假装做了）。
6) 演练期间观察到 srv1 的 secagent-redeploy.timer 处于 inactive（list-timers 显示 NEXT=n/a，LAST 11:35:26），
   secagent-redeploy.service 为 failed。这不是本次改动造成的（本改动没有碰发布链），但它是"发布巡检已经不跑了"
   的真实状态 —— 需要人工确认（另有多方在并行改动同一仓库/同一台机）。
7) ISM 保留期对照依赖 python3（两台已预装；缺 python3 时脚本会如实打印"跳过"，不假装检查过）。
   另外：本告警只核对"索引是否超过其 ISM 策略保留期"，不核对 ISM 是否真的执行了 delete 动作
   （更强的做法是查 GET /_plugins/_ism/explain/<index>，本次未做）。
8) dead man switch 的 ③ 面依赖一把 SSH 钥匙；若这把钥匙被误删/被 authorized_keys 改动覆盖，
   ③ 会失败并（正确地）在 9 分钟后告警 —— 但它也可能掩盖"密码学层被改过"这件事，
   所以 srv1 侧 authorized_keys 的改动都留了带时间戳的备份，撤销命令写在脚本输出里。
9) 通知未送达时【不】记录 last_alert（"没发出去"≠"报过了"）：下一轮 3 分钟后重试，
   这样 webhook 配好之后会把仍在持续的故障立刻补发出去。代价是未配置期间每 3 分钟一行日志。
10) 【并行改动造成的事故，留档供对照，不是本节的实现】2026-10-13 11:52-11:58 srv1 全站 502：
   /opt/secagent/.env 里一行含 `{{body}}` 的 NOTIFY_WEBHOOK_TEMPLATE 让 docker compose 的 .env
   解析器报 `unexpected character "{"`，compose 重建失败并把容器留在 Created；发布链因
   `/opt/secagent/scripts/srv1-redeploy.sh` 是 644（line 385 自调用 `"$0" --rollback-to` 需要 +x）
   而回滚失败，且下一轮 timer 以"digest 相同、无需变更"安静退出 —— 于是不会自愈。
   紧接着 dockerd 也起不来：`ZONE_CONFLICT: 'docker0' already bound to a zone`（firewalld 与 docker0
   冲突，参见 §16.4"顺带关掉的项：srv1 docker bridge"）。两条都需要人工处置。
   教训（与本节直接相关）：**告警出口的配置本身也是发布链的输入** —— 往 .env 里写模板必须
   确认 `docker compose config --quiet` 仍然 rc=0，否则"加一个通知"就能把应用打下去。
11) 容量体检的 unit 【刻意不写 Requires=docker.service】（只保留 After= 排序）。理由就是第 10 条：
   dockerd 起不来的那一刻，你更需要知道磁盘还剩多少；硬依赖会让监控跟着被监控对象一起消失。
   2026-10-13 在 docker 处于 failed 的状态下实测 `systemctl start secagent-capacity-srv1.service`
   仍然成功并给出磁盘数值（这就是这个选择的验证）。
```

---

## 22. 状态异地备份 + CI 漏洞扫描 + 博客自动发布（2026-10-13 落地）

> 三件加固，都是外部评审指出、站主确认后做的。每条都带运行态证据（命令 + 真实输出）。
> **动 CI 之前先看 22.7「已知会红的地方」** —— 两个门禁接入时的第一次运行本来就是红的，
> 那是它们在正确工作，不是谁把东西弄坏了。

### 22.1 为什么 data/ 必须异地备份（P0）

```
/opt/secagent/data/ 是【唯一状态】：没有数据库、没有第二份副本。
  blocked-ips.json        封禁名单
  response-audit.json     处置审计（不可重建 —— 审计记录没法"重新生成"）
  model-quota*.json       三池额度
  还有 tool-call-audit.json / security-events.json / kb-pending.json / vector-store.json
它在 srv1 上是 bind-mount（docker-compose.yml: ./data:/app/data，rw）。
磁盘坏 / 误删 / 误 mount 覆盖 → 处置审计链直接断掉，而且回不来。
```
2026-10-13 实测规模：10 个文件、4.8 MB → tar.gz 1741565 字节。

### 22.2 备份链（通道 / 落点 / 保留 / 定时）

| 项 | 值 |
|---|---|
| 打包源 | srv1 `/opt/secagent/data` |
| 脚本 | srv1 `/opt/secagent/scripts/srv1-data-backup.sh`（仓库 `scripts/srv1-data-backup.sh`，unit 在 `deploy/`）|
| 本地暂存 | srv1 `/var/backups/secagent-data/archives/`，保留最近 3 份 |
| 异地落点 | srv2 `/opt/secagent-backup/<YYYYMMDD-HHMMSS>/`，保留最近 14 份（目录 700 / 文件 600）|
| 定时 | srv1 `srv1-data-backup.timer`，每天 03:30（`Persistent=true`，错过窗口开机补跑）|
| 手动 | `sudo systemctl start srv1-data-backup.service` —— **写入型变更（封禁/审计/额度）之后应手动跑一次** |
| 日志 | srv1 `journalctl -u srv1-data-backup.service` + `/var/log/secagent-backup/backup.log`；srv2 `/var/log/secagent-backup/receive.log` |

**通道（与最初的设想不同，必须知道）**：项目里已有的 srv1→srv2 SSH 通道是一把
**只允许端口转发**的隧道密钥 —— srv2 侧写的是 `restrict,port-forwarding,permitopen="127.0.0.1:55000"`，
它连 shell 都开不了，**根本传不了文件**。所以这里另开了一把专用密钥（而不是把隧道钥匙放宽）：

- srv1 私钥：`/root/.ssh/backup_srv2_ed25519`（注释 `secagent-backup-from-srv1`）
- srv2 授权行（`/root/.ssh/authorized_keys`）：
  `command="/usr/local/sbin/secagent-backup-receive",restrict ssh-ed25519 AAAA…secagent-backup-from-srv1`
- 这把钥匙只有三个动词：`push`（收 tar 流）/ `drill`（抽测）/ `list`（清单）
- 接收端会拒收含绝对路径或 `..` 成员的归档（那是任意写原语），也拒收白名单外的成员

2026-10-13 实测（从 srv1 出发）：
```
$ ssh -i /root/.ssh/backup_srv2_ed25519 root@<srv2> hostname
错误：命令不在白名单内：hostname（只接受 push / drill / list）          exit=64
$ ssh -i … -N -R 19999:127.0.0.1:22 root@<srv2>
Error: remote port forwarding failed for listen port 19999            exit=255
$ ssh -i … root@<srv2> list                                            exit=0   ← 白名单内的动词正常
```

**为什么"先快照再打包"**：data/ 里是活文件（容器一直在写），直接 tar 可能读到写了一半的文件，
产出一份"能解开、但内容自相矛盾"的备份 —— 那比没有备份更危险，因为它看起来是成功的。
脚本先把整树 cp 到暂存目录，再逐文件复核 sha256，对不上就重拷（最多 3 次）；
仍对不上就**失败退出、不推送**（fail-closed）。

**保留策略实测**（2026-10-13，人为造 16 份旧备份再推一份）：
```
保留策略：删除旧备份 20240101-000005 … 000001   （旧的 5 份被删）
剩余 14 份；最新的三份真实备份全部完好，sha256 复验 MATCH
```

### 22.3 恢复抽测（每收一份自动做 + 随时手动做）

抽测 = 把备份**真的解压还原一次**，比对四个量：外层 sha256、文件数、路径集合、逐文件 sha256。
只比 sha256 不够 —— "数量对了但换了个文件"也要拦下来。

```
# 收备份时 srv2 会自动抽测；抽测不过就【删掉这份备份】并让推送失败（fail-closed）
# 手动抽测（默认最新一份）—— 本节最常用的命令：
ssh secagent-srv2 "sudo /usr/local/sbin/secagent-backup-drill.sh /opt/secagent-backup/<stamp>"

# 从 srv1 触发（走备份通道的 drill 动词，不必人工登 srv2）：
ssh secagent-srv1 "sudo bash /opt/secagent/scripts/srv1-data-backup.sh --drill"

# 看两边清单 / 只打包不推送（演练）：
ssh secagent-srv1 "sudo bash /opt/secagent/scripts/srv1-data-backup.sh --status"
ssh secagent-srv1 "sudo bash /opt/secagent/scripts/srv1-data-backup.sh --dry-run"
```

2026-10-13 实测（三次备份都通过）：
```
--- 恢复抽测 20261013-112609 ---
data-20261013-112609.tar.gz: OK
文件数：manifest=10  实际解出=10
逐文件 sha256 比对：全部 OK
恢复抽测 20261013-112609：10/10 一致（文件数 10 个，内容与归档时逐字节相同）
```

### 22.4 真的出事时怎么恢复（下面每条都在 2026-10-13 实跑过）

```
# ① 确认恢复哪一份，并且【先抽测】——别拿没验证过的去覆盖线上
ssh secagent-srv2 "sudo ls -1 /opt/secagent-backup/"
ssh secagent-srv2 "sudo /usr/local/sbin/secagent-backup-drill.sh /opt/secagent-backup/<stamp>"

# ② 在 srv2 上把归档放到 ubuntu 读得到的地方
#    （备份文件是 600 root:root，直接 scp 会 exit 1 —— 这是刻意的）
ssh secagent-srv2 "sudo cp /opt/secagent-backup/<stamp>/data-<stamp>.tar.gz /opt/secagent-backup/<stamp>/data-<stamp>.tar.gz.sha256 /tmp/ && sudo chmod 644 /tmp/data-<stamp>.tar.gz*"

# ③ 取回本机（备份通道是单向"只写"的，恢复必须走运维自己的 SSH 通道）
scp secagent-srv2:/tmp/data-<stamp>.tar.gz secagent-srv2:/tmp/data-<stamp>.tar.gz.sha256 .

# ④ 传到 srv1，先验归档自身没坏
scp data-<stamp>.tar.gz data-<stamp>.tar.gz.sha256 secagent-srv1:/tmp/
ssh secagent-srv1 "cd /tmp && sudo sha256sum -c data-<stamp>.tar.gz.sha256"
#    实测输出：data-20261013-112609.tar.gz: OK

# ⑤ 【恢复前先保住现状】——恢复错了还能回来
ssh secagent-srv1 "sudo cp -a /opt/secagent/data /opt/secagent/data.before-restore-$(date +%Y%m%d-%H%M%S)"

# ⑥ 取 manifest，解压到 data 的父目录
#    （归档里带数字 uid/gid 与权限，root 解压会原样恢复）
ssh secagent-srv2 "sudo cp /opt/secagent-backup/<stamp>/manifest.sha256 /tmp/ && sudo chmod 644 /tmp/manifest.sha256"
scp secagent-srv2:/tmp/manifest.sha256 .
scp manifest.sha256 secagent-srv1:/tmp/
ssh secagent-srv1 "sudo rm -rf /opt/secagent/data && sudo tar -xzf /tmp/data-<stamp>.tar.gz -C /opt/secagent data"

# ⑦ 校验（cwd 必须是 data 的父目录：manifest 里是 data/xxx 相对路径）
ssh secagent-srv1 "cd /opt/secagent && sudo sha256sum -c /tmp/manifest.sha256"

# ⑧ 核对属主/权限（必须与原状一致，否则容器写不进去）
ssh secagent-srv1 "sudo stat -c '%n mode=%a owner=%u:%g' /opt/secagent/data /opt/secagent/data/blocked-ips.json"
#    期望：目录 mode=750 owner=999:999；文件 mode=644 owner=999:999
#    ⚠️ 999 在 srv1 上叫 systemd-coredump:input、在 srv2 上叫 lxd:input ——
#       名字不同、数字相同。所以只用数字（或直接 tar 解压），不要按名字 chown。

# ⑨ 让容器重新加载状态（会短暂中断服务，何时执行由站主定）
ssh secagent-srv1 "sudo docker restart secagent"
```

> 本会话只做了「还原到临时目录 + 逐文件比对 + 属主核对」，**没有**在线上做覆盖恢复
> （那会破坏真实状态）。⑥ 里"解压到目标父目录"这个动作是在 `/tmp/owntest` 用同一份归档
> 实跑验证的：解出来正是 `data/ mode=750 owner=999:999`、`blocked-ips.json mode=644 owner=999:999`，
> 与线上逐项吻合，manifest 校验 10/10 OK。
> 另：完整链路（srv2 解出 → scp 回本机 → scp 到 srv1）也实跑过，10/10 一致 —— 即"异地那份
> 真的能拿回 srv1"，不是只在本机自证。

### 22.5 CI 加 Trivy 漏洞扫描（Gitleaks 之外，别重复）

Gitleaks 管「凭据泄漏」，Trivy 管「依赖停在了有已知漏洞的版本上」—— 两件事，别混。
两个门禁都是 **HIGH/CRITICAL 命中即失败**：

| 位置 | 扫什么 | 怎么阻断 | 备注 |
|---|---|---|---|
| `ci.yml` → job `trivy-fs` | 仓库：Maven 依赖（pom.xml + 构建出的 jar）| `--exit-code 1` | 与既有三 job **并行**，不拉长它们的墙钟时间；漏洞库走 `actions/cache` |
| `build-image.yml` → 步骤 6.5 | **本次要发布的镜像**（OS 包 + jar 内依赖）| `--exit-code 1` | 放在推 ACR **之前**：有高危就连 ACR 都不登录（fail-closed）|

- 版本钉死 **Trivy 0.75.0**，并校验官方 tar.gz 的 **sha256**（不用 `trivy-action`，理由写在 workflow 注释里）。
- 不开 Trivy 的 secret 扫描器：gitleaks 已覆盖，重复扫只是白花 CI 时间。
- **什么级别阻断**：只有 HIGH / CRITICAL 阻断；MEDIUM / LOW 只打印、不拦。
- 2026-10-13 本机实跑（同一个 0.75.0）fs 扫描：**59 项 HIGH/CRITICAL（48 HIGH + 11 CRITICAL）**，
  全部是"有补丁"的，集中在 `tomcat-embed-core`（23）、`spring-webmvc`/`spring-webflux`/`spring-web`、
  `jackson-databind`、`spring-ai-*`。
- ⚠️ **image 扫描本机没能验证**：Trivy 第一次扫镜像必须先下载 Java DB
  （`ghcr.io/aquasecurity/trivy-java-db`），本机网络在这一步长时间卡住（35 分钟只花了 20s CPU），
  而 `--skip-java-db-update` 被 Trivy 明确拒绝（"first run cannot skip downloading Java DB"）。
  所以这一步**需要 CI 首跑验证**（GitHub runner 网络正常，预期可跑通）。

### 22.6 博客：push 自动构建发布（补上"第十轮改完没上线"的根因）

`F:\7AAA\AI\blog` 新增 `.github/workflows/deploy.yml`：
push main → 装 Hugo **0.167.0**（钉版本 + 校验 sha256）→ `hugo --gc --minify --cleanDestinationDir`
→ `bash scripts/assert-build.sh public` → 发 gh-pages。

- **为什么选 peaceiris/actions-gh-pages 而不是官方 actions/deploy-pages**：本站是**分支部署**
  （源码在 main、产物在 gh-pages —— 本来就是 `deploy.ps1` 在做的事）。官方 `actions/deploy-pages`
  要求去 Settings → Pages 把 Source 改成 "GitHub Actions"，那是一次手工改设置、改错站点直接 404；
  用 peaceiris 与现有设置**零差异**，站主不用动任何设置，CI 只是把手工作业变自动。
- `force_orphan: true`：与 `deploy.ps1` 的 `git push -f` 行为对齐，gh-pages 保持单提交。
- **断言失败就不发布**：断言在发布步骤之前，失败即 job 失败，gh-pages 保持上一次的产物。
- 断言脚本放 `scripts/assert-build.sh`（**不是** `_dev/`）：博客 `.gitignore:45` 是 `_*/`，
  `_dev/` 整个目录被忽略（`git check-ignore -v _dev/assert-build.sh` → `.gitignore:45:_*/`），
  而 git 无法"重新包含"父目录已被排除的文件 —— 放 `_dev/` 的脚本根本进不了仓库，CI 也拿不到它。

断言清单（每条对应一种真实翻车方式）：产物非空 / index.html 存在 / CNAME=xiaokeqing.cn /
sitemap.xml 含 `https://xiaokeqing.cn/` / 全站无 `localhost` / 全站无 `/api/public/latest`。

2026-10-13 本机实测（Hugo 0.167.0 构建 49 个文件）：
```
[PASS] 产物有 49 个文件
[PASS] index.html 存在（61033 字节）
[PASS] CNAME = xiaokeqing.cn
[PASS] sitemap.xml 存在且是合法 urlset
[PASS] sitemap.xml 里的基址是 https://xiaokeqing.cn/
[PASS] 没有任何文件包含 localhost
[FAIL] 有文件引用已下线的 /api/public/latest      ← 见 22.7
```
假失败验证（都实跑过，撤销后恢复原状）：塞入 `localhost` → 断言 ⑤ 拦下；
删掉 CNAME → 断言 ③ 拦下；删掉 sitemap.xml → 断言 ④ 拦下。
阳性对照：在**副本**里去掉那两处死端点引用后，**7/7 全过**（证明这道闸可通过，不是永久红）。

### 22.7 已知会红的地方（动 CI 前必看）

两处"第一次跑就是红的"，都是门禁在正确工作：

1. **Trivy fs 首次必红**：仓库当前依赖树实测 **59 项 HIGH/CRITICAL（11 CRITICAL）**，都是真问题
   （`tomcat-embed-core 10.1.16`、`spring-webflux`/`spring-webmvc 6.1.1`、`spring-ai-vector-store`、
   `fastjson 1.2.83` 等）。要么升依赖，要么由站主**显式**决定放宽口径
   （`--ignore-unfixed` / `.trivyignore`）—— 在决定之前不要偷偷加：铁律是"不许静默放过"。
2. **博客断言首次必红**：站点的「关于」页把已下线的 `/api/public/latest` 当作"未上线端点"在**探测**，
   而这个字符串进了**每一个**页面 + `js/app.js`：
   - `static/js/app.js:1886` → `['/api/public/latest', '可选端点：最近事件（未上线时主页改用 audit）'],`
   - `layouts/partials/spa-view-about.html:72` → `② 可选端点 <code>/api/public/latest</code> …`
   在这两处被删掉之前，deploy.yml 会**正确地拦住发布**（gh-pages 不更新）。删掉后本机实测 7/7 全过。

---

## 23. 2026-10-13 生产事故复盘（站点 502，约 6 分钟；含 4 个独立缺陷）

### 23.1 时间线（CST）
```
11:35   我提交通知中枢（239f36f）→ CI 全绿 → 定时器自动部署
11:35–  应用崩溃循环：UnsatisfiedDependencyException: ResponseActionService:
         No default constructor found（RestartCount 冲到 11）
11:37   healthwatch 记「不健康 1/3」；我停掉 redeploy.timer 并执行回滚 → 回到好版本 c4f3f24（短暂恢复）
11:50   我把飞书写进 .env（NOTIFY_WEBHOOK_TEMPLATE 含 JSON 大括号）→ 手工部署
11:52:40 redeploy 失败：`failed to read /opt/secagent/.env: line 74: unexpected character "{"`
         → 容器被留在 **Created**（没运行）；同一日志里回滚也失败：`srv1-redeploy.sh: line 385: Permission denied`
11:55   timer 重试却判定「digest 相同 → 无需变更」安静退出 → **站点持续 502，不自愈**
11:55– 我重启 dockerd 想恢复 iptables 链，结果 dockerd 起不来：
         `ZONE_CONFLICT: 'docker0' already bound to a zone`（firewalld 自 10-10 22:36 一直开着）
11:59  停用 firewalld → dockerd 恢复 → 重新部署 → 12:00 恢复 ok/3974a5b，公网 200
```

### 23.2 四个独立缺陷（每一个单独都足以致命）
```
① 启动崩溃（代码）：ResponseActionService / UnblockScheduler 各有两个构造器、都没标 @Autowired
   → Spring 无法选择构造器。**CI 却是绿的**（单测直接 new，不加载 Spring 上下文）。
   修：两个类显式 @Autowired；新增门禁 `SpringBeanConstructorTest`（反射扫描所有 Spring 组件，
       多构造器必须恰好一个 @Autowired）——它当场又抓出第二个类，证明这道门禁有价值。
② .env 里放 JSON（配置）：env_file 解析不认含 `{` 的值 → 整个部署失败。
   修：.env 只放简单 URL；JSON 形状与双通道交给本机中继 scripts/notify-relay.py（Python 标准库）。
③ firewalld 与 docker0 冲突（环境·潜伏 3 天）：firewalld 自 10-10 22:36 就是 active，
   dockerd 只要一重启就会因 `ZONE_CONFLICT` 起不来 —— **任何一次重启/重启机器都会全站宕机**。
   修：停用 firewalld（恢复 10-10 之前的已知可用态）；docker 26.1.3 恢复正常。
   教训：srv1 的防火墙职责交给云安全组 + docker 自身链，别再开 firewalld。
④ 发布链盲区（流程）：容器"存在但没在运行"时，脚本只看 digest 相同 → 判定"无需变更"→ **永不自愈**；
   且自动回滚因为脚本自身缺 +x（644）而失败。
   修：脚本加「必须 .State.Running==true」判定；`chmod +x` 已执行（仓库里也补说明）。
```

### 23.3 通知链路（事故直接催生的能力）
```
· 应用侧：Spring 属性是 app.notify.* → 环境变量必须写 **APP_NOTIFY_***（原 .env.example 只写了
  NOTIFY_*，等于应用侧通知从未真正开启；启动自检如实打印 DISABLED 才暴露出来）。
  现已确认真实生效：`notify-webhook{...configured(minSeverity=HIGH,cooldown=300s,nightQuiet=22:00-07:00,
  sameIpMerge=600s,maxAttempts=3,auditFile=data/notify-audit.jsonl)}`
· srv1：scripts/notify-relay.py（systemd `secagent-notify-relay`，只监听 127.0.0.1:8899）
  收应用的通用 {"text":...} → 飞书 + QQ 邮件（smtp.qq.com:465，授权码在 .env，600）。
  分级路由：含 [严重]/[CRITICAL]/[高危]/[HIGH] → 双发；其余只飞书（邮件另有 600s 冷却）。
· srv2：独立配了 NOTIFY_WEBHOOK_URL + 飞书模板（关键词 SecAgent-srv2）→ **srv1 全死时它自己发得出去**，
  实测 notify.sh HIGH ... --force → HTTP 200 / exit 0。
· 实测：飞书 sent + 邮件 sent（seq=1..4 全部两条通道成功）；非高危只飞书 ✓
```

### 23.4 这次事故的正面产物
```
· 外部心跳（srv2→srv1 dead man switch）**真的在 11:54 抓到了这次故障**并尝试告警
  （当时 srv2 未配 webhook → notify.sh 如实返回 exit 3 只写日志；现已配好）
· 启动自检把"通知未配置"从"静默失效"变成"日志里明写"，才让 ②/③ 这两处暴露
· 容器"存在但没运行"的盲区、脚本缺 +x、env_file 不能放 JSON —— 三条都写进了文档与门禁
```

---

# 24. （保留位）

本节号刻意留空：§25 是这次检索改造与 stats24h 修复的正式落点，
编号与交付说明（TODO 板 / 交接文档）一致，便于对照。**不要在本节下新增内容。**

---

## 25. 混合检索（两路召回 + RRF + 轻量重排）与 stats24h 状态语义（2026-10-13 落地）

### 25.1 一句话说清这次改了什么

```
改造前：查询 → embedding → 余弦相似度 topK（剔 <0.30）→ 直接给模型
改造后：查询 ─┬→ 稠密通道（同上，候选取 30 条）
              └→ 稀疏通道（BM25，中文按字符 bigram、英文/数字按整词切，候选取 30 条）
                     ↓
              RRF 融合（按名次，k=60）        ← 免疫两路分数不同量纲
                     ↓
              轻量重排（稀有词IDF覆盖度 / 覆盖度 / 标题 / 长度惩罚 / 字符n-gram）
                     ↓
                    topK（默认 3，与改造前一致）
```

**为什么值得做（实测数字，不是"应该更准"）** —— 同一批 28 条 query、同一份 318 条语料、
同一套判据（`docs/rag-eval/` 里三份原始输出就是它的证据）：

| 口径 | fileHit@3 | evidenceHit@3 | evidenceHit@5 | MRR(evidence) |
|---|---|---|---|---|
| 改造前（纯稠密） | 27/28 = 96.4% | 27/28 = 96.4% | 27/28 = 96.4% | 0.8690 |
| **改造后（两路+RRF+重排）** | **28/28 = 100%** | **28/28 = 100%** | **28/28 = 100%** | **0.9821** |

消融（回答"到底是谁的功劳"）：

| 配置 | fileHit@3 | evidenceHit@3 | MRR |
|---|---|---|---|
| A 纯稠密（=改造前） | 27/28=96.4% | 27/28=96.4% | 0.8690 |
| B 稠密+重排（无稀疏） | 28/28=100% | 28/28=100% | 0.9583 |
| C 稠密+稀疏→RRF（无重排） | 28/28=100% | 28/28=100% | 0.9821 |
| D 稠密+稀疏+RRF+重排（默认） | 28/28=100% | 28/28=100% | 0.9821 |
| E 纯稀疏（BM25 单路） | 28/28=100% | 28/28=100% | 0.9583 |

**如实说明（不许省）**：
- `@3` 三项在 B/C/D/E 都到顶了，**能区分的只有 MRR**；28 条样本上
  "96.4% → 100%"就是 1 条 query 的差别，**不要当成"显著提升"**（Wilson 95% 区间在这个 n 下很宽）。
- 重排与稀疏各自都能把 MRR 推上去，**D 相对 C 的 +0.0000 说明重排在稀疏已经召回对的情况下
  没有再加分**；也就是说这份评测集测不出"重排的独立收益上限"。
- 稀疏单路（E）在本集上 fileHit@3 = 100% 是**评测集局限**造成的：期望关键词取自语料原文，
  与查询用词高度重合，天然对 BM25 有利（详见 25.5）。
- 重排是**词袋级统计**，不是 Cross-Encoder（差距见 25.5）。

### 25.2 参数（都在 `app.rag.*`，全部可不填；`.env.example` 里列了同一份）

| 环境变量 | 配置项 | 默认 | 含义 |
|---|---|---|---|
| `APP_RAG_SPARSE_ENABLED` | `app.rag.sparse.enabled` | `true` | 稀疏（BM25）通道开关 |
| `APP_RAG_RRF_K` | `app.rag.rrf.k` | `60` | RRF 的 k：越小越看重头部名次 |
| `APP_RAG_RERANK_ENABLED` | `app.rag.rerank.enabled` | `true` | 轻量重排开关 |
| `APP_RAG_TOP_K` | `app.rag.top-k` | `3` | 给模型的片段数（老键 `rag.top-k` 仍生效） |
| `APP_RAG_MIN_SCORE` | `app.rag.min-score` | `0.30` | 稠密相似度门槛（老键 `rag.min-score` 仍生效） |

代码内还有一批默认值（不打算暴露成环境变量，真要调就改 `RagProperties`）：
`candidateK=30`（两路各取多少进融合）、`sparseK1=1.2` / `sparseB=0.75`（BM25 标准值）、
`sparseLatinTrigram=true`、`rerankWeightRareCoverage=0.45` / `Coverage=0.25` / `Title=0.15` /
`Length=0.10` / `Bigram=0.05`、`rerankBothChannelBoost=0.05`、`rerankLengthRefChars=400`。

⚠️ **两个必须记住的坑**：
1. 只在 `.env` 里加一行 `APP_RAG_*` **不会生效**：`docker-compose.yml` 的 `environment:`
   段是显式透传的（同 `APP_QUOTA_*` 那个坑）。改配置要同时确认 compose 里有对应透传行
   —— 那几行已经加好了（`docker-compose.yml` 的"混合检索参数"段）。
2. `minScore` 只管**稠密通道**。只被 BM25 命中的片段（语义上与查询正交但没有它出现的词）
   **会**进入结果 —— 这是混合检索的定义，不是泄漏。实测例子：
   查询"CWE-918 的 SSRF 内部处置手册"里，一篇只含"漏洞/防御"的公开文档会以词面证据入选。
   如果哪天需要"必须语义也像"的严格口径，那要用 `APP_RAG_SPARSE_ENABLED=false`。

### 25.3 怎么复跑评测（离线、零费用、可重复）

```bash
# ① 门禁：28 条回归集 + 组件单测（CI 里跑的就是这条）
mvn -B test
#    新增的门禁测试：
#      org.example.rag.RagRetrievalRegressionTest        （28 条逐条 + 整体门槛 + 口径断言 + 回退一致性）
#      org.example.rag.RagRetrievalComponentsTest        （分词/BM25/RRF/重排的方向性断言）
#      org.example.publicapi.PublicKbVisibilityIsolationTest （可见性隔离安全不变量）

# ② 改前/改后对比（打印对照表，不需要任何 Key、不联网）
mvn -q -B test-compile
mvn -q -B dependency:build-classpath -Dmdep.outputFile=target/cp.txt -Dmdep.includeScope=test
java -cp "target/classes;target/test-classes;$(cat target/cp.txt)" \
     org.example.rag.RagRetrievalEvalMain --mode both      # 改前 vs 改后 + 逐条差异
java -cp "..." org.example.rag.RagRetrievalEvalMain --mode ablation   # A/B/C/D/E 消融
java -cp "..." org.example.rag.RagRetrievalEvalMain --trace q11       # 单条逐信号追踪（排障用）

# ③ 落档：把 ② 的输出写进 docs/rag-eval/（这三份就是上面那张表）
#      baseline-dense-only.txt   改前
#      after-hybrid-both.txt     改后 + 对照表
#      ablation.txt              A/B/C/D/E 消融
#    ⚠️ 放在 docs/ 而不是 scripts/rag-eval/out/：`.gitignore` 有 `out/` 规则（构建产物），
#       放 out/ 下不会入库，RUNBOOK 引用的证据文件就会"找不到"。

# ④ 查询集变了（增删 query / 改期望关键词）→ 必须重新生成查询向量，否则向量与查询对不上
python3 scripts/rag-eval/build-query-fixture.py            # 需要 .env 里有真实 DASHSCOPE_API_KEY
python3 scripts/rag-eval/build-query-fixture.py --dry-run  # 只自检期望可达性，不调接口
#    ⚠️ 换 embedding 模型（dashscope.embedding.model）后同样必须重跑
```

### 25.4 怎么回退纯稠密（一条配置，不改代码、不重新部署）

```bash
# srv1: /opt/secagent/.env
APP_RAG_SPARSE_ENABLED=false
APP_RAG_RERANK_ENABLED=false
# 然后重启容器（compose 的透传行已就位）
cd /opt/secagent && docker compose up -d
# 核对生效：启动日志里应出现
#   混合检索参数：稀疏=false ... 重排=false ...
#   检索链路就绪：... 稀疏语料来源=InMemoryVectorStoreGateway
```

回退**不会**改变排序口径 —— `RagRetrievalRegressionTest#denseOnlyFallbackMatchesLegacyOrdering`
会逐条比对"两个开关关掉后"与"改造前算法"的 top-3 列表，必须完全一致；
门禁跑红说明回退路径被改坏了，**这时候不许上线**。

### 25.5 已知局限（如实列，别让"CI 全绿"被读成"检索有保障"）

```
· 重排不是 Cross-Encoder：四个信号都是词袋统计量，读不出"限定词修饰的是哪个成分"这类交互。
  它的收益主要来自【纠名次】（把 RRF 里靠后的精确命中提到前面），补不回"两路都没召回的漏检"。
  代价换来的是常数级 CPU —— 本项目要能在 2C2G 小机上跑，所以没上模型重排。
· 重排的四个权重是在【这 28 条 query】上人工定档的，没有交叉验证 → 有 overfit 风险。
  换语料/换域名后应当重新跑 --mode ablation 再定，不要照抄这几个数字。
· 中文分词是字符 bigram，没有词典/句法：它会把"路径穿越"与"穿越路径"当近似词袋，
  也会让"的/了"这类高频字参与打分（由 IDF 自然压低）。需要词性/依存才能区分的语义差别它做不到。
· 评测夹具 28 条、集中在安全知识这一域，且期望关键词取自语料原文（对词面检索有利）。
  它测的是"能不能找到已知的正确答案"，**测不出**"问语料里根本没有的东西会不会硬答"
  （后者由拒答阈值与评测卷覆盖）。
· 本地 `mvn -B test` 与 CI 都是离线跑缓存向量：量的不是"线上 embedding 接口当次返回什么"。
```

### 25.6 `alerts.stats24h` 的状态语义（2026-10-13 修复冷启动抖动）

**现象**：同一 URL 连续请求，`stats24h.available` 在 true/false 之间交替，博客 Hero 第一个数字跟着抖。

**根因（两个确定性缺陷，不是网络随机）**：
```
① 查询路径把一个"每 60s 才异步刷新"的可用性标记当查询前提：
   `if (!available) return {available:false}` —— 标记为假时**根本不查**。
   而 docker compose up -d 会同时重启隧道与应用，隧道要 30+ 秒才连上，
   启动那次探测必然失败 → 从进程起来到下一次重探（最长 60s）之间，
   每个缓存过期的请求都在说"数据源不可用"，而 indexer 其实早就绪了。
② 查询失败与"查询成功但 24h 内 0 条"返回的是同一个 {available:false}，
   前端无法区分"我们坏了"与"这段时间太平"。
```

**修完之后的语义（`available` 口径不变，只新增字段 —— 公开 API 契约只增不改）**：

| `state` | `available` | 含义 | 前端应当 |
|---|---|---|---|
| `ok` | true | 查询成功且有数据 | 正常显示数字 |
| `no_data` | true | **查询成功**，24h 内确实 0 条 | 显示 0（这是真实结果） |
| `degraded` | false | 对端可达，但这次查询失败（`reason=QUERY_FAILED` / `CLIENT_NOT_READY`） | 显示降级 + 稍后重试 |
| `warming` | false | 链路尚未就绪（隧道/鉴权在建立，或熔断冷却中）`reason=DATA_SOURCE_WARMING` | 显示"正在预热"+重试，**不要报故障** |

另有两条自愈行为：**查询成功会把进程内的可用性标记扶正**（不必等下一次重探）；
`degraded`/`warming` 由"现场探测一次"区分（探测过 = degraded，探测不过 = warming）。

**修前/修后 10 次连续请求的 available 序列**（`WazuhSummary24hColdStartTest`，假 indexer 夹具）：

```
前置状态：available 字段 = false（模拟"启动探测失败、尚未重探"），但 indexer 已就绪
修复前： [false, false, false, false, false, false, false, false, false, false]   ← 标记永不被扶正
修复后： [true,  true,  true,  true,  true,  true,  true,  true,  true,  true ]   ← 首个请求即真值
链路真没起来时（探测也失败）：state 序列 = warming, warming, degraded, ok, ok, ok
                              available 序列 = false, false, false, true, true, true（单调朝好，无回抖）
```

**怎么用**：
```bash
curl -s http://127.0.0.1:9900/api/public/alerts | python3 -m json.tool | grep -A3 stats24hState
# 期望： "stats24hState": "ok" / "no_data" / "warming" / "degraded"
# 排查"数字在抖"时先看 state：如果一直是 ok 而数字还在变，那才是数据本身在变。
```

---

## 24. 应用侧访问日志与 Web 攻击检测（2026-10-13 落地）

> 补的是 §21.2 第 1 条那个"明确看不见"的洞：
> `Spring 不记未匹配路由` → `/wp-login.php`、`/.env`、`/../../etc/passwd`
> 这些 **URL 级扫描**在应用里"一行都不记"，返回 404 且日志无痕，
> 于是 srv1 上的 fail2ban / Wazuh 对这类攻击**完全瞎**（不是没配，是没有数据源）。
> 这一节写清楚：日志记什么、怎么轮转、两个 jail 怎么判、怎么临时关、封禁到底挡得住谁。
> ⚠️ 本文档在 srv1 上还缺 §21（那个版本只存在于 `/opt/secagent` 的未提交改动里），
> 本节凡引用 §21.x 的地方，请对着 `srv1:/opt/secagent/RUNBOOK.md` 看。

### 24.1 一行日志里有什么（字段白名单，顺序固定）

落盘：容器内 `data/access.jsonl` = 宿主 `/opt/secagent/data/access.jsonl`（compose 已挂载、§22 已纳入备份）。

```json
{"ts":"2026-10-13T20:43:44.253+08:00","method":"GET","path":"/wp-login.php","queryKeys":"","status":404,"clientIp":"198.51.100.9","ua":"wazuh-evidence/1.0","ms":3,"reqId":"1a1354a4cfd-c-af36"}
```

| 字段 | 语义 | 边界 |
|---|---|---|
| `ts` | 请求开始时间，ISO-8601 带时区 | **只到毫秒**（纳秒会让 fail2ban 的日期模板解析失败） |
| `method` | HTTP 方法 | 截断 16 字符 |
| `path` | **只有 path，没有查询串** | 截断 512 字符，控制字符替换成空格 |
| `queryKeys` | **只有查询键名**（逗号分隔，≤8 个，每个 ≤32 字符） | **查询值永不落盘** |
| `status` | 响应状态码（含 2xx/3xx/4xx/5xx 全记） | 2xx/3xx 也记，为了看"扫到了什么真的存在" |
| `clientIp` | 优先 `CF-Connecting-IP`，否则 `remoteAddr` | 必须是**合法 IP 字面量**，否则回落（见 24.6） |
| `ua` | User-Agent | 截断 200 字符，控制字符替换 |
| `ms` | 处理耗时（毫秒） | 异步写，不含写盘时间 |
| `reqId` | 本次请求关联 id | 目前只在本日志里，未进响应头/未进应用日志（见 24.7） |

**刻意不记**：请求体、查询串原文、Cookie、Authorization、Referer、响应体、原始 header 全集。
理由：这个文件会长期驻留、被 fail2ban/Wazuh 反复读、出事时可能被人打包带走排障 ——
里面出现凭据或用户数据就是二次泄露。
`AccessLogFilterTest` 对上述每一项都放了**哨兵值**断言，谁以后顺手多记一个字段，测试当场变红。

### 24.2 采样与容量

```
采样      ：全部记（含 2xx/3xx/4xx/5xx），只按 skip-paths 排除 —— 默认跳过 /api/health
            （容器 healthcheck 每 30 秒一次 = 一天 2880 行纯噪声）。
轮转      ：活动文件固定叫 access.jsonl（fail2ban/Wazuh 指的就是它，路径不许漂）；
            跨天 或 单文件超过 app.accesslog.max-file-mb（默认 64MB）→ 改名成
            access-<yyyyMMdd-HHmmss>.jsonl，再建新的活动文件。
保留      ：app.accesslog.retain-days（默认 7）天，按 mtime 删除更老的切分文件；
            活动文件永不删。容量上限 ≈ 7 × 64MB = 448MB（实测远低于此）。
写入      ：请求线程只入队（有界队列 8192），I/O 在独立写线程 secagent-accesslog-writer 上，
            每批 flush —— 这样 fail2ban/Wazuh 读到的延迟是秒级，而请求线程不做磁盘 I/O
            （§23 的教训：请求路径上做 I/O = 整站 502）。
写不出去时：队列满 → 丢弃该条 + 节流 WARN + 计数；写盘异常 → 计数 + 节流 WARN + 关句柄重开。
            **绝不阻塞请求线程，也绝不静默**（WARN 每 30 秒最多一条，带累计丢弃数）。
```

配置项（`.env.example` 有注释；键名不要留空，空串绑 boolean/int 会让应用起不来）：

| 键 | 默认 | 说明 |
|---|---|---|
| `APP_ACCESSLOG_ENABLED` | `true` | false 时启动日志明写 `ACCESSLOG DISABLED`（关闭可见，不静默） |
| `APP_ACCESSLOG_DIR` | `data` | 容器内目录；宿主是 `/opt/secagent/data` |
| `APP_ACCESSLOG_RETAIN_DAYS` | `7` | 保留天数（0 = 不清理） |
| `APP_ACCESSLOG_MAX_FILE_MB` | `64` | 单文件上限 |
| `APP_ACCESSLOG_SKIP_PATHS` | `/api/health` | 逗号分隔；`*` 结尾 = 前缀匹配 |

> 与 `APP_QUOTA_*` 不同：这里**不需要**在 `docker-compose.yml` 里显式透传 ——
> compose 的 `SPRING_APPLICATION_JSON` 没有覆盖 `app.accesslog.*`，env_file 里的键会正常生效。

### 24.3 fail2ban：两个 jail（srv1）

装机脚本：`scripts/srv1-fail2ban-webscan.sh`（`--plan/--apply/--status/--verify/--rollback`）。

| jail | 判据 | 阈值 | 动作 |
|---|---|---|---|
| `secagent-webscan` | 访问日志里 path 命中已知恶意路径（wp-login/.env/.git/phpmyadmin/穿越形态…） | 10 分钟内 2 次 → 封 4h | `iptables-allports[chain=INPUT]` |
| `secagent-webscan-4xx` | 单 IP 4xx 密度 | 2 分钟内 40 次 → 封 1h | 同上 |

- 来源：`/opt/secagent/data/access.jsonl`（**直接读 JSONL**，不复用 §21 的 app.log 镜像。
  理由：① 应用日志里根本没有这些请求；② 结构化字段能"只匹配 path、只取 clientIp"，
  误报面比自由文本小得多；③ 一条日志两处用会让"扫描规则"和"注入规则"互相干扰）。
- `ignoreip`：回环 + 两台服务器自有公网 IP。**刻意不放私网段**（一次性探针容器的源 IP 在私网里，
  放进去等于把容器侧验证和攻击一起放过）。
- **封禁动作必须是 `iptables-*`，不能用 firewalld 系**：§21.5 记过三种"假成功"
  （rich-rules 端口非法 / `--direct` 在 nft 后端静默无效 / docker 网桥绕过 zone）。

### 24.4 Wazuh：manager 规则（srv2）

装机脚本：`scripts/srv2-install-accesslog-rules.sh`（备份 → 写 → **`analysisd -t` 门禁** → 失败回滚 → 重启）。
采集侧：`scripts/srv1-wazuh-accesslog-localfile.sh` 给 agent 追加
`<localfile><log_format>json</log_format><location>/opt/secagent/data/access.jsonl</location>`。
⚠️ **不能给这个 localfile 加 `out_format`**（§21 对 app.log 是加了的）：加了前缀就不是 JSON，
内置 json 解码器立刻失效、规则一条都不命中，而且不会有任何报错。

| sid | level | 判据 |
|---|---|---|
| 100238 | 1 | 访问日志里的一次 4xx（只记账，低于 `log_alert_level=3`，不写 alerts.json） |
| 100239 | 8 | 同一 `clientIp` 120 秒内 4xx ≥ 40（`if_matched_sid` 100238 + `same_field clientIp`） |
| 100240 | 10 | path 命中已知恶意路径 |
| 100241 | 12 | 其中属于路径穿越形态（`if_sid` 100240） |

### 24.5 怎么验证（都要能重复跑）

```bash
# ① 应用侧：日志真的在记 URL 级探测（三种源 IP 都是 RFC5737，绝不会误封真实来源）
sudo bash /opt/secagent/scripts/srv1-fail2ban-webscan.sh --verify   # 失败2->封禁->内核规则->解封 全流程
#   单独看日志（探针走"直连源站"，正是绕过 CF 的形状）：
curl -s -o /dev/null -H 'CF-Connecting-IP: 198.51.100.9' -H 'User-Agent: selftest' \
     http://127.0.0.1:9900/wp-login.php
tail -1 /opt/secagent/data/access.jsonl

# ② fail2ban 状态（**不要**用"重启后链在不在"判断生效与否，见 24.8 坑 3）
sudo bash /opt/secagent/scripts/srv1-fail2ban-webscan.sh --status
sudo fail2ban-client status secagent-webscan
sudo iptables -S INPUT | grep f2b-            # 只在发生过封禁之后才看得到

# ③ Wazuh：agent 侧 + manager 侧
sudo bash /opt/secagent/scripts/srv1-wazuh-accesslog-localfile.sh --status
#   在 srv2 上：
docker exec wazuh.manager /var/ossec/bin/agent_control -l | grep -E '006|Active'
sudo bash /tmp/srv2-install-accesslog-rules.sh --check      # analysisd -t + 规则清单
docker exec wazuh.manager cat /var/ossec/logs/alerts/alerts.json | grep -a 100240 | tail -1
```

### 24.6 封禁边界（和 §21.6 是同一条，别记错）

srv1 的公网入站是 **cloudflared 隧道**，应用只监听 `127.0.0.1:9900`；
真实访客到达 srv1 时的源 IP 是 **127.0.0.1**，日志里的 `clientIp` 是 `CF-Connecting-IP`（真实访客）。

- ⇒ 在 srv1 上按 `clientIp` 做 L3 封禁**挡不住该访客经 Cloudflare 的后续流量**（它们从 CF 边缘进来）。
- 真正有效的场景：① **检测/留痕/进 SIEM**（本节的真实价值）；
  ② **绕过 Cloudflare 直连源站**的流量（一次性容器/直连探测正是这个形状，已功能性验证）；
  ③ 将来任何把 9900 暴露出去的场景。
- 真正的处置点在 **Cloudflare WAF/自定义规则**（需要 Zone 级 API Token，至今没有）或应用侧黑名单。
- `clientIp` 的可靠性：`CF-Connecting-IP` 在**能直连到应用**的场景下是**可伪造**的
  （实测：本地 curl 带一个假头，日志就记了那个假 IP，fail2ban 也照封）。
  当前 9900 只绑回环、外面够不到，所以不可伪造；**一旦把 9900 暴露出去，这个头就不能当证据用**。
  这也是 `ignoreip` 里必须写自有公网 IP 的原因（伪造自家 IP → 自我 DoS）。

### 24.7 怎么临时关掉（按影响面从小到大）

```bash
# 1) 只停主机侧封禁（检测/留痕继续，Wazuh 仍会告警）
sudo fail2ban-client stop secagent-webscan
sudo fail2ban-client stop secagent-webscan-4xx
# 恢复：start（或 sudo bash /opt/secagent/scripts/srv1-fail2ban-webscan.sh --apply）

# 2) 停 Wazuh 对访问日志的采集（fail2ban 不受影响；SIEM 上不再出这三条规则）
sudo bash /opt/secagent/scripts/srv1-wazuh-accesslog-localfile.sh --rollback

# 3) 彻底关掉应用侧访问日志（本节的检测能力全部失效）
#    在 /opt/secagent/.env 加：APP_ACCESSLOG_ENABLED=false  然后按发布链重建容器
#    （注意：不能用 docker compose up 手工重建 —— 会丢 digest 引用，见 CLAUDE.md 硬规矩 1）

# 4) 回滚整个 jail 配置
sudo bash /opt/secagent/scripts/srv1-fail2ban-webscan.sh --rollback
```

### 24.8 本次实测踩到的坑（都是"看起来成了、其实没成"）

```
坑 1  fail2ban 过滤器里的 % 是插值字符：正则里写 %2e%2e 会让 fail2ban-client -t 直接报
      "'%' must be followed by '%' or '(', found: '%2e%2e|...'"。必须写 %%2e%%2e。
      （--apply 的 -t 门禁当场拦下并自动回滚，坏配置没进生产。）

坑 2  fail2ban 会先用 datepattern 把时间戳【从行里删掉】再把剩下的文本交给 failregex，
      而它的捕获组覆盖 `{"ts":"<时间>"` 整段 → 任何以 ^\{"ts":" 锚定的正则都是 0 命中。
      对策：failregex 从 "method" 开始写（带不带时间戳前缀都能命中），并在样本上断言命中数（5/7）。
      另一个反向坑：ts 若带 9 位纳秒，%f（1-6 位）解析失败 → fail2ban 退化成"用当前时间"，
      findtime 窗口不再精确。所以应用侧把 ts 截断到了毫秒。

坑 3  【最容易骗过自己的一条】本机的 fail2ban actionstart **不会**在 jail 启动时建内核链：
      实测 restart 后盯 70 秒，iptables 里一行 f2b- 都没有、日志里也没有 ERROR；
      链与 INPUT 跳转是在【第一次真正封禁】时懒建出来的。
      ⇒ 判据必须是"试封一个 RFC5737 地址，断言 链 / INPUT 跳转 / 规则 / 解封 四件事"，
        不能是"重启后链在不在"。（§21 当时那条 iptables -S | grep f2b- 之所以成立，
        是因为那之前已经发生过真实封禁。）另外注意：chain 名有 28 字符上限，
        两个 jail 的名字 intentionally 短。

坑 4  Wazuh 的 `status` 是【静态字段】：<field name="status"> 会让 analysisd -t 报
      "Field 'status' is static" 并拒绝加载规则。改用 <regex type="pcre2"> 打原始行。

坑 5  frequency/timeframe 必须配 if_matched_sid（"Invalid use of frequency/context options"），
      所以要拆成"记账规则 + 聚合规则"两条。而记账规则【不能是 level 0】：
      实测 level 0 是**终止符**，命中即停止评估，后面 level 10/12 的具体规则一条都不报；
      level > 0 时是"level 最高者胜"（与文件顺序、id 大小无关）。
      现在记账规则用 level 1：既不是终止符，又低于 log_alert_level=3，不写 alerts.json。

坑 6  `<field name="path" type="pcre2">` 对 JSON 解码出来的动态字段**不按预期匹配**
      （实测同样一条 /wp-login.php 事件，<field> 版 0 命中，<regex> 版命中）。
      本文件一律用 <regex type="pcre2">，并用 "path":"[^"]*…[^"]*" 把关键字锁在 path 值里。

坑 7  wazuh-logtest **不带 -i 就读不到 stdin**，输出空白 —— 看起来像"规则不命中"，
      其实是根本没喂进去。调试一律 `docker exec -i wazuh.manager /var/ossec/bin/wazuh-logtest`。

坑 8  【把 agent 弄挂的一次】给 /var/ossec/etc/ossec.conf 追加配置时，
      我第一版用了 `install -m 0600 -o root -g root` → 文件从 root:wazuh 0640 变成 root:root 0600，
      而 wazuh-agentd 是**降权**以 uid 995(wazuh) 读它 → 报
      "ERROR: (1226): Error reading XML file 'etc/ossec.conf': (line 0)"（detail 为空 = 打不开，
      不是语法错），systemd 单元 failed，srv1 主机侧上报整条链路停摆。
      ⇒ 脚本现在先 stat 出原始 mode/user/group 再 install，并在改完后断言
        `sudo -u wazuh test -r <conf>`。教训：改别人的系统配置文件时，属主/权限是配置的一部分。
      另：python3 的 expat 认为 §21 那份 ossec.conf 注释里含 `--` 所以"不是合法 XML"，
      但 wazuh 自己的解析器接受它（同一文件 agentd 能起来）—— 别拿 python expat 当 wazuh 的校验器。

坑 9  排查时踩的自己的坑：`docker exec ... cat alerts.json | python3 - <<'PY'` 里，
      heredoc 会占掉 stdin，管道内容被丢掉 → 查询结果永远 0 条，看起来像"事件没到"。
      查 alerts.json 用 `python3 -c`（或先落盘再读）。
```

### 24.9 实测证据（2026-10-13 20:19–20:47，一次性容器 + 真实日志 + 真实告警）

> 取证方式：同一份 jar 起了一个**一次性容器**（`secagent:accesslog-test`，`--network host`、
> `SERVER_PORT=9901`、`SERVER_ADDRESS=127.0.0.1`、独立 data 目录），
> 只把**生产路径的 access.jsonl 以文件挂载**共享进来 ——
> 于是 fail2ban 与 Wazuh 的装机路径与线上完全一致，而线上容器（ACR digest）**一点没动**。
> 取证完已 `docker stop secagent-al-test`（镜像保留，重启命令见 §24.10）。
> 这么做是因为硬规矩 1（部署只走 CI→ACR→digest）；应用侧代码进线上要等站主 push → CI。

```bash
# ① URL 级探测在应用日志里可见（真实输出，未脱敏；源 IP 是 RFC5737 文档网段）
{"ts":"2026-10-13T20:43:44.253+08:00","method":"GET","path":"/wp-login.php","queryKeys":"","status":404,"clientIp":"198.51.100.9","ua":"wazuh-evidence/1.0","ms":3,"reqId":"1a1354a4cfd-c-af36"}
{"ts":"2026-10-13T20:43:44.264+08:00","method":"GET","path":"/.env","queryKeys":"","status":404,"clientIp":"198.51.100.9","ua":"wazuh-evidence/1.0","ms":2,"reqId":"1a1354a4d09-d-80e6"}
{"ts":"2026-10-13T20:43:44.275+08:00","method":"GET","path":"/etc/passwd","queryKeys":"","status":404,"clientIp":"198.51.100.11","ua":"wazuh-evidence/1.0","ms":2,"reqId":"1a1354a4d14-e-ca03"}

# ② fail2ban 封禁-解封全过程（真探针 → 真日志行 → 真封禁 → 内核规则 → 真解封）
==> 3/6 等待 fail2ban 按真实日志行触发封禁（maxretry=2）
  [OK]   fail2ban 已封禁 198.51.100.9（来源=它自己读到的访问日志行）
  `- Banned IP list:	198.51.100.9
==> 4/6 内核规则落地（封禁不是只记在 fail2ban 状态里）
  [OK]   iptables 链 f2b-secagent-webscan 里确实有 198.51.100.9
      -A f2b-secagent-webscan -s 198.51.100.9/32 -j REJECT --reject-with icmp-port-unreachable
      -A INPUT -p tcp -j f2b-secagent-webscan
==> 5/6 解封（unban）
  [OK]   内核规则已消失
  # 同刻 fail2ban.log：NOTICE [secagent-webscan] Ban 198.51.100.9 / Unban 198.51.100.9
  # 4xx jail 同样封了 192.0.2.55（55 条随机路径 404 → 2 分钟阈值 40 触发）

# ③ Wazuh manager 侧真实告警（alerts.json，agent=006 srv1）
sid=100240 L10 | srv1: URL 级 Web 扫描/探测命中已知恶意路径 | path=/wp-login.php clientIp=198.51.100.9
sid=100240 L10 | srv1: URL 级 Web 扫描/探测命中已知恶意路径 | path=/.env        clientIp=198.51.100.9
sid=100241 L12 | srv1: 路径穿越尝试（URL 里出现 ../ 或 etc/passwd 形态）      | path=/etc/passwd clientIp=198.51.100.11
sid=100239 L8  | srv1: 同一来源 IP 在 120 秒内产生大量 4xx（疑似目录/路径爆破） | clientIp=192.0.2.55（第 41 条 4xx 触发）
agent 侧：logcollector "Analyzing file: '/opt/secagent/data/access.jsonl'"
manager 侧：analysisd -t 通过；Total rules enabled 7020 → 7024
```

### 24.10 没做到 / 疑虑（如实列）

```
1. 【最重要】应用侧代码【还没进线上】：它不在任何已提交的 commit 里，所以线上容器
   （当前 digest sha256:6a00c2f…、commit 2c2c8ce）不会写 access.jsonl。
   本次取证用的是一次性容器。站主 push → CI 构建 → srv1-redeploy 之后才真正"线上可见"。
   在那之前：jail 与规则都已武装好、但数据源是空的（不会误封，也不会有告警）。
   一次性容器要重启（取证/演练用）：
     docker start secagent-al-test && curl -s http://127.0.0.1:9901/api/health
   它绑 127.0.0.1:9901、用独立 data 目录，只共享 access.jsonl 这一个文件。

2. 路径穿越的"裸形态"看不见：实测 `curl --path-as-is /../../etc/passwd` 与 `/%2e%2e%2f…`
   **在 Tomcat 连接层就被 400 掉**（不进入 filter 链），所以这类请求在访问日志里【没有行】。
   能看到的只有"归一化之后仍看得出是穿越目标"的形态（如 /etc/passwd），
   或经前置代理归一化后到达应用的形态。=> 100241 的价值低于名字暗示，
   真正的穿越防护要靠前置（CF WAF）与端口不暴露。

3. 查询串里的攻击形态看不见：只落键名不落值，所以 `?q=../../etc/passwd`、`?id=1' OR 1=1`
   这类"参数级注入"在访问日志与两个 jail 里都是不可见的（这是"不记敏感内容"的代价）。
   要覆盖它得靠应用侧注入防护（已有 PromptInjectionGuard 那条线）或 WAF。

4. 封禁对公网访客无效（见 24.6）：`secagent-webscan*` 目前是"检测 + 留痕 + 防直连"，
   不是"公网扫描被封住了"。真正的处置点（CF WAF / 应用侧黑名单）没做 —— 缺 Zone 级 API Token。

5. `clientIp` 依赖 CF-Connecting-IP，可伪造（见 24.6）；当前因端口只绑回环而安全，
   但"把 9900 暴露出去"或"加其它反代"时这条会立刻变成风险。

6. reqId 目前只有访问日志在用：没有进响应头、也没有进应用日志（MDC），
   所以它暂时无法把"这一行访问日志"和"那次 ERROR"关联起来。要关联得改应用日志格式
   （会影响 §21 的 Wazuh out_format），属于下一步，本次刻意没动。

7. 容量与备份：data/ 在 §22 的异地备份范围内，access.jsonl 最大 448MB 会进备份包。
   本次没改备份脚本；如果备份体积成为问题，应在 srv1-data-backup.sh 里排除 access*.jsonl
   （它们是日志不是状态）—— 这需要改 §22 的东西，留给站主决定。

8. 只做了 URL 级；"同一 IP 长期低频扫描"（慢速扫描）仍看不见 —— fail2ban 的 findtime 窗口
   与 Wazuh 的 timeframe 都是有界的。（srv2 的 Suricata 那条线覆盖网络层慢扫描，见 §11。）
```

---

# 【补录 2026-10-13 21:0x】以下 §21 原只存在于 srv1 的 /opt/secagent（从未提交），现捞回仓库；
# 因 §24/§25 已先入库，本节排在文末，编号仍用 21 以便与 RUNBOOK 交叉引用一致。

## 21. srv1 主机侧检测：fail2ban + wazuh-agent（2026-10-13 落地）

> 背景：外部评审指出「检测全在 srv2，srv1 被打穿没人知道」。
> 这一节记录 srv1 上现在到底装了什么、看得见哪些事件、怎么验证、怎么临时关掉，
> 以及本次实测撞出来的坑（含两处「假成功」）。

### 21.1 装了哪两样，各自在哪

| 组件 | 位置 | 作用 | 状态 |
|---|---|---|---|
| fail2ban（已有，本次补配置） | srv1 宿主 `/etc/fail2ban/` | sshd 爆破封禁 + 公开端点注入封禁 | active，2 个 jail |
| secagent-applog-mirror | srv1 宿主 systemd | 把应用容器 stdout 落到 `/var/log/secagent/app.log` | active |
| wazuh-agent 4.9.2 | srv1 宿主 RPM（`/var/ossec`） | 采集认证/单元/docker/应用日志上报 srv2 | active，manager 侧 ID **006** |
| secagent-wazuh-agent-tunnel | srv1 宿主 systemd | 把 srv2 的 `127.0.0.1:1514/1515` 映射到 srv1 回环 | active |
| srv1 自定义规则 | srv2 `/opt/wazuh/config/wazuh_cluster/rules/srv1_local_rules.xml` | 9 条规则（100200-100232） | 已装载（总 7020 条） |

入库（仓库 = srv1 `/opt/secagent`）：

- `scripts/srv1-fail2ban-setup.sh` / `scripts/srv1-fail2ban-verify.sh`
- `scripts/srv1-applog-mirror.sh`
- `scripts/srv1-wazuh-tunnel-setup.sh` / `scripts/srv2-authorize-wazuh-agent.sh`
- `scripts/srv1-wazuh-agent-install.sh`（`--enroll` 走 agent-auth）
- `scripts/srv2-install-srv1-rules.sh`（含 `analysisd -t` 门禁）
- `scripts/srv1-wazuh-make-events.sh` / `scripts/srv2-check-srv1-alerts.sh`
- `deploy/fail2ban/{jail.d,filter.d,sample}/`、`deploy/secagent-applog-mirror.service`
- `deploy/logrotate/secagent-applog`
- `deploy/secagent-wazuh-agent-tunnel.service`、`deploy/wazuh/{srv1-ossec.conf,srv1_local_rules.xml}`

### 21.2 反向确认：srv1 上现在**能被检测到**的事件（不是"已安装"）

实测来源与规则（括号里是已在 manager 上真实产生告警的规则号）：

| 事件类型 | 采集来源 | 规则 |
|---|---|---|
| SSH 登录成功 / PAM 会话开关 / sudo | `/var/log/secure` | 5715 / 5501,5502 / 5402,5403（内置，已实测出告警） |
| **ssh 爆破 → 主机侧真封禁（留痕）** | `/var/log/fail2ban.log` | **100210**（封）/ 100211（解）（已实测出告警） |
| **公开端点命中提示注入特征** | `/var/log/secagent/app.log` | **100220**（已实测出告警） |
| **应用 ERROR 单条** | 同上 | **100221**（已实测 19 条告警） |
| **应用 ERROR 突增（120s≥15）** | 同上 | **100222**（已实测出告警） |
| 任意 systemd 单元失败 | `/var/log/messages` | 40704（内置，已实测：`docker.service`、`secagent-healthwatch.service`、自测单元） |
| **secagent-\* 单元失败 / 看门狗判不健康** | `/var/log/messages` | **100200**（已实测：看门狗「不健康（第 2/3 次）」） |
| **容器退出且不被重启** | `/var/log/messages`（dockerd） | **100230**（logtest 已验证；尚无真实触发） |
| **docker 守护进程重启** | 同上 | **100231**（logtest 已验证） |
| **应用容器启动完成（=刚重启过）** | app.log | **100232**（logtest 已验证） |
| 网卡进混杂模式（容器创建痕迹） | `/var/log/messages` | 5104（内置，已实测 8 条） |
| agent 自身连上/断开 | wazuh-agent | 501 / 506（已实测） |

**明确看不见的（本次实测结论，别自欺）**：

1. **公开端点的 URL 级扫描/注入**（`/wp-login.php`、`/.env`、`/../../etc/passwd`、`?q=../etc/passwd`）
   —— 实测应用对这些请求**一行都不记**（Spring 不记未匹配路由），返回 404 且日志无痕。
   所以"用 fail2ban 盯扫描路径"在 srv1 上是**做不到**的，不是没配。
   要补只能从应用侧补 access log（需走 CI→ACR 重建，见 21.6）。
2. **`/var/log/messages` 里可控失败登录的"Failed password"** —— 本机 `PasswordAuthentication no`，
   密码失败这条路不存在；只有 `Invalid user`/`Connection closed by authenticating user` 形态。
   （fail2ban 的 aggressive 模式吃这两种，所以封禁照常生效，已实测。）
3. **docker 事件流的完整字段** —— `docker-listener` wodle 在这台机器上**不工作**（见 21.5），
   改用 dockerd 自己写进 `/var/log/messages` 的日志，字段只有 container/exitStatus/restartCount。

### 21.3 怎么验证（三条命令，都可重复跑）

```bash
# ① fail2ban：封禁-解封-连通性 全过程（含内核规则落地的功能性验证）
sudo bash /opt/secagent/scripts/srv1-fail2ban-setup.sh --status
sudo bash /opt/secagent/scripts/srv1-fail2ban-verify.sh --all

# ② Wazuh：agent 侧状态 + 让 manager 侧真的报警
sudo bash /opt/secagent/scripts/srv1-wazuh-agent-install.sh --status
sudo bash /opt/secagent/scripts/srv1-wazuh-make-events.sh --all   # 造可控事件
sudo bash /opt/secagent/scripts/srv1-wazuh-make-events.sh --cleanup

# ③ 在 srv2 上看告警（直接读 alerts.json，不依赖 indexer）
sudo bash scripts/srv2-check-srv1-alerts.sh              # 在 srv2 上执行
```

判据（缺一不可）：

- `fail2ban-client status sshd|secagent-public-api` 都在，且
  `iptables -S | grep f2b-` 能看到 `f2b-sshd` / `f2b-secagent-public-api` 两条链 + INPUT 跳转；
- `srv1-fail2ban-verify.sh` 里「封禁后从探针容器连不上、解封后连得上」；
- manager 侧 `agent_control -l` 里 ID 006 是 **Active**；
- `alerts.json` 里能看到 100200/100210/100220/100221/100222 里的大多数（21.2 表里标"已实测"的）。

### 21.4 怎么临时关掉（按影响面从小到大）

```bash
# 只关应用侧检测（保留 sshd 爆破封禁）
sudo fail2ban-client stop secagent-public-api
sudo fail2ban-client start secagent-public-api          # 恢复

# 关掉全部 fail2ban 封禁（检测还在，只是不动作）
sudo fail2ban-client stop
sudo fail2ban-client start

# 关掉主机侧上报（应用侧 fail2ban 不受影响）
sudo systemctl stop wazuh-agent
sudo systemctl start wazuh-agent

# 停掉日志镜像（注意：这会让 app 侧两类检测同时失效）
sudo systemctl stop secagent-applog-mirror

# 回滚到改造前（配置层面，带备份）
sudo bash /opt/secagent/scripts/srv1-fail2ban-setup.sh --rollback
sudo bash /opt/secagent/scripts/srv1-wazuh-agent-install.sh --rollback
```

### 21.5 实测踩到的坑（都是"看起来成了、实际没成"）

1. **fail2ban 封禁的三种假成功**
   - `firewallcmd-rich-rules` 用在本 jail（没有 `port` 概念）时，`<port>` 被填成 `1:65535`，
     firewalld 报 `INVALID_PORT` → 状态里显示已封、防火墙里什么都没有。
   - `firewallcmd-allports` 走 `firewall-cmd --direct`，而本机 firewalld 0.9.11 是 **nftables 后端**，
     `--direct` 静默无效：fail2ban 只写一行 `Ban x.x.x.x`（连 ERROR 都没有），内核里空空如也。
   - firewalld 的 zone rich rule 只对 zone 绑定的接口生效：**docker 网桥在 ACCEPT 目标的 docker 区**，
     从网桥进来的连接绕过 rich rule（实测封了照样连）。
   ⇒ 两个 jail 改成 `iptables-multiport` / `iptables-allports`（写进 `table ip filter` 的 INPUT 链，
   对所有接口生效），并用一次性容器做"封前能连/封后超时/解封恢复"的功能性验证。
2. **`fail2ban-client reload` 不会重跑 actionstart**：改了封禁动作后 reload，
   新动作的内核链根本不存在，之后每次封禁都只记状态、不落规则（假成功）。
   ⇒ 安装脚本一律 `systemctl restart fail2ban`，并在生效后**试封一个 RFC5737 地址**、
   断言内核规则真的出现又消失。
3. **systemd unit 里的 `%` 是 specifier**：`printf "... %s ..."` 里的 `%s` 被展开成 `/bin/sh`，
   日志文件里写进去的是 `(re)connect /bin/sh`，**真正的应用日志一行没落盘**，
   而 unit 显示 active。⇒ 循环搬进 `scripts/srv1-applog-mirror.sh`，unit 只调脚本。
4. **`docker logs -f` 在容器非 running 时正常退出**：只用 `Restart=always` 会得到
   "服务反复 Succeeded"的抖动。⇒ 脚本里套 `while` + 每次重连写标记行（缺口可见）。
5. **manager 规则的三条语法/语义坑**（改错会让 `wazuh-analysisd` 直接起不来 = 整个 SIEM 停摆）：
   - 一条规则里不能同时写 `<match>` 和 `<regex>`；
   - `<regex>` 默认是 osregex 方言，不支持 `(?:)`/`\d`/`|`，必须 `type="pcre2"`；
   - **`<match>` 对"没有 decoder 命中的事件"不生效**（只比对 decoder 解出的 log 字段），
     对自定义应用日志必须用 `type="pcre2"` 的 `<regex>`；
   ⇒ 更新规则一律走 `scripts/srv2-install-srv1-rules.sh`（备份 → 写 → `analysisd -t` → 失败回滚 → 重启）。
6. **预解码会吃掉"紧跟时间戳的那个词"**：应用日志行首是 ISO 时间戳，紧跟的 `ERROR/WARN/INFO`
   在预解码阶段被当成日志级别丢掉 —— 实测同一条 ERROR 行，`regex "ERROR"` 不命中、`regex "---\s*\["` 命中，
   于是"ERROR 突增"无从谈起。⇒ 在该 localfile 上加
   `<out_format>$(timestamp %Y-%m-%d %H:%M:%S) secagentapp: $(log)</out_format>`，
   让原始行整体落进正文，级别词重新可见（logtest 已验证：ERROR 行命中 100221、INFO 行不命中）。
   同理 fail2ban 那行不能写成 `fail2ban\.actions.*Ban`（程序名也被吃掉），要用 `\]\s+Ban\s+<ip>`。
7. **`docker-listener` wodle 在这台机器上不工作**：agent 日志里
   `Module docker-listener started.` → 约 1 分钟后 `Module finished.`，
   单独跑 `/var/ossec/wodles/docker/DockerListener` 也产不出事件，manager 侧 0 条 docker 告警。
   ⇒ 明确 `<disabled>yes</disabled>`（不留假覆盖），容器事件改由 dockerd 写进 `/var/log/messages`
   的日志覆盖（`ShouldRestart failed...` 已在里面实测看到，含本次崩溃重启循环的原文）。
8. **离线 client.keys 不能用 `manage_agents -e` 的输出直接填**：
   那是 base64 串，塞进 client.keys 会 `Authentication error. Wrong key or corrupt payload`，
   而且 agent 会**自己重新注册**，ID 一路飘（本次：003→004→005→006），manager 上留一堆僵尸 agent。
   ⇒ 用 `agent-auth -m 127.0.0.1 -p 1515 -A srv1-host`（隧道已通）；安装脚本默认**不再覆盖**
   已存在的 client.keys（要覆盖显式 `--force-keys`）。

### 21.6 封禁生效边界（最重要的一条，别记错）

srv1 的公网入站是 **cloudflared 隧道**，应用只监听 `127.0.0.1:9900`。
也就是说：攻击流量到达 srv1 时的**源 IP 是 127.0.0.1**。

- sshd jail：攻击者直连 22 端口，**封禁真实有效**（已用一次性容器做功能性验证）。
- `secagent-public-api` jail：它封的是应用日志里记录的真实访客 IP（`CF-Connecting-IP`）。
  在 srv1 上做 L3 封禁**挡不住这个访客后续的流量**（流量从 Cloudflare 进来）。
  它的真实价值是：① 检测+留痕（同一行日志进 Wazuh 出 100220 告警）；
  ② 对"绕过 Cloudflare 直连源站"以及任何将来把 9900 暴露出去的场景立即生效。
  **真正的处置点在 Cloudflare（WAF/自定义规则）或应用侧黑名单** —— 见 21.7 待办。
  jail 里 `ignoreip = 127.0.0.1/8 ::1` 是必须的：应用拿不到 `CF-Connecting-IP`/XFF 时
  `getRemoteAddr()` 就是 127.0.0.1，封了等于封自己。

### 21.7 没做 / 疑虑（如实列）

1. **公开端点的 URL 级滥用挡不住**（21.2 第 1 条）：应用不记 404/扫描路径，
   主机侧无从检测。建议下一步在应用侧开 Tomcat access log（`server.tomcat.accesslog.*`，
   走 CI→ACR 重建），拿到"请求行 + 真实 client IP"，那时候这条 jail 才能真正做扫描/注入封禁。
2. **`secagent-public-api` 的封禁对公网访客无效**（见 21.6），目前只是"检测+留痕+防直连"。
   没做：把封禁动作接到 Cloudflare（需要 Zone 级 API Token，本次没有可用凭据）。
3. **manager 端口可达性**：srv2 的 1514/1515 至今只绑 `127.0.0.1`，srv1 靠
   `secagent-wazuh-agent-tunnel`（专用密钥 + `permitopen 1514/1515`）过来。
   这条隧道断了，srv1 的主机侧上报就停（fail2ban 不受影响）。
   没做：隧道断连的**主动告警**（现在只能靠 manager 侧 agent 变 Disconnected 被动发现）。
4. **agent 断连时的行为**：agent 侧有 `time-reconnect=60`、`auto_restart=yes`，
   但断连期间的日志**不会补发**（`only-future-events=yes` 只跟新行）。也就是说
   隧道断 N 分钟 = 这 N 分钟的 srv1 事件永久丢失（fail2ban 仍在本机封禁，只是没上报）。
5. **agent 名字与文档不一致**：当前 manager 上的 srv1 agent 是 **ID 006、名字 = 主机名
   `iZbp1eix0bsjl4c6nhktorZ`**（agent-auth 用 `-A srv1-host` 注册的那次是 ID 005，
   被后来脚本里的旧 `--keys` 覆盖后又自动重注册成 006，005 已删除）。
   名字不影响功能，但看板上一眼认不出是哪台机器 —— 要改成 `srv1-host` 需要"删 006 → agent-auth 重注册"。
6. **`rootcheck` / `sca` 明确关掉了**（2 核 2GB 的机器上性价比太低），
   `syscheck` 只留 `/etc,/usr/bin,/usr/sbin,/bin,/sbin`（不含 docker/data 目录）。
   这三项属于"为省资源主动放弃"的覆盖面。
7. **未验证到的**：100230/100231/100232（docker 事件三条）只有 `wazuh-logtest` 的验证，
   等下一次真实的容器重启/退出才会产生第一条线上告警。
8. **实测当天的副作用**：为了做验证，`/var/log/secagent/app.log` 里被追加过 6 行合成的
   "公开提问命中注入特征…（来源=198.51.100.9）"日志（脚本 `--synthetic` 造的，已注明）；
   `/etc/systemd/system/secagent-detect-selftest.service` 是当时造的故意失败单元，**已删除**。
9. **本次现场发现的另一个真实事故**（不属于本任务范围，只记录）：
   12:00 前后应用容器在"坏 digest ↔ 回滚"之间反复重启（dockerd 日志里
   `restartCount=12`、`secagent-healthwatch.service: Failed`），
   规则 100200 抓到了看门狗的不健康判定、40704 抓到了单元失败 —— 这正是本节要补的那层可见性。

### 21.8 资源占用实测（2026-10-13 12:15，srv1）

| 组件 | RSS |
|---|---|
| `fail2ban-server` | 26.6 MB |
| wazuh-agent 全部进程（agentd+syscheckd+logcollector+modulesd+execd） | 53.1 MB |
| 应用日志镜像（`/bin/bash` 循环 + `docker logs -f`） | ~3 MB |
| **合计新增** | **≈ 83 MB** |

对照同刻整机：总内存 1870 MB、可用 1142 MB、load 0.59/0.34/0.36。
结论：**不会把 srv1 拖垮**（新增不到可用内存的 8%）。磁盘新增 `/var/log/secagent/` 约 0.3 MB/小时量级，
由 logrotate 按天保留 7 份（`copytruncate`，fail2ban 与 wazuh 两个读者都不会跟丢 inode）。


### 21.9 配置漂移风险（写在这里免得忘）

- `/etc/fail2ban/jail.d/sshd.local` 的权威副本在 `deploy/fail2ban/jail.d/sshd.local`。
  **但 `scripts/harden-ssh.sh` 里还内联着一份旧版 heredoc**（没有 `ignoreip` / `banaction` / `chain`）。
  重跑 `harden-ssh.sh` 会把这份旧配置写回去，把本次加固冲掉。
  下次动那个脚本时，把内联 heredoc 换成从 deploy/ 里 install（本次没改它，避免与并行改动冲突）。
- `/root/.ssh/wazuh_agent_srv2_ed25519` 与 srv2 上 `authorized_keys` 里
  `secagent-wazuh-agent-from-srv1` 那一行是**成对**的；只删一边 = 隧道起不来
  （srv1 侧会一直 `Permission denied (publickey)`）。
- srv2 上 `/opt/wazuh/config/wazuh_cluster/rules/srv1_local_rules.xml` 是 bind mount 进容器的，
  改它必须走 `scripts/srv2-install-srv1-rules.sh`（否则语法错会让 analysisd 起不来）。
- `/opt/secagent/vendor/srv1-client.keys` 是 agent 身份凭证，**不要入库**（`.gitignore` 里应有 vendor/）。

## 26. 离线地理富化与 `/api/public/geo`（DB-IP Lite，2026-10-13 落地）

```
【一句话】攻击来源分布地图 = 离线库（DB-IP Lite City + ASN，CC BY 4.0）+ 排序区间数组二分查找
          + indexer 端 terms 聚合；公开面只给【国家/省份/ASN + 计数 + 独立IP数 + 24×1h 时间桶】，
          响应里没有任何 IP（连掩码 IP 都没有）。设计/前端对接见 docs/design-geo-endpoint.md。

【为什么不用在线地理 API】红线：不调任何第三方地理/情报 API（隐私 + 配额 + 零依赖）。
          库文件放服务器、不进仓库、不进镜像（80MB+，且许可要求署名）。

—— 26.1 库：名字、版本、许可、署名（照抄，不许改写）——
  库名/版本：DB-IP Lite City <YYYY-MM>（主）+ DB-IP Lite ASN <YYYY-MM>（可选，用于机构榜）
  当前落地：2026-10（city 85,827,400 B / asn 7,015,072 B，均为 gz）
  许可：CC BY 4.0（可再分发、可商用，但【必须署名】）
  ★ 署名文案（公开页面与 API 的 note 里都要有，代码里是 GeoIpService.ATTRIBUTION，测试逐字断言）：
      IP 地理位置数据由 DB-IP (https://db-ip.com) 提供，CC BY 4.0
  备选库（未采用，写清理由）：MaxMind GeoLite2 City（许可更严、要 license key）、
      iptoasn.com ASN+country TSV（只有国家级，做不到省份）。

—— 26.2 文件怎么落地（srv1）——
  /opt/secagent/geoip/                         目录 700，属主 999:999（= 容器里的 uid/gid）
    dbip-city-lite-2026-10.csv.gz              文件 600，属主 999:999
    dbip-asn-lite-2026-10.csv.gz               文件 600，属主 999:999
    dbip-city-lite.csv.gz -> 上面那份的符号链接（稳定路径；月度更新只翻链接）
    dbip-asn-lite.csv.gz  -> 同上
  docker-compose.yml 里只读挂载：- /opt/secagent/geoip:/opt/geoip:ro
  容器内路径由 APP_GEOIP_CITY_DB / APP_GEOIP_ASN_DB 指定（默认 /opt/geoip/dbip-city-lite.csv.gz）。
  ⚠️ 600/700 是"宿主机上别的用户读不到"，不是"root 独占" —— 容器以 uid 999 跑，
     所以属主必须是 999:999（实测 docker exec secagent id → uid=999(secagent)）。
     若改成 root:root 700，容器里会 read 失败 → 应用如实报 GEO_DB_UNUSABLE（不会静默变空图）。

  首次落地/月度更新（下载 → 校验 → 原子替换 → 失败保留旧库并告警）：
    bash /opt/secagent/scripts/srv1-geoip-update.sh              # 当前月；当月未发布自动回退到上月
    bash scripts/srv1-geoip-update.sh --dry-run                  # 只下载+校验，绝不改动现有库
    bash scripts/srv1-geoip-update.sh --verify                   # 只校验正在用的库
    bash scripts/srv1-geoip-update.sh --month 2026-09            # 指定月份（补票/复现）
    bash scripts/srv1-geoip-update.sh --rollback                 # 把链接指回上一份（保留 current+prev）
    bash scripts/srv1-geoip-update.sh --self-test                # 不需要网络/root 的纯函数自测
  脚本校验项（任一不过就【保留旧库】并 notify HIGH）：gzip 完整性、体积区间（city 50–200MB /
    asn 2–40MB）、首行形状、行数 ≥100 万、必须含 IPv6 段（首行 ::,…）。
  更新频率：每月一次（DB-IP 在每月 1 日发布上月数据）。cron 建议（srv1，root）：
    17 4 3 * *  bash /opt/secagent/scripts/srv1-geoip-update.sh >> /opt/secagent/logs/geoip-cron.log 2>&1

  ★★ 实测：srv1 直连 download.db-ip.com 只有 30–200 KB/s（Cloudflare，中国出口），
     86MB 的 city 库要 20–45 分钟而且会中途掉速 —— 脚本原先只支持"自己下载"，
     在这种链路上月度更新很可能一直失败。所以把两件事拆开（2026-10-13 落地）：
       · **下载可以在任何地方做**（本机/CI/别的机器，能拿到文件就行）；
       · **校验与原子落地必须在 srv1 上做**（同一套判据、同一条替换路径，不许绕过）。
     推荐链路（本次首次落地就是这么做的，27 秒传完 86MB）：
       # 在能快速访问 db-ip.com 的机器上
       curl -fsS -O https://download.db-ip.com/free/dbip-city-lite-2026-10.csv.gz
       curl -fsS -O https://download.db-ip.com/free/dbip-asn-lite-2026-10.csv.gz
       scp dbip-*-lite-2026-10.csv.gz srv1:/tmp/geodb/
       # 在 srv1 上（root）
       bash /opt/secagent/scripts/srv1-geoip-update.sh --from-dir /tmp/geodb --month 2026-10
       # 加 --dry-run 可先只校验不落地；sha256sum 应该与本机一致（本次 d0a4d944… / ed175994…）
     ★ --from-dir 模式下**校验一个都不少**（gzip/体积/首行/行数/v6 段），
       失败依旧"保留旧库 + notify HIGH"：实测给一个截断的 city 包 → 日志写
       "校验失败：不是完整的 gzip"，旧库的 链接/inode/mtime/sha256 四项全同（没被碰过）。

  ★ 库是【启动时装载】的：更新后必须重建容器才生效 ——
    bash /opt/secagent/scripts/srv1-redeploy.sh --force
    （不要 docker compose up 手工重建：会丢 digest 引用，见 CLAUDE.md 硬规矩 1）

  ★ 首次落地实测（2026-10-13 21:46，srv1，已核对）：
      /opt/secagent/geoip                      drwx------ root:root 700
        dbip-city-lite-2026-10.csv.gz          -rw------- 999:999 85,827,400 B  sha256 d0a4d944…
        dbip-asn-lite-2026-10.csv.gz           -rw------- 999:999  7,015,072 B  sha256 ed175994…
        dbip-city-lite.csv.gz -> dbip-city-lite-2026-10.csv.gz     （稳定链接）
        dbip-asn-lite.csv.gz  -> dbip-asn-lite-2026-10.csv.gz
      校验耗时 9.2 s（含解压 300MB 数行数 7,786,864 —— 与真库行数逐位相同）
      --verify 复查："当前在用的库校验全部通过"
      --rollback 在只有一份库时如实报"找不到上一份"（不会假装回滚成功）
      注意：文件属主显示成 `systemd-coredump:input` —— 那是 srv1 上 uid/gid **999 的名字**，
            容器里同一个数字就叫 `secagent`。**按数字认，别按名字认**（与 §22.4 同一条纪律）。

—— 26.3 内存与耗时（真库实测；同一份库，两处都测过）——
  【本机】装载 12,128 ms（7,786,864 行 city + 477,362 行 asn，0 坏行）
  【srv1 实测，2026-10-13 22:0x，一台临时容器 + 与生产完全相同的 JVM 参数（-Xmx1g -XX:+UseSerialGC）
    经只读挂载读 /opt/geoip】装载 17,203 ms / GC 后常驻 152 MB（代码内估算 163 MB）
    关掉 IPv6 的对照：装载 12,239 ms / 常驻 70 MB（省约 82 MB，IPv6 来源归为"未定位"）
    查询吞吐 200,000 次/76 ms ≈ 2,631 次/ms（含 IP 解析）
  （实测姿势：把 target/classes 里的 geoip 类 + slf4j-api.jar 传进 /tmp/geobench，
    用 `docker run --rm --entrypoint java -v /opt/secagent/geoip:/opt/geoip:ro ... GeoIpBenchMain`
    跑一次 —— 不碰生产容器、不占生产端口。★ 注意必须写 `--entrypoint`，否则镜像 ENTRYPOINT 会
    再起一份完整应用，见 26.8-5。）
  索引结构 排序区间数组 + 二分查找
  区间行数 city v4 3,620,434（完全连续）/ v6 4,166,430；asn v4 402,389 / v6 74,973
  记录池去重后 194,466 个城市记录 + 82,135 个 ASN 记录
  ⇒ srv1 现状：容器 mem_limit 1536m、JAVA_OPTS -Xmx1g、当前 RSS 289MB。
    装载后 RSS 预期 ~450MB（1.5GB 上限内，实测装载期间宿主 used 689MB / 1870MB）；
    装载在【后台线程】做，不阻塞健康检查（start_period 120s），装载期间端点如实返回 GEO_DB_LOADING。
  ⇒ 内存吃紧就关 IPv6：APP_GEOIP_IPV6_ENABLED=false 实测省 82MB，
    代价是 IPv6 来源一律归为"未定位"（不上地图）。

—— 26.4 降级语义（四种，谁都别想冒充谁）——
  GEO_DB_MISSING    库文件不存在（还没跑更新脚本 / 卷没挂上）→ available=false + note
  GEO_DB_UNUSABLE   文件在但读不了（不是 gzip / 截断 / 坏行>1% / 区间乱序）
  GEO_DB_LOADING    正在后台装（真库 12 秒）
  GEO_DISABLED      app.geoip.enabled=false（站主要关掉）
  DATA_SOURCE_UNAVAILABLE / QUERY_FAILED   indexer 侧取数失败（与地理库无关）
  ★ 一律【不返回空分布】—— "没装好"与"这段时间没有攻击"必须是不同的话。
  ★ 降级实测（改名/破坏库文件即可复现）：
      mv /opt/secagent/geoip/dbip-city-lite.csv.gz{,.bak}   → GEO_DB_MISSING
      echo not-gzip > /opt/secagent/geoip/dbip-city-lite.csv.gz → GEO_DB_UNUSABLE
      两者都要在重建容器后 curl /api/public/geo 看 reason（别只看代码）。
  ★ 回滚：bash scripts/srv1-geoip-update.sh --rollback（保留 current+prev 两份，更早的自动删）

—— 26.5 口径与红线（改代码前先看这五条）——
  1. 公开面只给【聚合】：国家/省份/ASN + count + uniqueIps + 时间桶。不含 IP（连掩码都不给）、
     不含单条告警、不含内网资产与目的地址。测试用正则扫整段响应体断言"无 IP 形态字符串"。
  2. 排除再聚合：我方公网/内网出口（APP_GEOIP_SELF_IPS，逗号分隔；实测不填的后果是
     "data.srcip 第 2 名就是 srv2 自己的 IP"，地图上会出现我们自己的服务器）、
     内网/环回/链路本地/CGNAT、RFC5737 文档网段、组播与保留段 —— 只进 coverage 计数，不上地图。
  3. 分母诚实披露：coverage.totalAlerts / withSourceIp / geocoded / excludedSelf /
     excludedInternal / excludedReserved / unlocated / invalid / sourceBuckets / sourceBucketsTruncated。
     实测 24h 有 11 万条告警，但带来源 IP 的只是其中一部分（两种字段 data.srcip 与 data.src_ip 都查）
     —— 页面必须写"有来源 IP 的 N 条 / 总 M 条"，不许把几百条画成"全量攻击分布"。
  4. 入榜门槛：count ≥ APP_GEOIP_MIN_COUNT(3) 且占比 ≥ APP_GEOIP_MIN_SHARE_PERCENT(1%)。
     只为防两件具体的事："1 次探测就上榜"和"长尾噪声占满榜单"。
  5. 富化只补 SecurityAlert.srcGeo（内部形状 国家|省|城市|ASN|AS机构，未知段写 -），
     **公开面不输出逐条 srcGeo**（/alerts、/alerts/{aggId}、/latest 里该字段恒为 null；有测试钉住）。

—— 26.6 怎么临时关掉（按影响面从小到大）——
  1) 只关地理分布端点（其余公开端点不受影响）：
       /opt/secagent/.env 加 APP_GEOIP_ENABLED=false → 重建容器 → /api/public/geo 返回 GEO_DISABLED
  2) 省内存保功能：APP_GEOIP_IPV6_ENABLED=false（省 ~80MB，IPv6 归为"未定位"）
  3) 彻底关闭并释放内存：把 compose 里的 /opt/secagent/geoip 挂载注释掉 → 重建容器
     （端点照样在，但如实返回 GEO_DB_MISSING）
     ⚠️ 不改 compose、只删库文件的话，容器里挂载点仍在、只是文件没了 → 同样是 GEO_DB_MISSING。
  4) 回滚到"没有地理富化"的代码版本：按发布链部署上一个 tag（scripts/srv1-redeploy.sh 的
     last-known-good 机制），库文件留着不影响任何既有端点。

—— 26.7 没做到 / 疑虑（如实列，别当成已完成）——
  · 城市级准确率：Lite 库是"IP 段 → 注册地"，不是"人/设备所在地"。国家级大体可信，
    省级可用，城市级经常错（移动网络、云机房、VPN 出口全都会偏）；页面文案不要出现城市级断言。
  · 内网/NAT：内网段按 RFC1918/6598 判为 INTERNAL 并与我方 IP 一起排除；运营商 NAT 之后的
    真实用户无法区分（一个出口 IP 背后可能是几千人）；`10.0.0.10` 这种"内网源地址"在
    Suricata 侧大量存在（实测 24h 43,282 条），它们只进 coverage，不上地图。
  · 体积与更新失败后果：city 库 86MB（gz）/300MB+（解压），只留 current+prev 两份（约 200MB 磁盘）；
    更新失败只会通知 + 保留旧库，地图继续按旧版本绘制（不会变坏图），但如果连续几个月更新失败，
    新分配的 IP 段会显示成"未定位" —— 这正是 coverage.unlocated 存在的意义。
  · 常驻 164MB 对 srv1 的影响：容器上限 1.5GB、堆 1GB、当前 RSS 287MB ⇒ 装载后约 450MB，
    实测同一台机 1GB 堆可以装载；但 HeapDumpOnOutOfMemoryError 会往 /app/data 写 dump，
    真出现 OOM 要先看是否是地理库导致的（那时用 APP_GEOIP_IPV6_ENABLED=false 或 enabled=false 兜住）。
  · TOP N 截断：terms size = APP_GEOIP_TOP_IPS(1000)，超出部分不参与地图；
    响应里 sourceBucketsTruncated=true 时页面必须标注"仅显示最集中的 N 个来源"。
  · IPv6：默认加载，但 Wazuh 侧告警的来源字段是否稳定携带 IPv6 尚未在长周期上验证
    （本轮只验证了库侧与端点侧）。

—— 26.8 落地实测踩到的坑（都是"看起来成了、其实没成"）——
  1) `set -o pipefail` + "提前退出的管道"会把成功读成失败：
     `zcat big.gz | grep -q -m1 '^::,'` —— grep 命中即退，zcat 收到 SIGPIPE（141），
     pipefail 下整条管道判失败 ⇒ 校验把**真库**判成"缺少 IPv6 段"而拒收。
     修法：把这类判断放进 `( set +o pipefail; ... )` 子壳。同类写法还有 `printf | grep -qE`。
  2) bash 里 `local m="$1" c="...$m..."` 在 `set -u` 下直接 `m: unbound variable` 退出，
     而且报错行号指向函数里更靠后的行（看起来完全不像这一行的问题）—— 必须拆成两条 local。
  3) case 模式里写带引号的逗号（`*","*","*",*)`）在 srv1 的 bash 上报
     `syntax error near unexpected token`，报错行同样指向**另一句**。用 tr 数逗号替代。
  4) Windows 上生成 .sh 时注意行尾与编码：CRLF 会让 bash 报奇怪的语法错；
     传文件用 base64 或 scp（`Get-Content/Set-Content` 会把 UTF-8 读成 ANSI 把中文写坏）。
  5) ★★ 别用 `docker rm/stop` 配 `--filter ancestor=<secagent镜像>` 做清理：
     这个选择器**会把生产容器一起选中**（2026-10-13 21:58 我因此把线上容器删掉，
     服务中断约 30 秒）。按容器名/ID 精确操作。
     同理，`docker run --rm <secagent镜像> sh -c 'ls ...'` 不会执行你的命令 ——
     镜像 ENTRYPOINT 会让它**再起一份完整应用**（占内存）。要验证容器视角的文件可读性，
     用 `docker run --rm --entrypoint sh -u 999:999 -v ...:ro <镜像> -c 'ls -l /opt/geoip'`。
  6) 误删容器后的正确恢复路径（本次实跑）：`cd /opt/secagent && bash scripts/srv1-redeploy.sh --force`
     —— 它按发布指针用 **digest** 重建，并跑部署前硬校验 + 健康核对，
     恢复后的 embeddedGitCommit / artifactMd5 与事故前逐位相同（没有引入新代码）。
     注意：这种秒级中断**不会**触发 healthwatch（分钟级巡检）—— 别以为"没人报警 = 没发生"。
  7) **稳定符号链接会把"版本号"吃掉**：部署面用的是
     `dbip-city-lite.csv.gz → dbip-city-lite-2026-10.csv.gz`，而版本号是从**文件名**解析的。
     不解析链接的话，线上 `geoSource` 会变成"DB-IP Lite City 未知版本"（实测：srv1 上第一次
     跑 bench 就是 `city=null`），而单测直接指向带月份的文件，看不见这个问题。
     现在 `GeoIpDatabase.versionOf()` 与 `GeoIpService.loadBlocking()` 都会解析链接（修完 srv1 复测
     `city=2026-10 / asn=2026-10`）。**凡是"从文件名取信息"的逻辑，都要想一遍链接形态。**
  8) 目录权限只 `chmod 700` 不够，必须连**属主一起 chown 到 999:999**：
     首次落地时目录是 root:root 700，容器（uid 999）连 traverse 都不行，
     文件 600 设得再对也读不到（实测：`AccessDeniedException: /opt/geoip/dbip-city-lite.csv.gz`）。
     脚本现在会在落地后 chown 目录并做"按数字核对属主+u+x/u+r"的可读性自检
     （不用 `runuser -u 999`：util-linux 只认用户名，而 uid 999 的名字每台机器不一样）。

<!-- 【补录 2026-10-14】§27 公开面 IP 显示口径：站主拍板"公开面显示真实来源 IP"，
     并与"永不公开"两条一起落地。因 §26 已被 GeoIP 端点预留，本节编号用 27。 -->

## 27. 公开面 IP 显示口径：真实 IP + 两条永不公开（2026-10-14 落地）

```
【站主决定】公开面不再硬掩码 —— 显示【观测到的真实来源 IP】。
【为什么还要有开关】"要不要掩码"如果散落在多个端点里，必然出现第三种口径
  （一个页面真实、一个页面掩码），而且不会报错。所以做成【一处控制、一个来源】。
【唯一开关读取点】org.example.publicapi.PublicIpPolicy（配置 app.public.mask-ips）
  · 它是所有公开端点读口径的唯一入口（含后加的 /api/public/geo）
  · 代码层保证：PublicIpSwitchConfigTest 会扫描 publicapi 包，
    发现第二处 "${app.public.mask-ips" 直接构建失败
```

### 27.1 开关语义（两态，逐字对比）

```
app.public.mask-ips = false  ★默认（站主拍板：显示真实 IP）
  结构化 IP 字段          45.83.91.12                        真实地址（自动剥端口）
  内网/保留/链路地址      内网/未知                          ← 任何口径下都不作为攻击源
  认不出的取值            未知                               不猜、不原样透出
  自由文本里的公网 IP     原样保留
  自由文本里的内网 IP     内网/未知
  ipDisclosure.masked     false
  note 类文案             "…来源 IP 显示观测到的真实地址（内网/保留地址写作「内网/未知」）…"

app.public.mask-ips = true   （改造前口径，一键回退用）
  结构化 IP 字段          45.83.***.***                      与 2026-10-14 之前【逐字节相同】
  内网/保留/链路地址      内部地址
  认不出的取值            ***
  自由文本里的任何 IP     一律 PublicIpMask.maskAll（公网掩码、内网→内部地址）
  ipDisclosure.masked     true
  note 类文案             与改造前【逐字节相同】（原句照旧，不许改字）
```

**影响面（全部走 PublicIpPolicy，一个都不会漏）**：

| 端点 | 受影响的字段 |
|---|---|
| `GET /api/public/overview` | 无来源 IP 字段；仅带 `ipDisclosure`（口径声明） |
| `GET /api/public/alerts` | `list[].srcIp`（聚合来源）、`stats` 统计文本 |
| `GET /api/public/alerts/{aggId}` | `members[].srcIp`、`summary.srcIp` |
| `GET /api/public/honeypot` | `topSources[].key`、`timeline[].srcIp`、`timeline[].detail` 文本内的 IP |
| `GET /api/public/audit` | `blocks[].ip`、`actions[].target`、`actions[].reason` 文本内的 IP |
| `GET /api/public/latest` | `latestEvent.srcIp`、`latestBlock.ip` |
| `GET /api/public/kb` | 片段/标题里内嵌的 IP（经 PublicOutputGuard） |
| `POST /api/public/ask` | 回答正文与引用片段里的 IP、`clientIp`（新增字段） |
| `GET /api/public/geo` | 该端点**不给任何 IP**（设计如此）；只继承 `ipDisclosure` 与资产名过滤 |

### 27.2 怎么一键切回掩码（一条配置，不改代码、不重新部署）

```bash
# srv1: /opt/secagent/.env
APP_PUBLIC_MASK_IPS=true
# 然后按发布链重建容器（★不要用 docker compose up 手工重建 —— 会丢 digest 引用）
# 核对生效：GET https://demo.xiaokeqing.cn/api/public/latest | jq .data.ipDisclosure
#   期望 {"masked":true,...}，且 .data.latestEvent.srcIp 形如 "45.83.***.***"
# 再核对：honeypot 的内网来源应显示「内部地址」（不是「内网/未知」）
```

⚠️ **两个必须同时确认的地方**（本项目在这里踩过坑，见 §6.7 与 `APP_RAG_*` 注释）：
1. `docker-compose.yml` 的 `environment` 段必须有 `APP_PUBLIC_MASK_IPS` 透传行（已入库）；
2. 该键**不许留空**：空字符串绑到 boolean 会让应用直接启动失败（不是静默降级）。
   要掩码就显式写 `true`。

### 27.3 口径字段 `ipDisclosure`（所有公开响应同一位置、同一形状）

```jsonc
// 每个 /api/public/** 的 data 里都有（统一由 PublicApiController.ok(...) / ship(...) 补上）
"ipDisclosure": {
  "masked": false,                                    // 与开关一致：true=展示的是网段掩码
  "notice": "观测到的来源地址，未经验证，仅供参考",     // 两个口径同一句话（避免口径漂移）
  "removalContact": "https://xiaokeqing.cn/about/"    // 移除/更正入口（app.public.removal-contact）
}
```

- 页面只要读这三个键就能渲染"口径声明 + 移除入口"，**不需要知道开关细节**（博客仓库不需要改）。
- `removalContact` 默认是博客关于页；站主要换成邮箱就改 `APP_PUBLIC_REMOVAL_CONTACT`。
- 该字段是**新增字段**，既有字段一个都没改名/删除（硬约束）；ETag / 限流 / CORS / 快照语义不变
  （`ipDisclosure` 是常量，不影响 ETag 稳定性）。

### 27.4 为什么"口令"与"资产名"永不公开（与开关无关）

这两条**不是**"敏感度取舍"，是站主定的硬约束，代码里独立于开关、永远不会被打开：

1. **蜜罐抓到的完整口令 / 凭据（CredentialStructure）**
   - 公开一个真实口令 = 替攻击者完成一次撞库验证，对任何复用了该口令的第三方站点都是直接伤害 ——
     与我们被不被投诉无关。
   - 现在只出**结构**：`username`（用户名可以给）、`passwordLength`、`passwordCharClasses`、
     `weakPassword`（粗判：内置常见弱口令表 / ≤8 位且单一字符类 / ≤6 位）。
   - **同时修掉两个真实泄露点**（改造前就在漏）：
     · `honeypot.topCredentials[].key` 原本是 `"root / 123456"` —— **完整口令原文直出**；
       现在 `key` 保持同一个键名，值改成结构摘要 `"root / 6 位·数字·弱口令"`，并新增 4 个结构字段；
     · `honeypot.timeline[].detail` 是蜜罐规则描述原文（`…用户=root 口令=123456 来源=…`），
       改造前只掩了 IP —— **完整口令随 timeline 出过公网**。现在整段先过 `口令=[口令已隐藏]`。
   - 公开问答链路上也加了中文口令规则（`PublicOutputGuard` 的 `口令|密码[:=：]…` 一律打码）。
   - 测试：`CredentialStructureTest`（每个口令形态都断言原文不出现）、
     `PublicIpDisclosureE2ETest.credentialsNeverReachThePublicPayload`（**两种口径 × 四个端点**）。

2. **内部资产名（PublicAssetFilter，配置 `app.public.asset-blocklist`）**
   - 字段白名单挡得住结构化的 `dstAsset`，挡不住自由文本里的 `web-01` ——
     而 F5 方案 B 会把命中的知识库引用片段**直出到回答正文**，实测这些 mock 名就是这么出去的。
   - 现在公开响应出海前对**整棵 data 树**过一遍停用词表（`PublicApiController.ship(...)` 的 deep-scrub），
     命中即替换为 `[内部标识已脱敏]`；`PublicOutputGuard` 里也过一遍（覆盖回答正文与引用）。
   - 默认词表 = **实测泄露过的名字**：`web-01/web-02/web-03`、`db-01`、`auth.log`、
     `/api/order/detail`、`/upload/files/`。**刻意不收 `srv1`/`srv2`**（公开端点本就用它说明两台机器在线状态，
     收掉等于改既有口径）。
   - 规则正则原文、内网地址同样不在公开面出现（前者从未出参，后者 →「内网/未知」/「内部地址」）。

### 27.5 怎么验证（都可重复跑）

```bash
# ① 开关与口径（一条命令看两件事）
curl -s https://demo.xiaokeqing.cn/api/public/latest | jq '{ip: .data.latestEvent.srcIp, disclosure: .data.ipDisclosure}'
#   默认（真实态）期望： ip 形如 "106.37.205.248"，disclosure.masked=false
#   切到掩码后期望：      ip 形如 "106.37.***.***"，disclosure.masked=true

# ② 口令永不出现在任何公开响应里（两种口径都跑一遍；这里用 grep 做"整包体检"）
for u in latest alerts honeypot audit; do
  curl -s "https://demo.xiaokeqing.cn/api/public/$u" | grep -E '口令=[^[]|密码=[^[]' && echo "★ $u 漏口令"
done

# ③ 内网地址没有被当成攻击源（应只见「内网/未知」/「内部地址」）
curl -s https://demo.xiaokeqing.cn/api/public/honeypot | grep -E '172\.18\.|10\.0\.0\.' && echo "★ 漏内网"

# ④ 内部资产名没随引用直出（F5-B 直出的正文也要看）
curl -s https://demo.xiaokeqing.cn/api/public/alerts | grep -E 'web-0[0-9]|auth\.log|/api/order/detail' && echo "★ 漏资产名"

# ⑤ 本地全绿
mvn -B test
```

**测试清单（新增，共 6 个类 / 37 条）**：
`PublicIpPolicyTest`（两态 / 默认值 / 内网不当攻击源 / 掩码态与 PublicIpMask 逐字节一致 / 口径字段形状）、
`PublicMaskedRegressionTest`（**三个端点的掩码态黄金串逐字节比对**，冻结串在 `src/test/resources/publicapi/masked-golden-*.json`）、
`PublicIpDisclosureE2ETest`（两种口径 × 四个端点的端到端契约 + 口令不泄露 + 资产名过滤 + 内网不当攻击源）、
`CredentialStructureTest`、`PublicAssetFilterTest`、`PublicIpSwitchConfigTest`（默认值 / .env 模板 / compose 透传 / "开关只有一个读取点"）。

### 27.6 没做到 / 疑虑（如实列，别让"CI 全绿"被读成"没风险"）

1. **真实 IP 会被爬走**：这是站主拍板接受的代价。公开面现在给出的是一份**可被第三方直接采集的
   攻击源清单**（含时间、类型、来源地址）—— 对做威胁情报聚合的人是有价值的输入。
   本改造的取舍是"公开透明优先"；如果哪天想收回，**一条配置即可**（§27.2），不需要改代码。
2. **口径漂移只能靠测试发现**：`PublicIpSwitchConfigTest` 只能保证"开关只有一个读取点"，
   不能保证"每个端点都用它"。真正兜底的是 `PublicIpDisclosureE2ETest`
   —— 它固定在 4 个端点上；**以后新增公开端点时必须同时加进那个清单**（否则新端点可能是掩码态）。
3. **可能漏改的地方**（已核查，但结构性风险仍在）：
   - 公开面之外的地方**不动**（`ResponseGuard`、通知模板、内部界面仍按原口径）；
   - `publicAggregate`/`publicAlert`/`timelineForPublic`/`topSourcesForPublic`/`actionTextForPublic`
     是**白名单式**逐个字段处理 —— 将来有人往这些方法里加新字段时，必须显式套 `policy().display(...)`；
   - 内部资产名词表是**静态词表**，只能挡住"名字已知"的资产；新资产名不会自动进表。
     它是兜底，不是"资产信息过滤器"（真正的边界仍是公开字段白名单）。
4. **口令"结构"仍有信息量**：长度 + 字符类 + 弱口令标记对针对性爆破是有用的信息
   （例如"就是 6 位纯数字"）。站主明确允许给结构，所以这里按"允许"落地；
   如果哪天要更保守，把 `topCredentials` 换成"只有弱口令计数"是更小的公开面。
5. **弱口令标记是粗判**：三条判据（内置常见表 / ≤8 位单一字符类 / ≤6 位）都是启发式，
   不是密码强度评估。页面措辞必须按"粗判"写，别让人读成"我们已经评估过你的密码强度"。
6. **`/api/public/geo` 与本次改造的交集只有 `ipDisclosure` 与资产名过滤**：
   该端点本身不给任何 IP（设计如此），它的运维见 §26（由 GeoIP 那一路负责）。
