# RUNBOOK · 部署与发版核验（srv1 / ACR / 本地构建）

> 适用对象：负责把 `sec-agent` 发布到 srv1 的人（含 AI）。
> 本文只讲**部署链路怎么走、怎么证明真的生效、出事怎么退**。
> 架构与业务细节看 [RUNBOOK.md](../RUNBOOK.md)；从零搭机器看 [00-从零运行傻瓜手册-Windows.md](00-从零运行傻瓜手册-Windows.md)。
>
> 立此文档的直接原因：2026-10-18 一天内连续三次「看起来成功、线上还是旧代码」（见第 2 节）。
> 三次事故的共性**不是技术故障，而是缺少判据**——每一步都打印了 OK，但没有一步去核对"线上跑的到底是不是我刚做的东西"。

---

## 0. 三条铁律（读操作、写操作都适用）

1. **成功不看命令输出，看指纹。** `docker compose up -d` 打印 `Started`、`git reset --hard` 打印 `HEAD is now at`、`docker build` 打印 `Successfully tagged`——这三句话都**不构成**"线上已是新代码"的证据。唯一证据是第 3 节的三件事全部对上。
2. **srv1 上的 `docker-compose.yml` 是站主手工维护的**，不是仓库版本。任何从仓库方向覆盖它的操作（`git reset`、`git checkout --`、`git restore`）都必须先备份。
3. **ACR `:stable` 指针 = 线上生效开关。** 谁把 `:stable` 推到哪个 digest，5 分钟内 `secagent-redeploy.timer` 就把 srv1 换成那个 digest。本地直接起的容器不是"部署完成"，只是"等 timer 来纠正的中间态"。

---

## 1. 官方发布链：三条路，三种适用场景

| | 路 A：GitHub Actions → ACR → timer | 路 B：本机 `build-on-server.sh` | 路 C：ACR push + `srv1-redeploy.sh --expect-commit` |
|---|---|---|---|
| 典型场景 | **常规发版**（默认走这条） | 应急验证、拷 ACR 拿不到的新 jar、排查"构建本身对不对" | 手工构建/手工 push 了镜像，或需要**立刻**上线不等到下个 5 分钟窗口 |
| 谁构建 | GitHub Runner | srv1 本机 docker | 你自己（本机 docker） |
| 谁部署 | timer（每 5 分钟） | 脚本当场 `compose up -d` | `srv1-redeploy.sh` 当场按 digest 部署 |
| 线上镜像 | ACR `:stable` digest | `secagent:local`（**临时态**） | ACR 某 digest |
| 持久性 | 持久 | **非持久**，下个 timer 窗口会被拉回指针镜像 | 持久 |
| 需要 label | 是（工作流自动打） | 否 | 是（`org.opencontainers.image.revision` = full sha） |
| 失败表现 | Actions 红；`deploy-chain-check.sh` 告警 | exit 7（镜像一致性硬校验）或 build 失败 | exit 1 已自动回滚 / 3 前置不满足 |

### 1.1 路 A：GitHub Actions → ACR → timer（默认路径）

```bash
# 本机：确认工作区干净、HEAD 就是要发的提交
git status --porcelain          # 必须为空
git rev-parse HEAD              # 记下 full sha

git push origin main            # 或 gh workflow run build-image.yml
```

工作流 `.github/workflows/build-image.yml` 是 **fail-closed** 的，顺序为：
工作区干净 + HEAD==GITHUB_SHA → `mvn test` → `package` → **解开 jar 校验 `BOOT-INF/classes/git.properties` 里 `git.commit.id`==GITHUB_SHA 且 `git.dirty`==false** → 算 jar md5/sha256 → 用 `Dockerfile.runtime` 构建并打两个 label：

- `org.opencontainers.image.revision=<GITHUB_SHA>`
- `artifact-md5=<JAR_MD5>`

再从镜像里 `docker create` + `cp` 出 jar 重算 md5 与本地比对 → Trivy 扫 HIGH/CRITICAL（`exit-code 0`，结果 JSON 上传）→ 登录 ACR → **先 push `<short-sha>`，最后 push `stable`**（`stable` 是生效开关，所以放最后）→ 把 `stable` 和 `<short-sha>` 的 `RepoDigests` 拉回来比 digest 是否一致 → 写 job summary 表格。

srv1 侧确认（不部署也能看）：

```bash
sudo systemctl list-timers secagent-redeploy.timer --no-pager   # NEXT / LAST
sudo journalctl -u secagent-redeploy.service --since "30 min ago" | tail -40
sudo bash /opt/secagent/scripts/srv1-redeploy.sh --dry-run      # 只看不做
```

`secagent-redeploy.timer`：`OnCalendar=*:0/5`（**每 5 分钟**，别写成 `*/5`——那是每 5 秒）、`RandomizedDelaySec=45`、`Persistent=true`；service 的 `ExecStart=/bin/bash /opt/secagent/scripts/srv1-redeploy.sh`，`WorkingDirectory=/opt/secagent`。

`stable` 推上去到 srv1 生效，最长延迟约 5 分钟 + 45 秒。要马上生效就别等 timer：

```bash
sudo bash /opt/secagent/scripts/srv1-redeploy.sh --expect-commit <full-sha>
```

- 退出码：`0` 已同步 / `1` 失败并已回滚 / `2` 锁未取得 / `3` 前置条件错误。
- 它在你按了 `--expect-commit` 时会做**三方指纹核对**：镜像 label `revision`==期望 commit、镜像 label `artifact-md5`==jar md5、容器起来后 `/api/health` 的 `embeddedGitCommit`==revision 且 `artifactMd5`==label 且 `status=ok` 且 `fingerprintMismatch=false`。任一项不满足，当场回滚。

### 1.2 路 B：本机构建 + srv1 部署（应急用）

```powershell
# 1) 把源码同步到 srv1（含 compose 保护，详见 2.1）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\sync-source-to-srv1.ps1 -HardReset

# 2) 构建 + 部署（-AllowDirty 允许服务器侧有未跟踪文件）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\deploy-remote-build.ps1 -AllowDirty
```

`deploy-remote-build.ps1` 会把 `scripts/build-on-server.sh` scp 到 srv1 再 `bash` 它；`build-on-server.sh` 现在在 `docker compose up -d --force-recreate secagent` 之后**硬校验**容器实际镜像 ID 与 `secagent:local` 是否一致，不一致直接 `exit 7`（详见 2.2）。

**这条路的结果不是持久态。** 因为 compose 的 `image:` 通常指向 ACR `:stable`，`secagent-redeploy.timer` 在下一个 5 分钟窗口会按指针 digest 把容器换回去（这就是事故 C）。所以：

- 只是**临时验证**（跑 10 分钟看行为）→ 可以，但要知道它会被换回。
- 需要**持续跑本地镜像** → 先 `sudo systemctl stop secagent-redeploy.timer`，完事务必 `enable --now` 打开，并在文档/群里有交代。
- 需要**正式上线** → 别停在这里，走 1.3 把镜像推成 `:stable`。

### 1.3 路 C：ACR push + `srv1-redeploy.sh --expect-commit`

手工构建时**必须自己打 label**，否则部署闸门会拒绝（闸门要求 label 存在且等于期望 commit）：

```bash
FULL_SHA=$(git rev-parse HEAD)
SHORT=$(git rev-parse --short HEAD)
JAR_MD5=$(md5sum target/sec-agent.jar | cut -d' ' -f1)
REG=crpi-bhyvm4rwtqasz9y3-vpc.cn-hangzhou.personal.cr.aliyuncs.com/xiaokeqing/secagent

docker build -f Dockerfile.runtime \
  --label "org.opencontainers.image.revision=$FULL_SHA" \
  --label "artifact-md5=$JAR_MD5" \
  -t $REG:$SHORT .
docker push $REG:$SHORT
docker push $REG:stable          # 生效开关，最后推

# srv1 上（按 digest 部署 + 三方指纹核对）
sudo bash /opt/secagent/scripts/srv1-redeploy.sh --expect-commit $FULL_SHA
```

> 手工 push 前请先跑 `bash scripts/preflight-release.sh`（有阻塞项退出码 1）确认没有把不该发的状态推上去。

---

## 2. 今天三个事故：形状、判据、修法

### 2.1 事故 A：`git reset --hard` 把服务器 compose 覆盖成仓库版

**形状**：srv1 上 `sudo git reset --hard <sha>`。因为 `docker-compose.yml` 在 srv1 是 **tracked 但被站主改过**（`git status` 里就一行 ` M docker-compose.yml`），`--hard` 把它恢复成仓库提交版：仓库版 `image:` 指向阿里云 `:stable`，站主手工加的 TTS 段（`APP_TTS_*`）、quota 段（`daily-limit` 等）全部消失。命令输出一切正常（`HEAD is now at ...`），没有一行报错。

**判据**：

```bash
# 0=线上 compose 与仓库版一致；1=线上被改过（正常态！站主本来就改过）
sudo git -C /opt/secagent diff --quiet HEAD -- docker-compose.yml; echo "exit=$?"

# 指纹对比（事故前的正常值：7910ddb41978b7abd2a467f31758e9ab）
sudo md5sum /opt/secagent/docker-compose.yml /root/docker-compose.yml.srv1-.bak

# 段落还在不在
sudo grep -nE 'APP_TTS_|daily-limit|mem_limit|^ *image:' /opt/secagent/docker-compose.yml | head
```

**修法**（事后）：

```bash
sudo cp -a /root/docker-compose.yml.srv1-.bak /opt/secagent/docker-compose.yml
sudo md5sum /opt/secagent/docker-compose.yml      # 应与备份一致
```

**已固化**：`scripts/sync-source-to-srv1.ps1` 的 `-AlignHead`（`reset --soft`）/ `-HardReset`（`reset --hard`）路径现在自带 compose 保护：

- reset 前：`git -C <RemoteDir> diff --quiet HEAD -- docker-compose.yml`，exit=`1` 表示线上被改过 → 先 `cp -a` 备份到 `/root/docker-compose.yml.syncbak-<yyyyMMdd-HHmmss>`，打印 `[OK] 已备份 ... -> ...（md5=...）`；exit=`0` 表示一致，无需备份；**其它退出码直接放弃 reset**（宁可不重置，也不冒险覆盖）。
- reset 后：`install` 到同目录临时文件 + `mv -f`（同目录 rename 是原子的）恢复，并把恢复后的 md5 与备份比对，打印 `[OK] 已恢复 ...（md5=...，与备份一致）`；不一致就 Fail。
- reset 失败也照样恢复，不会留下"仓库版 compose"这种半成品状态。

实机验证（2026-10-18）：`-AlignHead` 与 `-HardReset` 两条路径都跑过，compose md5 前后都是 `7910ddb4…`，`git status` 仍只有那一行 ` M docker-compose.yml`。

**⚠️ 仍然注意**：保护只覆盖 `docker-compose.yml` 这一个文件。srv1 上还有 `vendor/`、`al-test/`、`scripts/*.sh` 等未跟踪文件，`--hard` 不会动它们（`git clean` 才会）——**永远不要在 srv1 上跑 `git clean -fdx`**。

### 2.2 事故 B：构建出 `secagent:local`，起来的却是 ACR 旧镜像

**形状**：`docker compose up -d --force-recreate secagent` 打印 `Started`/`Recreated`，一切正常。但容器实际用的是 ACR 旧镜像 **digest `4ecf4741…`**（`sha256:4ecf474105b86d7f54646f386176877ac3776d7a13e1b58bfbdfefafe87893ba`），不是刚构建的 `secagent:local`。原因：compose 的 `image:` 指向 ACR 引用，`up` 会去拉那个引用；`secagent:local` 构建成功只是"镜像存在"，和"容器用了它"是两件事。

**判据**（三步，缺一不可）：

```bash
# ① 容器实际用的镜像 ID
cd /opt/secagent && docker inspect "$(docker compose ps -q secagent)" --format '{{.Image}}'

# ② 本地构建的镜像 ID
docker image inspect secagent:local --format '{{.Id}}'

# ③ ①≠② 就是事故 B。再用 jar 指纹交叉确认：
docker exec secagent md5sum /app/app.jar
docker image inspect secagent:local --format '{{index .Config.Labels "artifact-md5"}}'
```

（本机路径会打印"期望 / 实际"两行然后 `exit 7`。）

**修法**：把 compose 的 `image:` 改回 `secagent:local`（站主原本就是这么写的），或**走官方路径**把它变成 ACR 的 `:stable`（推镜像 → `--expect-commit`）。

**已固化**：`scripts/build-on-server.sh` 在 `docker compose up -d --force-recreate secagent` 之后加了硬校验（原命令不变，紧跟其后）：

```bash
if ! EXPECT_IMAGE_ID="$(docker image inspect secagent:local --format '{{.Id}}' 2>/dev/null)"; then ... exit 7; fi
ACTUAL_IMAGE_ID="$(docker inspect "$(docker compose ps -q secagent)" --format '{{.Image}}')"
# 空值 → exit 7；不等 → 打印"期望（secagent:local）/实际（容器 .Image）"两行 → exit 7
```

用 `if !` 形式是因为 `set -euo pipefail` **不捕获命令替换失败**——`X=$(cmd)` 失败时脚本会继续往下跑，`if !` 才能拦住。

### 2.3 事故 C：timer 把本地部署的容器换回指针镜像

**形状**：本地部署成功后一切正常，容器跑得好好的。5 分钟内 `secagent-redeploy.timer` 触发，按 ACR `:stable` 指针的 digest 巡检，发现容器不是指针镜像 → 换回指针镜像。人看到的是"我明明部署了，过一会儿又变回去了"，而 `journalctl` 里那次的输出全是 `[OK]`。

**判据**：

```bash
sudo systemctl list-timers secagent-redeploy.timer --no-pager
sudo systemctl cat secagent-redeploy.service | grep ExecStart
sudo journalctl -u secagent-redeploy.service --since "2 hours ago" | tail -60
# 看容器镜像是不是又回到 ACR 引用
docker ps --filter name=secagent --format '{{.Names}} {{.Image}} {{.Status}}'
```

**修法**：不要跟 timer 对抗，走官方路径把"你想跑的东西"变成 `:stable`（路 A 或路 C）。确实需要长时间跑本地镜像时，显式 `sudo systemctl stop secagent-redeploy.timer`，并把这件事写进交接。

---

## 3. 发版后必须核对的三件事

**缺一件就别宣布发版成功。** 三件都过，才算"线上是新代码"。

### 3.1 `/api/health` 的三个字段

```bash
curl -s http://127.0.0.1:9900/api/health | python3 -m json.tool | grep -E '"(status|buildSha|embeddedGitCommit|expectedReleaseCommit|artifactMd5|fingerprintMismatch)"'
```

| 字段 | 要求 | 含义 |
|---|---|---|
| `buildSha` | == 你刚发的 **full sha** | 进程自报的构建来源提交 |
| `fingerprintMismatch` | **必须 `false`** | 应用发现"我该是的版本"与"我实际是"不一致时为 `true`，并给 `fingerprintIssues` |
| `artifactMd5` | == 镜像 label `artifact-md5` | jar 内容的 md5 |

辅助字段：`embeddedGitCommit`（jar 内 `git.properties` 的 commit，最硬的证据）、`expectedReleaseCommit`（应与 `buildSha` 相同）、`sourceSha`（源码侧，可能 `unknown`）。

> 用 `127.0.0.1:9900`，**不要**从公网经 CDN 取——会拿到缓存或别的实例。

### 3.2 容器内 jar 的 md5

```bash
docker exec secagent md5sum /app/app.jar
```

必须等于 `artifactMd5`，也等于镜像 label（`docker image inspect <ref> --format '{{index .Config.Labels "artifact-md5"}}'`）。这条查的是"容器里那份文件"，`/api/health` 查的是"进程自己报的身份"——两者都要对，才排除"进程是新的、jar 是旧的"这种怪状态。

### 3.3 `home.js` 的 keys

`/api/public/home` 与 `/api/public/home.js` 是**同一端点**（不是静态文件，仓库里没有 `home.js` 这个文件）。`data` 下有 **5 个业务块 + 1 个统一字段**：

```bash
curl -s http://127.0.0.1:9900/api/public/home.js | python3 -c 'import sys,json; d=json.load(sys.stdin); print(sorted(d["data"].keys()))'
# 期望：['alerts', 'audit', 'geo', 'health', 'honeypot', 'ipDisclosure']
```

- `alerts` / `geo` / `honeypot`：三个必有块（各自独立快照缓存 + 失败兜底）。
- `audit` 是**可选块**：上游处置审计日志取不到就**不放这个键**（只降级，不让首屏 500，`buildHome()` 里 `catch RuntimeException` 后会打一条 warn），所以少了 `audit` 未必是发版失败，但**必须看见 `health` 块**——`data.health` 里的 `buildSha`/`artifactMd5` 是给前端/外部核验用的第二份自报。
- `ipDisclosure`：所有公开端点的统一口径字段，由 `ok(...)` 信封统一补（每个子块自己也 `ship(...)` 过一次）；**它少了说明信封层被改坏了**，比少一个业务块更严重。
- 线上常见"看起来成功"：只 curl 了 `/api/health`（200）就收工，而首页少了一块、或 `home.js` 结构还是旧的。

---

## 4. 回滚

回滚基准文件：`/opt/secagent/last-known-good.json`（由 `srv1-redeploy.sh` 第 8 步写入，`python3 -m json.tool` 校验过），含 `digest`、`ref`、`commit`、`artifactMd5`、`deployedAt`、`previousImageId`、`pointerTag`。

```bash
# 先干看（不动作）
sudo bash /opt/secagent/scripts/srv1-rollback.sh --dry-run

# 回滚到 last-known-good（默认行为）
sudo bash /opt/secagent/scripts/srv1-rollback.sh

# 回滚到指定的某个 digest（事故现场用）
sudo bash /opt/secagent/scripts/srv1-rollback.sh --to sha256:<digest>
# 也可以连 commit 和 md5 一起指定，回滚后一并核对
sudo bash /opt/secagent/scripts/srv1-rollback.sh --to sha256:<digest> --commit <sha> --md5 <md5>
```

- 退出码：`0` 成功 / `1` 失败 / `3` 前置条件不满足。
- 回滚**不改** `last-known-good.json`（避免把回滚目标污染成新基准），另写 `/opt/secagent/last-rollback.json`。
- 回滚过程会把 compose 备份进 `/opt/secagent/releases/docker-compose.yml.bak-rollback-<yyyyMMdd-HHmmss>`（`srv1-rollback.sh` 内做），`releases/` 下已有多份 `docker-compose.yml.bak-<日期>`、`health-watchdog.state`、`secagent-state.env`。
- 回滚完仍然要跑第 3 节的三件事——回滚本身也可能"看起来成功"。

---

## 5. 常见误判（每条都真发生过）

1. **"`/api/health` 返回 200，所以发版成功"** —— 200 只说明进程活着、路由在。旧代码一样 200。**必须比 `buildSha` / `artifactMd5` / `fingerprintMismatch`。**
2. **"`docker compose up -d` 打印了 `Started`"** —— 它只说"容器起来了"，没说"起来的是哪个镜像"（事故 B）。
3. **"`secagent:local` 构建成功"** —— 镜像存在 ≠ 容器用它。
4. **"`git log -1` 显示新 commit"** —— 那只证明**服务器上的源码目录**是新的，jar 可能是旧的。作数的是 jar 内 `git.properties`（`embeddedGitCommit`）。
5. **"`status: ok`"** —— 不看 `fingerprintMismatch`。它为 `true` 时就是在喊"线上不是我该有的样子"，附带的 `fingerprintIssues` 会指出差在哪。
6. **"curl 了 https://域名/api/health"** —— 可能经 CDN 缓存或打到别的实例；核验一律 `127.0.0.1:9900`。
7. **"`docker images` 里一堆 `<none>` 无所谓"** —— `4ecf4741…` 这个旧 digest 就是事故 B 的主角，留在本地容易被 `up` 误用。
8. **"回滚了就好了"** —— 回滚后同样要三件事核对；而且若 `:stable` 指针还指向坏 digest，下个 timer 窗口会把它推回来，必须把指针一起处理好。

---

## 附录 A：路径速查

| 是什么 | 位置 |
|---|---|
| 应用目录 / compose | `/opt/secagent/docker-compose.yml` |
| 部署脚本 | `/opt/secagent/scripts/srv1-redeploy.sh` |
| 回滚脚本 | `/opt/secagent/scripts/srv1-rollback.sh` |
| 回滚基准 | `/opt/secagent/last-known-good.json`、`/opt/secagent/last-rollback.json` |
| 历史备份 | `/opt/secagent/releases/` |
| compose 手工备份（站主） | `/root/docker-compose.yml.srv1-.bak` |
| compose 同步备份（脚本自动） | `/root/docker-compose.yml.syncbak-<时间戳>` |
| 定时器 | `secagent-redeploy.timer` / `secagent-redeploy.service` |
| 健康端点 | `http://127.0.0.1:9900/api/health` |
| 首页聚合端点 | `http://127.0.0.1:9900/api/public/home`（=`/api/public/home.js`） |
| ACR | `crpi-bhyvm4rwtqasz9y3-vpc.cn-hangzhou.personal.cr.aliyuncs.com/xiaokeqing/secagent` |

## 附录 B：一条命令体检

```bash
# 链路体检（指针/定时器/回滚基准是否自洽），0=全绿 1=有告警
sudo bash /opt/secagent/scripts/deploy-chain-check.sh
sudo bash /opt/secagent/scripts/deploy-chain-check.sh --json    # 机器可读

# 公网侧端到端核验
bash scripts/verify-public-endpoint.sh
```

## 变更记录

- **2026-10-18**：新建本文。同日两个脚本加固：
  - `scripts/sync-source-to-srv1.ps1`：`-AlignHead`/`-HardReset` 前置 compose 备份 + 后置原子恢复（新增 `Backup-ComposeIfDirty` / `Restore-Compose`），防事故 A。
  - `scripts/build-on-server.sh`：`compose up` 后加容器镜像 ID 硬校验，不一致 `exit 7`，防事故 B。