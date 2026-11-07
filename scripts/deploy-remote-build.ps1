<#
.SYNOPSIS
  去本机化的部署：本机只编译 jar，服务器自己构建镜像并重启。
  **构建前 fail-closed 校验源码，构建后校验 jar 的来源，部署后严格核对 health。**

.DESCRIPTION
  分工（为什么这样分）：
    · 本机：JDK + Maven 打包 jar（几十 MB）—— **不需要 Docker**、不吃本机镜像空间
    · 服务器 1：docker build --network=host 构建镜像 + compose 重建

  对比原来的做法（本机 docker build → docker save 311MB → scp）：
  那个做法在【本机没 Docker / C 盘满 / 内网无梯子】时完全发不了版（实测踩过：C 盘被镜像占满导致瘫痪）。
  现在只依赖 mvn + scp，服务器有 Docker 与磁盘即可。

  构建来源校验链（本脚本不再只是"把 jar 传上去"，而是每一环都留下了可核验的证据）：
    ① 构建前  —— 工作区干净 + HEAD == 目标 commit，否则**连 mvn 都不跑**
    ② 构建后  —— 从 jar 里把 git.properties 读出来，核对 git.commit.id.abbrev == 目标 commit、
                 git.dirty == false；对不上**连 scp 都不做**（防止 -SkipBuild 复用旧 jar）
    ③ 服务器侧 —— build-on-server.sh 再核对一次源码树（clean + HEAD == 目标）+ 镜像内 jar MD5 硬校验
                 + 部署前记录镜像 ID、部署后断言容器 .Image == 本次构建镜像 ID（防复用旧 image）
                 + 对运行中的容器做 `docker exec md5sum /app/app.jar` 一致性断言（防 app.jar 不是本次产物）
    ④ 部署后  —— **轮询** /api/health（最多 120s、每 3s）直到 status=ok 且 embeddedGitCommit == 目标
                 commit，再核对 buildSha 一致、fingerprintMismatch=false；超时才失败并打印最后一次
                 health 全量 JSON（避免"容器还在 starting"被误判成部署失败）
    ⑤ 冲突检测 —— 服务器上的 secagent-redeploy.timer 会按 ACR digest 把容器滚回旧镜像；
                 检测到 active 时打印醒目警告与建议命令，但**不自动停**（停不停由站主决定）

  为什么①③是"源码"校验而不是多余：真实事故是老 Dockerfile 在镜像内用**服务器上的旧 src** 编译，
  于是 BUILD_SHA（环境变量自述）显示新版本、容器里跑的是旧代码。
  只信环境变量就会一直被骗；所以要么源码确实就是目标 commit，要么就别构建。

.EXAMPLE
  pwsh -File scripts/deploy-remote-build.ps1
  pwsh -File scripts/deploy-remote-build.ps1 -SkipBuild          # 复用已有 jar（仍会校验 jar 的来源）
  pwsh -File scripts/deploy-remote-build.ps1 -TargetCommit deadbeef   # 演示 fail-closed：中止
  pwsh -File scripts/deploy-remote-build.ps1 -AllowDirty         # 显式承认工作区脏
#>
param(
  [string]$SshHost = 'secagent-srv1',
  [string]$RemoteDir = '/opt/secagent',
  # 目标 commit（默认 = 当前 HEAD）。存在的意义：让"HEAD == 目标"成为一个**真的会被违反**的断言，
  # 而不是自己跟自己比 —— 传错一个 commit 就必须中止。
  [string]$TargetCommit = '',
  [switch]$SkipBuild,
  # 工作区有未提交改动时的显式放行（默认不放行）。放行意味着"这个 jar 不对应任何 commit"，
  # jar 内 git.properties 会带 dirty=true，health 会一直显示 degraded —— 这是设计如此。
  [switch]$AllowDirty
)

$ErrorActionPreference = 'Continue'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

function Step($n, $msg) { Write-Host "==> $n $msg" }
function Fail($msg) { Write-Host "[X] $msg" -ForegroundColor Red; exit 1 }
function Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }

# 读取服务器上某个 systemd unit 的状态（active/inactive/failed/unknown）。
function Get-RemoteUnitState([string]$unit) {
  $s = (ssh -o ConnectTimeout=20 $SshHost "systemctl is-active $unit 2>/dev/null || true" 2>$null | Out-String).Trim()
  if (-not $s) { return 'unknown' }
  return $s
}

# ============================================================
# 【冲突检测】secagent-redeploy.timer 每 5 分钟按 ACR stable digest 巡检：
#   只要发布指针和当前运行 digest 对不上，它就会 pull + 重建，把容器滚回 ACR 里的镜像。
#   实测后果：手工部署刚把 embeddedGitCommit 做到 6994a3d，几分钟后它又退回 69aff26。
#
# 为什么不自动 stop：停 timer 是有副作用的决定（可能正等人 push 正式版本；
#   也可能本次只是临时验证，之后仍要靠 timer 巡检）。脚本只负责把风险说清楚。
# ============================================================
function Show-TimerConflictWarning {
  $timer = Get-RemoteUnitState 'secagent-redeploy.timer'
  $svc   = Get-RemoteUnitState 'secagent-redeploy.service'
  if ($timer -ne 'active' -and $svc -ne 'active') {
    Write-Host "    [OK] secagent-redeploy.timer/service 均未激活（不会被 ACR 巡检滚回旧镜像）"
    return $false
  }
  Write-Host ""
  Write-Host ("  " + ("!" * 76)) -ForegroundColor Red
  Write-Host "  [!!] 警告：服务器上的 ACR 巡检定时器正在运行，可能覆盖本次手工部署" -ForegroundColor Red
  Write-Host ("  " + ("!" * 76)) -ForegroundColor Red
  Write-Host "       secagent-redeploy.timer   = $timer" -ForegroundColor Yellow
  Write-Host "       secagent-redeploy.service = $svc" -ForegroundColor Yellow
  Write-Host "       它每 5 分钟读一次 ACR 的 stable digest；一旦触发重建，容器会被换回 ACR 里的镜像" -ForegroundColor Yellow
  Write-Host "       （实测：embeddedGitCommit 从 6994a3d 退回 69aff26，手工部署被覆盖）。" -ForegroundColor Yellow
  Write-Host "       本脚本【不会自动停】它。若本次必须让手工部署保持，请先执行：" -ForegroundColor Yellow
  Write-Host "           sudo systemctl stop secagent-redeploy.timer" -ForegroundColor White
  Write-Host "       部署并核对完成后，按需恢复：" -ForegroundColor Yellow
  Write-Host "           sudo systemctl start secagent-redeploy.timer" -ForegroundColor White
  Write-Host ""
  return $true
}

$mvn = 'F:\Maven\apache-maven-3.9.12-bin\apache-maven-3.9.12\bin\mvn.cmd'
if (-not $mvn -or -not (Test-Path $mvn)) { $mvn = 'mvn' }

# 从 jar 里读出 git.properties（构建时由 git-commit-id-maven-plugin 固化进去）
# 注意：Spring Boot repackage 之后的 fat jar 里，classes 在 BOOT-INF/classes/ 下，
# 所以条目名是 BOOT-INF/classes/git.properties（运行时 classpath 上仍然是 git.properties）。
function Get-JarGitProperties([string]$jarPath) {
  Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null
  $zip = [System.IO.Compression.ZipFile]::OpenRead($jarPath)
  try {
    $entry = $zip.Entries |
      Where-Object { $_.FullName -eq 'BOOT-INF/classes/git.properties' -or $_.FullName -eq 'git.properties' } |
      Select-Object -First 1
    if (-not $entry) { return $null }
    $sr = New-Object System.IO.StreamReader($entry.Open(), [System.Text.Encoding]::UTF8)
    try { $text = $sr.ReadToEnd() } finally { $sr.Dispose() }
    $props = @{}
    foreach ($line in ($text -split "`r?`n")) {
      if ($line -match '^\s*([^#=]+)=(.*)$') { $props[$Matches[1].Trim()] = $Matches[2].Trim() }
    }
    return $props
  } finally { $zip.Dispose() }
}

# ============================================================
# 0) 【fail-closed ①】构建前的源码校验
#    失败就退非零、且什么都不做：不编译、不上传、不建房、不重启。
# ============================================================
$head = (git rev-parse HEAD 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $head) { Fail "当前目录不是 git 工作区，无法确定版本 —— 中止" }
$head = $head.Trim()

$targetFull = if ($TargetCommit) { (git rev-parse --verify --quiet "${TargetCommit}^{commit}" 2>$null) } else { $head }
if ($LASTEXITCODE -ne 0 -or -not $targetFull) {
  Fail "目标 commit '$TargetCommit' 在本仓库不存在（或不是 commit）—— 中止，绝不继续构建"
}
$targetFull = $targetFull.Trim()
$sha = (git rev-parse --short $targetFull).Trim()
Step "0/4" "目标版本 = $sha（HEAD=$($head.Substring(0, 12))）"

if ($head -ne $targetFull) {
  Fail "工作区 HEAD=$($head.Substring(0,12)) ≠ 目标 commit=$($targetFull.Substring(0,12))：源码不是目标版本，绝不继续构建（先 git checkout 到该 commit）"
}

$dirty = @(git status --porcelain)
if ($dirty.Count -gt 0) {
  if (-not $AllowDirty) {
    Write-Host "[X] 工作区不干净（$($dirty.Count) 项未提交改动）—— 中止（脏源码无法用 commit 唯一定位）" -ForegroundColor Red
    $dirty | Select-Object -First 10 | ForEach-Object { Write-Host "      $_" }
    Write-Host "    确认无误可显式放行：-AllowDirty（jar 会被标记 embeddedGitDirty=true，health 将显示 degraded）"
    exit 1
  }
  Warn "工作区有 $($dirty.Count) 项未提交改动，但显式传了 -AllowDirty → 放行（这个 jar 不能等价于任何 commit）"
  $dirty | Select-Object -First 10 | ForEach-Object { Write-Host "      $_" }
}
$worktreeState = if ($dirty.Count -gt 0) { '脏（已显式放行）' } else { '干净' }
Step "0/4" "[OK] 源码校验通过：HEAD == 目标 commit=$sha，工作区$worktreeState"

# 【部署前】先看 ACR 巡检 timer 是否会覆盖本次部署（只警告，不自动停）
$timerActive = Show-TimerConflictWarning

# 1) 本机编译（不需要 Docker）
if (-not $SkipBuild) {
  Step "1/4" "本机编译 + 单测（mvn package）"
  $env:JAVA_HOME = if ($env:JAVA_HOME) { $env:JAVA_HOME } else { 'C:\Users\T\.jdks\ms-17.0.20.1' }
  & $mvn -B package 2>&1 | Select-String -Pattern 'Tests run:.*Failures: \d+, Errors|BUILD|ERROR' |
    Select-Object -Last 3 | ForEach-Object { Write-Host "    $($_.Line)" }
  if ($LASTEXITCODE -ne 0) { Fail "本机编译失败，中止（未上传任何东西、未碰服务器）" }
} else {
  Step "1/4" "跳过编译（复用已有 jar —— 来源校验仍会执行）"
}

$jar = Join-Path $repo 'target\sec-agent-1.0-SNAPSHOT.jar'
if (-not (Test-Path $jar)) { Fail "找不到 jar: $jar" }

# ============================================================
# 2) 【fail-closed ②】jar 的来源校验：这个 jar 是哪个 commit 编的？
#    光有 MD5 只能证明"跑的是这个 jar"，证明不了"它是哪个 commit 的产物"。
#    所以直接从 jar 内的 git.properties 读出 commit/dirty 来核对；
#    对不上就**连 scp 都不做** —— 尤其是 -SkipBuild 复用旧 jar 的场景。
# ============================================================
Step "2/4" "校验 jar 内固化的来源（git.properties）"
$props = Get-JarGitProperties $jar
if (-not $props) {
  Fail "jar 里没有 git.properties —— 无法证明这个 jar 是哪个 commit 编的，中止（未上传）"
}
$jarCommit = "$($props['git.commit.id.abbrev'])"
$jarCommitFull = "$($props['git.commit.id'])"
$jarDirty = "$($props['git.dirty'])"
Write-Host "    jar 内固化：commit=$jarCommit (full=$jarCommitFull) dirty=$jarDirty branch=$($props['git.branch']) buildTime=$($props['git.build.time'])"
if ($jarCommitFull -ne $targetFull) {
  Fail "jar 是 commit '$jarCommitFull' 编的，不是目标 commit '$targetFull' —— jar 与目标版本不符，中止（未上传）"
}
if ($jarDirty -eq 'true' -and -not $AllowDirty) {
  Fail "jar 内 git.dirty=true（构建时工作区是脏的）—— 这个产物不对应任何 commit，中止（未上传）"
}
Write-Host "    [OK] jar 来源 = $jarCommit（== 目标 commit），dirty=$jarDirty"

# 3) 上传源码产物与构建脚本（不上传镜像）
Step "3/4" "上传 jar / Dockerfile.runtime / 服务器构建脚本"
scp -o ConnectTimeout=20 $jar "${SshHost}:/tmp/sec-agent.jar" | Out-Null
# 必须上传 Dockerfile.runtime（单阶段、直接用上传的 jar）而不是 Dockerfile（多阶段、会在镜像内用服务器源码编译）
scp -o ConnectTimeout=20 (Join-Path $repo 'Dockerfile.runtime') "${SshHost}:$RemoteDir/Dockerfile.runtime" | Out-Null
scp -o ConnectTimeout=20 (Join-Path $repo 'scripts\build-on-server.sh') "${SshHost}:$RemoteDir/scripts/build-on-server.sh" | Out-Null
Write-Host "    上传完成（jar 约 $([math]::Round((Get-Item $jar).Length/1MB,0)) MB；不再传 311MB 镜像）"

# 4) 服务器侧构建 + 重启（脚本内部还会再做一次源码校验与镜像内 jar MD5 硬校验）
Step "4/4" "服务器侧 docker build --network=host + compose 重建"
$allowDirtyRemote = if ($AllowDirty) { '1' } else { '0' }
$out = ssh -o ConnectTimeout=20 $SshHost "tr -d '\r' < $RemoteDir/scripts/build-on-server.sh > /tmp/b.sh && chmod +x /tmp/b.sh && ALLOW_DIRTY=$allowDirtyRemote bash /tmp/b.sh /tmp/sec-agent.jar $sha" 2>&1
$sshCode = $LASTEXITCODE
$out | ForEach-Object { Write-Host "    $_" }
if ($sshCode -ne 0) {
  Fail "服务器侧构建/校验失败（exit=$sshCode）—— fail-closed 中止；注意 exit 6/7/8 发生在容器已重建之后，线上状态以日志与 /api/health 为准"
}

# 5) 【fail-closed ④】部署后**轮询**核对 health
#    为什么必须轮询：docker compose up --force-recreate 返回时新容器才刚刚开始启动，
#    Spring 上下文初始化要 40~90 秒。若立刻读 /api/health：
#      · 旧容器的端口可能还在应答 → 读到【旧版本指纹】；
#      · 或者新容器还没监听 → 读到空。
#    实测后果：脚本把"新容器其实已经起来"误判成失败（exit 6 / fail-closed 中止）。
#    判据：status == ok 且 embeddedGitCommit == 目标 sha；最多 120 秒、每 3 秒一次。
#    超时才失败，并把最后一次 health 的【全量 JSON】原样打出来（排查用）。
Step "5/5" "轮询 /api/health（最多 120s / 每 3s）直到 status=ok 且 embeddedGitCommit=$sha"
$healthDeadline = (Get-Date).AddSeconds(120)
$healthRaw = ''
$j = $null
$attempt = 0
while ((Get-Date) -lt $healthDeadline) {
  $attempt++
  $raw = ssh -o ConnectTimeout=20 $SshHost "curl -s -m 10 http://127.0.0.1:9900/api/health" 2>$null
  if ($raw) {
    $healthRaw = ($raw | Out-String).Trim()
    $candidate = $null
    try { $candidate = $healthRaw | ConvertFrom-Json } catch { $candidate = $null }
    if ($candidate) {
      $j = $candidate
      $curStatus = "$($candidate.status)"
      $curCommit = "$($candidate.embeddedGitCommit)"
      Write-Host ("    第 {0,2} 次：status={1} embeddedGitCommit={2}" -f $attempt, $curStatus, $curCommit)
      if ($curStatus -eq 'ok' -and $curCommit -eq $sha) { break }
    } else {
      Write-Host ("    第 {0,2} 次：响应不是 JSON，继续等" -f $attempt)
    }
  }
  Start-Sleep -Seconds 3
}
if (-not $j -or "$($j.status)" -ne 'ok' -or "$($j.embeddedGitCommit)" -ne $sha) {
  Write-Host ""
  Write-Host "    [X] 120 秒内没有等到 status=ok 且 embeddedGitCommit=$sha" -ForegroundColor Red
  if ($healthRaw) {
    Write-Host "    最后一次 /api/health 全量 JSON：" -ForegroundColor Yellow
    Write-Host $healthRaw
  } else {
    Write-Host "    最后一次 /api/health：无响应（120s 内 curl 没拿到任何 JSON）" -ForegroundColor Yellow
  }
  if ($timerActive) {
    Write-Host "    提示：secagent-redeploy.timer 处于 active，可能已把容器滚回旧镜像；先 stop timer 再重试。" -ForegroundColor Yellow
  }
  Fail "部署后核对超时（120s）：未达到 status=ok 且 embeddedGitCommit=$sha"
}
Write-Host "    $healthRaw"

if ("$($j.embeddedGitCommit)" -ne $sha) {
  Fail "线上 embeddedGitCommit=$($j.embeddedGitCommit) ≠ 目标 commit=$sha（jar 内固化值与目标版本不一致）"
}
if ("$($j.buildSha)" -ne $sha) {
  Fail "线上 buildSha=$($j.buildSha) ≠ 目标 commit=$sha（容器环境变量没注入对，compose 可能没生效）"
}
if ($j.fingerprintMismatch) {
  Fail "线上 fingerprintMismatch=true：$($j.fingerprintMismatchReason)"
}
if ("$($j.status)" -ne 'ok') {
  Fail "线上 status=$($j.status)（期望 ok）：$($j.fingerprintIssues -join ' / ')"
}
Write-Host "[OK] 部署完成：embeddedGitCommit = buildSha = $sha，fingerprintMismatch=false，status=ok"
if ($timerActive) {
  Write-Host ""
  Write-Host "  [!!] 提醒：secagent-redeploy.timer 仍为 active —— 它随时可能按 ACR digest 把容器滚回旧镜像。" -ForegroundColor Yellow
  Write-Host "       若要让本次手工部署保持，请执行：sudo systemctl stop secagent-redeploy.timer" -ForegroundColor Yellow
}
