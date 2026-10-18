# ============================================================
# sync-source-to-srv1.ps1 —— 把本仓库当前提交送到 srv1 的 /opt/secagent 仓库里。
#
# 为什么需要它：
#   deploy-remote-build.ps1 的服务器侧 fail-closed 校验要求「目标 commit 在服务器仓库里真实存在，
#   且 HEAD == 目标 commit」。而 srv1 无法访问 GitHub（拉取失败），本机推 GitHub 也没有可用 key，
#   所以每次发版前必须先把对象送过去 —— 以前是手工 bundle，漏了这一步就会报
#   「目标 commit 'xxx' 在服务器仓库里不存在 —— 不能证明源码就是它编的，中止」。
#
# 做法（四步，都可重复执行）：
#   ① 本机 git bundle create <tmp> main   —— 只带对象，不带工作区
#   ② scp 到 srv1 /tmp/                    —— 4~5 MB，几秒
#   ③ srv1: git fetch <bundle> main        —— 只 fetch，不 checkout
#      （绝不覆盖服务器上被手工改过的 docker-compose.yml / .env）
#   ④ 加 -AlignHead 时才 git reset --soft：只移动 HEAD，工作区与配置原样保留
#      -HardReset 会 git reset --hard（工作区回到仓库版本）—— 仓库里的
#      docker-compose.yml 与 srv1 上被手工改过的那份【不同】（真实事故 A），
#      所以 reset 之前先备份到 /root/docker-compose.yml.syncbak-<时间戳>，
#      reset 之后原子恢复并核对 md5；输出固定打印「已备份 / 已恢复」两行。
#
# 用法：
#   powershell -File scripts\sync-source-to-srv1.ps1               # 只把对象送到位
#   powershell -File scripts\sync-source-to-srv1.ps1 -AlignHead    # 并把 HEAD 指到该提交（reset --soft）
#   powershell -File scripts\sync-source-to-srv1.ps1 -HardReset    # 连工作区一起回到仓库版本（reset --hard）
#   powershell -File scripts\sync-source-to-srv1.ps1 -Target <sha>
#
# 之后照常跑：scripts\deploy-remote-build.ps1 -AllowDirty
# ============================================================
param(
    [string]$SshHost = 'secagent-srv1',
    [string]$RemoteDir = '/opt/secagent',
    [string]$Target = '',
    [switch]$AlignHead,
    # 工作区也回到仓库版本（git reset --hard）。会给线上 compose 带来真实风险，
    # 因此脚本内置「先备份、再 reset、再原子恢复」的保护（见 Backup-ComposeIfDirty）。
    [switch]$HardReset
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

function Step($n, $msg) { Write-Host ("==> " + $n + " " + $msg) }
function Fail($msg) { Write-Host ("[X] " + $msg) -ForegroundColor Red; exit 1 }
function Ok($msg) { Write-Host ("    [OK] " + $msg) -ForegroundColor Green }
function Warn($msg) { Write-Host ("    [!] " + $msg) -ForegroundColor Yellow }

# ---- compose 保护（真实事故 A 的防线，2026-10-18 固化进脚本）----
# 事故形状：srv1 上的 docker-compose.yml 被站主手工改过（TTS / quota 段，
#   image 指向本地镜像），而仓库里的版本指向 ACR :stable。`git reset --hard`
#   会把这份【线上真配置】直接覆盖成仓库版本 —— 之后 up -d 就按仓库版重建容器，
#   看着"发布成功"、其实配置丢了（当时靠 /root/docker-compose.yml.srv1-.bak 手工救回）。
# 判据命令（远端）：git -C /opt/secagent diff --quiet HEAD -- docker-compose.yml; echo $?
#   0 = 一致（reset 不会改它，无需备份）；1 = 被改过（必须先备份）。
# 恢复用「同目录 install 出临时文件 + mv」：同一文件系统内 rename 是原子的，
#   不会留下半截配置；恢复后核对 md5，防止"备份成功、恢复失败"被忽略。
function Backup-ComposeIfDirty {
    $composeRel = 'docker-compose.yml'
    $composePath = $RemoteDir + '/' + $composeRel
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $bak = '/root/docker-compose.yml.syncbak-' + $stamp
    $checkCmd = 'sudo git -C ' + $RemoteDir + ' diff --quiet HEAD -- ' + $composeRel + '; echo "compose_diff_exit=$?"'
    $chk = @(ssh -o BatchMode=yes $SshHost $checkCmd 2>&1)
    $hit = @($chk | Where-Object { ([string]$_).Trim() -match '^compose_diff_exit=[0-9]+$' })
    if ($hit.Count -eq 0) { Fail ("无法判断远端 compose 是否被改（输出：" + ($chk -join ' / ') + "）") }
    $code = [int]((([string]$hit[$hit.Count - 1]).Trim()) -replace 'compose_diff_exit=', '')
    if ($code -eq 0) {
        Ok ("远端 compose 与仓库 HEAD 一致（diff_exit=0）—— 无需备份/恢复")
        return @{ Needed = $false }
    }
    if ($code -ne 1) { Fail ("git diff 返回 " + $code + "（非 0/1）—— 无法判断 compose 状态，中止（宁可不 reset）") }
    $bakCmd = 'sudo cp -a ' + $composePath + ' ' + $bak + ' && sudo chmod 644 ' + $bak + ' && sudo md5sum ' + $bak
    $bout = @(ssh -o BatchMode=yes $SshHost $bakCmd 2>&1)
    $bmd5 = ''
    if ($LASTEXITCODE -eq 0 -and $bout.Count -gt 0) { $bmd5 = ((([string]$bout[$bout.Count - 1]).Trim()) -split '\s+')[0] }
    if ($bmd5 -notmatch '^[0-9a-f]{32}$') { Fail ("备份远端 compose 失败（输出：" + ($bout -join ' / ') + "）") }
    Write-Host ("    [OK] 已备份 " + $composePath + " -> " + $bak + "（md5=" + $bmd5 + "）") -ForegroundColor Green
    return @{ Needed = $true; Path = $bak; Md5 = $bmd5; Target = $composePath }
}

function Restore-Compose($state) {
    if (-not $state.Needed) { return }
    $tmp = $state.Target + '.sync-restore'
    $cmd = 'sudo install -m 644 ' + $state.Path + ' ' + $tmp + ' && sudo mv -f ' + $tmp + ' ' + $state.Target + ' && sudo md5sum ' + $state.Target
    $out = @(ssh -o BatchMode=yes $SshHost $cmd 2>&1)
    $md5 = ''
    if ($LASTEXITCODE -eq 0 -and $out.Count -gt 0) { $md5 = ((([string]$out[$out.Count - 1]).Trim()) -split '\s+')[0] }
    if ($md5 -ne $state.Md5) {
        Fail ("已备份但未恢复成功：预期 md5=" + $state.Md5 + "，实际 md5=" + $md5 + "，备份仍在 " + $state.Path + " —— 请人工恢复")
    }
    Write-Host ("    [OK] 已恢复 " + $state.Target + "（md5=" + $md5 + "，与备份一致）") -ForegroundColor Green
}

# ---- 0) 目标提交 ----
$head = (git rev-parse HEAD).Trim()
$headShort = (git rev-parse --short $head).Trim()
if (-not $Target) { $Target = $head }
$targetFull = (git rev-parse --verify --quiet ($Target + '^{commit}'))
if (-not $targetFull) { Fail ("目标 " + $Target + " 在本仓库不存在") }
$targetFull = $targetFull.Trim()
$sha = (git rev-parse --short $targetFull).Trim()
Step "0/4" ("目标提交 = " + $sha + " / HEAD = " + $headShort)

# ---- 0.5) 快路径：srv1 直连 GitHub（2026-10-17 实测 1.4s，比 bundle 省 5MB 上传）----
$direct = $false
$probeCmd = "timeout 25 sudo env GIT_TERMINAL_PROMPT=0 git -C " + $RemoteDir + " fetch origin main >/dev/null 2>&1; sudo git -C " + $RemoteDir + " rev-parse --short FETCH_HEAD"
$pout = @(ssh -o BatchMode=yes $SshHost $probeCmd 2>$null)
$pf = if ($pout.Count -gt 0) { ([string]$pout[$pout.Count - 1]).Trim() } else { "" }
if ($pf.Length -ge 7 -and $targetFull.StartsWith($pf)) {
    $direct = $true
    Step "1-3/4" ("srv1 直连 GitHub 已拿到 " + $pf + "（跳过 bundle 中转）")
} else {
    Warn ("srv1 直连 GitHub 未拿到目标提交（" + $pf + "），退化走 bundle")
}

if (-not $direct) {

# ---- 1) 打 bundle ----
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$bundle = Join-Path $env:TEMP ("secagent-" + $stamp + ".bundle")
git bundle create $bundle main 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $bundle)) { Fail "git bundle 失败" }
$mb = [math]::Round((Get-Item $bundle).Length / 1MB, 1)
Step "1/4" ("bundle 已生成（" + $mb + " MB）")

# ---- 2) 上传 ----
$remoteBundle = "/tmp/secagent-" + $stamp + ".bundle"
scp -o BatchMode=yes -q $bundle ($SshHost + ":" + $remoteBundle)
if ($LASTEXITCODE -ne 0) { Fail "scp 失败" }
Step "2/4" ("已上传到 " + $SshHost + ":" + $remoteBundle)

# ---- 3) 服务器侧 fetch ----
$fetchCmd = "sudo git -C " + $RemoteDir + " fetch " + $remoteBundle + " main 2>&1 | tail -2; sudo git -C " + $RemoteDir + " rev-parse --short FETCH_HEAD"
$out = ssh -o BatchMode=yes $SshHost $fetchCmd
if ($LASTEXITCODE -ne 0) { Fail ("服务器侧 fetch 失败：" + $out) }
$fetched = ($out | Select-Object -Last 1).Trim()
Step "3/4" ("服务器已拿到 FETCH_HEAD = " + $fetched)
if ($fetched.Length -lt 7) { Fail ("没能确认服务器侧提交（输出：" + $out + "）") }
if (-not $targetFull.StartsWith($fetched)) {
    Warn ("服务器 FETCH_HEAD(" + $fetched + ") 与目标(" + $sha + ") 不一致 —— main 可能落后，请核对")
}
}  # end if (-not $direct)



# ---- 4) 可选：对齐 HEAD ----
# -AlignHead → reset --soft（只移动指针，工作区与配置原样保留）
# -HardReset → reset --hard（工作区也回到仓库版本 —— 会覆盖 srv1 手工改过的
#              docker-compose.yml，所以必须"先备份、再 reset、再原子恢复"）
if ($AlignHead -or $HardReset) {
    if ($AlignHead -and $HardReset) { Fail " -AlignHead 与 -HardReset 不能同时给（二者都是对齐 HEAD，语义冲突）" }
    $resetMode = if ($HardReset) { '--hard' } else { '--soft' }
    # ① 必须在 reset 之前判断+备份：reset --hard 会当场覆盖掉线上真配置
    $composeState = Backup-ComposeIfDirty
    $align = 'sudo git -C ' + $RemoteDir + ' reset ' + $resetMode + ' ' + $targetFull + ' 2>&1 | tail -1; sudo git -C ' + $RemoteDir + ' log --oneline -1'
    $out2 = @(ssh -o BatchMode=yes $SshHost $align 2>&1)
    if ($LASTEXITCODE -ne 0) {
        # reset 失败也要把配置放回去（否则备份只是躺在 /root 里，线上配置还是丢的）
        Restore-Compose $composeState
        Fail ("reset " + $resetMode + " 失败：" + ($out2 -join ' / '))
    }
    # ② reset 之后原子恢复，并核对 md5 与备份一致
    Restore-Compose $composeState
    Step "4/4" ("服务器 HEAD 已指到 " + $sha + "（reset " + $resetMode + "）")
    Ok ([string]($out2 | Select-Object -Last 1))
} else {
    Step "4/4" "未对齐 HEAD（需要时加 -AlignHead 或 -HardReset）"
}

Remove-Item -LiteralPath $bundle -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "下一步：powershell -File scripts\deploy-remote-build.ps1 -AllowDirty" -ForegroundColor Cyan
