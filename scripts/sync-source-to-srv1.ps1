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
#
# 用法：
#   powershell -File scripts\sync-source-to-srv1.ps1               # 只把对象送到位
#   powershell -File scripts\sync-source-to-srv1.ps1 -AlignHead    # 并把 HEAD 指到该提交
#   powershell -File scripts\sync-source-to-srv1.ps1 -Target <sha>
#
# 之后照常跑：scripts\deploy-remote-build.ps1 -AllowDirty
# ============================================================
param(
    [string]$SshHost = 'secagent-srv1',
    [string]$RemoteDir = '/opt/secagent',
    [string]$Target = '',
    [switch]$AlignHead
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

function Step($n, $msg) { Write-Host ("==> " + $n + " " + $msg) }
function Fail($msg) { Write-Host ("[X] " + $msg) -ForegroundColor Red; exit 1 }
function Ok($msg) { Write-Host ("    [OK] " + $msg) -ForegroundColor Green }
function Warn($msg) { Write-Host ("    [!] " + $msg) -ForegroundColor Yellow }

# ---- 0) 目标提交 ----
$head = (git rev-parse HEAD).Trim()
$headShort = (git rev-parse --short $head).Trim()
if (-not $Target) { $Target = $head }
$targetFull = (git rev-parse --verify --quiet ($Target + '^{commit}'))
if (-not $targetFull) { Fail ("目标 " + $Target + " 在本仓库不存在") }
$targetFull = $targetFull.Trim()
$sha = (git rev-parse --short $targetFull).Trim()
Step "0/4" ("目标提交 = " + $sha + " / HEAD = " + $headShort)

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

# ---- 4) 可选：对齐 HEAD（只移动指针，工作区不动）----
if ($AlignHead) {
    $align = "sudo git -C " + $RemoteDir + " reset --soft " + $targetFull + " 2>&1 | tail -1; sudo git -C " + $RemoteDir + " log --oneline -1"
    $out2 = ssh -o BatchMode=yes $SshHost $align
    if ($LASTEXITCODE -ne 0) { Fail ("reset --soft 失败：" + $out2) }
    Step "4/4" ("服务器 HEAD 已指到 " + $sha + "（工作区与 docker-compose.yml 原样保留）")
    Ok (($out2 | Select-Object -Last 1))
} else {
    Step "4/4" "未对齐 HEAD（需要时加 -AlignHead）"
}

Remove-Item -LiteralPath $bundle -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "下一步：powershell -File scripts\deploy-remote-build.ps1 -AllowDirty" -ForegroundColor Cyan
