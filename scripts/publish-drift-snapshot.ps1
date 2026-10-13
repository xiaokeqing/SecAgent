<#
.SYNOPSIS
  把权威仓库的 scripts/ deploy/ 打成「只读快照」推给 srv1 —— 漂移巡检的权威基准。

.DESCRIPTION
  为什么需要它：
    srv1 现在【连不上 GitHub】（实测 github.com:443 超时、ssh.github.com:443 能建 TCP
    但 Permission denied (publickey)，/root/.ssh 下没有任何 GitHub 凭据）。
    所以漂移巡检的"首选基准 git fetch origin main"在 srv1 上走不通，
    必须由权威仓库这一侧（本机）把权威提交的文件树 + 哈希清单推过去，
    srv1 只读消费；快照过期 → 巡检直接失败（fail-closed），不会静默拿旧快照当权威。

  哈希口径：文件内容【去掉全部 CR】后的 sha256（sha256-cr-stripped）。
    为什么去掉 CR：.gitattributes 对 *.ps1 是 eol=crlf，Linux 检出后是 LF，
    按原始字节比会在 srv1 上恒定误报 9 个 .ps1。两侧同口径后 CRLF↔LF 不再是漂移。

  流程：解析提交 → 逐 blob 取内容（cat-file，二进制安全）→ 写 MANIFEST.sha256 + SNAPSHOT-INFO
        → tar.gz → scp 到服务器 → 在服务器上 `srv1-repo-snapshot.sh --install`（校验+原子替换+置只读）。

.EXAMPLE
  pwsh -File scripts/publish-drift-snapshot.ps1
  pwsh -File scripts/publish-drift-snapshot.ps1 -Commit HEAD~1 -NoInstall   # 只打包不安装
#>
[CmdletBinding()]
param(
  [string]$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
  [string]$Server = 'secagent-srv1',
  [string[]]$Dirs = @('scripts', 'deploy'),
  [string]$Commit = 'HEAD',
  [string]$RemoteScript = '/opt/secagent/scripts/srv1-repo-snapshot.sh',
  [string]$RemoteTmp = '/tmp',
  [switch]$NoInstall,
  [switch]$KeepTgz
)

$ErrorActionPreference = 'Stop'
function Say($m) { Write-Host "publish-snapshot: $m" }
function Fail($m) { Write-Host "publish-snapshot: [X] $m" -ForegroundColor Red; exit 1 }

function Get-CrStrippedSha256([string]$Path) {
  $b = [System.IO.File]::ReadAllBytes($Path)
  $out = New-Object 'System.Collections.Generic.List[byte]'
  foreach ($x in $b) { if ($x -ne 13) { $out.Add($x) } }
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try { $hash = $sha.ComputeHash($out.ToArray()) } finally { $sha.Dispose() }
  ($hash | ForEach-Object { $_.ToString('x2') }) -join ''
}

if (-not (Test-Path (Join-Path $Repo '.git'))) { Fail "不是 git 仓库：$Repo" }

# ---------- 1) 解析权威提交 ----------
$commit = (& git -C $Repo rev-parse "$Commit^{commit}" 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $commit) { Fail "git rev-parse $Commit 失败（$Repo）" }
$commit = ("$commit").Trim()
Say "权威提交：$commit（$Repo 的 $Commit）"

# ---------- 2) 列出文件（带上 blob sha，后面用它取内容） ----------
$lsLines = & git -C $Repo ls-tree -r $commit -- $Dirs
if ($LASTEXITCODE -ne 0) { Fail "git ls-tree 失败" }
$files = @()
foreach ($l in $lsLines) {
  if ($l -match '^\d+ blob ([0-9a-f]{40,64})\t(.+)$') {
    $files += [pscustomobject]@{ Blob = $Matches[1]; Path = $Matches[2] }
  }
}
if ($files.Count -eq 0) { Fail "提交 $commit 下 $($Dirs -join ',') 里没有文件" }
$bad = $files | Where-Object { $_.Path -match '\s' }
if ($bad) { Fail "有含空白的路径，服务器侧脚本不处理（请改快照脚本）：$($bad[0].Path)" }
Say "待快照文件数：$($files.Count)"

# ---------- 3) 生成快照内容 ----------
$stage = Join-Path $env:TEMP ("repo-snapshot-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path (Join-Path $stage 'tree') -Force | Out-Null
$manifest = New-Object 'System.Collections.Generic.List[string]'
foreach ($f in $files) {
  $dest = Join-Path $stage ('tree/' + $f.Path)
  New-Item -ItemType Directory -Path (Split-Path $dest -Parent) -Force | Out-Null
  cmd /c "git -C `"$Repo`" cat-file blob $($f.Blob) > `"$dest`""
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path $dest)) { Fail "取内容失败：$($f.Path)" }
  $manifest.Add("$(Get-CrStrippedSha256 $dest)  $($f.Path)")
}
$utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText((Join-Path $stage 'MANIFEST.sha256'), (($manifest -join "`n") + "`n"), $utf8)

# 【时区坑】不能用 Get-Date -UFormat %s：Windows 上它把"本地墙钟时间"当 UTC 算，
# 东八区会凭空多出 8 小时，快照会显得"来自未来"，新鲜度判断被白送 8 小时余量。
$epoch = [long][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$info = @(
  "SNAP_COMMIT=$commit",
  "SNAP_TIME_EPOCH=$epoch",
  "SNAP_HASHMODE=sha256-cr-stripped",
  "SNAP_FILES=$($files.Count)",
  "SNAP_SOURCE=publish-drift-snapshot.ps1@${env:COMPUTERNAME}:$Repo"
) -join "`n"
[System.IO.File]::WriteAllText((Join-Path $stage 'SNAPSHOT-INFO'), ($info + "`n"), $utf8)
Say "快照内容已生成：$stage"

# ---------- 4) 打包 ----------
$name = "repo-snapshot-$([DateTime]::Now.ToString('yyyyMMdd-HHmmss')).tgz"
$tgz = Join-Path $env:TEMP $name
if (Test-Path $tgz) { Remove-Item $tgz -Force }
& tar -czf $tgz -C $stage SNAPSHOT-INFO MANIFEST.sha256 tree
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $tgz)) { Fail "tar 打包失败" }
Say "已打包：$tgz（$((Get-Item $tgz).Length) 字节）"

if ($NoInstall) {
  Say "按 -NoInstall：只打包，不安装。"
  Write-Output $tgz
  exit 0
}

# ---------- 5) 推到服务器并安装 ----------
& scp -o BatchMode=yes -q $tgz "${Server}:$RemoteTmp/"
if ($LASTEXITCODE -ne 0) { Fail "scp 失败（${Server}:$RemoteTmp）" }
Say "已传到 ${Server}:$RemoteTmp/$name"

& ssh -o BatchMode=yes $Server "bash $RemoteScript --install $RemoteTmp/$name"
if ($LASTEXITCODE -ne 0) { Fail "服务器侧安装失败：bash $RemoteScript --install $RemoteTmp/$name" }

& ssh -o BatchMode=yes $Server "bash $RemoteScript --status"
if ($LASTEXITCODE -ne 0) { Fail "服务器侧 --status 失败" }

& ssh -o BatchMode=yes $Server "rm -f $RemoteTmp/$name"
if (-not $KeepTgz) { Remove-Item $tgz -Force -ErrorAction SilentlyContinue; Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue }
Say "完成。"
