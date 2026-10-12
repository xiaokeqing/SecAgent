<#
.SYNOPSIS
  S2 两张卷子的 nightly / release 门禁（安全卷 + 质量卷，真调模型端到端）。

.DESCRIPTION
  分层原则：确定性部分（规则/护栏/schema/探针逻辑）已作为 JUnit 进每次 CI 硬门禁；
  这里跑的是**真 LLM 端到端**，故只在 nightly / release 前跑，不进 CI。

  门禁规则：
    · 代码护栏拦截率必须 100%  → 不达标 exit 1（release 阻断）
    · 质量卷探针必须通过       → 不通过则该轮质量卷作废（脚本会标出）
    · 其余指标按基线容差 + 趋势（不因单次波动阻塞；模型供应商会静默升级）

  用量提醒（实测）：一次提问约消耗 2 次模型调用（Planner 路由 + 生成），
  安全卷 18 例 + 质量卷 7 例 ≈ 25 次提问 ≈ **50 次模型调用 = 恰好是一天的配额上限**。
  因此：要么把 app.quota.daily-limit 调高，要么两张卷子分日跑。

.EXAMPLE
  pwsh -File scripts/eval-nightly.ps1                # 本地跑（自动开 SSH 隧道）
  pwsh -File scripts/eval-nightly.ps1 -Base https://demo.xiaokeqing.cn   # 走公网
#>
param(
  [string]$Base = 'http://127.0.0.1:8790',   # 默认走 SSH 隧道，绕开 CDN 抖动
  [string]$OutDir = 'eval-runs',
  [string]$SshHost = 'secagent-srv1',
  [int]$TunnelPort = 8790,
  [switch]$SkipTunnel
)

$ErrorActionPreference = 'Continue'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

function New-EvalDirs { param($d) if (-not (Test-Path $d)) { New-Item -ItemType Directory -Force $d | Out-Null } }
New-EvalDirs $OutDir

# ---- 凭据：从服务器 .env 读取（不落盘、不写日志）----
$creds = ssh -o ConnectTimeout=20 $SshHost "grep -E '^SECAGENT_(USERNAME|PASSWORD)=' /opt/secagent/.env | cut -d= -f2-"
if (-not $creds -or $creds.Count -lt 2) {
  Write-Error "无法读取凭据（$SshHost:/opt/secagent/.env）"
  exit 2
}
$u = $creds[0].Trim(); $p = $creds[1].Trim()

# ---- 隧道（默认开启）----
$tunnel = $null
if (-not $SkipTunnel -and $Base -like '*127.0.0.1*') {
  $tunnel = Start-Job -ScriptBlock {
    param($h, $port)
    ssh -o ConnectTimeout=15 -o ServerAliveInterval=30 -N -L "$port`:127.0.0.1:9900" $h
  } -ArgumentList $SshHost, $TunnelPort
  Start-Sleep -Seconds 8
  Write-Host "[nightly] SSH 隧道已就绪：127.0.0.1:$TunnelPort -> $SshHost:9900"
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$node = 'F:\node.js\node.exe'
if (-not (Test-Path $node)) { $node = 'node' }

try {
  foreach ($paper in @('safety', 'quality')) {
    $out = Join-Path $OutDir "eval-$paper-$stamp.json"
    Write-Host "`n[nightly] ===== 跑 $paper 卷 ====="
    & $node scripts/eval-papers.mjs --base $Base --user $u --pass $p --paper $paper --out $out
    $code = $LASTEXITCODE
    Write-Host "[nightly] $paper 卷 exit=$code，结果：$out"
    if ($paper -eq 'safety' -and $code -ne 0) {
      Write-Host '[nightly] [X] 安全卷门禁未通过（代码护栏拦截率必须 100%）—— release 阻断'
      exit 1
    }
    if ($paper -eq 'quality' -and $code -ne 0) {
      Write-Host '[nightly] [!] 质量卷未通过（可能是探针失败导致本轮作废，或配额耗尽）—— 需人工复核'
    }
  }
  Write-Host "`n[nightly] 完成。结果目录：$OutDir"
  Write-Host '[nightly] 提示：把本脚本挂到 Windows 任务计划（每日）即为 nightly 门禁。'
} finally {
  if ($tunnel) { Stop-Job $tunnel -ErrorAction SilentlyContinue; Remove-Job $tunnel -Force -ErrorAction SilentlyContinue }
}
