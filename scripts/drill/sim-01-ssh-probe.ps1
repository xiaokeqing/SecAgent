<#
  sim-01 · SSH 连接与版本探测（安全版）
  ============================================================
  动作：对 srv2 蜜罐 SSH 端口发起 10 次 TCP 连接，各自发送不同的
        SSH-2.0-<client> 横幅（内含 runId 演练标记），【不尝试登录】。
  预期检出：Cowrie 规则 100100（新的 SSH 连接）+ 100104（SSH 客户端版本）。

  内置护栏（违反即中止，退出码非 0）：
    ① 目标白名单：只允许 47.96.106.187 / 43.143.114.79，其他目标直接拒绝
    ② 总请求数 <= $MaxRequests，相邻请求间隔 >= $MinIntervalMs
    ③ 唯一 runId（DRILL-sim-01-<时间戳>），随横幅落到告警里，便于精确定位
    ④ 非破坏性：只发客户端横幅，不认证、不登录、不执行命令
    ⑤ 演练前打印"目标/动作/预计请求数/runId"，演练后打印开始/结束时间（ISO 秒级）
#>
[CmdletBinding()]
param(
    # ---- 可调参数（端口/路径等都在脚本顶部） ----
    [string]$TargetIp        = '43.143.114.79',   # srv2（腾讯云上海）
    [int]   $TargetPort      = 2222,              # Cowrie 蜜罐 SSH 端口
    [int]   $Connections     = 10,                # 预计请求数
    [int]   $MinIntervalMs   = 500,               # 相邻请求最小间隔
    [int]   $ConnectTimeoutMs= 5000,
    [int]   $BannerReadMs    = 2500,
    [int]   $HoldAfterBannerMs = 400,             # 发完横幅稍等，确保蜜罐落盘
    [string]$RunIdPrefix     = 'DRILL-sim-01',
    [string]$EvidenceDir     = (Join-Path $PSScriptRoot '..\..\_tmp')
)

$ErrorActionPreference = 'Stop'

# ============================================================
# 护栏常量（不要为了"打得更爽"去放宽它们）
# ============================================================
$AllowedTargets = @('47.96.106.187', '43.143.114.79')   # srv1 / srv2，仅此两台
$MaxRequests    = 30                                    # 单剧本请求数硬上限

# ---- 输出（同时落 UTF-8 日志，便于当证据） ----
$RunId = "$RunIdPrefix-" + (Get-Date -Format 'yyyyMMddTHHmmss')
$script:LogLines = New-Object System.Collections.Generic.List[string]
function Say {
    param([string]$Text = '', [string]$Color = 'Gray')
    Write-Host $Text -ForegroundColor $Color
    $script:LogLines.Add($Text)
}

# ---- 护栏 ①：目标白名单 ----
function Assert-WhitelistedTarget {
    param([string]$Ip)
    if ($AllowedTargets -notcontains $Ip) {
        Say "[护栏拒绝] 目标 '$Ip' 不在白名单（$($AllowedTargets -join ' / ')）。本演练只允许打自己的资产，脚本中止。" 'Red'
        Say "[护栏拒绝] 若确实需要新目标，请先改 $($MyInvocation.MyCommand.Name) 顶部的 `$AllowedTargets —— 这是故意设计的人工闸门。" 'Red'
        exit 90
    }
}

# ---- 护栏 ②：请求计数 + 最小间隔 ----
$script:RequestCount = 0
$script:LastRequestAt = $null
function Get-RequestSlot {
    param([string]$What = 'request')
    if ($script:RequestCount -ge $MaxRequests) {
        Say "[护栏中止] 请求数已达上限 $MaxRequests（当前动作：$What），停止发送。" 'Red'
        exit 91
    }
    if ($script:LastRequestAt -ne $null) {
        $elapsed = ((Get-Date) - $script:LastRequestAt).TotalMilliseconds
        if ($elapsed -lt $MinIntervalMs) {
            Start-Sleep -Milliseconds ([int][Math]::Ceiling($MinIntervalMs - $elapsed))
        }
    }
    $script:RequestCount++
    $script:LastRequestAt = Get-Date
}

# ---- 底层：一次 TCP 连接（只能连白名单目标） ----
function Invoke-Probe {
    param([string]$Ip, [int]$Port, [int]$TimeoutMs)
    Assert-WhitelistedTarget -Ip $Ip
    Get-RequestSlot -What "tcp-connect $Ip`:$Port"
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($Ip, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            return [pscustomobject]@{ ok = $false; serverBanner = ''; note = 'connect 超时（端口被丢弃或不可达）' }
        }
        $client.EndConnect($iar)
        $stream = $client.GetStream()
        $stream.ReadTimeout = $BannerReadMs
        $buf = New-Object byte[] 256
        $n = 0
        try { $n = $stream.Read($buf, 0, 256) } catch { $n = -1 }
        $server = ''
        if ($n -gt 0) { $server = ([Text.Encoding]::ASCII.GetString($buf, 0, $n)).Trim() }
        return [pscustomobject]@{ ok = $true; serverBanner = $server; stream = $stream; note = '' }
    } catch {
        return [pscustomobject]@{ ok = $false; serverBanner = ''; note = "connect 失败: $($_.Exception.Message)" }
    }
}

# ============================================================
# 演练前须知（要求：目标/动作/预计请求数/runId）
# ============================================================
Assert-WhitelistedTarget -Ip $TargetIp
if ($Connections -gt $MaxRequests) {
    Say "[护栏拒绝] 本剧本 Connections=$Connections 超过硬上限 $MaxRequests，脚本中止。" 'Red'; exit 92
}

$clients = @(
    'OpenSSH_8.9p1', 'libssh2_1.11.1', 'PuTTY_Release_0.78', 'Go', 'Python-paramiko_3.4.0',
    'OpenSSH_9.2', 'WinSCP_release_6.1.2', 'JSCH-0.1.55', 'MobaXterm_23.2', 'SecureCRT_9.4.2'
)

Say ''
Say '==================== sim-01 演练前 ====================' 'Cyan'
Say "  目标        : $TargetIp`:$TargetPort  (srv2 · Cowrie 蜜罐，白名单内)"
Say "  动作        : $Connections 次 TCP 连接，各发送不同 SSH-2.0-<client> 横幅；不认证、不登录"
Say "  预计请求数  : $Connections  (硬上限 $MaxRequests，间隔 >= ${MinIntervalMs}ms)"
Say "  runId       : $RunId"
Say '  破坏性 payload: 无（只发协议横幅；不投递 webshell、不执行命令、不做爆破）'
Say '======================================================='

$startedAt = Get-Date
Say ("  开始时间(ISO): " + $startedAt.ToString('yyyy-MM-ddTHH:mm:sszzz')) 'Yellow'

$results = @()
for ($i = 1; $i -le $Connections; $i++) {
    $clientName = $clients[($i - 1) % $clients.Count]
    # 横幅里带 runId 演练标记，便于在告警里精确定位与剔除
    $banner = "SSH-2.0-$clientName`_$RunId`_c$('{0:d2}' -f $i)`r`n"
    $r = Invoke-Probe -Ip $TargetIp -Port $TargetPort -TimeoutMs $ConnectTimeoutMs
    $sent = $false
    if ($r.ok -and $r.stream) {
        try {
            $bytes = [Text.Encoding]::ASCII.GetBytes($banner)
            $r.stream.Write($bytes, 0, $bytes.Length)
            $r.stream.Flush()
            Start-Sleep -Milliseconds $HoldAfterBannerMs
            $sent = $true
        } catch { }
        try { $r.stream.Close() } catch { }
    }
    $results += [pscustomobject]@{
        n           = $i
        clientBanner= $banner.Trim()
        serverBanner= $r.serverBanner
        bannerSent  = $sent
        ok          = $r.ok
        note        = $r.note
    }
    Say ("  [{0:d2}/{1}] server=`"{2}`"  client=`"{3}`"  sent={4}  {5}" -f $i, $Connections, $r.serverBanner, $banner.Trim(), $sent, $r.note)
}

$endedAt = Get-Date
Say '----------------------- 演练后 -----------------------' 'Cyan'
Say "  runId       : $RunId"
Say ("  开始时间(ISO): " + $startedAt.ToString('yyyy-MM-ddTHH:mm:sszzz'))
Say ("  结束时间(ISO): " + $endedAt.ToString('yyyy-MM-ddTHH:mm:sszzz'))
Say ("  实际请求数  : $script:RequestCount / 上限 $MaxRequests   用时 $([int]($endedAt - $startedAt).TotalSeconds) 秒")
Say ("  连接成功    : " + (@($results | Where-Object { $_.ok }).Count) + " / $Connections")

# ---- 证据落盘 ----
if (-not (Test-Path $EvidenceDir)) { New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null }
$evidence = [pscustomobject]@{
    scenario    = 'sim-01'
    title       = 'SSH 连接与版本探测'
    runId       = $RunId
    target      = "$TargetIp`:$TargetPort"
    startedAt   = $startedAt.ToString('yyyy-MM-ddTHH:mm:sszzz')
    endedAt     = $endedAt.ToString('yyyy-MM-ddTHH:mm:sszzz')
    startedAtUtc= $startedAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    endedAtUtc  = $endedAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    requests    = $script:RequestCount
    maxRequests = $MaxRequests
    minIntervalMs = $MinIntervalMs
    guardrails  = @('target-whitelist', 'request-cap', 'min-interval', 'unique-runId', 'non-destructive')
    results     = $results
}
$jsonPath = Join-Path $EvidenceDir "$RunId.json"
$evidence | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 $jsonPath
$logPath  = Join-Path $EvidenceDir "$RunId-console.txt"
[IO.File]::WriteAllLines($logPath, $script:LogLines, (New-Object Text.UTF8Encoding($false)))
Say "  证据 JSON   : $jsonPath"
Say "  控制台日志  : $logPath"
Say '======================================================='
Say ''
