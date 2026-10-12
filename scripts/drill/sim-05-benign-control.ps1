<#
  sim-05 · 良性对照（安全版）
  ============================================================
  动作：完全正常的运维动作 —— 从本机对 srv1 的健康接口发 3 次正常请求
        （经 SSH 本地端口转发打到 srv1 的 /api/health，本机只与白名单里的 srv1 通信）。
  预期：零告警。若产生告警 -> 如实记为误报。

  ★ 现场事实：srv1 的 9900 只绑 127.0.0.1 + firewalld 只放行 ssh，
    因此"从本机打健康接口"必须走 SSH 隧道 —— 这本身就是正常运维动作。
    另外：srv1 上没有 Wazuh agent（见报告），所以"零告警"有一半是结构性的，
    报告里必须写清楚，不能拿它当"检测能力"的功劳。

  内置护栏：
    ① 目标白名单：脚本先用 `ssh -G <别名>` 解析别名，主机不在白名单就拒绝执行
       （回环地址只允许用于本条已校验的隧道，且远端固定为白名单里的 srv1:9900）
    ② 请求数 <= 30、间隔 >= 500ms
    ③ runId（只进日志与时间窗，不污染线上数据）
    ④ 非破坏性：只读健康接口
    ⑤ 演练前后打印目标/动作/请求数/runId/ISO 起止时间
#>
[CmdletBinding()]
param(
    # ---- 可调参数 ----
    [string]$SshAlias        = 'secagent-srv1',   # 白名单主机 srv1 的 ssh 别名
    [string]$TargetIp        = '47.96.106.187',   # 白名单里的 srv1
    [int]   $TunnelLocalPort = 19900,
    [int]   $RemoteHealthPort= 9900,
    [string]$HealthPath      = '/api/health',
    [int]   $Requests        = 3,
    [int]   $MinIntervalMs   = 500,
    [int]   $TimeoutMs       = 8000,
    [string]$RunIdPrefix     = 'DRILL-sim-05',
    [string]$EvidenceDir     = (Join-Path $PSScriptRoot '..\..\_tmp')
)

$ErrorActionPreference = 'Stop'

# ============================================================
# 护栏常量
# ============================================================
$AllowedTargets = @('47.96.106.187', '43.143.114.79')
$MaxRequests    = 30

$RunId = "$RunIdPrefix-" + (Get-Date -Format 'yyyyMMddTHHmmss')
$script:LogLines = New-Object System.Collections.Generic.List[string]
function Say {
    param([string]$Text = '', [string]$Color = 'Gray')
    Write-Host $Text -ForegroundColor $Color
    $script:LogLines.Add($Text)
}
function Assert-WhitelistedTarget {
    param([string]$Ip, [string]$Where = '')
    if ($AllowedTargets -notcontains $Ip) {
        Say "[护栏拒绝] 目标 '$Ip' 不在白名单（$($AllowedTargets -join ' / ')）$Where。脚本中止。" 'Red'
        exit 90
    }
}

# ---- 护栏①a：别名解析出来的真实主机必须在白名单 ----
$sshG = & ssh -G $SshAlias 2>$null
$resolvedHost = ($sshG | Where-Object { $_ -match '^hostname\s+' } | Select-Object -First 1) -replace '^hostname\s+', ''
$resolvedHost = "$resolvedHost".Trim()
Say ''
Say '==================== sim-05 演练前 ====================' 'Cyan'
Say "  ssh 别名    : $SshAlias  -> 解析主机 $resolvedHost"
if ($resolvedHost -ne $TargetIp) {
    if ($AllowedTargets -notcontains $resolvedHost) {
        Say "[护栏拒绝] 别名 $SshAlias 解析到 '$resolvedHost'，既不是 $TargetIp 也不在白名单里。脚本中止。" 'Red'
        exit 90
    }
}
Assert-WhitelistedTarget -Ip $TargetIp -Where '（本剧本声明的 srv1）'

if ($Requests -gt $MaxRequests) { Say "[护栏拒绝] Requests=$Requests 超过硬上限 $MaxRequests。" 'Red'; exit 92 }

Say "  目标        : $TargetIp`:$RemoteHealthPort$HealthPath  (srv1 · 只读健康接口，白名单内)"
Say "  动作        : 起一条 SSH 本地端口转发（127.0.0.1:$TunnelLocalPort -> srv1:127.0.0.1:$RemoteHealthPort），发 $Requests 次正常 GET"
Say "  预计请求数  : $Requests (HTTP) + 1 (隧道 SSH)  (硬上限 $MaxRequests，间隔 >= ${MinIntervalMs}ms)"
Say "  runId       : $RunId"
Say '  破坏性 payload: 无（只读接口）'
Say '======================================================='

$startedAt = Get-Date
Say ("  开始时间(ISO): " + $startedAt.ToString('yyyy-MM-ddTHH:mm:sszzz')) 'Yellow'

# ---- 起隧道 ----
$tunnel = $null
$mode = 'tunnel'
try {
    $tunnel = Start-Process -FilePath 'ssh' `
        -ArgumentList @('-N', '-o', 'BatchMode=yes', '-o', 'ExitOnForwardFailure=yes',
                        '-o', 'ConnectTimeout=10', '-L', "127.0.0.1:$TunnelLocalPort`:127.0.0.1:$RemoteHealthPort", $SshAlias) `
        -PassThru -WindowStyle Hidden
    $ready = $false
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 500
        $probe = New-Object System.Net.Sockets.TcpClient
        try {
            $iar = $probe.BeginConnect('127.0.0.1', $TunnelLocalPort, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(500)) { $probe.EndConnect($iar); $ready = $true }
        } catch { } finally { $probe.Close() }
        if ($ready) { break }
        if ($tunnel.HasExited) { break }
    }
} catch { $ready = $false }
$tunnelCount = 1
if (-not $ready) {
    $mode = 'ssh-remote-curl(fallback)'
    Say '  [提示] 本地端口转发没起来，回退到"经 SSH 在 srv1 上执行只读健康检查"（仍然是正常运维动作）。' 'Yellow'
}

# ---- 发 3 次正常请求（原始 socket，绕开本机代理，避免把流量丢给第三方） ----
$results = @()
$last = $null
for ($i = 1; $i -le $Requests; $i++) {
    if ($last -ne $null) {
        $el = ((Get-Date) - $last).TotalMilliseconds
        if ($el -lt $MinIntervalMs) { Start-Sleep -Milliseconds ([int][Math]::Ceiling($MinIntervalMs - $el)) }
    }
    $last = Get-Date
    $rec = [pscustomobject]@{ n = $i; mode = $mode; statusLine = ''; bytes = 0; note = '' }
    if ($mode -eq 'tunnel') {
        # 护栏①b：只有本条经过校验的隧道允许用回环地址，远端固定为白名单 srv1
        Assert-WhitelistedTarget -Ip $TargetIp -Where '（隧道对端）'
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $iar = $client.BeginConnect('127.0.0.1', $TunnelLocalPort, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
                $client.EndConnect($iar)
                $stream = $client.GetStream()
                $stream.ReadTimeout = $TimeoutMs
                $req = "GET $HealthPath HTTP/1.1`r`nHost: 127.0.0.1`r`nUser-Agent: $RunId`r`nAccept: */*`r`nConnection: close`r`n`r`n"
                $b = [Text.Encoding]::ASCII.GetBytes($req)
                $stream.Write($b, 0, $b.Length); $stream.Flush()
                $ms = New-Object IO.MemoryStream
                $buf = New-Object byte[] 4096
                try {
                    while (($n = $stream.Read($buf, 0, 4096)) -gt 0) { $ms.Write($buf, 0, $n) }
                } catch { }
                $txt = [Text.Encoding]::ASCII.GetString($ms.ToArray())
                $rec.bytes = $txt.Length
                $rec.statusLine = ($txt -split "`r`n")[0]
                $stream.Close()
            } else { $rec.note = 'connect 隧道超时' }
        } catch { $rec.note = $_.Exception.Message } finally { $client.Close() }
    } else {
        $out = & ssh -o BatchMode=yes -o ConnectTimeout=10 $SshAlias "curl -s -o /dev/null -w '%{http_code}' --max-time 8 http://127.0.0.1:$RemoteHealthPort$HealthPath" 2>&1
        $rec.statusLine = "HTTP代码 $out（由 srv1 本机发起）"
        $rec.bytes = -1
    }
    $results += $rec
    Say ("  [{0}/{1}] {2}  ->  {3} {4}" -f $i, $Requests, $mode, $rec.statusLine, $rec.note)
}

if ($tunnel -and -not $tunnel.HasExited) { Stop-Process -Id $tunnel.Id -Force -ErrorAction SilentlyContinue }
$totalRequests = $Requests + $tunnelCount
$endedAt = Get-Date
Say '----------------------- 演练后 -----------------------' 'Cyan'
Say "  runId       : $RunId"
Say ("  开始时间(ISO): " + $startedAt.ToString('yyyy-MM-ddTHH:mm:sszzz'))
Say ("  结束时间(ISO): " + $endedAt.ToString('yyyy-MM-ddTHH:mm:sszzz'))
Say ("  实际请求数  : $Requests (HTTP) + 1 (隧道 SSH) = $totalRequests / 上限 $MaxRequests   用时 $([int]($endedAt - $startedAt).TotalSeconds) 秒")
Say '  预期        : 零告警（良性对照）。若出现告警 -> 报告里记"误报"。'

if (-not (Test-Path $EvidenceDir)) { New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null }
$evidence = [pscustomobject]@{
    scenario = 'sim-05'
    title    = '良性对照（正常运维动作）'
    runId    = $RunId
    target   = "$TargetIp`:$RemoteHealthPort$HealthPath via ssh:$SshAlias"
    startedAt= $startedAt.ToString('yyyy-MM-ddTHH:mm:sszzz')
    endedAt  = $endedAt.ToString('yyyy-MM-ddTHH:mm:sszzz')
    startedAtUtc = $startedAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    endedAtUtc   = $endedAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    requests = $totalRequests
    maxRequests = $MaxRequests
    minIntervalMs = $MinIntervalMs
    guardrails = @('target-whitelist','ssh-alias-resolution-check','request-cap','min-interval','unique-runId','non-destructive')
    mode     = $mode
    results  = $results
}
$jsonPath = Join-Path $EvidenceDir "$RunId.json"
$evidence | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 $jsonPath
$logPath = Join-Path $EvidenceDir "$RunId-console.txt"
[IO.File]::WriteAllLines($logPath, $script:LogLines, (New-Object Text.UTF8Encoding($false)))
Say "  证据 JSON   : $jsonPath"
Say "  控制台日志  : $logPath"
Say '======================================================='
Say ''
