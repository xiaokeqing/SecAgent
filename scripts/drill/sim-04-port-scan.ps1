<#
  sim-04 · 端口扫描特征（安全版）
  ============================================================
  动作：对 srv2 的 8 个端口做【串行】TCP 连接尝试，间隔 500ms，
        不发任何应用层数据（最多读一下对端 banner，用来判断端口是否真有服务）。
  预期检出：Suricata ET SCAN 类规则。若无命中 -> 如实记为漏报（这正是要发现的东西）。

  ★ 注意：本机走 clash TUN，对"被丢弃的端口"可能出现"本地假连通"，
    因此脚本对每个端口额外读一次 banner，并把结果分成
      OPEN(有服务响应) / 无响应(可能被丢弃) 两类，避免把假象写成"开放"。

  内置护栏：
    ① 目标白名单 47.96.106.187 / 43.143.114.79，其他目标直接拒绝
    ② 总请求数 <= 30、间隔 >= 500ms（串行，不做并发/半开/拒绝服务式扫描）
    ③ runId（本剧本流量里没有载荷，故 runId 只用于日志与时间窗对齐）
    ④ 非破坏性：只做 TCP 连接，不发漏洞利用、不做 SYN flood
    ⑤ 演练前后打印目标/动作/请求数/runId/ISO 起止时间
#>
[CmdletBinding()]
param(
    # ---- 可调参数 ----
    [string]$TargetIp        = '43.143.114.79',                # srv2（腾讯云上海）
    [int[]] $Ports           = @(21, 22, 23, 25, 80, 443, 3306, 2222),
    [int]   $MinIntervalMs   = 500,
    [int]   $ConnectTimeoutMs= 3000,
    [int]   $BannerReadMs    = 1500,
    [string]$RunIdPrefix     = 'DRILL-sim-04',
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
    param([string]$Ip)
    if ($AllowedTargets -notcontains $Ip) {
        Say "[护栏拒绝] 目标 '$Ip' 不在白名单（$($AllowedTargets -join ' / ')）。脚本中止。" 'Red'
        exit 90
    }
}
$script:RequestCount = 0
$script:LastRequestAt = $null
function Get-RequestSlot {
    param([string]$What = 'request')
    if ($script:RequestCount -ge $MaxRequests) { Say "[护栏中止] 请求数已达上限 $MaxRequests（$What）。" 'Red'; exit 91 }
    if ($script:LastRequestAt -ne $null) {
        $elapsed = ((Get-Date) - $script:LastRequestAt).TotalMilliseconds
        if ($elapsed -lt $MinIntervalMs) { Start-Sleep -Milliseconds ([int][Math]::Ceiling($MinIntervalMs - $elapsed)) }
    }
    $script:RequestCount++
    $script:LastRequestAt = Get-Date
}

Assert-WhitelistedTarget -Ip $TargetIp
if ($Ports.Count -gt $MaxRequests) { Say "[护栏拒绝] 端口数 $($Ports.Count) 超过硬上限 $MaxRequests，脚本中止。" 'Red'; exit 92 }

Say ''
Say '==================== sim-04 演练前 ====================' 'Cyan'
Say "  目标        : $TargetIp  端口 $($Ports -join ', ')  (srv2，白名单内)"
Say "  动作        : $($Ports.Count) 个端口串行 TCP 连接（不发应用层数据）"
Say "  预计请求数  : $($Ports.Count)  (硬上限 $MaxRequests，间隔 >= ${MinIntervalMs}ms)"
Say "  runId       : $RunId  （扫描流量无载荷，runId 用于日志与时间窗对齐）"
Say '  破坏性 payload: 无（不并发、不半开、不做 DoS）'
Say '======================================================='

$startedAt = Get-Date
Say ("  开始时间(ISO): " + $startedAt.ToString('yyyy-MM-ddTHH:mm:sszzz')) 'Yellow'

$results = @()
foreach ($port in $Ports) {
    Get-RequestSlot -What "tcp-connect $port"
    $rec = [pscustomobject]@{ port = $port; tcpHandshake = $false; banner = ''; verdict = ''; note = '' }
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($TargetIp, $port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($ConnectTimeoutMs)) {
            $client.EndConnect($iar)
            $rec.tcpHandshake = $true
            $stream = $client.GetStream()
            $stream.ReadTimeout = $BannerReadMs
            $buf = New-Object byte[] 128
            $n = -1
            try { $n = $stream.Read($buf, 0, 128) } catch { $n = -1 }
            if ($n -gt 0) {
                $rec.banner = ([Text.Encoding]::ASCII.GetString($buf, 0, $n)).Trim()
                $rec.verdict = 'OPEN(有服务响应)'
            } else {
                $rec.verdict = '无响应'
                $rec.note = '握手"成功"但对端不吐数据：可能是被 ufw/安全组丢弃，被本地 TUN 伪造了握手'
            }
            $stream.Close()
        } else {
            $rec.verdict = '超时(丢弃)'
            $rec.note = 'connect 超时'
        }
    } catch {
        $rec.verdict = '拒绝/异常'
        $rec.note = $_.Exception.Message
    } finally { $client.Close() }
    $results += $rec
    Say ("    port={0,-6} verdict={1,-18} banner=`"{2}`" {3}" -f $port, $rec.verdict, $rec.banner, $rec.note)
}

$endedAt = Get-Date
Say '----------------------- 演练后 -----------------------' 'Cyan'
Say "  runId       : $RunId"
Say ("  开始时间(ISO): " + $startedAt.ToString('yyyy-MM-ddTHH:mm:sszzz'))
Say ("  结束时间(ISO): " + $endedAt.ToString('yyyy-MM-ddTHH:mm:sszzz'))
Say ("  实际请求数  : $script:RequestCount / 上限 $MaxRequests   用时 $([int]($endedAt - $startedAt).TotalSeconds) 秒")
Say "  有服务响应  : $(@($results | Where-Object { $_.verdict -eq 'OPEN(有服务响应)' }).Count)/$($Ports.Count)"
Say '  口径说明    : 服务器侧权威端口清单以 srv2 `sudo ss -lntup` 为准，本脚本结果只做交叉验证。'

if (-not (Test-Path $EvidenceDir)) { New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null }
$evidence = [pscustomobject]@{
    scenario = 'sim-04'
    title    = '端口扫描特征'
    runId    = $RunId
    target   = "$TargetIp ports=$($Ports -join ',')"
    startedAt= $startedAt.ToString('yyyy-MM-ddTHH:mm:sszzz')
    endedAt  = $endedAt.ToString('yyyy-MM-ddTHH:mm:sszzz')
    startedAtUtc = $startedAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    endedAtUtc   = $endedAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    requests = $script:RequestCount
    maxRequests = $MaxRequests
    minIntervalMs = $MinIntervalMs
    guardrails = @('target-whitelist','request-cap','min-interval','unique-runId','non-destructive')
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
