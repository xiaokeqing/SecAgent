<#
  sim-03 · Web 路径探测（安全版）
  ============================================================
  动作：对【我方资产】的 HTTP 端口发 6 个典型可疑路径的 GET 请求：
          /.env  /phpmyadmin  /upload/files/x.asp;.jpg  /admin/login.php  /wp-login.php  /.git/config
        URL 与 User-Agent 里都带 runId 演练标记。
        【只发 GET，不投递 webshell、不传文件、不带任何执行 payload】

  预期检出：Suricata HTTP 规则 / 蜜罐 Web 记录。

  ★ 现场事实（脚本会打印探测结论，不美化）：
    srv2 上 ufw 只放行 22 与 2222，全项目唯一故意对外开放的端口是 Cowrie 的 2222；
    【没有 web 蜜罐进程在监听】。所以本剧本分两条腿跑：
      腿 A：打到常规 HTTP 端口 $HoneypotWebPort（默认 80）——预期被丢弃；
      腿 B：同样的 6 个路径打到唯一开放的 2222（Cowrie）——看 Suricata 会不会把
            "非标准端口上的 HTTP 探测"识别出来。
    "有没有 web 蜜罐"的结论以服务器侧 ss 为准（见报告），不靠猜测。

  内置护栏：
    ① 目标白名单 47.96.106.187 / 43.143.114.79，其他目标直接拒绝
    ② 总请求数 <= 30、间隔 >= 500ms
    ③ 唯一 runId，写进 URL 查询串与 User-Agent
    ④ 非破坏性：只有 GET，无 payload、无上传、无 webshell
    ⑤ 演练前后打印目标/动作/请求数/runId/ISO 起止时间
#>
[CmdletBinding()]
param(
    # ---- 可调参数 ----
    [string]$TargetIp        = '43.143.114.79',   # srv2（腾讯云上海）
    [int[]] $ProbePorts      = @(80, 2222),       # 腿A=80(期望无 web 蜜罐)，腿B=2222(唯一开放端口)
    [int]   $HoneypotWebPort = 80,                # 设计文档里的"蜜罐 Web 端口"
    [int]   $MinIntervalMs   = 500,
    [int]   $ConnectTimeoutMs= 4000,
    [int]   $ReadTimeoutMs   = 2500,
    [string]$RunIdPrefix     = 'DRILL-sim-03',
    [string]$EvidenceDir     = (Join-Path $PSScriptRoot '..\..\_tmp')
)

$ErrorActionPreference = 'Stop'

# ============================================================
# 护栏常量
# ============================================================
$AllowedTargets = @('47.96.106.187', '43.143.114.79')
$MaxRequests    = 30
$WebPaths = @(
    '/.env',
    '/phpmyadmin',
    '/upload/files/x.asp;.jpg',
    '/admin/login.php',
    '/wp-login.php',
    '/.git/config'
)

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
$total = $WebPaths.Count * $ProbePorts.Count
if ($total -gt $MaxRequests) { Say "[护栏拒绝] 预计请求数 $total 超过硬上限 $MaxRequests，脚本中止。" 'Red'; exit 92 }

Say ''
Say '==================== sim-03 演练前 ====================' 'Cyan'
Say "  目标        : $TargetIp  端口 $($ProbePorts -join ', ')  (srv2，白名单内)"
Say "  动作        : 6 个可疑 Web 路径 × $($ProbePorts.Count) 个端口 = $total 个 HTTP GET（带 runId 标记）"
Say "  路径        : $($WebPaths -join ' ')"
Say "  预计请求数  : $total  (硬上限 $MaxRequests，间隔 >= ${MinIntervalMs}ms)"
Say "  runId       : $RunId"
Say '  破坏性 payload: 无（仅 GET；不投递 webshell、不上传文件、不带命令）'
Say '======================================================='

$startedAt = Get-Date
Say ("  开始时间(ISO): " + $startedAt.ToString('yyyy-MM-ddTHH:mm:sszzz')) 'Yellow'

$results = @()
foreach ($port in $ProbePorts) {
    Say "  --- 端口 $port ---" 'DarkCyan'
    foreach ($p in $WebPaths) {
        Get-RequestSlot -What "http-get $p -> $port"
        $pathWithMarker = "$p" + "?drill=$RunId"
        $req = "GET $pathWithMarker HTTP/1.1`r`nHost: $TargetIp`:$port`r`nUser-Agent: $RunId`r`nAccept: */*`r`nConnection: close`r`n`r`n"
        $rec = [pscustomobject]@{ port = $port; path = $p; tcp = $false; statusLine = ''; serverBanner = ''; note = '' }
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $iar = $client.BeginConnect($TargetIp, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne($ConnectTimeoutMs)) {
                $client.EndConnect($iar)
                $rec.tcp = $true
                $stream = $client.GetStream()
                $stream.ReadTimeout = $ReadTimeoutMs
                # 先看服务器是否主动打招呼（web 蜜罐/HTTP 服务通常会等你发请求，SSH 会先发 banner）
                $pre = New-Object byte[] 256
                try {
                    $n = $stream.Read($pre, 0, 256)
                    if ($n -gt 0) {
                        $rec.serverBanner = ([Text.Encoding]::ASCII.GetString($pre, 0, $n)).Trim()
                        if ($rec.serverBanner -like 'SSH-*') { $rec.note = '该端口是 SSH 服务（Cowrie），不是 web 服务' }
                    } else { $rec.note = '连接立即被关闭' }
                } catch { }
                $bytes = [Text.Encoding]::ASCII.GetBytes($req)
                $stream.Write($bytes, 0, $bytes.Length); $stream.Flush()
                $buf = New-Object byte[] 512
                try {
                    $n2 = $stream.Read($buf, 0, 512)
                    if ($n2 -gt 0) {
                        $txt = [Text.Encoding]::ASCII.GetString($buf, 0, $n2)
                        $rec.statusLine = ($txt -split "`r`n")[0]
                        if (-not $rec.serverBanner) { $rec.serverBanner = ($txt -split "`r`n")[0] }
                    } else { if (-not $rec.note) { $rec.note = '无响应（端口被丢弃，或对端不认识 HTTP）' } }
                } catch {
                    if (-not $rec.note) { $rec.note = '读超时（SYN 被丢弃或对端不响应 HTTP）' }
                }
                $stream.Close()
            } else {
                $rec.note = 'connect 超时（SYN 被丢弃）'
            }
        } catch {
            $rec.note = "异常: $($_.Exception.Message)"
        } finally { $client.Close() }
        $results += $rec
        Say ("    port={0,-5} {1,-28} tcp={2,-5} status=`"{3}`" banner=`"{4}`" {5}" -f $port, $p, $rec.tcp, $rec.statusLine, $rec.serverBanner, $rec.note)
    }
}

$endedAt = Get-Date
$httpAnswered = @($results | Where-Object { $_.statusLine -match '^HTTP/' }).Count
$sshAnswered  = @($results | Where-Object { $_.serverBanner -like 'SSH-*' }).Count
Say '----------------------- 演练后 -----------------------' 'Cyan'
Say "  runId       : $RunId"
Say ("  开始时间(ISO): " + $startedAt.ToString('yyyy-MM-ddTHH:mm:sszzz'))
Say ("  结束时间(ISO): " + $endedAt.ToString('yyyy-MM-ddTHH:mm:sszzz'))
Say ("  实际请求数  : $script:RequestCount / 上限 $MaxRequests   用时 $([int]($endedAt - $startedAt).TotalSeconds) 秒")
Say "  探测结论    : TCP 连上 $((@($results | Where-Object { $_.tcp })).Count)/$total；真正回 HTTP 的 $httpAnswered 个；回 SSH banner 的 $sshAnswered 个"
Say '  探测结论    : 若"真正回 HTTP 的"为 0，则说明我方资产上【没有可打的 web 蜜罐/HTTP 服务】——'
Say '                这是客观事实，报告里按"无法产生预期流量"如实记录，不伪造命中。'

if (-not (Test-Path $EvidenceDir)) { New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null }
$evidence = [pscustomobject]@{
    scenario = 'sim-03'
    title    = 'Web 路径探测'
    runId    = $RunId
    target   = "$TargetIp ports=$($ProbePorts -join ',')"
    startedAt= $startedAt.ToString('yyyy-MM-ddTHH:mm:sszzz')
    endedAt  = $endedAt.ToString('yyyy-MM-ddTHH:mm:sszzz')
    startedAtUtc = $startedAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    endedAtUtc   = $endedAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    requests = $script:RequestCount
    maxRequests = $MaxRequests
    minIntervalMs = $MinIntervalMs
    guardrails = @('target-whitelist','request-cap','min-interval','unique-runId','non-destructive')
    httpAnswered = $httpAnswered
    sshAnswered  = $sshAnswered
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
