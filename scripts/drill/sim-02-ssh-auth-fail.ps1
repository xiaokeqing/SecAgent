<#
  sim-02 · SSH 登录失败尝试（安全版）
  ============================================================
  动作：对 srv2 蜜罐 SSH 端口做 8 次认证尝试，用户名一律用 runId 演练标记，
        口令是随机编造的假口令：
          第 1-4 次：password 认证（故意用错误口令）
          第 5-8 次：publickey 认证（投递临时生成的一次性密钥，必然不被接受）
        【不做成功爆破、不执行任何命令、不进 shell】

  预期检出：Cowrie 100101 登录失败 + 100110 复合规则（120 秒内 5 次失败 -> 暴力破解）。
  已知偏差（如实记录，不美化）：srv2 Cowrie 使用默认 userdb（通配放行），
    口令认证会被"接受"，因此密码那 4 次落到 100102（登录成功）；
    publickey 那 4 次才可能落到 100101。

  内置护栏：
    ① 目标白名单 47.96.106.187 / 43.143.114.79，其他目标直接拒绝
    ② 请求数 <= 30、间隔 >= 500ms（脚本与内嵌 Python 双重限速）
    ③ 唯一 runId，且用 runId 当用户名，直接写进告警描述便于定位
    ④ 非破坏性：无真实口令、无 webshell、不执行命令、不进交互 shell
    ⑤ 演练前后打印目标/动作/请求数/runId/ISO 起止时间
#>
[CmdletBinding()]
param(
    # ---- 可调参数 ----
    [string]$TargetIp         = '43.143.114.79',   # srv2（腾讯云上海）
    [int]   $TargetPort       = 2222,              # Cowrie 蜜罐 SSH 端口
    [int]   $Attempts         = 8,                 # 预计请求数（认证尝试次数）
    [int]   $PasswordAttempts = 4,                 # 其中前几次用 password 认证
    [int]   $MinIntervalMs    = 500,               # 相邻请求最小间隔
    [int]   $ConnectTimeoutMs = 8000,
    [string]$RunIdPrefix      = 'DRILL-sim-02',
    [string]$PythonExe        = '',                # 留空则自动探测
    [string]$EvidenceDir      = (Join-Path $PSScriptRoot '..\..\_tmp')
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

Assert-WhitelistedTarget -Ip $TargetIp
if ($Attempts -gt $MaxRequests) { Say "[护栏拒绝] Attempts=$Attempts 超过硬上限 $MaxRequests，脚本中止。" 'Red'; exit 92 }
if ($PasswordAttempts -gt $Attempts) { Say "[护栏拒绝] PasswordAttempts 不能大于 Attempts。" 'Red'; exit 92 }

# ---- 找 Python（paramiko 用来做真实的 SSH 认证握手） ----
if (-not $PythonExe) {
    foreach ($cand in @("$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
                        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
                        'F:\Pycharm\python3.9\python.exe', 'python.exe', 'python3.exe')) {
        try {
            if ($cand -match '[\\/]' ) { if (Test-Path $cand) { $PythonExe = $cand; break } }
            else { $c = Get-Command $cand -ErrorAction SilentlyContinue; if ($c) { $PythonExe = $c.Source; break } }
        } catch { }
    }
}
if (-not $PythonExe) { Say "[环境不足] 找不到 Python（sim-02 需要 paramiko 做真实认证握手）。脚本中止，不伪造数据。" 'Red'; exit 93 }

$pyCheck = & $PythonExe -c "import paramiko;print(paramiko.__version__)" 2>&1
if ($LASTEXITCODE -ne 0) { Say "[环境不足] $PythonExe 没有 paramiko：$pyCheck —— 脚本中止，不伪造数据。" 'Red'; exit 93 }

Say ''
Say '==================== sim-02 演练前 ====================' 'Cyan'
Say "  目标        : $TargetIp`:$TargetPort  (srv2 · Cowrie 蜜罐，白名单内)"
Say "  动作        : $Attempts 次 SSH 认证尝试（前 $PasswordAttempts 次 password / 其余 publickey），用户名=runId，口令为假口令"
Say "  预计请求数  : $Attempts  (硬上限 $MaxRequests，间隔 >= ${MinIntervalMs}ms)"
Say "  runId       : $RunId"
Say '  破坏性 payload: 无（不猜真实口令、不投递 webshell、不执行命令、不进 shell）'
Say "  Python      : $PythonExe (paramiko $pyCheck)"
Say '======================================================='

# ---- 内嵌 Python：真实 SSH 认证握手（限速/计数在 Python 内再保一层） ----
$pyFile = Join-Path $env:TEMP "sim02-$RunId.py"
$py = @'
import json, sys, time
import paramiko

host = sys.argv[1]; port = int(sys.argv[2]); runid = sys.argv[3]
attempts = int(sys.argv[4]); pw_attempts = int(sys.argv[5])
interval = float(sys.argv[6]) / 1000.0
timeout = float(sys.argv[7]) / 1000.0
result_file = sys.argv[8]

passwords = ["DrillWrong-1!", "DrillWrong-2!", "DrillWrong-3!", "DrillWrong-4!",
             "DrillWrong-5!", "DrillWrong-6!", "DrillWrong-7!", "DrillWrong-8!"]
# 注意：Cowrie 不广播 rsa-sha2-*，用 RSA 私钥会报
# "Unable to agree on a pubkey algorithm for signing a 'ssh-rsa' key!"，
# 所以优先用 ECDSA（签名算法固定，能真的走到服务端被拒绝那一步）。
try:
    key = paramiko.ECDSAKey.generate()
    key_kind = key.get_name()
except Exception:
    key = paramiko.RSAKey.generate(2048)
    key_kind = "ssh-rsa"
out = []
last = None
for i in range(1, attempts + 1):
    if last is not None:
        gap = interval - (time.time() - last)
        if gap > 0:
            time.sleep(gap)
    username = runid if i == 1 else "%s-a%02d" % (runid, i)
    mode = "password" if i <= pw_attempts else "publickey"
    rec = {"n": i, "mode": mode, "username": username, "tcp": False, "authAccepted": None, "serverBanner": "", "error": ""}
    t = None
    try:
        t = paramiko.Transport((host, port))
        t.banner_timeout = timeout
        t.start_client(timeout=timeout)
        rec["tcp"] = True
        rec["serverBanner"] = (t.remote_version or "")[:120]
        if mode == "password":
            try:
                t.auth_password(username=username, password=passwords[(i - 1) % len(passwords)])
                rec["authAccepted"] = True
            except paramiko.AuthenticationException:
                rec["authAccepted"] = False
            except Exception as e:
                rec["authAccepted"] = False
                rec["error"] = type(e).__name__ + ": " + str(e)[:200]
        else:
            try:
                t.auth_publickey(username=username, key=key)
                rec["authAccepted"] = True
            except paramiko.AuthenticationException:
                rec["authAccepted"] = False
            except Exception as e:
                rec["authAccepted"] = False
                rec["error"] = type(e).__name__ + ": " + str(e)[:200]
    except Exception as e:
        rec["error"] = type(e).__name__ + ": " + str(e)[:200]
    finally:
        try:
            if t: t.close()
        except Exception:
            pass
    last = time.time()
    out.append(rec)
with open(result_file, "w", encoding="utf-8") as f:
    json.dump(out, f, ensure_ascii=False)
print(json.dumps({"written": result_file, "attempts": len(out), "keyKind": key_kind}, ensure_ascii=False))
'@
[IO.File]::WriteAllText($pyFile, $py, (New-Object Text.UTF8Encoding($false)))

$startedAt = Get-Date
Say ("  开始时间(ISO): " + $startedAt.ToString('yyyy-MM-ddTHH:mm:sszzz')) 'Yellow'

$pyResultFile = Join-Path $env:TEMP "sim02-result-$RunId.json"
if (Test-Path $pyResultFile) { Remove-Item $pyResultFile -Force }
# 注意：paramiko 的日志走 stderr，PS 5.1 在 $ErrorActionPreference='Stop' 下会把
# 原生程序的 stderr 当成终止性错误，所以这里临时降级为 Continue。
$eapSaved = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$raw = & $PythonExe $pyFile $TargetIp $TargetPort $RunId $Attempts $PasswordAttempts $MinIntervalMs $ConnectTimeoutMs $pyResultFile 2>&1
$pyExit = $LASTEXITCODE
$ErrorActionPreference = $eapSaved
if ($pyExit -ne 0) {
    Say "[执行失败] 内嵌 Python 退出码 $pyExit，输出：" 'Red'
    $raw | ForEach-Object { Say "    $_" 'Red' }
    Say "  说明：若为 paramiko 握手问题，如实记录为'本剧本未能产生流量'，不伪造数据。" 'Red'
}
$attemptsResult = @()
if (Test-Path $pyResultFile) {
    # 坑：PS 5.1 的 ConvertFrom-Json 把 JSON 数组当成"单个管线对象"，
    # 所以不能写 @(... | ConvertFrom-Json)（会变成"数组套数组"，Count 恒为 1）。
    try {
        $parsed = (Get-Content -Raw -Encoding UTF8 $pyResultFile) | ConvertFrom-Json
        foreach ($x in $parsed) { $attemptsResult += $x }
    } catch { Say "[解析失败] $($_.Exception.Message)" 'Red' }
} else {
    Say "[警告] Python 没有落结果文件，原始输出：$raw" 'Red'
}
$keyKind = ''
foreach ($line in @($raw)) { if ("$line" -match '"keyKind"\s*:\s*"([^"]+)"') { $keyKind = $Matches[1] } }

$endedAt = Get-Date
foreach ($a in $attemptsResult) {
    Say ("  [{0:d2}/{1}] mode={2,-9} user={3,-34} tcp={4} authAccepted={5} server=`"{6}`" {7}" -f `
        $a.n, $Attempts, $a.mode, $a.username, $a.tcp, $a.authAccepted, $a.serverBanner, $a.error)
}
$sentCount = @($attemptsResult).Count
if ($sentCount -gt $MaxRequests) { Say "[护栏违反] 实际尝试数 $sentCount 超过上限，必须排查。" 'Red' }
if ($keyKind) { Say "  一次性公钥算法: $keyKind（publickey 尝试用，用完即弃）" }

Say '----------------------- 演练后 -----------------------' 'Cyan'
Say "  runId       : $RunId"
Say ("  开始时间(ISO): " + $startedAt.ToString('yyyy-MM-ddTHH:mm:sszzz'))
Say ("  结束时间(ISO): " + $endedAt.ToString('yyyy-MM-ddTHH:mm:sszzz'))
Say ("  实际请求数  : $sentCount / 上限 $MaxRequests   用时 $([int]($endedAt - $startedAt).TotalSeconds) 秒")
Say ("  认证被接受  : " + (@($attemptsResult | Where-Object { $_.authAccepted -eq $true }).Count) + " 次；被拒绝 " + (@($attemptsResult | Where-Object { $_.authAccepted -eq $false }).Count) + " 次")
Say '  备注：蜜罐侧会把任意口令记成"登录成功"(100102)，而 SSH 协议层仍可能回失败'
Say '        （paramiko 判为拒绝）—— 两侧口径不同，报告里两个口径都列，不挑好看的那个。'

if (-not (Test-Path $EvidenceDir)) { New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null }
$evidence = [pscustomobject]@{
    scenario = 'sim-02'
    title    = 'SSH 登录失败尝试'
    runId    = $RunId
    target   = "$TargetIp`:$TargetPort"
    startedAt= $startedAt.ToString('yyyy-MM-ddTHH:mm:sszzz')
    endedAt  = $endedAt.ToString('yyyy-MM-ddTHH:mm:sszzz')
    startedAtUtc = $startedAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    endedAtUtc   = $endedAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    requests = $sentCount
    maxRequests = $MaxRequests
    minIntervalMs = $MinIntervalMs
    guardrails = @('target-whitelist','request-cap','min-interval','unique-runId','non-destructive')
    python = "$PythonExe (paramiko $pyCheck)"
    publicKeyKind = $keyKind
    attempts = $attemptsResult
}
$jsonPath = Join-Path $EvidenceDir "$RunId.json"
$evidence | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 $jsonPath
$logPath = Join-Path $EvidenceDir "$RunId-console.txt"
[IO.File]::WriteAllLines($logPath, $script:LogLines, (New-Object Text.UTF8Encoding($false)))
Say "  证据 JSON   : $jsonPath"
Say "  控制台日志  : $logPath"
Say '======================================================='
Say ''
