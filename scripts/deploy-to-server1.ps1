# ============================================================
# 部署 SecAgent 到服务器 1（一条命令走完全流程）
# ------------------------------------------------------------
# 用法：
#   & .\scripts\deploy-to-server1.ps1
#
# 为什么要把这一步做成脚本：
#   我原来每次都是现敲一遍 PowerShell 命令。问题是"部署"其实是
#   一串必须按顺序完成的动作，少一步就出问题，而且【少一步是静默的】：
#
#     构建镜像 -> docker save -> scp 镜像
#              -> scp compose（配置也必须传！）
#              -> scp 版本号文件
#              -> 远程 docker load + compose up
#              -> 【验证线上版本号与本地 HEAD 一致】
#
#   真实踩过的两个坑：
#     · 只传了镜像没传 compose -> compose 靠 git pull，而那条链路时好时坏
#       -> 新加的环境变量压根没被引用，但日志只有一行 warning，看不出来
#     · 忘了部署 -> 线上跑的还是有缺陷的旧版本，从外部完全看不出来
#
#   所以这里做两件事：
#     1) 把全流程固定下来，不依赖"我记得"
#     2) 最后【强制校验】线上版本号与本地 HEAD 一致，不一致就报错退出
# ============================================================

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$Repo   = 'F:\7AAA\AI\SecAgent\sec-agent'
$Deploy = 'F:\7AAA\AI\SecAgent\_deploy'
$Ip     = '47.96.106.187'
$Key    = "$env:USERPROFILE\.ssh\ssh_mcp_ed25519"
$SSH    = @('-i',$Key,'-o','BatchMode=yes','-o','StrictHostKeyChecking=no','-o','ConnectTimeout=20')
$Tar    = Join-Path $Deploy 'secagent-image.tar'

function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function OK($m)   { Write-Host "  [OK] $m" -ForegroundColor Green }
function Bad($m)  { Write-Host "  [XX] $m" -ForegroundColor Red }

Set-Location $Repo

# ── 0. 前置检查：工作区必须干净且已推送 ──────────────────────
Step "0/6 前置检查"
$dirty = git status --short
if ($dirty) {
  Bad "工作区有未提交改动 —— 先提交再部署（否则线上版本无法与仓库对应）"
  $dirty | ForEach-Object { Write-Host "      $_" }
  exit 1
}
$sha = (git rev-parse --short HEAD).Trim()
$ahead = [int](git rev-list --count origin/main..HEAD 2>$null)
if ($ahead -gt 0) { Bad "有 $ahead 个未推送提交 —— 先推送再部署"; exit 1 }
OK "工作区干净且已推送，HEAD=$sha"

# ── 1. 构建 ──────────────────────────────────────────────────
Step "1/6 编译 + 测试 + 构建镜像"
$env:JAVA_HOME = 'C:\Users\T\.jdks\ms-17.0.20.1'
$mvnOut = mvn -B package 2>&1
if ($LASTEXITCODE -ne 0) {
  Bad "构建失败"
  $mvnOut | Select-String -Pattern 'ERROR|FAIL' | Select-Object -First 15 | ForEach-Object { Write-Host "      $($_.Line.Trim())" }
  exit 1
}
($mvnOut | Select-String -Pattern 'Tests run:.*Failures' | Select-Object -Last 1) | ForEach-Object { OK $_.Line.Trim() }
docker build -t secagent:local . 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Bad "docker build 失败"; exit 1 }
OK "镜像已构建"

# ── 2. 导出并上传 ────────────────────────────────────────────
Step "2/6 导出并上传镜像（约 100 秒）"
if (Test-Path $Tar) { Remove-Item -Force $Tar }
docker save -o $Tar secagent:local 2>&1 | Out-Null
$mb = [math]::Round((Get-Item $Tar).Length/1MB,0)
$sw = [System.Diagnostics.Stopwatch]::StartNew()
scp @SSH $Tar "root@${Ip}:/root/secagent-image.tar" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Bad "镜像上传失败"; exit 1 }
$sw.Stop()
OK ("$mb MB，$([math]::Round($sw.Elapsed.TotalSeconds,0)) 秒")

# ── 3. 上传配置与版本号（这是本次修的重点）──────────────────
Step "3/6 上传配置与版本号"
# ⚠️ compose 必须走 scp，不能靠服务器 git pull。
#    那条链路（阿里云 -> GitHub）实测时好时坏，而"配置没更新"是静默的。
scp @SSH (Join-Path $Repo 'docker-compose.yml') "root@${Ip}:/root/deploy-compose.yml" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Bad "compose 上传失败"; exit 1 }
OK "docker-compose.yml 已上传"

# 版本号取自【本地 HEAD】—— 服务器上的 git 可能是旧的
$shaFile = Join-Path $env:TEMP 'build-sha.txt'
[System.IO.File]::WriteAllText($shaFile, $sha, (New-Object System.Text.UTF8Encoding($false)))
scp @SSH $shaFile "root@${Ip}:/root/build-sha.txt" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Bad "版本号文件上传失败"; exit 1 }
OK "build-sha.txt 已上传（$sha）"

# 部署脚本自身也要同步（它可能刚改过）
$depSrc = Join-Path $Repo 'scripts\server-deploy.sh'
$t = [System.IO.File]::ReadAllText($depSrc, [System.Text.Encoding]::UTF8) -replace "`r`n","`n"
[System.IO.File]::WriteAllText($depSrc, $t, (New-Object System.Text.UTF8Encoding($false)))
scp @SSH $depSrc "root@${Ip}:/root/server-deploy.sh" 2>&1 | Out-Null
OK "server-deploy.sh 已上传"

# ── 4. 远程部署 ──────────────────────────────────────────────
Step "4/6 远程部署"
$out = ssh @SSH "root@$Ip" 'bash /root/server-deploy.sh' 2>&1
$out | Select-String -Pattern '==>|\[OK\]|\[!\]|\[X\]|BUILD_SHA' | ForEach-Object { Write-Host "    $($_.Line)" }
if ($LASTEXITCODE -ne 0) { Bad "远程部署失败"; exit 1 }

# ── 5. 【强制校验】线上版本与本地一致 ────────────────────────
Step "5/6 校验线上版本（防部署漂移）"
Start-Sleep -Seconds 5
$health = ssh @SSH "root@$Ip" 'curl -s --max-time 15 http://127.0.0.1:9900/api/health' 2>&1
try {
  $j = $health | ConvertFrom-Json
  $live = "$($j.buildSha)"
  if ($live -eq $sha) {
    OK "线上 buildSha=$live 与本地 HEAD 一致"
  } elseif ($live -eq 'unknown') {
    Bad "线上没报告版本号 —— compose 可能没生效（检查 BUILD_SHA 是否写进容器）"
    exit 1
  } else {
    Bad "部署漂移！本地 HEAD=$sha，线上=$live"
    exit 1
  }
  OK ("健康接口正常：向量 $($j.documentVectors) 条，存储 $($j.vectorStore)")
} catch {
  Bad "健康接口不可解析: $health"
  exit 1
}

# ── 6. 对外可达性 ────────────────────────────────────────────
Step "6/6 对外可达性"
$ok = $false
foreach ($i in 1..3) {
  try {
    $r = Invoke-WebRequest -Uri 'https://demo.xiaokeqing.cn/api/health' -TimeoutSec 45 -UseBasicParsing
    if ($r.StatusCode -eq 200) { OK "demo.xiaokeqing.cn HTTP 200（第 $i 次）"; $ok = $true; break }
  } catch { Start-Sleep -Seconds 4 }
}
if (-not $ok) { Write-Host "  [!!] 外网访问失败 —— 可能是链路抖动，用整体检查复查" -ForegroundColor Yellow }

Write-Host "`n============================================"
Write-Host " 部署完成  版本 $sha" -ForegroundColor Green
Write-Host "============================================"
