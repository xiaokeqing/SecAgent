<#
.SYNOPSIS
  去本机化的部署：本机只编译 jar，服务器自己构建镜像并重启。

.DESCRIPTION
  分工（为什么这样分）：
    · 本机：JDK + Maven 打包 jar（几十 MB）—— **不需要 Docker**、不吃本机镜像空间
    · 服务器 1：docker build --network=host 构建镜像 + compose 重建

  对比原来的做法（本机 docker build → docker save 311MB → scp）：
  那个做法在【本机没 Docker / C 盘满 / 内网无梯子】时完全发不了版（实测踩过：C 盘被镜像占满导致瘫痪）。
  现在只依赖 mvn + scp，服务器有 Docker 与磁盘即可。

.EXAMPLE
  pwsh -File scripts/deploy-remote-build.ps1
  pwsh -File scripts/deploy-remote-build.ps1 -SkipBuild     # 复用已有 jar
#>
param(
  [string]$SshHost = 'secagent-srv1',
  [string]$RemoteDir = '/opt/secagent',
  [switch]$SkipBuild
)

$ErrorActionPreference = 'Continue'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

function Step($n, $msg) { Write-Host "==> $n $msg" }

# 0) 版本指纹
$sha = (git rev-parse --short HEAD).Trim()
Step "0/4" "部署版本 = $sha"

# 1) 本机编译（不需要 Docker）
if (-not $SkipBuild) {
  Step "1/4" "本机编译 + 单测（mvn package）"
  $env:JAVA_HOME = if ($env:JAVA_HOME) { $env:JAVA_HOME } else { 'C:\Users\T\.jdks\ms-17.0.20.1' }
  $mvn = 'F:\Maven\apache-maven-3.9.12-bin\apache-maven-3.9.12\bin\mvn.cmd'
  if (-not (Test-Path $mvn)) { $mvn = 'mvn' }
  & $mvn -B package 2>&1 | Select-String -Pattern 'Tests run:.*Failures: \d+, Errors|BUILD|ERROR' |
    Select-Object -Last 3 | ForEach-Object { Write-Host "    $($_.Line)" }
  if ($LASTEXITCODE -ne 0) { Write-Error "本机编译失败，中止"; exit 1 }
} else {
  Step "1/4" "跳过编译（复用已有 jar）"
}

$jar = Join-Path $repo 'target\sec-agent-1.0-SNAPSHOT.jar'
if (-not (Test-Path $jar)) { Write-Error "找不到 jar: $jar"; exit 1 }

# 2) 只上传源码产物与构建脚本（不上传镜像）
Step "2/4" "上传 jar / Dockerfile / 服务器构建脚本"
scp -o ConnectTimeout=20 $jar "${SshHost}:/tmp/sec-agent.jar" | Out-Null
# 必须上传 Dockerfile.runtime（单阶段、直接用上传的 jar）而不是 Dockerfile（多阶段、会在镜像内用服务器源码编译）
scp -o ConnectTimeout=20 (Join-Path $repo 'Dockerfile.runtime') "${SshHost}:$RemoteDir/Dockerfile.runtime" | Out-Null
scp -o ConnectTimeout=20 (Join-Path $repo 'scripts\build-on-server.sh') "${SshHost}:$RemoteDir/scripts/build-on-server.sh" | Out-Null
Write-Host "    上传完成（jar 约 $([math]::Round((Get-Item $jar).Length/1MB,0)) MB；不再传 311MB 镜像）"

# 3) 服务器侧构建 + 重启
Step "3/4" "服务器侧 docker build --network=host + compose 重建"
ssh -o ConnectTimeout=20 $SshHost "tr -d '\r' < $RemoteDir/scripts/build-on-server.sh > /tmp/b.sh && chmod +x /tmp/b.sh && bash /tmp/b.sh /tmp/sec-agent.jar $sha" 2>&1 |
  Select-Object -Last 10 | ForEach-Object { Write-Host "    $_" }

# 4) 核对
Step "4/4" "核对线上版本指纹"
$health = ssh -o ConnectTimeout=20 $SshHost "curl -s -m 15 http://127.0.0.1:9900/api/health" 2>$null
Write-Host "    $health"
if ($health -notmatch [regex]::Escape($sha)) {
  Write-Host "[!] 线上 buildSha 与本次版本不一致 —— 请查上面的构建/重启输出"
  exit 1
}
Write-Host "[OK] 部署完成，线上 buildSha = $sha"
