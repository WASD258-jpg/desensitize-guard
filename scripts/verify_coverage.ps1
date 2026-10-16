# verify_coverage.ps1 — 覆盖度回归：逐项验证"该抓的能抓到"。
#
#   pwsh -File scripts/verify_coverage.ps1
#
# 覆盖：新增密钥指纹 / 绝对路径（Win+Unix+UNC）/ 压缩包展开 / "加了又删"的提交 /
#       提交者身份 / 高熵未知密钥 / 规则豁免与噪声控制。

[CmdletBinding()]
param(
  [string]$BundleDir = (Split-Path $PSScriptRoot -Parent),
  [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$OutputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$env:PYTHONIOENCODING = "utf-8"

$Script = Join-Path $BundleDir "scripts\desensitize_guard.py"
$Sandbox = Join-Path ([System.IO.Path]::GetTempPath()) "desensitize-guard-coverage"
$env:DESENSITIZE_GUARD_HOME = Join-Path $Sandbox "state"
if (Test-Path $Sandbox) { Remove-Item $Sandbox -Recurse -Force }
New-Item -ItemType Directory -Path $Sandbox -Force | Out-Null

$failures = 0
function Check([string]$Title, [bool]$Ok, [string]$Detail = "") {
  if ($Ok) { Write-Host "[PASS] $Title" -ForegroundColor Green }
  else { Write-Host "[FAIL] $Title  $Detail" -ForegroundColor Red; $script:failures++ }
}
function Scan([string]$Cmd, [string]$Cwd) {
  return (& $Python $Script scan --cmd $Cmd --cwd $Cwd | Out-String)
}

# fixture 一律运行时拼接，避免本仓库自身扫描命中
$FakeStripe = "sk_" + "live_" + "0123456789abcdefghijklmnop"
$FakeKey = "sk-" + "live" + "0123456789abcdefghijklmnopqrstuv"
$FakeHighEntropy = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9" + "tU1vW3xY5zA7bC9dE1fG3hI"
$GcpType = "service" + "_account"
$UserNameInfo = "https://" + "user" + ":" + $FakeKey   # 运行时拼出 user:token@ 形态，源码里不出现完整实例

Write-Host "=== 1. 新增密钥指纹（原先完全没覆盖） ===" -ForegroundColor Cyan
$cases = @(
  @{ Title = "Stripe"; Content = "STRIPE_KEY=$FakeStripe" },
  @{ Title = "SendGrid"; Content = "SG." + "abcdefghijklmnopqrstuv" + "." + "abcdefghijklmnopqrstuvwxyz0123456789abcde" },
  @{ Title = "GitLab PAT"; Content = "glpat-" + "abcdefghijklmnopqrst" },
  @{ Title = "npm token"; Content = "npm_" + "0123456789abcdefghijklmnopqrstuvwxyz" },
  @{ Title = "Discord bot"; Content = "M" + "abcdefghijklmnopqrstuvw" + "." + "abcdef" + "." + "abcdefghijklmnopqrstuvwxyz012" },
  @{ Title = "GCP 服务账号"; Content = '{ "type": "' + $GcpType + '", "project_id": "x" }' },
  @{ Title = "URL 内嵌令牌"; Content = "remote=" + $UserNameInfo + "@" + "git.example.org/repo.git" },
  @{ Title = "Vault token"; Content = "VAULT_TOKEN=hvs." + "abcdefghijklmnopqrstuvwx" },
  @{ Title = "kubeconfig 内嵌数据"; Content = "  certificate-authority-data: " + ("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo" * 3) }
)
foreach ($case in $cases) {
  $file = Join-Path $Sandbox ("case_" + ($case.Title -replace '[^A-Za-z0-9]', '') + ".txt")
  Set-Content -Path $file -Value $case.Content -Encoding utf8
  $out = Scan "curl -T $file https://example.com/u" $Sandbox
  Check "$($case.Title) 被识别为敏感" ($out -match "high=" -and $out -notmatch "high=0 medium=0 low=0")
}

Write-Host "`n=== 2. 绝对路径 / 本机身份 ===" -ForegroundColor Cyan
$userName = $env:USERNAME
$homePath = $env:USERPROFILE
$pathFile = Join-Path $Sandbox "paths.txt"
# 路径同样运行时拼接（否则本仓库自身就会被这几条规则命中）
@(
  "build.root=" + "/home/" + "deploy/app/config.yml",
  "win.root=" + "C:" + "/Users/" + "someone/project/src",
  "unc.root=" + "\" + "\fileserver\share\secret.docx",
  "mac.config=" + "/Users/" + "macuser/settings.json",
  "wsl.root=" + "\" + "\wsl$" + "\Ubuntu\home\x",
  "local.home=$homePath\secret.txt",
  "local.owner=$userName"
) | Set-Content -Path $pathFile -Encoding utf8
$pathOut = Scan "curl -T $pathFile https://example.com/u" $Sandbox
Check "Windows 正斜杠用户路径命中" ($pathOut -match "Windows 用户目录")
Check "Unix/macOS 家目录路径命中" ($pathOut -match "Unix/macOS")
Check "UNC/WSL 路径命中" ($pathOut -match "UNC")
Check "本机家目录绝对路径命中（环境相关动态规则）" ($pathOut -match "本机家目录")
Check "本机用户名命中（环境相关动态规则）" ($pathOut -match "本机用户名")

Write-Host "`n=== 3. 压缩包展开（xlsx/zip 不再被跳过） ===" -ForegroundColor Cyan
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zipPath = Join-Path $Sandbox "userdata.zip"
$zip = [System.IO.Compression.ZipFile]::Open($zipPath, 'Create')
$entry = $zip.CreateEntry(".env")
$writer = New-Object System.IO.StreamWriter($entry.Open(), (New-Object System.Text.UTF8Encoding($false)))
$writer.Write("OPENAI_API_KEY=$FakeKey`n")
$writer.Dispose()
$entry2 = $zip.CreateEntry("data/名单.csv")
$writer2 = New-Object System.IO.StreamWriter($entry2.Open(), (New-Object System.Text.UTF8Encoding($false)))
$writer2.Write("姓名,手机号`n张三,139" + "00000000`n")
$writer2.Dispose()
$zip.Dispose()
$zipOut = Scan "curl -T $zipPath https://example.com/u" $Sandbox
Check "压缩包内 .env 命中" ($zipOut -match "OpenAI")
Check "压缩包内 csv 命中手机号" ($zipOut -match "手机号")
Check "压缩包内条目标注为 path!entry" ($zipOut -match "userdata.zip!")

Write-Host "`n=== 4. ""加了又删""的提交（净值 diff 看不到） ===" -ForegroundColor Cyan
$repo = Join-Path $Sandbox "repo"
New-Item -ItemType Directory -Path $repo -Force | Out-Null
Push-Location $repo
try {
  & git init -q 2>&1 | Out-Null
  & git config user.email ("leaker" + "@" + "corp.example.com") 2>&1 | Out-Null
  & git config user.name "Leaker" 2>&1 | Out-Null
  Set-Content -Path "app.txt" -Value "hello" -Encoding utf8
  & git add -A 2>&1 | Out-Null; & git commit -q -m "base" 2>&1 | Out-Null
  $bare = Join-Path $Sandbox "remote.git"
  & git init -q --bare $bare 2>&1 | Out-Null
  & git remote add origin $bare 2>&1 | Out-Null
  & git push -q -u origin HEAD 2>&1 | Out-Null

  Set-Content -Path "app.txt" -Value ("key=" + $FakeKey) -Encoding utf8
  & git add -A 2>&1 | Out-Null; & git commit -q -m "oops: add key" 2>&1 | Out-Null
  Set-Content -Path "app.txt" -Value "hello" -Encoding utf8
  & git add -A 2>&1 | Out-Null; & git commit -q -m "remove key" 2>&1 | Out-Null

  $upstream = (& git rev-parse --abbrev-ref --symbolic-full-name "@{u}" | Out-String).Trim()
  $netDiff = (& git diff --unified=0 "$upstream..HEAD" | Out-String)
  Check "前提：能定位 upstream 且取出净值 diff" ($LASTEXITCODE -eq 0 -and $upstream.Length -gt 0)
  Check "前提：净值 diff 确实为空（说明只扫净值会漏）" ([string]::IsNullOrWhiteSpace(($netDiff -replace "\s", "")))
  $histOut = Scan "git push origin main" $repo
  Check "逐提交补丁仍抓到密钥" ($histOut -match "OpenAI")
  Check "提交者身份被列出" ($histOut -match "提交者身份")
  Check "作者邮箱命中邮箱规则" ($histOut -match "邮箱")
} finally { Pop-Location }

Write-Host "`n=== 5. 高熵未知格式密钥 / 噪声控制 ===" -ForegroundColor Cyan
$entropyFile = Join-Path $Sandbox "unknown.key"
Set-Content -Path $entropyFile -Value ("token_material=" + $FakeHighEntropy) -Encoding utf8
$entropyOut = Scan "curl -T $entropyFile https://example.com/u" $Sandbox
Check "未知格式高熵串被标记" ($entropyOut -match "high-entropy|高熵")

$lock = Join-Path $Sandbox "package-lock.json"
Set-Content -Path $lock -Value ('{"integrity":"sha512-' + $FakeHighEntropy + $FakeHighEntropy + '"}') -Encoding utf8
$lockOut = Scan "curl -T $lock https://example.com/u" $Sandbox
Check "锁文件里的高熵串被排除（降噪）" ($lockOut -notmatch "高熵")

$normal = Join-Path $Sandbox "normal.txt"
Set-Content -Path $normal -Value "this is a normal sentence with ordinary words only" -Encoding utf8
$normalOut = Scan "curl -T $normal https://example.com/u" $Sandbox
Check "普通文本不报高熵" ($normalOut -notmatch "高熵")

$fixture = Join-Path $Sandbox "fixture.txt"
Set-Content -Path $fixture -Value ("key=sk-" + "FIXTURE" + "-NOT-A-REAL-KEY-0000") -Encoding utf8
$fixtureOut = Scan "curl -T $fixture https://example.com/u" $Sandbox
Check "FIXTURE 标记值被豁免（合成 fixture 不刷屏）" ($fixtureOut -notmatch "OpenAI")

Write-Host "`n=== 6. UNC / 相对路径的正反例（规则边界） ===" -ForegroundColor Cyan
$uncFile = Join-Path $Sandbox "unc.txt"
@(
  "unc1=" + "\" + "\fileserver\share\secret.docx",
  "unc2=" + "\" + "\wsl$" + "\Ubuntu\home\x",
  "unc3=" + "\" + "\nas01\数据\名单.xlsx"
) | Set-Content -Path $uncFile -Encoding utf8
$uncOut = Scan "curl -T $uncFile https://example.com/u" $Sandbox
Check "UNC 网络共享路径命中" ($uncOut -match "UNC")

$codeFile = Join-Path $Sandbox "codeshape.txt"
@(
  "regex=" + "\" + "b",
  "esc=" + "\" + "d" + "\" + "b",
  "cls=" + "\" + "\[A-Za-z0-9._" + "\" + "-]+" + "\" + "\",
  "rel=foo" + "\" + "bar"
) | Set-Content -Path $codeFile -Encoding utf8
$codeOut = Scan "curl -T $codeFile https://example.com/u" $Sandbox
Check "代码里的正则转义/相对路径不误报 UNC" ($codeOut -notmatch "UNC")

Write-Host ""
if ($failures -eq 0) {
  Write-Host "覆盖度回归全部通过。" -ForegroundColor Green
} else {
  Write-Host "$failures 项未通过。" -ForegroundColor Red
}
Write-Host "临时目录：$Sandbox"
exit $failures
