# verify_integration.ps1 — 真实 git 仓库场景：验证 "推送前扫描即将出网的内容" 真的能抓出敏感项。
#
#   pwsh -File scripts/verify_integration.ps1

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
$Sandbox = Join-Path ([System.IO.Path]::GetTempPath()) "desensitize-guard-git"
$env:DESENSITIZE_GUARD_HOME = Join-Path $Sandbox "state"
if (Test-Path $Sandbox) { Remove-Item $Sandbox -Recurse -Force }
New-Item -ItemType Directory -Path $Sandbox -Force | Out-Null

$failures = 0
function Check([string]$Title, [bool]$Ok, [string]$Detail = "") {
  if ($Ok) { Write-Host "[PASS] $Title" -ForegroundColor Green }
  else { Write-Host "[FAIL] $Title  $Detail" -ForegroundColor Red; $script:failures++ }
}

Write-Host "=== 搭一个临时仓库（本地 fixture） ===" -ForegroundColor Cyan
$repo = Join-Path $Sandbox "repo"
New-Item -ItemType Directory -Path $repo -Force | Out-Null
Push-Location $repo
try {
  & git init -q 2>&1 | Out-Null
  # fixture 故意不在文件里写成完整字面量：本仓库自身被脱敏扫描时不产生命中，运行时才拼出来
  $FixtureKey = "sk-" + "FIXTURE" + "-NOT-A-REAL-KEY-1111"
  $FixturePhone = "139" + "00000000"
  $FixtureId = "110101" + "199003070000"
  $FixtureEmail = "fixture" + "@" + "example.com"
  & git config user.email $FixtureEmail 2>&1 | Out-Null
  & git config user.name "fixture" 2>&1 | Out-Null
  Set-Content -Path "README.md" -Value "demo" -Encoding utf8
  & git add . 2>&1 | Out-Null
  & git commit -q -m "init" 2>&1 | Out-Null
  # 第一次提交：假装已经推过（建立 upstream 基线）
  & git remote add origin (Join-Path $Sandbox "remote.git") 2>&1 | Out-Null
  & git init -q --bare (Join-Path $Sandbox "remote.git") 2>&1 | Out-Null
  & git push -q -u origin HEAD 2>&1 | Out-Null

  Write-Host "=== 提交一份含密钥/pii 的配置（临时目录内，不进仓库） ===" -ForegroundColor Cyan
  @"
OPENAI_API_KEY=$FixtureKey
OWNER_PHONE=$FixturePhone
OWNER_ID=$FixtureId
"@ | Set-Content -Path ".env.local" -Encoding utf8
  @"
| 姓名 | 手机号 | 学号 |
| --- | --- | --- |
| 张三 | $FixturePhone | 2023001234 |
"@ | Set-Content -Path "社团名单.csv" -Encoding utf8
  & git add -A 2>&1 | Out-Null
  & git commit -q -m "add fixture data" 2>&1 | Out-Null

  $scan = (& $Python $Script scan --cmd "git push origin main" --cwd $repo | Out-String)
  Check "报告识别到 git push" ($scan -match "git push")
  Check "命中 .env 密钥" ($scan -match "OpenAI|密钥")
  Check "命中手机号" ($scan -match "手机号")
  Check "命中身份证号" ($scan -match "身份证")
  Check "命中凭据类文件名 .env.local" ($scan -match "\.env")
  Check "报告不回显完整密钥" ($scan -notmatch [regex]::Escape($FixtureKey))
  Check "决策为 needs_confirmation" ($scan -match "DECISION:\s*needs_confirmation")

  $hookOut = ('{"tool_name":"pwsh","tool_input":{"command":"git push origin main"},"cwd":"' + ($repo -replace '\\','\\') + '"}'
    | & $Python $Script hook --dialect dsh-native --json-decision | Out-String)
  Check "hook 判定 ask" ($hookOut -match '"kind":\s*"ask"')

  & $Python $Script approve --cmd "git push origin main" --answer no --note "先脱敏" | Out-Null
  $hookNo = ('{"tool_name":"pwsh","tool_input":{"command":"git push origin main"},"cwd":"' + ($repo -replace '\\','\\') + '"}'
    | & $Python $Script hook --dialect dsh-native --json-decision | Out-String)
  Check "用户选 no 后 hook 判定 deny" ($hookNo -match '"kind":\s*"deny"')

  & $Python $Script approve --cmd "git push origin main" --answer yes --note "确认直接推送" | Out-Null
  $hookYes = ('{"tool_name":"pwsh","tool_input":{"command":"git push origin main"},"cwd":"' + ($repo -replace '\\','\\') + '"}'
    | & $Python $Script hook --dialect dsh-native --json-decision | Out-String)
  Check "用户选 yes 后 hook 放行" ($hookYes -match '"kind":\s*"allow"')
} finally {
  Pop-Location
}

Write-Host ""
if ($failures -eq 0) {
  Write-Host "集成场景全部通过：真实仓库的出网内容会被扫描，且确认流程能真正改变 hook 决策。" -ForegroundColor Green
} else {
  Write-Host "$failures 项未通过。" -ForegroundColor Red
}
Write-Host "临时仓库：$repo"
exit $failures
