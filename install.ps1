# install.ps1 — 把 desensitize-guard 装到 dsh / Claude Code / Codex 三端。
#
# 幂等：重复执行只刷新内容，不重复插入 hook 条目。
# 安全：改动前自动备份（*.bak-<时间戳>）；脚本缺失/语法不过时跳过该步骤而不是硬失败。
#
# 用法：
#   pwsh -File install.ps1                 # 全部安装（含 dsh 原生插件）
#   pwsh -File install.ps1 -DryRun         # 只打印将要做的事
#   pwsh -File install.ps1 -EnableDshPlugin:$false   # 不碰 dsh profile 配置

[CmdletBinding()]
param(
  [string]$BundleDir = $PSScriptRoot,
  [switch]$EnableDshPlugin = $true,
  [switch]$SkipSkillCopies,
  [switch]$SkipClaudeCode,
  [switch]$SkipCodex,
  [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$OutputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$env:PYTHONIOENCODING = "utf-8"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Home_ = $env:USERPROFILE
$CanonicalRoot = Join-Path $Home_ ".agents\skills"
$CanonicalDir = Join-Path $CanonicalRoot "desensitize-guard"
$Markers = @("desensitize_guard.py")

function Say([string]$Text, [string]$Kind = "info") {
  $prefix = switch ($Kind) { "ok" { "[ OK ]" } "warn" { "[WARN]" } "step" { "[STEP]" } default { "[INFO]" } }
  Write-Host "$prefix $Text"
}

function Backup-Path([string]$Path) {
  if (-not (Test-Path $Path)) { return }
  $target = "$Path.bak-$Stamp"
  if ($DryRun) { Say "将备份 $Path -> $target" "step"; return }
  Copy-Item -Path $Path -Destination $target -Recurse -Force
  Say "已备份 $Path -> $target" "ok"
}

function Test-TextSame([string]$Left, [string]$Right) {
  if (-not (Test-Path $Left) -or -not (Test-Path $Right)) { return $false }
  try {
    return (Get-FileHash $Left -Algorithm SHA256).Hash -eq (Get-FileHash $Right -Algorithm SHA256).Hash
  } catch { return $false }
}

$Script = Join-Path $CanonicalDir "scripts\desensitize_guard.py"
$Python = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } else { "python3" }

# ---------------------------------------------------------------- 1. 校验核心脚本
$CoreScript = Join-Path $BundleDir "scripts\desensitize_guard.py"
if (-not (Test-Path $CoreScript)) { throw "找不到 $CoreScript —— 请在 desensitize-guard 目录里运行本脚本" }
Say "核心脚本：$CoreScript"
& $Python $CoreScript selftest
if ($LASTEXITCODE -ne 0) { Say "自检未通过，仍继续安装，但请先修规则/脚本" "warn" }

# ---------------------------------------------------------------- 2. 装 skill（三端 skill 根目录）
if (-not $SkipSkillCopies) {
  $targets = @(
    @{ Name = "canonical  (~/.agents/skills)"; Dir = $CanonicalDir; On = $true },
    @{ Name = "dsh        (~/.dsh/skills)"; Dir = Join-Path $Home_ ".dsh\skills\desensitize-guard"; On = $true },
    @{ Name = "claude     (~/.claude/skills)"; Dir = Join-Path $Home_ ".claude\skills\desensitize-guard"; On = -not $SkipClaudeCode },
    @{ Name = "codex      (~/.codex/skills)"; Dir = Join-Path $Home_ ".codex\skills\desensitize-guard"; On = -not $SkipCodex }
  )
  foreach ($target in $targets) {
    if (-not $target.On) { Say "跳过 $($target.Name)"; continue }
    $dest = $target.Dir
    $parent = Split-Path $dest -Parent
    if ($DryRun) { Say "将安装 skill -> $dest" "step"; continue }
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    if (Test-Path $dest) {
      $sameSkill = Test-TextSame (Join-Path $dest "SKILL.md") (Join-Path $BundleDir "SKILL.md")
      $sameScript = Test-TextSame (Join-Path $dest "scripts\desensitize_guard.py") $CoreScript
      if ($sameSkill -and $sameScript) { Say "$($target.Name) 已是最新，跳过" "ok"; continue }
      Remove-Item $dest -Recurse -Force
    }
    Copy-Item -Path $BundleDir -Destination $dest -Recurse -Force
    Say "已安装 skill -> $dest" "ok"
  }
}

# ---------------------------------------------------------------- 3. Claude Code hook
function Install-JsonHookGroup {
  param(
    [string]$ConfigPath,
    [string]$Command,
    [string]$Matcher,
    [string]$Event = "PreToolUse",
    [string]$Description
  )
  if (Test-Path $ConfigPath) {
    $raw = Get-Content -Raw -Encoding utf8 $ConfigPath
    $config = if ([string]::IsNullOrWhiteSpace($raw)) { @{} } else { $raw | ConvertFrom-Json -AsHashtable }
  } else {
    $config = @{}
  }
  if (-not $config.ContainsKey("hooks") -or $null -eq $config["hooks"]) { $config["hooks"] = @{} }
  if (-not $config["hooks"].ContainsKey($Event) -or $null -eq $config["hooks"][$Event]) { $config["hooks"][$Event] = @() }
  $groups = @($config["hooks"][$Event])
  foreach ($group in $groups) {
    foreach ($hook in @($group["hooks"])) {
      if ($null -ne $hook -and $hook["command"] -and ($Markers | Where-Object { $hook["command"] -like "*$_*" })) {
        Say "$ConfigPath 已存在 desensitize-guard hook，跳过" "ok"
        return
      }
    }
  }
  $newGroup = @{ matcher = $Matcher; hooks = @(@{ type = "command"; command = $Command; timeout = 30 }) }
  $config["hooks"][$Event] = @($groups) + @($newGroup)
  if ($Description -and -not $config.ContainsKey("description")) { $config["description"] = $Description }
  if ($DryRun) { Say "将写入 hook -> $ConfigPath" "step"; return }
  Backup-Path $ConfigPath
  New-Item -ItemType Directory -Path (Split-Path $ConfigPath -Parent) -Force | Out-Null
  ($config | ConvertTo-Json -Depth 24) | Set-Content -Path $ConfigPath -Encoding utf8
  Say "已写入 hook -> $ConfigPath" "ok"
}

if (-not $SkipClaudeCode) {
  $claudeSettings = Join-Path $Home_ ".claude\settings.json"
  Install-JsonHookGroup -ConfigPath $claudeSettings `
    -Command "python `"$Script`" hook --dialect claude" `
    -Matcher "Bash|PowerShell|pwsh|bash|mcp__.*"
}

if (-not $SkipCodex) {
  $codexHooks = Join-Path $Home_ ".codex\hooks.json"
  Install-JsonHookGroup -ConfigPath $codexHooks `
    -Command "python `"$Script`" hook --dialect codex" `
    -Matcher "Bash|mcp__.*" `
    -Description "desensitize-guard：出网动作前确认是否需要脱敏（Codex 不支持 ask，用 deny + 理由让模型问用户）"
  Say "提醒：Codex 需在 CLI 里执行 /hooks 审核并信任该 hook（按定义 hash 记录）" "warn"
}

# ---------------------------------------------------------------- 4. dsh 原生插件
if ($EnableDshPlugin) {
  $pluginSrc = Join-Path $BundleDir "bindings\dsh-plugin"
  $pluginEntry = Join-Path $pluginSrc "lib\index.js"
  $node = Get-Command node -ErrorAction SilentlyContinue
  if (-not (Test-Path $pluginEntry)) {
    Say "找不到 dsh 插件源码，跳过：$pluginEntry" "warn"
  } elseif (-not $node) {
    Say "未找到 node，跳过插件语法校验与安装" "warn"
  } else {
    & node --check $pluginEntry
    if ($LASTEXITCODE -ne 0) {
      Say "插件语法校验失败，跳过 dsh 插件安装" "warn"
    } else {
      $profilesRoot = Join-Path $Home_ ".dsh\profiles"
      if (-not (Test-Path $profilesRoot)) {
        Say "未找到 ~/.dsh/profiles，跳过 dsh 插件" "warn"
      } else {
        foreach ($profile in Get-ChildItem -Directory $profilesRoot) {
          $nodeModules = Join-Path $profile.FullName "node_modules"
          if (-not (Test-Path $nodeModules)) { Say "$($profile.Name)：无 node_modules，跳过" "warn"; continue }
          $pluginDest = Join-Path $nodeModules "dsh-desensitize-guard"
          if ($DryRun) {
            Say "将安装插件 -> $pluginDest" "step"
          } else {
            if (Test-Path $pluginDest) { Remove-Item $pluginDest -Recurse -Force }
            Copy-Item -Path $pluginSrc -Destination $pluginDest -Recurse -Force
            Say "已安装插件 -> $pluginDest" "ok"
          }
          $patch = Join-Path $profile.FullName "cordis.patch.yml"
          $patchText = if (Test-Path $patch) { Get-Content -Raw -Encoding utf8 $patch } else { "" }
          if ($patchText -like "*dsh-desensitize-guard*") {
            Say "$($profile.Name)：cordis.patch.yml 已包含插件，跳过" "ok"
            continue
          }
          $block = @"

# --- desensitize-guard：出网前脱敏确认闸门（uninstall.ps1 可移除）---
- insert:
    - id: desensitize-guard
      name: dsh-desensitize-guard
"@
          if ($DryRun) { Say "将追加 patch -> $patch" "step"; continue }
          if (Test-Path $patch) { Backup-Path $patch }
          Add-Content -Path $patch -Value $block -Encoding utf8
          Say "已追加插件挂载 -> $patch" "ok"
        }
        Say "dsh 需要重启（关闭并重开 DeepSeek Harness）才会加载新插件" "warn"
      }
    }
  }
} else {
  Say "按要求未改动 dsh profile 配置（-EnableDshPlugin:`$false）"
}

# ---------------------------------------------------------------- 5. 验证提示
Write-Host ""
Say "安装完成。验证方式：" "ok"
Write-Host "  1) 判定自检      : $Python `"$Script`" selftest"
Write-Host "  2) 扫描一条命令  : $Python `"$Script`" scan --cmd `"git push origin main`""
Write-Host "  3) 查看放行/审计 : $Python `"$Script`" status"
Write-Host "  4) 三端 hook 试跑: pwsh -File `"$BundleDir\scripts\verify_guard.ps1`""
Write-Host "  5) Codex 里执行 /hooks 信任该 hook；dsh 重启后生效"
Write-Host ""
Say "回滚：pwsh -File `"$BundleDir\uninstall.ps1`"（保留 ~/.dsh/desensitize-guard 审计数据）"
