# uninstall.ps1 — 撤销 desensitize-guard 的三端绑定。
#
# 默认保留 ~/.dsh/desensitize-guard（放行 token 与审计）；要一起删用 -PurgeState。

[CmdletBinding()]
param(
  [string]$BundleDir = $PSScriptRoot,
  [switch]$PurgeState,
  [switch]$KeepSkillCopies,
  [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$OutputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$Home_ = $env:USERPROFILE
$Markers = @("desensitize_guard.py")

function Say([string]$Text, [string]$Kind = "info") {
  $prefix = switch ($Kind) { "ok" { "[ OK ]" } "warn" { "[WARN]" } default { "[INFO]" } }
  Write-Host "$prefix $Text"
}

function Remove-HookGroups([string]$ConfigPath) {
  if (-not (Test-Path $ConfigPath)) { Say "跳过（不存在）：$ConfigPath"; return }
  $config = (Get-Content -Raw -Encoding utf8 $ConfigPath) | ConvertFrom-Json -AsHashtable
  if (-not $config.ContainsKey("hooks")) { Say "无 hooks 段：$ConfigPath"; return }
  $changed = $false
  foreach ($event in @($config["hooks"].Keys)) {
    $kept = @()
    foreach ($group in @($config["hooks"][$event])) {
      $ours = $false
      foreach ($hook in @($group["hooks"])) {
        if ($null -ne $hook -and $hook["command"] -and ($Markers | Where-Object { $hook["command"] -like "*$_*" })) { $ours = $true }
      }
      if ($ours) { $changed = $true } else { $kept += $group }
    }
    if ($kept.Count -eq 0) { $config["hooks"].Remove($event) } else { $config["hooks"][$event] = $kept }
  }
  if (-not $changed) { Say "未发现 desensitize-guard hook：$ConfigPath"; return }
  if ($DryRun) { Say "将清理 hook -> $ConfigPath"; return }
  Copy-Item $ConfigPath "$ConfigPath.bak-$(Get-Date -Format 'yyyyMMdd-HHmmss')" -Force
  ($config | ConvertTo-Json -Depth 24) | Set-Content -Path $ConfigPath -Encoding utf8
  Say "已清理 hook -> $ConfigPath" "ok"
}

Remove-HookGroups (Join-Path $Home_ ".claude\settings.json")
Remove-HookGroups (Join-Path $Home_ ".codex\hooks.json")

if (-not $KeepSkillCopies) {
  $skillDirs = @(
    (Join-Path $Home_ ".agents\skills\desensitize-guard"),
    (Join-Path $Home_ ".dsh\skills\desensitize-guard"),
    (Join-Path $Home_ ".claude\skills\desensitize-guard"),
    (Join-Path $Home_ ".codex\skills\desensitize-guard")
  )
  foreach ($dir in $skillDirs) {
    if (-not (Test-Path $dir)) { Say "跳过（不存在）：$dir"; continue }
    if ($DryRun) { Say "将删除 $dir"; continue }
    Remove-Item $dir -Recurse -Force
    Say "已删除 skill 副本：$dir" "ok"
  }
}

$profilesRoot = Join-Path $Home_ ".dsh\profiles"
if (Test-Path $profilesRoot) {
  foreach ($profile in Get-ChildItem -Directory $profilesRoot) {
    $pluginDest = Join-Path $profile.FullName "node_modules\dsh-desensitize-guard"
    if (Test-Path $pluginDest) {
      if ($DryRun) { Say "将删除插件 $pluginDest" } else { Remove-Item $pluginDest -Recurse -Force; Say "已删除插件：$pluginDest" "ok" }
    }
    $patch = Join-Path $profile.FullName "cordis.patch.yml"
    if (-not (Test-Path $patch)) { continue }
    $text = Get-Content -Raw -Encoding utf8 $patch
    if ($text -notlike "*dsh-desensitize-guard*") { continue }
    $cleaned = [regex]::Replace(
      $text,
      "(?s)\r?\n# --- desensitize-guard：.*?name: dsh-desensitize-guard\r?\n?",
      "`n"
    )
    $cleaned = [regex]::Replace($cleaned, "(?s)\r?\n?- insert:\s*\r?\n\s*- id: desensitize-guard\s*\r?\n\s*name: dsh-desensitize-guard\s*\r?\n?", "`n")
    if ($DryRun) { Say "将清理 patch -> $patch"; continue }
    Copy-Item $patch "$patch.bak-$(Get-Date -Format 'yyyyMMdd-HHmmss')" -Force
    Set-Content -Path $patch -Value $cleaned -Encoding utf8
    Say "已清理插件挂载 -> $patch" "ok"
  }
  Say "dsh 需重启后插件才彻底卸载" "warn"
}

if ($PurgeState) {
  $stateDir = Join-Path $Home_ ".dsh\desensitize-guard"
  if (Test-Path $stateDir) {
    if ($DryRun) { Say "将删除状态目录 $stateDir" } else { Remove-Item $stateDir -Recurse -Force; Say "已删除状态目录：$stateDir" "ok" }
  }
} else {
  Say "已保留放行 token 与审计：~/.dsh/desensitize-guard（-PurgeState 可一并删除）"
}

Say "卸载完成。"
