# desensitize-guard — 出网前"是否需要脱敏"确认门（dsh / Claude Code / Codex 通用）

一个 skill + 一个判定脚本 + 三份薄绑定，让智能体在 **git push / 上传 / 发布 / 外发类 MCP** 之前，
先用**宿主自带的提问能力**问用户一句"这次要不要脱敏"，拿到答复才继续。

- 结论：**能实现**，但必须分两层。skill 只是"劝"（模型可以跳过），真正"必问"要靠 harness 的 pre-tool 闸门。
- 本机现状（实测）：`dsh-purge` 已应用 66/68 补丁，其中 `#30 HOOKS_CLAUDE_DENY_ALLOW` 把 `hooks.json` 桥接的
  deny/ask 都改成放行（源码里可见 `/* [dsh-purge] hooks deny→allow */`），所以 **dsh 侧必须走原生 cordis 插件**；
  Claude Code / Codex 的 hook 未被削弱，照常用。

## 目录

- [架构](#架构)
- [三端能力矩阵（本机实测）](#三端能力矩阵本机实测)
- [安装](#安装)
- [验证](#验证)
- [工具用法](#工具用法)
- [判定规则](#判定规则)
- [已知限制](#已知限制)

## 架构

```
                       ┌───────────────────────────────┐
   用户答复 ──────────► │ approvals.json（放行 token）  │◄──── approve --answer yes/no
                       └───────────────┬───────────────┘
                                       │ 命中 → 放行；未命中 → 询问
   git push / upload / publish ──► [ 闸门 ] ──► tools/pre-execute
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        │                              │                              │
   dsh 原生插件                    Claude Code hook                Codex hook
   kind=ask → 宿主审批 UI          permissionDecision=ask          permissionDecision=deny
   （直接问用户）                  （CC 自己弹权限确认）            （模型据理由自己问用户）
        └──────────────────────────────┴──────────────────────────────┘
                                       │
                      scripts/desensitize_guard.py（同一份判定引擎）
                 出网判定 · 即将出网内容采集 · 敏感扫描 · 决策 · token/审计
```

要点：

1. **判定逻辑只有一份**：`scripts/desensitize_guard.py`。三端绑定都只是把它包成各自方言，避免行为漂移。
2. **"询问"由宿主承担**，不靠模型自觉：dsh 走审批 UI、CC 走权限确认、Codex 走 deny + 模型提问。
3. **放行靠 token 而不是改配置**：token 绑定"命令指纹 + 仓库根 + 有效期"，同一命令确认一次即可重试，
   改一个字符就要重新确认。
4. **hook 永不打断调用轮次**：脚本缺失、超时、payload 异常都按放行 + 警告处理（可用 `failClosed` 反转）。

## 三端能力矩阵（本机实测）

| 能力 | dsh（本机，已 purge） | Claude Code | Codex CLI/App |
| --- | --- | --- | --- |
| 读取 skill | ✅ `~/.dsh/skills`、`~/.agents/skills`（rank 400/500） | ✅ `~/.claude/skills` | ✅ `~/.codex/skills` |
| skill frontmatter | `name` + `description`（+ whenToUse/metadata） | `name` + `description`（+ allowed-tools） | `name` + `description`（+ metadata、`agents/openai.yaml`） |
| hook 方言 | `dsh-hooks-claude-code` / `-codex` 桥接，但已补丁成 deny/ask→放行 | PreToolUse，支持 `ask`（原生弹窗） | PreToolUse，**只支持 allow/deny**，不支持 ask |
| 本项目的拦截路径 | **原生 cordis 插件** `tools/pre-execute → {kind:"ask"}` → 宿主审批 UI | PreToolUse → `permissionDecision:"ask"` | PreToolUse → `permissionDecision:"deny"` + 理由 |
| hook 生效前置 | 重启 dsh | 无需额外步骤 | 需在 CLI 里 `/hooks` 审核信任（按定义 hash 记录） |
| 模型侧提醒 | 可用桥接的 `additionalContext`（本机仍生效） | `additionalContext` | deny 理由文本 |

> dsh 核心的 `tools/pre-execute` 瀑布仍完整支持 `{kind:"ask"}`/`{kind:"deny"}`（`dsh-tools` 里只有一条与审批无关的 purge 标记），
> 所以"原生插件 + 宿主审批 UI 问用户"这条路是通的；被补丁削弱的是 **hooks.json 桥接**，不是宿主内核。

## 安装

```powershell
# 预览将要做的事
pwsh -File .\install.ps1 -DryRun

# 正式安装（skill 三端副本 + CC settings.json + Codex hooks.json + dsh 原生插件）
pwsh -File .\install.ps1

# 不碰 dsh profile 配置（只装 skill 与 CC/Codex hook）
pwsh -File .\install.ps1 -EnableDshPlugin:$false

# 回滚
pwsh -File .\uninstall.ps1            # 保留放行 token/审计
pwsh -File .\uninstall.ps1 -PurgeState  # 一并删除
```

安装会做（全部改动前自动备份为 `*.bak-<时间戳>`，hook 条目按标记幂等跳过）：

| 目标 | 动作 |
| --- | --- |
| `~/.agents/skills/desensitize-guard` | 规范副本（判定脚本从这里被引用） |
| `~/.dsh/skills`、`~/.claude/skills`、`~/.codex/skills` | 各自一份副本 |
| `~/.claude/settings.json` | 追加 `PreToolUse` 组（matcher `Bash\|PowerShell\|pwsh\|bash\|mcp__.*`） |
| `~/.codex/hooks.json` | 追加 `PreToolUse` 组（matcher `Bash\|mcp__.*`，`commandWindows` 同步给出） |
| `~/.dsh/profiles/*/node_modules/dsh-desensitize-guard` | 原生插件本体（先 `node --check`） |
| `~/.dsh/profiles/*/cordis.patch.yml` | 追加 `- insert: [{id: desensitize-guard, name: dsh-desensitize-guard}]` |

装完要做两件手工动作：**Codex 里执行 `/hooks` 信任该 hook**；**重启 DeepSeek Harness 加载插件**。

## 验证

三套可复跑的验证，均已在 Windows + Python 3.13 + Node 22 下全绿：

```powershell
python .\scripts\desensitize_guard.py selftest      # 5 条规则用例
pwsh -File .\scripts\verify_guard.ps1               # 22 项：三端方言/拦截/放行/确认流程/模式/扫描
pwsh -File .\scripts\verify_integration.ps1         # 真实 git 仓库 fixture：出网内容扫描 + 确认改变决策
node .\scripts\verify_dsh_plugin.mjs                # 插件与判定引擎的对接契约
```

`verify_integration.ps1` 会现搭一个临时仓库、提交含 `sk-…`、手机号、身份证号、`.env.local` 的改动，
断言：报告命中四类敏感项、**不回显完整密钥**、决策 `needs_confirmation`；然后 `approve --answer no`
使 hook 判 `deny`，`--answer yes` 后判 `allow`。

## 工具用法

```powershell
$G = "$env:USERPROFILE\.agents\skills\desensitize-guard\scripts\desensitize_guard.py"

python $G scan --cmd "git push origin main"            # 出网判定 + 出网内容 + 敏感扫描（报告已掩码）
python $G scan --cmd "curl -F file=@a.env https://x/u" --json
python $G approve --cmd "git push origin main" --answer yes --note "用户：直接推"
python $G approve --cmd "git push origin main" --answer no  --note "用户：先脱敏"
python $G status --json                                # 有效 token + 审计尾部
python $G hook --dialect claude|codex|dsh-native       # 供 hook/插件调用（stdin 收 payload）
```

| 命令 | 语义 | 退出码 |
| --- | --- | --- |
| `scan` | 只读报告，输出末行 `DECISION: not_egress / needs_confirmation / approved / user_declined` | 恒为 0（避免被当成失败） |
| `approve` | 写放行 token（`yes`）/ 继续拦截（`no`），并写审计 | 0/1 |
| `hook` | 方言决策输出：CC `ask`、Codex `deny`、dsh `{kind}` | 0（`--exit2` 时 2） |

环境开关：`DESENSITIZE_GUARD_MODE=gate|warn|off`、`DESENSITIZE_GUARD_HOME=<状态目录>`（默认 `$DSH_HOME/desensitize-guard`）、
`DESENSITIZE_GUARD_TTL_MIN=20`。

## 判定规则

`rules/rules.json` 三段，改文件即时生效（无需重启）：

- **egress**：出网动作正则（git push / git remote / gh release,gist,pr / curl,wget 上传 / scp,rsync,sftp,nc / aws,az,gcloud,gsutil,rclone,ossutil / docker,npm,twine,vercel,netlify / PowerShell 上传 / POST 本地文件）+ 外发类 MCP 工具名模式。
- **sensitive**：密钥（OpenAI/Anthropic/GitHub/AWS/Slack/Google/JWT/PEM/带口令连接串/Webhook）、
  PII（身份证、手机号、邮箱、银行卡、学号工号、姓名、地址）、内网信息（私网 IP、内部域名、本机用户名路径）。
- **path_rules**：`.env*`、`.credentials.yaml`、`id_rsa`、`.npmrc` 等凭据文件名，以及 `.xlsx/.csv/.sql/.bak` 等批量个人数据文件。

采集范围：`git push` 用 `git diff <upstream>..HEAD`（无 upstream 时退化为 index + 工作区），
其余命令从参数里解析被上传的本地文件（`-T`、`--upload-file`、`-F file=@…`、`--data-binary @…` 等）。
样例一律掩码后再进对话，完整密钥不会出现在报告或转录里。

## 已知限制

- **skill 本身不可强制**：模型可能不加载 skill、或忘了问。真正的兜底是 hook/插件；skill 负责把交互流程讲清楚。
- **Codex 没有 `ask`**：只能 `deny` + 理由，然后靠模型去问用户。可靠但多一轮往返。
- **本机 dsh 的 hooks.json 桥接已被 purge 改成放行**：想恢复"桥接也能拦"，需 `purge_revert`（会一并撤销其它清洗）；
  用原生插件路线即可，不必动 purge。
- **hook 是护栏不是铁笼**：换一条等价命令（网页上传、邮件、`gh api`）仍要各自被规则覆盖；规则表按需扩充。
- **`--note` 靠模型自觉填写**：审计能记录"谁在何时放行了哪条命令"，但无法证明用户真的答复过；
  需要更强保证时把 `approve` 改成需要终端交互（读一次本地确认码）。
- 大文件、二进制只做文件名规则判定，不做逐行扫描（`skip_scan_extensions` 控制）。
