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
3. **放行靠 token 而不是改配置**：token 绑定"命令指纹 + 仓库根 + **内容指纹** + 有效期"。
   内容指纹覆盖净值 diff、逐提交补丁、身份与 `.git/config`、命令行指向的本地文件内容（大小+mtime+sha256），
   所以**同一条命令在 TTL 内换了内容也会重新询问**；回滚内容则指纹复原、原 token 继续有效。
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

## 判定规则与覆盖范围

`rules/rules.json`（settings/egress/sensitive/path_rules），改文件即时生效（无需重启）。

**扫描面**（`git push` 时不只是净值 diff）：

| 扫描面 | 说明 |
| --- | --- |
| 净值 diff | `git diff <upstream>..HEAD`；无 upstream 时改为**整仓逐文件全文扫描** |
| 逐提交补丁 | `git log -p` —— 抓「**加了又删**」的密钥（净值 diff 里看不到，只扫净值必漏） |
| 提交信息与作者身份 | 提交信息正文、作者/提交者 `Name <email>`、分支/标签名 —— 这些**会随仓库公开** |
| `.git/config` | remote URL 里内嵌的令牌（`https://user:***@host/...`） |
| 命令行指向的本地文件 | `-T` / `--upload-file` / `-F file=@…` / `--data-binary @…` 等参数解析 |
| 压缩包内部 | `.zip/.xlsx/.docx/.pptx/.jar/.apk/.whl/.epub` 展开后扫文本条目（XML 去标签），以 `包!条目` 定位 |
| 环境相关动态规则 | 运行时生成：本机家目录、用户名、主机名、**工作区绝对路径** —— 静态正则做不到这一类 |

**已覆盖的敏感类型**：

- 密钥/令牌指纹：OpenAI（含 `sk-proj/svcacct/admin`）、Anthropic、GitHub（PAT/`ghs_`/`ghu_`）、GitLab PAT、AWS（`AKIA/ASIA/AGPA/AIDA/AROA` + secret 赋值）、阿里云 `LTAI`、腾讯云 `AKID`、Stripe、Twilio、SendGrid、Mailgun、npm、PyPI、Discord bot、Telegram bot、Slack（`xox*/xapp-`）、Google API Key、GCP 服务账号 JSON、Azure AccountKey/SAS、Vault、New Relic、Postman、PlanetScale、Grafana、DigitalOcean、HuggingFace、Shopify、Square、Sentry DSN、Firebase FCM、Cloudinary、PEM/OpenSSH/PGP 私钥、JSON 内联私钥、kubeconfig 内嵌证书数据、JWT、`Authorization: Bearer/Basic`、URL 内嵌用户名口令、带口令连接串、预签名 URL（AWS/GCS）、群机器人 Webhook、通用「密钥赋值」、加密钱包私钥/助记词
- PII：中国身份证、手机号、座机、邮箱、银行卡、美国 SSN、IBAN、车牌、学号/工号、真实姓名、地址、护照/证件/社保字段、QQ/微信
- 内网/位置：私网 IP、内部域名、内部治理端点（jenkins/gitlab/jira/grafana…）、Windows 用户目录（**两种分隔符**）、Unix/macOS 家目录、UNC/WSL 网络路径、其他盘符绝对路径
- 文件类型：`.env*`、`.credentials.*`、`id_rsa`、`.npmrc/.pypirc/.netrc/.pgpass/.git-credentials`、`.aws/credentials`、`.kube/config`、`kubeconfig*`、`service-account*.json`、`.terraform/`、`*.tfstate/*.tfvars`、`*.pem/*.p12/*.pfx/*.key/*.jks/*.kdbx/*.ovpn`、浏览器 Cookies/`Login Data`/`*.har/*.pcap`、`*.xlsx/*.csv/*.sql/*.bak/*.docx/*.pdf/*.log`
- 未知格式：高熵长串（≥40 位、**必须含数字**、≥3 类字符、香农熵 ≥4.2），锁文件/lockfile/min.js/`rules.json` 已排除以降噪

**降噪机制**：

- 行内 `desensitize-guard:allow` 豁免该行（用于"我确认这条 fixture 无风险"）。
- `settings.ignore` 正则豁免，默认忽略：`example.com` 等保留域名、`*@(users.)noreply.github.com`（GitHub 官方私密邮箱）、含 `FIXTURE` 的合成值。
- `settings.entropy_exclude_paths` 排除锁文件、压缩产物与规则文件自身。
- 同一命中值跨扫描面重复出现时折叠为一行并标 `×N`，避免 diff / 逐提交补丁 / 文件行三重刷屏。
- 高熵规则要求"含数字"，否则 `SendGrid/Mailgun/npm/PyPI/...` 这类文档串会被整段报成密钥。

```powershell
# 验证覆盖度（21 项）与既有回归（22 项 + 集成 + 插件契约）
pwsh -File .\scripts\verify_coverage.ps1
pwsh -File .\scripts\verify_guard.ps1
pwsh -File .\scripts\verify_integration.ps1
node .\scripts\verify_dsh_plugin.mjs
```

## 结构性不覆盖（别把它当 DLP）

- **skill 本身不可强制**：模型可能不加载 skill、或忘了问。真正的兜底是 hook/插件；skill 负责把交互流程讲清楚。
- **Codex 没有 `ask`**：只能 `deny` + 理由，然后靠模型去问用户。可靠但多一轮往返。
- **本机 dsh 的 hooks.json 桥接已被 purge 改成放行**：想恢复"桥接也能拦"，需 `purge_revert`（会一并撤销其它清洗）；

  用原生插件路线即可，不必动 purge。
- **hook 是护栏不是铁笼**：换一条等价命令（网页上传、邮件、`gh api`）仍要各自被规则覆盖；规则表按需扩充。
- **`--note` 靠模型自觉填写**：审计能记录"谁在何时放行了哪条命令"，但无法证明用户真的答复过；
  需要更强保证时把 `approve` 改成需要终端交互（读一次本地确认码）。
- **二进制/图片不解析内容**：图片（截图里的密钥）、加密压缩包、`.pcap` 载荷、PDF 正文只做文件名判定，不做 OCR / 解密。
- **未识别格式的密钥仍可能漏**：高熵规则只覆盖 ≥40 位且 ≥3 类字符的串；短令牌、纯字母长串（如某些 API key）、
  被 base64 二次编码的密钥、被拆散拼接的密钥都可能漏检。
- **远端历史不在范围**：只扫"这次要发出去的东西"；仓库里早已存在的老密钥需要 `git filter-repo` 之类处理，本工具不管。
- **大文件与超量文件截断**：单文件 >256KB、压缩包条目 >40 个 / 单条目 >128KB、整仓 >300 个文件时只扫一部分。
- **非 git 出网依赖参数可解析**：`curl -F` / `-T` 这类能从命令行拿到路径；如果路径是运行时拼出来的（变量、脚本内生成），
  命令行里看不到就不在扫描面内。
- **Git LFS 指针**：仓库里是 lfs 指针文件，真实内容在 `.git/lfs/objects`，当前不跟进去扫。
- **状态目录别放进仓库**：放行 token 与审计默认在 `$DSH_HOME/desensitize-guard`；若把 `DESENSITIZE_GUARD_HOME`
  指到仓库内，记得加进 `.gitignore`（否则 token/审计会被一起提交，且 `git reset --hard` 会把它冲掉）。
- **指纹是"内容"绑定，不是"人"绑定**：任何能跑 `approve` 的进程都能落库放行；要防"模型自问自答"，
  需把 `approve` 改成需要一次终端交互确认。

