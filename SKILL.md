---
name: desensitize-guard
description: 在把内容送出本机之前用宿主自带工具向用户确认是否需要脱敏。适用于 git push、git remote set-url、gh release/gist/pr 上传、curl/wget/scp/rsync/sftp 传输、aws/gcloud/az/rclone/ossutil 上传、npm/docker/twine 发布、任何"上传/发送/发布"类 MCP 工具，以及把仓库、配置、数据文件、日志交给第三方之前。
---

# 出网前脱敏确认（desensitize-guard）

**规则**：只要一次动作会把本机内容交给本机之外的任何一方，就必须先用宿主自带的提问能力问用户一句"这次要不要脱敏"，拿到答复后才能继续。禁止在用户答复前放行。

## 何时触发

- 版本控制出网：`git push`、`git lfs push`、`git remote add/set-url`、`git send-email`
- 托管平台上传：`gh release create/upload`、`gh gist create`、`gh pr create`、`gh api -X POST`、网页端上传、issue/PR 评论带附件
- 文件/数据外发：`curl -T/-F/--data-binary @`、`wget --post-file`、`scp`、`sftp`、`rsync`、`nc`、`ftp`、`Invoke-RestMethod -InFile`、`Start-BitsTransfer`
- 云与制品：`aws s3 cp/sync`、`az storage blob upload`、`gcloud storage cp`、`gsutil cp`、`rclone copy/sync`、`ossutil cp`、`coscmd upload`、`docker push`、`npm/pnpm publish`、`twine upload`、`vercel/netlify/firebase deploy`
- 工具层外发：任何名称含 `upload` / `send_file` / `publish` / `post` / `webhook` / `mail` / `drive_create` 的 MCP 或第三方工具
- 附件/图片/表格交给外部模型、客服、群机器人、网盘

不触发：纯本地命令（`git status`、`git diff`、`pnpm build`、读写文件、跑测试、`git commit` 本地提交）。本地提交不需要询问，除非用户主动要求。

## 执行流程

1. **先出报告，不要先问**。运行（`<SKILL_DIR>` = 本 skill 所在目录）：

   ```bash
   python "<SKILL_DIR>/scripts/desensitize_guard.py" scan --cmd "<完整命令>"
   ```

   输出包含：出网动作、仓库、即将出网的文件、命中敏感项（已脱敏样例）、放行指纹。把这份报告原样摘要给用户看。

2. **用宿主自带工具问用户**，不要用纯文本自问自答：
   - dsh：`ask_user_question`
   - Claude Code：`AskUserQuestion`
   - Codex：原生提问/审批弹窗（没有提问工具时，用一句话明确请求确认并等待用户回复）

   问题模板：

   > 这次要执行 `<命令>`，会把 `<文件数/范围>` 送出本机，扫描命中 high=`<n>`。是否需要脱敏？
   > 选项：① 直接推送，无需脱敏 ② 先脱敏（我来改写/替换/剔除后再推） ③ 取消这次出网

3. **按答复落库**（把用户原话写进 `--note`）：

   ```bash
   # 用户选①
   python "<SKILL_DIR>/scripts/desensitize_guard.py" approve --cmd "<原命令>" --answer yes --note "<用户原话>"
   # 用户选②③
   python "<SKILL_DIR>/scripts/desensitize_guard.py" approve --cmd "<原命令>" --answer no --note "<用户原话>"
   ```

4. **重试或改道**：`yes` 后原命令会放行（token 默认 20 分钟、按命令指纹绑定）；`no` 时按用户要求先脱敏——改写文件、删除凭据行、替换真实姓名/手机号/身份证/路径，再重新 `scan` 一次并再次确认。

5. 出网完成后如用户要求"这次以后都别再问"，用 `status --json` 展示现有 token，并让用户明确授权；不要自行放宽。

## 硬性约束

- 不许伪造用户答复：`approve` 必须在真实提问之后执行，`--note` 保留用户原话。
- 不许绕过闸门：不要为了推成功而改 hook 配置、删 token 文件、加 `--no-verify`、换协议（改为 `gh api`、网页上传、邮件发送同样受管）。
- 报告里的样例已被掩码；原文（完整密钥/身份证号）不要复制进对话或写入提交信息。
- 用户说"直接推"就把这次当作已确认；用户没说就不要自行推断。
- 若 hook/插件已经拦截并给出理由，按理由里的步骤走，不要重复尝试同一命令。

## 被拦截时（hook 反馈）

出现 `desensitize-guard` 或"需要用户确认是否脱敏"字样的拒绝，说明闸门生效：回到步骤 1 出报告 → 步骤 2 问用户 → 步骤 3 落库 → 步骤 4 重试。不要改用别的命令绕开同一次出网。

## 快速参考

| 命令 | 用途 |
| --- | --- |
| `scan --cmd "<cmd>" [--json]` | 出网判定 + 敏感扫描报告 |
| `approve --cmd "<cmd>" --answer yes\|no --note "<原话>"` | 记录用户答复、放行/继续拦 |
| `status [--json]` | 有效 token 与审计尾部 |
| `hook --dialect claude\|codex\|dsh-native` | 供 hook/插件调用，非人工使用 |
| `selftest` | 规则自检 |

环境开关：`DESENSITIZE_GUARD_MODE=off|warn|gate`、`DESENSITIZE_GUARD_HOME=<状态目录>`、`DESENSITIZE_GUARD_TTL_MIN=<分钟>`。
