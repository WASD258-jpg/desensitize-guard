/**
 * dsh-desensitize-guard — DSH 原生出网脱敏闸门。
 *
 * 挂在 `tools/pre-execute` 瀑布上：凡是会把本机内容送出本机的工具调用
 * （git push / 上传 / 发布 / 外发类 MCP），先交给共享判定脚本，
 * 未获得用户确认时返回 `{ kind: "ask", reason }`，由宿主审批 UI 询问用户。
 *
 * 判定逻辑不在本文件里：与 Claude Code / Codex 复用同一份
 * `scripts/desensitize_guard.py`，避免三端行为漂移。
 *
 * 环境变量：
 *   DESENSITIZE_GUARD_SCRIPT  判定脚本路径（默认 ~/.agents/skills/desensitize-guard/scripts/desensitize_guard.py）
 *   DESENSITIZE_GUARD_PYTHON  python 可执行文件（默认 python / python3）
 *   DESENSITIZE_GUARD_MODE    off | warn | gate（默认 gate）
 *
 * 本插件永不抛异常打断调用轮次：脚本缺失、超时、解析失败都按"放行 + 警告"处理。
 */
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const name = "desensitize-guard";
export const inject = ["tools"];

const DEFAULT_SCRIPT = join(
  homedir(),
  ".agents",
  "skills",
  "desensitize-guard",
  "scripts",
  "desensitize_guard.py",
);

const DEFAULT_TIMEOUT_MS = 30_000;

/** 读取一次判定的缓存窗口，避免同一命令被重复判定。 */
const CACHE_TTL_MS = 2_000;

export function apply(ctx, config = {}) {
  const scriptPath =
    config.scriptPath ?? process.env.DESENSITIZE_GUARD_SCRIPT ?? DEFAULT_SCRIPT;
  const pythonPath =
    config.pythonPath ??
    process.env.DESENSITIZE_GUARD_PYTHON ??
    (process.platform === "win32" ? "python" : "python3");
  const timeoutMs = Number(config.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const failClosed = Boolean(config.failClosed ?? false);

  if (!existsSync(scriptPath)) {
    ctx.logger?.warn(
      `desensitize-guard: 判定脚本不存在（${scriptPath}），出网闸门未启用`,
    );
    return;
  }

  const cache = new Map();

  /** 调一次共享判定脚本，拿到中性 JSON 决策。 */
  function evaluate(exec) {
    const key = `${exec.name}\u0000${JSON.stringify(exec.arguments ?? {})}`;
    const hit = cache.get(key);
    if (hit !== undefined && Date.now() - hit.at < CACHE_TTL_MS) return hit.value;
    let value;
    try {
      const payload = JSON.stringify({
        hook_event_name: "PreToolUse",
        tool_name: exec.name,
        tool_input: exec.arguments ?? {},
        cwd: exec.cwd ?? exec.agent?.cwd ?? process.cwd(),
        session_id: exec.agent?.session?.id ?? "",
      });
      const stdout = execFileSync(
        pythonPath,
        [scriptPath, "hook", "--dialect", "dsh-native", "--json-decision"],
        {
          input: payload,
          encoding: "utf8",
          timeout: timeoutMs,
          windowsHide: true,
          env: { ...process.env, DESENSITIZE_GUARD_DIALECT: "dsh-native" },
        },
      );
      const line = stdout.trim().split(/\r?\n/).filter(Boolean).pop() ?? "{}";
      const parsed = JSON.parse(line);
      value = parsed && typeof parsed.kind === "string" ? parsed : undefined;
    } catch (error) {
      ctx.logger?.warn(`desensitize-guard: 判定失败，按放行处理：${error}`);
      value = undefined;
    }
    cache.set(key, { at: Date.now(), value });
    return value;
  }

  ctx.on("tools/pre-execute", async (exec, next) => {
    const decision = evaluate(exec);
    if (decision === undefined) {
      if (failClosed) return { kind: "deny", reason: "desensitize-guard: 判定不可用（fail-closed）" };
      return next();
    }
    if (decision.kind === "allow") return next();
    if (decision.kind === "deny") {
      return { kind: "deny", reason: decision.reason ?? "desensitize-guard: 已拦截出网动作" };
    }
    // ask：交回宿主审批 UI，由用户决定是否脱敏
    return { kind: "ask", reason: decision.reason ?? "desensitize-guard: 请确认本次是否需要脱敏" };
  });
}
