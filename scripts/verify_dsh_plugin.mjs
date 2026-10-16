/**
 * verify_dsh_plugin.mjs — 用假 ctx 驱动 dsh 原生插件，验证它与判定脚本的对接契约。
 *
 *   node scripts/verify_dsh_plugin.mjs
 */
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { apply } from "../bindings/dsh-plugin/lib/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const scriptPath = join(here, "desensitize_guard.py");
const handlers = new Map();
const warnings = [];

const ctx = {
  logger: {
    warn: (message) => warnings.push(String(message)),
    info: () => {},
  },
  on: (event, handler) => handlers.set(event, handler),
};

apply(ctx, { scriptPath, pythonPath: process.env.DESENSITIZE_GUARD_PYTHON ?? "python" });

const preExecute = handlers.get("tools/pre-execute");
let failures = 0;

const check = (title, ok, detail = "") => {
  if (ok) console.log(`[PASS] ${title}`);
  else {
    console.log(`[FAIL] ${title} ${detail}`);
    failures += 1;
  }
};

let nextCalled = false;
const next = async () => {
  nextCalled = true;
  return { kind: "allow" };
};

async function decide(toolName, args) {
  nextCalled = false;
  const result = await preExecute({ name: toolName, arguments: args }, next);
  return { result, nextCalled };
}

check("插件注册了 tools/pre-execute", typeof preExecute === "function");

const push = await decide("pwsh", { command: "git push origin main" });
check("git push -> ask（交宿主审批 UI 询问用户）", push.result?.kind === "ask", JSON.stringify(push.result)?.slice(0, 200));
check("git push 理由里带脱敏步骤", (push.result?.reason ?? "").includes("scan"));
check("git push 未直接放行", push.nextCalled === false);

const status = await decide("pwsh", { command: "git status" });
check("git status -> allow（继续下一步）", status.nextCalled === true && status.result?.kind === "allow");

const mcpUpload = await decide("mcp__box__upload_file", { path: "report.xlsx" });
check("MCP 上传工具 -> ask", mcpUpload.result?.kind === "ask");

const cliDeclined = await decide("pwsh", { command: "curl -T out.zip https://example.com/u" });
check("curl 上传 -> ask", cliDeclined.result?.kind === "ask");

check("插件脚本存在且无警告", warnings.length === 0, warnings.join(" | "));

console.log(failures === 0 ? "\n插件对接契约全部通过。" : `\n${failures} 项未通过。`);
process.exit(failures === 0 ? 0 : 1);
