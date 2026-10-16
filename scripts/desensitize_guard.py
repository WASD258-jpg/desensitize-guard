#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""desensitize-guard —— 出网动作（git push / 上传 / 发布 / 外发类 MCP）前的脱敏确认门。

一个脚本，三端复用：

* dsh          : 原生 cordis 插件通过 ``hook --dialect dsh-native --json-decision`` 调用，
                 拿到 ``{"kind": "ask"}`` 后交给宿主审批 UI 询问用户。
* Claude Code  : ``~/.claude/settings.json`` 的 PreToolUse hook，
                 输出 ``permissionDecision: "ask"`` 由 Claude Code 自己弹权限确认。
* Codex CLI/App: ``~/.codex/hooks.json`` 的 PreToolUse hook（Codex 不支持 ask），
                 输出 ``permissionDecision: "deny"``，模型看到理由后自己问用户。

子命令：

  hook    读 stdin 的 hook payload，判定并输出对应方言的决策（供 hook/插件调用）
  scan    给智能体用的报告；用于把"要推送什么、含哪些敏感项"讲给用户听
  approve 用户答复后写入放行 token（带命令指纹与有效期）
  status  查看当前有效 token / 审计尾部
  selftest 内置用例自检

模式（环境变量 ``DESENSITIZE_GUARD_MODE``）：``gate``（默认，拦截+询问）/ ``warn``（只提示不拦）/ ``off``。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_TTL_MIN = 20
MAX_FILE_BYTES = 262_144
MAX_DIFF_BYTES = 2 * 1024 * 1024
MAX_FINDINGS = 60
GIT_TIMEOUT_S = 25
SKILL_DIR = Path(__file__).resolve().parents[1]
DEFAULT_RULES = SKILL_DIR / "rules" / "rules.json"


# --------------------------------------------------------------------------- 基础工具

def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def state_dir() -> Path:
    override = os.environ.get("DESENSITIZE_GUARD_HOME")
    if override:
        return Path(override).expanduser()
    dsh_home = os.environ.get("DSH_HOME") or str(Path.home() / ".dsh")
    return Path(dsh_home) / "desensitize-guard"


def store_path() -> Path:
    return state_dir() / "approvals.json"


def audit_path() -> Path:
    return state_dir() / "audit.jsonl"


def mode() -> str:
    value = (os.environ.get("DESENSITIZE_GUARD_MODE") or "gate").strip().lower()
    return value if value in {"gate", "warn", "off"} else "gate"


def ttl_minutes() -> int:
    try:
        return max(1, int(os.environ.get("DESENSITIZE_GUARD_TTL_MIN", DEFAULT_TTL_MIN)))
    except ValueError:
        return DEFAULT_TTL_MIN


def load_rules(path: str | None = None) -> dict:
    rules_path = Path(path).expanduser() if path else DEFAULT_RULES
    with open(rules_path, "r", encoding="utf-8") as handle:
        rules = json.load(handle)
    rules.setdefault("egress", [])
    rules.setdefault("sensitive", [])
    rules.setdefault("path_rules", [])
    for rule in rules["egress"]:
        rule["_re"] = re.compile(rule["pattern"]) if rule.get("pattern") else None
        if rule.get("tool_name_pattern"):
            rule["_tool_re"] = re.compile(rule["tool_name_pattern"])
    for rule in rules["sensitive"]:
        rule["_re"] = re.compile(rule["pattern"], re.MULTILINE)
    for rule in rules["path_rules"]:
        rule["_re"] = re.compile(rule["pattern"])
    return rules


def read_store() -> dict:
    path = store_path()
    if not path.exists():
        return {"version": 1, "tokens": []}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {"version": 1, "tokens": []}
    data.setdefault("version", 1)
    data.setdefault("tokens", [])
    return data


def write_store(data: dict) -> None:
    directory = state_dir()
    directory.mkdir(parents=True, exist_ok=True)
    temporary = store_path().with_suffix(".tmp")
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
    os.replace(temporary, store_path())


def audit(event: str, **fields) -> None:
    directory = state_dir()
    directory.mkdir(parents=True, exist_ok=True)
    record = {"at": iso(now()), "event": event, **fields}
    try:
        with open(audit_path(), "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def norm_command(command: str) -> str:
    return " ".join((command or "").split()).strip().lower()


def command_hash(command: str, extra: str = "") -> str:
    digest = hashlib.sha256()
    digest.update(norm_command(command).encode("utf-8"))
    digest.update(b"\n")
    digest.update((extra or "").encode("utf-8"))
    return digest.hexdigest()[:32]


# --------------------------------------------------------------------------- payload 解析

def extract_command(tool_name: str, tool_input) -> str:
    """从各 harness 的 tool_input 里取出命令行。"""
    if isinstance(tool_input, str):
        return tool_input
    if isinstance(tool_input, list):
        return " ".join(str(part) for part in tool_input)
    if isinstance(tool_input, dict):
        for key in ("command", "cmd", "script", "shell_command", "input", "query", "args"):
            value = tool_input.get(key)
            if isinstance(value, str):
                return value
            if isinstance(value, list):
                return " ".join(str(part) for part in value)
        return json.dumps(tool_input, ensure_ascii=False)
    return ""


def payload_fields(payload: dict) -> tuple[str, str, dict, str]:
    tool_name = str(payload.get("tool_name") or payload.get("tool") or "")
    tool_input = payload.get("tool_input")
    if tool_input is None:
        tool_input = payload.get("arguments") or payload.get("input") or {}
    cwd = str(payload.get("cwd") or payload.get("workspace") or os.getcwd())
    command = extract_command(tool_name, tool_input)
    return tool_name, command, (tool_input if isinstance(tool_input, dict) else {}), cwd


# --------------------------------------------------------------------------- 出网判定

def classify_egress(rules: dict, tool_name: str, command: str) -> list[dict]:
    hits: list[dict] = []
    for rule in rules["egress"]:
        if rule.get("_re") is not None and rule["_re"].search(command or ""):
            hits.append(rule)
            continue
        tool_re = rule.get("_tool_re")
        if tool_re is not None and tool_name and tool_re.search(tool_name):
            hits.append(rule)
    return hits


def remote_label(command: str) -> str:
    match = re.search(r"\bgit\s+push\b\s*(?:[^\s|;&]+)?\s*([^\s|;&]+)?", command or "")
    if match and match.group(1):
        return match.group(1)
    return ""


# --------------------------------------------------------------------------- 内容采集

def run_git(args: list[str], cwd: str) -> str:
    """跑 git 并强制按 UTF-8 解码。

    Windows 默认会用本地代码页解码 git 输出，含中文的路径会变乱码、后续读取全部失败；
    同时关掉 core.quotepath，避免非 ASCII 路径被转义成 \\346 八进制串。
    """
    try:
        completed = subprocess.run(
            ["git", "-c", "core.quotepath=false", *args],
            cwd=cwd,
            capture_output=True,
            timeout=GIT_TIMEOUT_S,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if completed.returncode != 0:
        return ""
    return completed.stdout


def git_root(cwd: str) -> str:
    return run_git(["rev-parse", "--show-toplevel"], cwd).strip()


def git_change_set(cwd: str) -> dict:
    """取"即将出网"的改动集合：优先 upstream..HEAD，其次整仓（首次出网），最后 index/工作区。"""
    info: dict = {"root": git_root(cwd), "source": "", "text": "", "files": [], "full_scan": False}
    if not info["root"]:
        return info
    upstream = run_git(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"], cwd).strip()
    if upstream:
        info["source"] = f"git diff {upstream}..HEAD"
        info["text"] = run_git(["diff", "--unified=0", f"{upstream}..HEAD"], cwd)
        names = run_git(["diff", "--name-only", f"{upstream}..HEAD"], cwd)
    else:
        tracked = [line.strip() for line in run_git(["ls-files"], cwd).splitlines() if line.strip()]
        if tracked:
            # 无 upstream：远端什么都没有，本次 push 会把整个仓库发出去 → 逐文件全文扫描
            info["source"] = "整仓首次出网（无 upstream）：git ls-files 逐文件扫描"
            info["files"] = tracked
            info["full_scan"] = True
        else:
            info["source"] = "git diff --cached + git diff HEAD（无 upstream、无已跟踪文件）"
            info["text"] = run_git(["diff", "--unified=0", "--cached"], cwd) + run_git(
                ["diff", "--unified=0", "HEAD"], cwd
            )
            names = run_git(["diff", "--name-only", "--cached"], cwd) + run_git(
                ["diff", "--name-only", "HEAD"], cwd
            )
    info["text"] = info["text"][:MAX_DIFF_BYTES]
    if not info["full_scan"]:
        info["files"] = sorted({line.strip() for line in names.splitlines() if line.strip()})
    return info


FILE_TOKEN_RE = re.compile(r"[^\s\"'|;&<>]+")


def clean_token(token: str) -> str:
    """把 `-F file=@a.zip` / `--data-binary @a.json` 这类 token 还原成路径。"""
    value = token.strip(",;\"'")
    if value.startswith("@"):
        value = value[1:]
    match = re.match(r"^[A-Za-z_][A-Za-z0-9_\-]*=(.*)$", value)
    if match:
        value = match.group(1)
    if value.startswith("@"):
        value = value[1:]
    return value.strip(",;\"'")


def candidate_files(command: str, cwd: str) -> list[str]:
    """从命令行里猜出会被上传的本地文件。"""
    found: list[str] = []
    for token in FILE_TOKEN_RE.findall(command or ""):
        cleaned = clean_token(token)
        if not cleaned or cleaned.startswith("-"):
            continue
        path = Path(cleaned)
        if not path.is_absolute():
            path = Path(cwd) / cleaned
        try:
            if path.is_file():
                found.append(str(path))
        except OSError:
            continue
    unique: list[str] = []
    for item in found:
        if item not in unique:
            unique.append(item)
    return unique[:50]


# --------------------------------------------------------------------------- 敏感扫描

def mask_value(kind: str, raw: str) -> str:
    value = raw.strip()
    if kind == "email" and "@" in value:
        local, _, domain = value.partition("@")
        return f"{local[:2]}***@{domain}"
    digits = re.sub(r"\D", "", value)
    if kind == "pii" and len(digits) >= 11:
        keep_tail = 4
        return f"{digits[:3]}{'*' * max(0, len(digits) - 3 - keep_tail)}{digits[-keep_tail:]}"
    if len(value) <= 8:
        return value[:2] + "*" * max(0, len(value) - 2)
    return f"{value[:4]}…{value[-2:]}(len {len(value)})"


def rule_kind_tag(rule: dict) -> str:
    return rule.get("kind") or rule.get("severity") or "sensitive"


ALLOW_MARKER = "desensitize-guard:allow"


def line_has_allow_marker(text: str, position: int) -> bool:
    """命中所在行含 `desensitize-guard:allow` 时跳过——用于"确认无风险"的 fixture/示例。"""
    start = text.rfind("\n", 0, position) + 1
    end = text.find("\n", position)
    line = text[start:] if end < 0 else text[start:end]
    return ALLOW_MARKER in line


def scan_text(rules: dict, text: str, where: str) -> list[dict]:
    findings: list[dict] = []
    if not text:
        return findings
    for rule in rules["sensitive"]:
        for match in rule["_re"].finditer(text):
            if line_has_allow_marker(text, match.start()):
                continue
            value = match.group(0)
            kind = "email" if rule["id"] == "email" else ("pii" if rule["kind"] == "pii" else rule["kind"])
            findings.append(
                {
                    "rule": rule["id"],
                    "title": rule["title"],
                    "kind": rule["kind"],
                    "severity": rule["severity"],
                    "where": where,
                    "sample": mask_value(kind, value),
                }
            )
            if len(findings) >= MAX_FINDINGS:
                return findings
    return findings


def scan_paths(rules: dict, paths: list[str]) -> list[dict]:
    findings: list[dict] = []
    for item in paths:
        for rule in rules["path_rules"]:
            if rule["_re"].search(item):
                findings.append(
                    {
                        "rule": rule["id"],
                        "title": rule["title"],
                        "kind": "path",
                        "severity": rule["severity"],
                        "where": item,
                        "sample": Path(item).name,
                    }
                )
    return findings


def scan_files(rules: dict, paths: list[str]) -> list[dict]:
    skip = {ext.lower() for ext in rules.get("skip_scan_extensions", [])}
    findings: list[dict] = []
    for item in paths:
        path = Path(item)
        if path.suffix.lower() in skip:
            continue
        try:
            size = path.stat().st_size
            if size > MAX_FILE_BYTES:
                findings.append(
                    {
                        "rule": "oversize-file",
                        "title": "体积过大，未逐行扫描",
                        "kind": "path",
                        "severity": "low",
                        "where": item,
                        "sample": f"{size} bytes",
                    }
                )
                continue
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw[:4096]:
            continue
        text = raw.decode("utf-8", errors="replace")
        for index, line in enumerate(text.splitlines(), start=1):
            for finding in scan_text(rules, line, f"{item}:{index}"):
                findings.append(finding)
                if len(findings) >= MAX_FINDINGS:
                    return findings
    return findings


MAX_FULL_SCAN_FILES = 300


def build_report(rules: dict, tool_name: str, command: str, cwd: str) -> dict:
    hits = classify_egress(rules, tool_name, command)
    change = {"root": "", "source": "", "files": [], "full_scan": False}
    label = remote_label(command)
    is_push = any(rule["id"] == "git-push" for rule in hits)
    if is_push:
        change = git_change_set(cwd)
    files = candidate_files(command, cwd)
    findings: list[dict] = []
    if is_push:
        if change.get("full_scan"):
            # 整仓首次出网：按路径规则 + 逐文件全文扫描
            relative = change.get("files", [])[:MAX_FULL_SCAN_FILES]
            absolute = [str(Path(change["root"]) / item) for item in relative]
            findings += scan_paths(rules, relative)
            findings += scan_files(rules, absolute)
        else:
            findings += scan_text(rules, change.get("text", ""), change.get("source") or "git diff")
            findings += scan_paths(rules, change.get("files", []))
    findings += scan_paths(rules, files)
    findings += scan_files(rules, files)
    deduped: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for finding in findings:
        key = (finding["rule"], finding["where"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    severity_rank = {"high": 0, "medium": 1, "low": 2}
    deduped.sort(key=lambda item: severity_rank.get(item["severity"], 3))
    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in deduped:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return {
        "tool_name": tool_name,
        "command": command,
        "cwd": cwd,
        "egress": [{"id": rule["id"], "title": rule["title"], "severity": rule["severity"]} for rule in hits],
        "is_egress": bool(hits),
        "remote": label,
        "repo": change.get("root", ""),
        "diff_source": change.get("source", ""),
        "outgoing_files": change.get("files", [])[:50],
        "candidate_files": files,
        "findings": deduped,
        "counts": counts,
        "cmd_key": command_hash(command, change.get("root", "")),
    }


def human_report(report: dict) -> str:
    if not report["is_egress"]:
        return "未检测到出网动作：无需脱敏确认。"
    lines = ["## 出网动作待脱敏确认"]
    lines.append(f"- 动作：{'、'.join(item['title'] for item in report['egress'])}")
    lines.append(f"- 命令：`{report['command'][:400]}`")
    if report["repo"]:
        lines.append(f"- 仓库：{report['repo']}")
    if report["diff_source"]:
        lines.append(f"- 出网内容来源：{report['diff_source']}")
    if report["outgoing_files"]:
        preview = "、".join(report["outgoing_files"][:20])
        lines.append(f"- 出网文件（{len(report['outgoing_files'])}）：{preview}")
    elif report["candidate_files"]:
        preview = "、".join(Path(item).name for item in report["candidate_files"][:20])
        lines.append(f"- 上传文件（{len(report['candidate_files'])}）：{preview}")
    counts = report["counts"]
    lines.append(f"- 敏感命中：high={counts.get('high', 0)} medium={counts.get('medium', 0)} low={counts.get('low', 0)}")
    if report["findings"]:
        lines.append("")
        lines.append("| 严重度 | 类别 | 位置 | 脱敏样例 |")
        lines.append("| --- | --- | --- | --- |")
        for finding in report["findings"][:30]:
            lines.append(
                f"| {finding['severity']} | {finding['title']} | `{finding['where'][:120]}` | `{finding['sample']}` |"
            )
        if len(report["findings"]) > 30:
            lines.append(f"| … | 其余 {len(report['findings']) - 30} 条省略 | | |")
    else:
        lines.append("- 未命中任何敏感模式（仍建议人工确认一次）")
    lines.append("")
    lines.append(f"- 放行指纹：`{report['cmd_key']}`")
    lines.append(
        "- 下一步：向用户确认是否需要脱敏；用户答复后用 "
        f"`approve --cmd \"<原命令>\" --answer yes|no` 落库，再重试原命令。"
    )
    return "\n".join(lines)


# --------------------------------------------------------------------------- token

def find_token(data: dict, report: dict) -> dict | None:
    key = report["cmd_key"]
    for token in data.get("tokens", []):
        if token.get("cmd_key") != key:
            continue
        try:
            if parse_iso(token["expires_at"]) < now():
                continue
        except (KeyError, ValueError):
            continue
        return token
    return None


def add_token(report: dict, answer: str, note: str, actor: str) -> dict:
    data = read_store()
    expires = now() + timedelta(minutes=ttl_minutes())
    token = {
        "id": hashlib.sha256(f"{report['cmd_key']}{time.time()}".encode()).hexdigest()[:12],
        "created_at": iso(now()),
        "expires_at": iso(expires),
        "answer": answer,
        "cmd": report["command"][:2000],
        "cmd_key": report["cmd_key"],
        "repo": report.get("repo", ""),
        "egress": [item["id"] for item in report["egress"]],
        "findings_high": report["counts"].get("high", 0),
        "findings_total": len(report["findings"]),
        "note": note,
        "actor": actor,
    }
    data["tokens"] = [t for t in data.get("tokens", []) if t.get("cmd_key") != report["cmd_key"]]
    data["tokens"].append(token)
    data["tokens"] = data["tokens"][-200:]
    write_store(data)
    audit("approve", answer=answer, cmd_key=report["cmd_key"], actor=actor, note=note)
    return token


ASK_TOOL = {
    "claude": "AskUserQuestion",
    "codex": "提问/审批确认（Codex 原生提问或审批弹窗）",
    "dsh-native": "ask_user_question",
    "auto": "ask_user_question / AskUserQuestion",
}


def next_step_text(dialect: str, report: dict) -> str:
    script = str(SKILL_DIR / "scripts" / "desensitize_guard.py")
    tool = ASK_TOOL.get(dialect, ASK_TOOL["auto"])
    return (
        "检测到出网动作，尚未完成脱敏确认，已拦截本次调用。\n"
        f"1) 运行 `python \"{script}\" scan --cmd \"{report['command'][:200]}\"` 取得待脱敏清单；\n"
        f"2) 用 {tool} 询问用户：本次出网内容是否需要脱敏（选项：直接推送 / 先脱敏 / 取消）；\n"
        f"3) 用户答复后运行 `python \"{script}\" approve --cmd \"{report['command'][:200]}\" "
        "--answer yes|no --note \"<用户原话>\"`；\n"
        "4) 然后重试原命令。禁止在用户答复前自行 approve。"
    )


def decision_for(payload: dict, rules: dict, dialect: str) -> dict:
    tool_name, command, _tool_input, cwd = payload_fields(payload)
    report = build_report(rules, tool_name, command, cwd)
    if not report["is_egress"]:
        return {"kind": "allow", "reason": "", "report": report, "approved": False}
    data = read_store()
    token = find_token(data, report)
    if token is not None and token.get("answer") == "yes":
        audit("hook-allow", cmd_key=report["cmd_key"], rule=report["egress"][0]["id"], dialect=dialect)
        return {"kind": "allow", "reason": "desensitize-guard: 用户已确认（放行）", "report": report, "approved": True}
    if token is not None and token.get("answer") == "no":
        reason = f"desensitize-guard: 用户已选择先脱敏/取消（注意：{token.get('note') or '无备注'}）"
        audit("hook-deny", cmd_key=report["cmd_key"], dialect=dialect)
        return {"kind": "deny", "reason": reason, "report": report, "approved": False}
    reason = human_report(report) + "\n\n" + next_step_text(dialect, report)
    audit(
        "hook-ask",
        cmd_key=report["cmd_key"],
        rule=report["egress"][0]["id"],
        high=report["counts"].get("high", 0),
        dialect=dialect,
    )
    return {"kind": "ask", "reason": reason, "report": report, "approved": False}


# --------------------------------------------------------------------------- 方言输出

def emit_for_dialect(result: dict, dialect: str, exit2: bool = False) -> int:
    kind = result["kind"]
    if kind == "allow":
        if result.get("approved"):
            print(json.dumps({"systemMessage": "desensitize-guard: 已确认，放行"}, ensure_ascii=False))
        return 0
    if mode() == "warn":
        print(json.dumps({"systemMessage": "desensitize-guard: 仅提示模式，未拦截"}, ensure_ascii=False))
        return 0
    reason = result["reason"]
    if dialect == "codex":
        if exit2:
            print(reason, file=sys.stderr)
            return 2
        if kind == "ask":
            reason = "【需要用户确认是否脱敏】\n" + reason
        print(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": reason,
                    },
                    "systemMessage": "desensitize-guard: 已拦截出网动作，等待脱敏确认",
                },
                ensure_ascii=False,
            )
        )
        return 0
    if dialect == "dsh-native":
        print(json.dumps({"kind": "ask" if kind == "ask" else "deny", "reason": reason}, ensure_ascii=False))
        return 0
    # claude-code（dsh 的 hooks-claude-code 桥接同方言）
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask" if kind == "ask" else "deny",
                    "permissionDecisionReason": reason,
                    "additionalContext": reason,
                },
                "systemMessage": "desensitize-guard: 检测到出网动作，等待脱敏确认",
            },
            ensure_ascii=False,
        )
    )
    return 0


def resolve_dialect(explicit: str, payload: dict) -> str:
    if explicit and explicit != "auto":
        return explicit
    env = (os.environ.get("DESENSITIZE_GUARD_DIALECT") or "").strip()
    if env:
        return env
    if isinstance(payload.get("tool_input"), list) or "turn_id" in payload:
        return "codex"
    return "claude"


# --------------------------------------------------------------------------- 子命令

def cmd_hook(args: argparse.Namespace) -> int:
    raw = sys.stdin.read()
    # 容错：Windows PowerShell 管道可能带 UTF-8 BOM，harness 也可能带前导空白/换行
    raw = raw.lstrip("\ufeff \t\r\n")
    if raw.endswith("\x00"):
        raw = raw.rstrip("\x00")
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except ValueError:
        audit("hook-bad-payload", raw_prefix=raw[:200])
        return 0
    if not isinstance(payload, dict):
        return 0
    if mode() == "off":
        return 0
    rules = load_rules(args.rules)
    dialect = resolve_dialect(args.dialect, payload)
    try:
        result = decision_for(payload, rules, dialect)
    except Exception as error:  # 钩子永不打断调用轮次
        audit("hook-error", error=repr(error))
        return 0
    if args.json_decision:
        if mode() == "warn" and result["kind"] != "allow":
            result = {**result, "kind": "allow", "warn_only": True}
        print(json.dumps(result, ensure_ascii=False))
        return 0
    return emit_for_dialect(result, dialect, exit2=args.exit2)


def report_decision(report: dict) -> str:
    if not report["is_egress"]:
        return "not_egress"
    token = find_token(read_store(), report)
    if token is None:
        return "needs_confirmation"
    return "approved" if token.get("answer") == "yes" else "user_declined"


def cmd_scan(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    cwd = args.cwd or os.getcwd()
    report = build_report(rules, args.tool or "", args.cmd or "", cwd)
    decision = report_decision(report)
    audit("scan", is_egress=report["is_egress"], decision=decision, cmd_key=report["cmd_key"])
    if args.json:
        print(json.dumps({**report, "decision": decision}, ensure_ascii=False, indent=2))
    else:
        print(human_report(report))
        print(f"\nDECISION: {decision}")
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    cwd = args.cwd or os.getcwd()
    report = build_report(rules, args.tool or "", args.cmd or "", cwd)
    if not report["is_egress"]:
        print("未检测到出网动作：无需放行 token。")
        return 0
    answer = (args.answer or "yes").strip().lower()
    if answer not in {"yes", "no"}:
        print("--answer 只能是 yes 或 no", file=sys.stderr)
        return 1
    if not (args.note or "").strip():
        print("提示：--note 请填写用户原话，便于审计（可留空但建议填）", file=sys.stderr)
    token = add_token(report, answer, args.note or "", args.actor or "agent")
    print(
        json.dumps(
            {
                "ok": True,
                "answer": answer,
                "cmd_key": report["cmd_key"],
                "expires_at": token["expires_at"],
                "note": "yes=下次同一命令直接放行；no=继续拦截并提示先脱敏",
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    data = read_store()
    live = []
    for token in data.get("tokens", []):
        try:
            expired = parse_iso(token["expires_at"]) < now()
        except (KeyError, ValueError):
            expired = True
        if not expired:
            live.append(token)
    tail: list[str] = []
    if audit_path().exists():
        with open(audit_path(), "r", encoding="utf-8") as handle:
            tail = handle.read().splitlines()[-10:]
    if args.json:
        print(json.dumps({"state_dir": str(state_dir()), "live_tokens": live, "audit_tail": tail}, ensure_ascii=False, indent=2))
        return 0
    print(f"state_dir: {state_dir()}")
    print(f"mode: {mode()}  ttl_min: {ttl_minutes()}")
    print(f"有效放行 token：{len(live)}")
    for token in live:
        print(f"  - {token['cmd_key']} answer={token['answer']} 过期={token['expires_at']} cmd={token['cmd'][:80]}")
    if tail:
        print("审计尾部：")
        for line in tail:
            print(f"  {line}")
    return 0


SELFTEST_CASES = [
    ("git push 出网被拦", {"tool_name": "Bash", "tool_input": {"command": "git push origin main"}, "cwd": "."}, "ask"),
    ("普通读取放行", {"tool_name": "Bash", "tool_input": {"command": "git status"}, "cwd": "."}, "allow"),
    ("curl 上传被拦", {"tool_name": "Bash", "tool_input": {"command": "curl -T out.zip https://example.com/u"}, "cwd": "."}, "ask"),
    ("MCP 上传工具被拦", {"tool_name": "mcp__box__upload_file", "tool_input": {"path": "report.xlsx"}, "cwd": "."}, "ask"),
    ("构建命令放行", {"tool_name": "pwsh", "tool_input": {"command": "pnpm run build"}, "cwd": "."}, "allow"),
]


def cmd_selftest(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    failures = 0
    for title, payload, expected in SELFTEST_CASES:
        result = decision_for(payload, rules, "dsh-native")
        actual = result["kind"]
        ok = actual == expected
        failures += 0 if ok else 1
        print(f"[{'PASS' if ok else 'FAIL'}] {title}: 期望 {expected}，实际 {actual}")
    print(f"\n规则文件：{args.rules or DEFAULT_RULES}")
    print(f"状态目录：{state_dir()}")
    print("结果：全部通过" if failures == 0 else f"结果：{failures} 项未通过")
    return 0 if failures == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="desensitize-guard 出网脱敏确认门")
    parser.add_argument("--rules", help="规则文件路径", default=None)
    sub = parser.add_subparsers(dest="command", required=True)

    hook = sub.add_parser("hook", help="hook 模式：读 stdin payload 输出决策")
    hook.add_argument("--dialect", default="auto", choices=["auto", "claude", "codex", "dsh-native"])
    hook.add_argument("--json-decision", action="store_true", help="输出中性 JSON（供 dsh 原生插件消费）")
    hook.add_argument("--exit2", action="store_true", help="codex 方言使用 exit 2 阻断")
    hook.set_defaults(func=cmd_hook)

    scan = sub.add_parser("scan", help="出网/脱敏扫描报告")
    scan.add_argument("--cmd", default="")
    scan.add_argument("--tool", default="")
    scan.add_argument("--cwd", default=None)
    scan.add_argument("--json", action="store_true")
    scan.set_defaults(func=cmd_scan)

    approve = sub.add_parser("approve", help="记录用户答复并放行")
    approve.add_argument("--cmd", required=True)
    approve.add_argument("--tool", default="")
    approve.add_argument("--cwd", default=None)
    approve.add_argument("--answer", default="yes")
    approve.add_argument("--note", default="")
    approve.add_argument("--actor", default="agent")
    approve.set_defaults(func=cmd_approve)

    status = sub.add_parser("status", help="查看放行 token 与审计尾部")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)

    selftest = sub.add_parser("selftest", help="内置用例自检")
    selftest.set_defaults(func=cmd_selftest)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
