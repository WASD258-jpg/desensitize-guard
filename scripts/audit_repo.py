#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""audit_repo.py —— 存量审计：扫一个（或全部）仓库里"有没有没脱敏的数据、能不能补救"。

与 `desensitize_guard.py hook` 的区别：
  * hook 只看"这次要发出去什么"；
  * 审计要把**整仓工作区 + 全部 git 历史**挖一遍 —— 因为"加了又删"的密钥照样躺在历史里。

用法：
  python audit_repo.py --local <路径> [--local <路径> ...]
  python audit_repo.py --github [--only name1,name2] [--include-forks] [--max-mb 300]
  python audit_repo.py --local <路径> --fix-plan          # 额外生成补救脚本（不自动执行）

输出：控制台 markdown 报告 + `<out>/<repo>-audit.json` + `<out>/index.md` 汇总。
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import desensitize_guard as g  # noqa: E402

MAX_HISTORY_BYTES = 20 * 1024 * 1024
MAX_HISTORY_NAMES = 40_000
GIT_TIMEOUT_S = 300

# rule id → (处理类别, 补救建议)
REMEDIATION: dict[str, tuple[str, str]] = {
    "credential-file": ("rewrite+rotate", "从历史移除该文件 → **轮换里面的凭据** → 加进 .gitignore"),
    "cloud-credential-file": ("rewrite+rotate", "云凭据文件：移除历史 + 轮换 AccessKey/密钥"),
    "private-key-file": ("rewrite+rotate", "密钥/证书文件：移除历史 + 重新签发证书/密钥"),
    "browser-session-data": ("rewrite+rotate", "会话/抓包数据：移除历史 + 注销对应会话"),
    "iac-state": ("rewrite+rotate", "IaC state 含明文密钥：移除历史 + 轮换所有被引用的凭据"),
    "office-db-dump": ("review", "批量个人数据：确认是否该公开；不该就移除历史并重写"),
    "oversize-file": ("review", "体积过大未逐行扫描：需要人工看一眼"),
    "email": ("review", "公开仓库会暴露邮箱；可换 GitHub 私密邮箱（见 commit --amend --reset-author）"),
    "local-home-path": ("review", "本机绝对路径：泄露用户名/目录结构，重写历史或忽略"),
    "local-workspace-path": ("review", "本机工作区绝对路径：同上"),
    "local-username": ("review", "本机用户名"),
    "local-hostname": ("review", "本机主机名"),
    "unix-home-path": ("review", "绝对路径"),
    "windows-user-path": ("review", "绝对路径"),
    "unc-or-wsl-path": ("review", "网络共享/WSL 路径"),
    "abs-other-drive-path": ("review", "盘符绝对路径"),
    "private-ip": ("ignore", "内网 IP：一般可保留"),
    "internal-host": ("ignore", "内部域名：一般可保留"),
    "internal-api-endpoint": ("ignore", "内部端点：一般可保留"),
    "high-entropy-token": ("review", "未知格式长串：人工确认是不是密钥"),
    "cn-plate": ("review", "车牌"),
    "cn-landline": ("review", "座机"),
}
DEFAULT_REMEDIATION = ("rewrite+rotate", "按密钥处理：移除历史 + **先轮换**（历史重写收不回已泄露的凭据）")


def git(args: list[str], cwd: Path, timeout: int = GIT_TIMEOUT_S) -> str:
    try:
        done = subprocess.run(
            ["git", "-c", "core.quotepath=false", *args],
            cwd=str(cwd),
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return done.stdout if done.returncode == 0 else ""


def remediation_for(rule_id: str) -> tuple[str, str]:
    return REMEDIATION.get(rule_id, DEFAULT_REMEDIATION)


def dedupe(findings: list[dict]) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for finding in findings:
        key = (finding["rule"], finding["sample"])
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    rank = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda item: rank.get(item["severity"], 3))
    return out


def introducing_authors(repo: Path, raw: str, limit: int = 30) -> list[str]:
    """用 git log -S 定位引入该值的提交作者（判断"是上游带的还是我自己漏的"）。"""
    if not raw or len(raw) < 8:
        return []
    out = git(["log", "--all", f"-S{raw}", "--format=%h|%an|%ae|%ad", "--date=short"], repo, timeout=60)
    seen: list[str] = []
    for line in out.splitlines()[:limit]:
        entry = "|".join(line.split("|")[1:4])
        if entry and entry not in seen:
            seen.append(entry)
    return seen[:3]


def audit_repo(repo: Path, rules: dict, label: str) -> dict:
    # 审计需要在内存里保留命中原文，用于 git log -S 归因；写报告前会剔除
    rules = {**rules, "_keep_raw": True}
    head_paths = [line.strip() for line in git(["ls-files"], repo).splitlines() if line.strip()]
    head_absolute = [str(repo / item) for item in head_paths]

    head_findings = g.scan_paths(rules, head_paths) + g.scan_files(rules, head_absolute)

    history_names_raw = git(["rev-list", "--objects", "--all"], repo)[:4_000_000]
    history_names: list[str] = []
    for line in history_names_raw.splitlines()[:MAX_HISTORY_NAMES]:
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[1].strip():
            history_names.append(parts[1].strip())
    history_findings = g.scan_paths(rules, sorted(set(history_names)))

    patch = git(["log", "-p", "--all", "--no-color", "-U0", f"--max-count=4000"], repo)
    patch = patch[:MAX_HISTORY_BYTES]
    patch_findings = g.scan_text(rules, patch, "git log -p --all（逐提交补丁）", {})

    identities = []
    for line in git(["log", "--all", "--format=%an <%ae>%n%cn <%ce>"], repo).splitlines():
        entry = line.strip()
        if entry and entry not in identities:
            identities.append(entry)
    identity_findings = []
    for entry in identities:
        identity_findings += g.scan_text(rules, entry, f"提交者身份 {entry}", {})

    all_findings = head_findings + history_findings + patch_findings + identity_findings
    head_keys = {(f["rule"], f["sample"]) for f in head_findings}
    for finding in all_findings:
        finding["in_head"] = (finding["rule"], finding["sample"]) in head_keys
    findings = dedupe(all_findings)
    findings = g.limit_entropy_findings(findings, rules)
    for finding in findings:
        finding.setdefault("bucket", remediation_for(finding["rule"])[0])

    remotes = [line.strip() for line in git(["remote", "-v"], repo).splitlines()]
    owner = ""
    match = re.search(r"[/:]([^/:]+)/[^/]+?(?:\.git)?\s*\((?:fetch|push)\)", " ".join(remotes))
    if match:
        owner = match.group(1)

    # 归因：谁引入的（判断"上游带入"还是"自己漏的"）——只对需要用动作的项做，最多 25 个
    for finding in findings[:25]:
        if finding["severity"] not in {"high", "medium"}:
            continue
        authors = introducing_authors(repo, finding.get("raw", ""))
        finding["introduced_by"] = authors
        if owner and authors and not any(owner.lower() in item.lower() for item in authors):
            finding["origin"] = "上游历史带入"
        elif authors:
            finding["origin"] = "自有提交"
    for finding in findings:
        finding.pop("raw", None)

    buckets = {"rewrite+rotate": [], "review": [], "ignore": []}
    for finding in findings:
        bucket, advice = remediation_for(finding["rule"])
        finding["bucket"] = bucket
        finding["advice"] = advice
        buckets[bucket].append(finding)

    return {
        "label": label,
        "path": str(repo),
        "head_files": len(head_paths),
        "history_objects": len(history_names),
        "history_scanned_bytes": len(patch),
        "remotes": remotes,
        "owner": owner,
        "branch": git(["rev-parse", "--abbrev-ref", "HEAD"], repo).strip(),
        "commits": len([line for line in git(["rev-list", "--all", "--count"], repo).splitlines()]),
        "identities": identities,
        "findings": findings,
        "counts": {
            "total": len(findings),
            "rewrite+rotate": len(buckets["rewrite+rotate"]),
            "review": len(buckets["review"]),
            "ignore": len(buckets["ignore"]),
            "high": sum(1 for f in findings if f["severity"] == "high"),
            "in_head": sum(1 for f in findings if f["in_head"]),
        },
    }


def render_repo(report: dict) -> str:
    counts = report["counts"]
    lines = [f"### {report['label']}"]
    lines.append(
        f"- 提交 {report['commits']} 个 / HEAD 文件 {report['head_files']} 个 / 历史对象 {report['history_objects']} 个"
        f" / 历史补丁扫了 {report['history_scanned_bytes'] // 1024} KB"
    )
    if report["remotes"]:
        lines.append(f"- remote：{'; '.join(report['remotes'][:2])}")
    lines.append(
        f"- 命中：**{counts['total']}** 项（需轮换+重写 {counts['rewrite+rotate']} / 待人工确认 {counts['review']} / 可忽略 {counts['ignore']}；"
        f"其中 high={counts['high']}，仍在 HEAD 里 {counts['in_head']}）"
    )
    if not report["findings"]:
        lines.append("- ✅ 未发现未脱敏数据")
        return "\n".join(lines)
    lines.append("")
    lines.append("| 处理 | 严重度 | 规则 | 位置 | 位置类型 | 脱敏样例 | 引入者 | 建议 |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for finding in report["findings"][:40]:
        where = finding["where"][-140:]
        scope = "HEAD 里" if finding["in_head"] else "仅历史"
        authors = "、".join(finding.get("introduced_by", []) or ["—"])[:80]
        origin = finding.get("origin", "")
        who = f"{authors}（{origin}）" if origin else authors
        lines.append(
            f"| {finding['bucket']} | {finding['severity']} | `{finding['rule']}` | `{where}` | {scope} | `{finding['sample']}` | {who} | {finding['advice']} |"
        )
    if len(report["findings"]) > 40:
        lines.append(f"| … | | | | | | | 其余 {len(report['findings']) - 40} 项见 JSON |")
    return "\n".join(lines)


def write_fix_plan(report: dict, out_dir: Path) -> Path:
    """生成"可补救命但需你点头"的脚本：先备份镜像，再移除历史文件，force push 需手工放开。"""
    repo = Path(report["path"])
    name = report["label"]
    sensitive_paths: list[str] = []
    for finding in report["findings"]:
        if finding["bucket"] != "rewrite+rotate":
            continue
        counter = finding["where"]
        if counter.endswith((".env", ".pem", ".key", ".tfstate")) or "credentials" in counter or "id_rsa" in counter:
            candidate = counter.split(":")[0]
            if candidate and candidate not in sensitive_paths:
                sensitive_paths.append(candidate)
    body = [
        "# 由 desensitize_guard audit_repo.py 生成：历史清理预案（**默认不执行**）",
        "# 顺序很重要：先轮换密钥 → 再重写历史 → 最后强推（历史重写收不回已泄露的凭据）",
        f"$repo = '{repo}'",
        "Set-Location $repo",
        "",
        "# 0) 备份一份镜像（重写前必做）",
        f"git clone --mirror $repo \"{out_dir}\\{name}-backup.git\"",
        "",
        "# 1) 轮换这些文件里出现过的凭据（人工：平台后台/CI 变量/机器上）",
    ]
    for item in sensitive_paths or ["（脚本没自动识别到明确文件，请按报告逐项处理）"]:
        body.append(f"#    - {item}")
    body += [
        "",
        "# 2) 重写历史（二选一）",
        "#    A. git-filter-repo（推荐，先 pip install git-filter-repo）",
    ]
    for item in sensitive_paths:
        body.append(f"#    git filter-repo --path \"{item}\" --invert-paths --force")
    body += [
        "#    B. 无 filter-repo 时用 filter-branch（慢，慎用）",
        "#    git filter-branch --index-filter 'git rm --cached --ignore-unmatch <path>' --prune-empty -- --all",
        "",
        "# 3) 校验：确认目标文件已从历史消失",
        "#    git log --all --oneline --name-only | Select-String '<path>'",
        "",
        "# 4) 强推（**确认第 1、3 步做完再放开**；协作者需重新 clone）",
        "#    git push --force-with-lease origin --all",
        "#    git push --force-with-lease origin --tags",
        "",
        "# 5) 公开仓库额外动作：GitHub 缓存/派生副本无法保证清除，必要时联系 GitHub Support 清 cache",
    ]
    path = out_dir / f"{name}-remediation.ps1"
    path.write_text("\n".join(body), encoding="utf-8")
    return path


def gh_repos(include_forks: bool, only: list[str]) -> list[dict]:
    gh = shutil.which("gh") or r"C:\Program Files\GitHub CLI\gh.exe"
    try:
        done = subprocess.run(
            [gh, "repo", "list", "--limit", "200", "--json",
             "name,visibility,isFork,diskUsage,pushedAt,sshUrl,url"],
            capture_output=True, encoding="utf-8", errors="replace", timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SystemExit(f"调用 gh 失败：{error}")
    repos = json.loads(done.stdout or "[]")
    if only:
        repos = [r for r in repos if r["name"] in only]
    if not include_forks:
        repos = [r for r in repos if not r["isFork"]]
    repos.sort(key=lambda r: r.get("pushedAt") or "", reverse=True)
    return repos


def main() -> int:
    parser = argparse.ArgumentParser(description="仓库存量审计：找没脱敏的数据并给出补救建议")
    parser.add_argument("--local", action="append", default=[], help="本地仓库路径（可多次）")
    parser.add_argument("--github", action="store_true", help="用 gh 列出自己的仓库并逐个审计")
    parser.add_argument("--only", default="", help="只审计这些仓库名（逗号分隔）")
    parser.add_argument("--include-forks", action="store_true", help="连 fork 一起审计")
    parser.add_argument("--max-mb", type=int, default=300, help="超过该体积的仓库跳过克隆（默认 300MB）")
    parser.add_argument("--rules", default=None)
    parser.add_argument("--out", default=None, help="报告输出目录")
    parser.add_argument("--work-dir", default=None, help="克隆用的临时目录")
    parser.add_argument("--fix-plan", action="store_true", help="额外生成补救脚本（不执行）")
    args = parser.parse_args()

    rules = g.load_rules(args.rules)
    out_dir = Path(args.out).expanduser() if args.out else g.state_dir() / "audit"
    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir = Path(args.work_dir).expanduser() if args.work_dir else Path(tempfile.gettempdir()) / "desensitize-audit-clones"
    work_dir.mkdir(parents=True, exist_ok=True)

    targets: list[tuple[str, Path]] = [(Path(item).name, Path(item).resolve()) for item in args.local]

    if args.github:
        only = [name.strip() for name in args.only.split(",") if name.strip()]
        for repo in gh_repos(args.include_forks, only):
            size_mb = (repo.get("diskUsage") or 0) / 1024
            if size_mb > args.max_mb:
                print(f"[skip] {repo['name']}：{size_mb:.0f}MB 超过 --max-mb {args.max_mb}")
                continue
            dest = work_dir / repo["name"]
            if dest.exists():
                print(f"[reuse] {repo['name']}（本地已有克隆）")
            else:
                print(f"[clone] {repo['name']}（{size_mb:.0f}MB，{repo['visibility']}）…")
                done = subprocess.run(
                    ["git", "clone", "--quiet", repo["url"], str(dest)],
                    capture_output=True, encoding="utf-8", errors="replace",
                )
                if done.returncode != 0:
                    print(f"[fail] 克隆失败：{(done.stderr or '').strip()[:200]}")
                    continue
            targets.append((repo["name"], dest))

    if not targets:
        print("没有可审计的目标：用 --local <路径> 或 --github")
        return 2

    reports = []
    for label, repo in targets:
        if not (repo / ".git").exists():
            print(f"[skip] {label}：不是 git 仓库（{repo}）")
            continue
        print(f"[scan] {label} …")
        report = audit_repo(repo, rules, label)
        reports.append(report)
        path = out_dir / f"{label}-audit.json"
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        if args.fix_plan and report["counts"]["rewrite+rotate"]:
            plan = write_fix_plan(report, out_dir)
            report["fix_plan"] = str(plan)

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    summary = [f"# 仓库存量脱敏审计（{stamp}）", ""]
    total = {"rewrite+rotate": 0, "review": 0, "ignore": 0, "high": 0, "in_head": 0}
    for report in reports:
        summary.append(render_repo(report))
        summary.append("")
        for key in total:
            total[key] += report["counts"][key]
    summary.append("## 汇总")
    summary.append(
        f"- 审计 {len(reports)} 个仓库；需轮换+重写历史 **{total['rewrite+rotate']}** 项、"
        f"待人工确认 {total['review']} 项、可忽略 {total['ignore']} 项；其中 high={total['high']}，仍在 HEAD 里 {total['in_head']} 项"
    )
    summary.append("- 顺序永远一样：**先轮换凭据 → 再重写历史 → 最后强推**（历史重写收不回已泄露的钥匙）")
    index = out_dir / "index.md"
    index.write_text("\n".join(summary), encoding="utf-8")

    print("\n".join(summary))
    print(f"\n报告目录：{out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
