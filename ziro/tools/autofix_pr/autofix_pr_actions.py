"""One-click autofix PRs — commit remediation patches to a new branch and open a PR via `gh` CLI."""

from __future__ import annotations

import os
import shlex
import subprocess
import time
from typing import Any

from ziro.tools.registry import register_tool


def _run(cmd: str, cwd: str, timeout: int = 60) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=cwd,
        )
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


@register_tool(sandbox_execution=True)
def create_autofix_pr(
    agent_state: Any,
    repo_path: str,
    findings: list[dict[str, Any]],
    branch_name: str = "",
    pr_title: str = "",
    pr_body: str = "",
    base_branch: str = "",
    push: bool = True,
) -> dict[str, Any]:
    """Create a git branch with remediation commits and open a PR via `gh` CLI.

    findings: list of dicts with keys {finding_id, title, severity, patch_diff}.
    Each patch_diff is a unified diff applied via `git apply`. Commits are
    grouped by severity (one commit per finding).

    Requires gh CLI authenticated against the repo's remote. Returns PR URL.
    """
    if not os.path.isabs(repo_path):
        repo_path = os.path.join("/workspace", repo_path)
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        return {"success": False, "error": f"Not a git repository: {repo_path}"}

    # Determine base branch
    if not base_branch:
        rc, out, _ = _run("git symbolic-ref refs/remotes/origin/HEAD", repo_path)
        if rc == 0:
            base_branch = out.strip().split("/")[-1]
        else:
            base_branch = "main"

    branch_name = branch_name or f"ziro/autofix-{int(time.time())}"
    pr_title = pr_title or f"Ziro security fixes ({len(findings)} findings)"

    # Create branch
    rc, out, err = _run(f"git checkout -b {shlex.quote(branch_name)}", repo_path)
    if rc != 0:
        return {"success": False, "error": f"Failed to create branch: {err}"}

    commits_created = 0
    commit_log: list[dict[str, Any]] = []

    for f in findings:
        patch = f.get("patch_diff", "") or ""
        if not patch.strip():
            continue

        # Write patch to a temp file and apply
        patch_file = f"/tmp/ziro_autofix_{f.get('finding_id', int(time.time()*1000))}.patch"
        try:
            with open(patch_file, "w", encoding="utf-8") as fh:
                fh.write(patch if patch.endswith("\n") else patch + "\n")
            rc, out, err = _run(f"git apply {shlex.quote(patch_file)}", repo_path)
            if rc != 0:
                # Try --3way
                rc, out, err = _run(f"git apply --3way {shlex.quote(patch_file)}", repo_path)
                if rc != 0:
                    commit_log.append({
                        "finding_id": f.get("finding_id", ""),
                        "status": "patch_failed",
                        "error": err[:300],
                    })
                    continue

            sev = (f.get("severity") or "MEDIUM").upper()
            title = f.get("title", "untitled")[:60]
            rc, out, err = _run("git add -u", repo_path)
            msg = f"fix({sev.lower()}): {title}\n\nFinding: {f.get('finding_id', '')}\nAutomated remediation by Ziro."
            rc, out, err = subprocess.run(
                ["git", "commit", "-m", msg],
                capture_output=True, text=True, check=False, cwd=repo_path,
            ).returncode, "", ""
            if rc == 0:
                commits_created += 1
                commit_log.append({"finding_id": f.get("finding_id", ""), "status": "committed"})
            else:
                commit_log.append({
                    "finding_id": f.get("finding_id", ""),
                    "status": "commit_failed",
                })
        finally:
            if os.path.exists(patch_file):
                try:
                    os.unlink(patch_file)
                except Exception:
                    pass

    if commits_created == 0:
        return {
            "success": False,
            "error": "No patches applied cleanly",
            "branch": branch_name,
            "attempted": len(findings),
            "log": commit_log,
        }

    if not push:
        return {
            "success": True,
            "branch": branch_name,
            "commits": commits_created,
            "pushed": False,
            "log": commit_log,
        }

    # Push
    rc, out, err = _run(f"git push -u origin {shlex.quote(branch_name)}", repo_path)
    if rc != 0:
        return {
            "success": False,
            "error": f"git push failed: {err[:500]}",
            "branch": branch_name,
            "commits": commits_created,
        }

    # Build PR body
    if not pr_body:
        lines = [
            "## Security fixes from Ziro",
            "",
            f"This PR addresses {commits_created} finding(s) discovered during an automated scan.",
            "",
            "| Severity | Finding | Status |",
            "| --- | --- | --- |",
        ]
        for f in findings:
            lines.append(
                f"| {(f.get('severity') or 'MEDIUM').upper()} | {f.get('title', 'untitled')[:80]} | auto-patched |"
            )
        lines += [
            "",
            "### Review checklist",
            "- [ ] Each commit addresses one finding",
            "- [ ] Patches don't introduce regressions",
            "- [ ] Tests still pass",
            "",
            "Generated by [Ziro](https://github.com/Xyeino/ziro).",
        ]
        pr_body = "\n".join(lines)

    # Open PR via gh CLI
    body_file = f"/tmp/ziro_pr_body_{int(time.time())}.md"
    try:
        with open(body_file, "w", encoding="utf-8") as fh:
            fh.write(pr_body)
        pr_cmd = (
            f"gh pr create --title {shlex.quote(pr_title)} "
            f"--body-file {shlex.quote(body_file)} "
            f"--base {shlex.quote(base_branch)} "
            f"--head {shlex.quote(branch_name)}"
        )
        rc, out, err = _run(pr_cmd, repo_path, timeout=120)
    finally:
        try:
            os.unlink(body_file)
        except Exception:
            pass

    if rc != 0:
        return {
            "success": False,
            "error": f"gh pr create failed: {err[:500]}",
            "branch": branch_name,
            "commits": commits_created,
        }

    pr_url = out.strip().splitlines()[-1] if out.strip() else ""

    return {
        "success": True,
        "branch": branch_name,
        "base": base_branch,
        "commits": commits_created,
        "pushed": True,
        "pr_url": pr_url,
        "log": commit_log,
    }
