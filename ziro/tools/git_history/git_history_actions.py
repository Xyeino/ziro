"""Git history secret scanning via gitleaks wrapper."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from typing import Any

from ziro.tools.registry import register_tool


def _run(cmd: str, timeout: int = 180) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return r.returncode, r.stdout or "", r.stderr or ""
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return 127, "", str(e)


@register_tool(sandbox_execution=True)
def scan_git_history(
    agent_state: Any,
    repo_path: str,
    max_findings: int = 100,
    timeout: int = 300,
) -> dict[str, Any]:
    """Scan a git repository's full history (all commits, all branches) for secrets.

    Wraps `gitleaks detect --no-git=false` which walks every commit in every
    branch and the reflog. Catches secrets that were added and later removed
    — common mistake that regular code scan misses because the file no
    longer contains the secret in the working tree.

    Requires gitleaks installed in the sandbox. Returns findings with commit
    hash, file path, rule name, secret preview, and author.
    """
    if not os.path.isabs(repo_path):
        repo_path = os.path.join("/workspace", repo_path)
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        return {"success": False, "error": f"Not a git repo: {repo_path}"}

    out_file = f"/tmp/gitleaks-{abs(hash(repo_path)) % 100000}.json"
    cmd = (
        f"gitleaks detect "
        f"--source {shlex.quote(repo_path)} "
        f"--report-format json "
        f"--report-path {shlex.quote(out_file)} "
        f"--no-banner --exit-code 0"
    )
    rc, stdout, stderr = _run(cmd, timeout=timeout)
    if rc == 127:
        return {"success": False, "error": "gitleaks not installed"}

    try:
        with open(out_file, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:  # noqa: BLE001
        return {
            "success": False,
            "error": f"Could not parse gitleaks output: {e}",
            "stdout": stdout[:1000],
            "stderr": stderr[:1000],
        }

    findings: list[dict[str, Any]] = []
    if isinstance(data, list):
        for item in data[:max_findings]:
            if not isinstance(item, dict):
                continue
            findings.append(
                {
                    "rule": item.get("RuleID", ""),
                    "description": item.get("Description", ""),
                    "file": item.get("File", ""),
                    "commit": item.get("Commit", ""),
                    "author": item.get("Author", ""),
                    "email": item.get("Email", ""),
                    "date": item.get("Date", ""),
                    "secret_preview": (item.get("Secret") or "")[:60],
                    "line": item.get("StartLine", 0),
                }
            )

    # Cleanup
    try:
        os.remove(out_file)
    except OSError:
        pass

    return {
        "success": True,
        "repo": repo_path,
        "findings_count": len(findings),
        "findings": findings,
    }
