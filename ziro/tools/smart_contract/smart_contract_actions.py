"""Smart contract security tooling — Echidna fuzzing, Halmos symbolic, Slither, Mythril."""

from __future__ import annotations

import os
import shlex
import subprocess
from typing import Any, Literal

from ziro.tools.registry import register_tool


def _run(cmd: str, timeout: int = 300, cwd: str = "/workspace") -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=cwd if os.path.isdir(cwd) else None,
        )
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"
    except FileNotFoundError as e:
        return 127, "", f"binary not found: {e}"
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


@register_tool(sandbox_execution=True)
def run_slither(
    agent_state: Any,
    target_path: str,
    severity_filter: str = "high,medium",
    timeout: int = 180,
) -> dict[str, Any]:
    """Run Slither static analyzer on a Solidity file or project.

    severity_filter: 'high', 'high,medium', 'all'. Returns findings in
    structured form with detector name, description, location, severity.
    """
    if not os.path.exists(target_path):
        target_path = os.path.join("/workspace", target_path)
    if not os.path.exists(target_path):
        return {"success": False, "error": f"path not found: {target_path}"}

    filter_map = {
        "high": "--exclude-informational --exclude-low --exclude-medium",
        "high,medium": "--exclude-informational --exclude-low",
        "all": "",
    }
    filt = filter_map.get(severity_filter, filter_map["high,medium"])
    cmd = f"slither {shlex.quote(target_path)} {filt} --json -"
    rc, out, err = _run(cmd, timeout=timeout)

    if rc == 127:
        return {"success": False, "error": "slither not installed"}

    try:
        import json as _json

        data = _json.loads(out) if out.strip() else {}
        detectors = data.get("results", {}).get("detectors", []) or []
        findings = [
            {
                "check": d.get("check", ""),
                "impact": d.get("impact", ""),
                "confidence": d.get("confidence", ""),
                "description": (d.get("description") or "")[:500],
                "elements": [
                    {"name": e.get("name", ""), "type": e.get("type", "")}
                    for e in (d.get("elements") or [])[:3]
                ],
            }
            for d in detectors
        ]
    except Exception:
        findings = []

    return {
        "success": True,
        "target": target_path,
        "detector_count": len(findings),
        "findings": findings[:100],
        "stderr_preview": err[-500:],
    }


@register_tool(sandbox_execution=True)
def run_mythril(
    agent_state: Any,
    target_path: str,
    execution_timeout: int = 120,
    max_depth: int = 22,
) -> dict[str, Any]:
    """Run Mythril symbolic execution on a Solidity contract.

    Finds reentrancy, integer over/underflow, unchecked external calls, etc.
    via symbolic constraint solving. Slower than Slither but catches deeper
    bugs.
    """
    if not os.path.exists(target_path):
        target_path = os.path.join("/workspace", target_path)
    if not os.path.exists(target_path):
        return {"success": False, "error": f"path not found: {target_path}"}

    cmd = (
        f"myth analyze {shlex.quote(target_path)} "
        f"-o json --execution-timeout {execution_timeout} --max-depth {max_depth}"
    )
    rc, out, err = _run(cmd, timeout=execution_timeout + 60)
    if rc == 127:
        return {"success": False, "error": "mythril not installed"}

    try:
        import json as _json

        data = _json.loads(out) if out.strip() else {}
        issues = data.get("issues", []) or []
        findings = [
            {
                "title": i.get("title", ""),
                "severity": i.get("severity", ""),
                "swc_id": i.get("swc-id", ""),
                "function": i.get("function", ""),
                "description": (i.get("description", {}).get("head") or "")[:300],
                "filename": i.get("filename", ""),
                "lineno": i.get("lineno", 0),
            }
            for i in issues
        ]
    except Exception:
        findings = []

    return {
        "success": True,
        "target": target_path,
        "issue_count": len(findings),
        "issues": findings[:50],
    }


@register_tool(sandbox_execution=True)
def run_echidna(
    agent_state: Any,
    target_dir: str,
    contract_name: str,
    test_limit: int = 50000,
    timeout: int = 600,
) -> dict[str, Any]:
    """Run Echidna property-based fuzzer against a Solidity contract.

    Requires a contract with echidna_* property functions defined. Runs
    test_limit iterations of random input fuzzing looking for property
    violations.
    """
    if not os.path.isabs(target_dir):
        target_dir = os.path.join("/workspace", target_dir)
    if not os.path.isdir(target_dir):
        return {"success": False, "error": f"not a directory: {target_dir}"}

    cmd = (
        f"echidna-test . --contract {shlex.quote(contract_name)} "
        f"--test-limit {test_limit} --format json"
    )
    rc, out, err = _run(cmd, timeout=timeout, cwd=target_dir)
    if rc == 127:
        return {"success": False, "error": "echidna-test not installed"}

    summary = out[-4000:] if out else err[-4000:]
    return {
        "success": True,
        "target_dir": target_dir,
        "contract": contract_name,
        "test_limit": test_limit,
        "exit_code": rc,
        "output_tail": summary,
        "hint": (
            "If Echidna found a failing property, the output contains "
            "'failed!' lines with the counterexample transaction trace. "
            "Reproduce via Foundry or hardhat to build PoC."
        ),
    }


@register_tool(sandbox_execution=True)
def run_halmos(
    agent_state: Any,
    target_dir: str,
    contract_name: str = "",
    function_name: str = "",
    loop_depth: int = 3,
    timeout: int = 300,
) -> dict[str, Any]:
    """Run Halmos symbolic execution on Foundry/Solidity tests.

    Halmos symbolically executes Solidity tests, looking for counter-examples
    to invariants. Deeper than Echidna fuzzing, more targeted than Mythril.
    Requires Foundry-style test layout.
    """
    if not os.path.isabs(target_dir):
        target_dir = os.path.join("/workspace", target_dir)
    if not os.path.isdir(target_dir):
        return {"success": False, "error": f"not a directory: {target_dir}"}

    parts = ["halmos"]
    if contract_name:
        parts.append(f"--contract {shlex.quote(contract_name)}")
    if function_name:
        parts.append(f"--function {shlex.quote(function_name)}")
    parts.append(f"--loop {loop_depth}")

    rc, out, err = _run(" ".join(parts), timeout=timeout, cwd=target_dir)
    if rc == 127:
        return {"success": False, "error": "halmos not installed (pipx install halmos)"}

    return {
        "success": True,
        "target_dir": target_dir,
        "exit_code": rc,
        "output_tail": (out or err)[-3000:],
    }
