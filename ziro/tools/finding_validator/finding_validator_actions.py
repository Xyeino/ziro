"""Finding validator pass — systematic PoC re-execution and verdict scoring.

After all exploitation agents finish, this module re-runs each vulnerability's
PoC from scratch and produces a pass/fail verdict per finding. Findings that
fail validation are demoted to 'POTENTIAL' or removed entirely from the final
report, eliminating the false-positive tax that manual review would otherwise
pay.

This complements the existing POC Validation Protocol in the prompt (which
tells individual agents to validate their work) — the tool module here
formalizes it as a separate dedicated pass with its own evidence trail.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from typing import Any, Literal

from ziro.tools.registry import register_tool


VerdictLevel = Literal[
    "CONFIRMED",
    "POTENTIAL",
    "UNREPRODUCED",
    "FALSE_POSITIVE",
    "INCONCLUSIVE",
]


def _load_vulnerabilities() -> list[dict[str, Any]]:
    """Read all vulnerabilities currently tracked by the active tracer."""
    try:
        from ziro.telemetry.tracer import get_global_tracer
    except Exception:
        return []

    tracer = get_global_tracer()
    if tracer is None:
        return []

    getter = getattr(tracer, "get_existing_vulnerabilities", None)
    if callable(getter):
        try:
            result = getter()
            if isinstance(result, list):
                return result
        except Exception:
            pass
    return []


def _score_evidence(
    poc_output: str,
    expected_markers: list[str],
    success_indicators: list[str],
    error_indicators: list[str],
    response_status: int | None,
) -> tuple[VerdictLevel, float, list[str]]:
    """Heuristic scoring of PoC re-execution output.

    Order of checks (first match wins):
    1. Expected marker strings appear in output → CONFIRMED
    2. Success indicators (e.g., 'root:x:', 'alert(1)', server delay > 5s) → CONFIRMED
    3. Error indicators AND no success signals → UNREPRODUCED or FALSE_POSITIVE
    4. Response 2xx with interesting length but no markers → POTENTIAL
    5. Fallthrough → INCONCLUSIVE
    """
    output_lower = poc_output.lower()
    reasons: list[str] = []
    confirmed_hits = 0

    for marker in expected_markers:
        if marker.lower() in output_lower:
            confirmed_hits += 1
            reasons.append(f"expected marker present: {marker[:50]}")

    success_hits = 0
    for indicator in success_indicators:
        if indicator.lower() in output_lower:
            success_hits += 1
            reasons.append(f"success indicator: {indicator[:50]}")

    error_hits = 0
    for indicator in error_indicators:
        if indicator.lower() in output_lower:
            error_hits += 1
            reasons.append(f"error indicator: {indicator[:50]}")

    if confirmed_hits >= 1 and error_hits == 0:
        return "CONFIRMED", 0.95, reasons
    if confirmed_hits >= 1 and success_hits > error_hits:
        return "CONFIRMED", 0.80, reasons
    if success_hits >= 2 and error_hits == 0:
        return "CONFIRMED", 0.75, reasons
    if error_hits >= 2 and success_hits == 0:
        return "FALSE_POSITIVE", 0.80, reasons
    if error_hits >= 1 and success_hits == 0:
        return "UNREPRODUCED", 0.70, reasons
    if response_status and 200 <= response_status < 300 and len(poc_output) > 200:
        return "POTENTIAL", 0.50, reasons + [f"2xx response with body but no markers"]
    return "INCONCLUSIVE", 0.30, reasons + ["no clear signal"]


@register_tool(sandbox_execution=True)
def validate_single_finding(
    agent_state: Any,
    finding_id: str = "",
    title: str = "",
    poc_command: str = "",
    expected_markers: list[str] | None = None,
    success_indicators: list[str] | None = None,
    error_indicators: list[str] | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Re-execute a single finding's PoC and score the output for a verdict.

    Runs poc_command in the sandbox and matches the output against three
    marker lists:

    - expected_markers: specific strings the exploit MUST produce for it to
      be considered confirmed (e.g., "root:x:0:0" for LFI to /etc/passwd,
      a unique random token for an XSS echo, "sleep(5)" timing response)
    - success_indicators: generic signals that suggest success (response
      bodies, shell prompts, SQL output columns)
    - error_indicators: signals that suggest the exploit failed (404, 403,
      WAF block page, "invalid input", stack traces indicating bad payload)

    Returns a verdict: CONFIRMED / POTENTIAL / UNREPRODUCED / FALSE_POSITIVE
    / INCONCLUSIVE, a confidence score, the raw output, and the reasons
    that contributed to the verdict.
    """
    try:
        expected_markers = expected_markers or []
        success_indicators = success_indicators or [
            "200 ok",
            "root:x:",
            "system",
            "administrator",
            "success",
            "privilege",
            "shell",
            "bash-",
        ]
        error_indicators = error_indicators or [
            "403 forbidden",
            "401 unauthorized",
            "404 not found",
            "waf block",
            "blocked",
            "access denied",
            "invalid input",
            "sorry, this page",
        ]

        if not poc_command:
            return {"success": False, "error": "poc_command is required"}

        start = time.time()
        try:
            result = subprocess.run(
                poc_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            duration = time.time() - start
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            combined = stdout + "\n" + stderr
            rc = result.returncode
        except subprocess.TimeoutExpired as e:
            duration = time.time() - start
            stdout = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
            stderr = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
            combined = stdout + "\n" + stderr + "\n[TIMEOUT]"
            rc = 124

        # Try to extract HTTP status from curl output
        status_match = re.search(r"HTTP/[\d.]+\s+(\d{3})", combined)
        response_status = int(status_match.group(1)) if status_match else None

        verdict, confidence, reasons = _score_evidence(
            combined,
            expected_markers,
            success_indicators,
            error_indicators,
            response_status,
        )

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"validate_single_finding failed: {e!s}"}
    else:
        return {
            "success": True,
            "finding_id": finding_id,
            "title": title,
            "verdict": verdict,
            "confidence": confidence,
            "reasons": reasons,
            "exit_code": rc,
            "duration_sec": round(duration, 2),
            "response_status": response_status,
            "output_preview": combined[:4000],
            "output_truncated": len(combined) > 4000,
            "poc_command": poc_command,
        }


@register_tool(sandbox_execution=False)
def list_findings_for_validation(
    agent_state: Any,
    severity_filter: str = "",
) -> dict[str, Any]:
    """List all currently-tracked vulnerabilities for the validator pass to process.

    Returns a compact summary suitable for iterating through — one row per
    finding with id, title, severity, and the poc_script_code field (if present)
    that the validator can re-execute.

    severity_filter: comma-separated list to filter by (e.g., "CRITICAL,HIGH").
    """
    try:
        vulns = _load_vulnerabilities()
        if not vulns:
            return {
                "success": True,
                "total": 0,
                "findings": [],
                "note": "No findings tracked yet — run exploitation agents first",
            }

        sev_filter = {s.strip().upper() for s in severity_filter.split(",") if s.strip()}

        rows: list[dict[str, Any]] = []
        for v in vulns:
            if not isinstance(v, dict):
                continue
            severity = (v.get("severity") or "UNKNOWN").upper()
            if sev_filter and severity not in sev_filter:
                continue
            rows.append(
                {
                    "id": v.get("id") or v.get("report_id") or "",
                    "title": (v.get("title") or "")[:140],
                    "severity": severity,
                    "endpoint": v.get("endpoint") or "",
                    "method": v.get("method") or "",
                    "has_poc": bool(v.get("poc_script_code")),
                    "poc_preview": (v.get("poc_script_code") or "")[:500],
                    "target": v.get("target") or "",
                }
            )

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"list_findings_for_validation failed: {e!s}"}
    else:
        return {
            "success": True,
            "total": len(rows),
            "findings": rows,
        }


@register_tool(sandbox_execution=False)
def record_validation_verdict(
    agent_state: Any,
    finding_id: str,
    verdict: str,
    confidence: float,
    reasons: list[str] | None = None,
    evidence: str = "",
) -> dict[str, Any]:
    """Persist a validation verdict against a finding in the tracer.

    Should be called after validate_single_finding completes. The verdict
    and evidence are attached to the existing vulnerability record so the
    final report can show the validation status next to each finding.

    Verdicts: CONFIRMED, POTENTIAL, UNREPRODUCED, FALSE_POSITIVE, INCONCLUSIVE

    FALSE_POSITIVE findings should be dropped from the final report by the
    reporting agent. POTENTIAL and UNREPRODUCED findings should be included
    but clearly marked with their status so the client can see that the
    validator flagged uncertainty.
    """
    try:
        reasons = reasons or []
        valid_verdicts = {
            "CONFIRMED",
            "POTENTIAL",
            "UNREPRODUCED",
            "FALSE_POSITIVE",
            "INCONCLUSIVE",
        }
        verdict_upper = verdict.upper()
        if verdict_upper not in valid_verdicts:
            return {
                "success": False,
                "error": f"Invalid verdict '{verdict}'. Must be one of {sorted(valid_verdicts)}",
            }

        from ziro.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return {"success": False, "error": "No active tracer"}

        # Try multiple setter shapes for tracer compatibility
        setter = getattr(tracer, "record_validation_verdict", None)
        if callable(setter):
            try:
                setter(finding_id=finding_id, verdict=verdict_upper, confidence=confidence, reasons=reasons, evidence=evidence)
                return {"success": True, "finding_id": finding_id, "verdict": verdict_upper, "persisted": True}
            except Exception:
                pass

        # Fallback: write to a workspace file as an audit trail
        audit_dir = "/workspace/validation"
        os.makedirs(audit_dir, exist_ok=True)
        audit_path = os.path.join(audit_dir, "verdicts.jsonl")
        with open(audit_path, "a", encoding="utf-8") as f:
            f.write(
                json.dumps(
                    {
                        "finding_id": finding_id,
                        "verdict": verdict_upper,
                        "confidence": confidence,
                        "reasons": reasons,
                        "evidence_preview": evidence[:2000],
                        "recorded_at": time.time(),
                    }
                )
                + "\n"
            )

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"record_validation_verdict failed: {e!s}"}
    else:
        return {
            "success": True,
            "finding_id": finding_id,
            "verdict": verdict_upper,
            "persisted": False,
            "audit_file": audit_path,
            "note": "Tracer did not accept the verdict setter — wrote to workspace audit file instead",
        }
