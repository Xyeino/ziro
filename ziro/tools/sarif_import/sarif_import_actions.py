"""Import SARIF from external SAST tools and feed into engagement state + validator queue."""

from __future__ import annotations

import json
import os
from typing import Any

from ziro.tools.registry import register_tool


@register_tool(sandbox_execution=False)
def import_sarif(
    agent_state: Any,
    sarif_path: str,
    only_severities: list[str] | None = None,
    max_findings: int = 200,
) -> dict[str, Any]:
    """Parse a SARIF 2.1 file (Semgrep / CodeQL / Bandit / Snyk / Checkmarx export)
    and register each finding into the engagement state as unconfirmed.

    Use at scan start for white-box engagements where the client provided their
    existing SAST output. Ziro's dynamic agents then pick up each unconfirmed
    finding and attempt to exploit it against the running app (static-dynamic
    correlation).
    """
    if not os.path.isabs(sarif_path):
        sarif_path = os.path.join("/workspace", sarif_path)
    if not os.path.isfile(sarif_path):
        return {"success": False, "error": f"SARIF file not found: {sarif_path}"}

    try:
        with open(sarif_path, encoding="utf-8") as f:
            doc = json.load(f)
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to parse SARIF JSON: {e!s}"}

    sev_filter = {s.strip().upper() for s in (only_severities or [])}
    findings_imported: list[dict[str, Any]] = []

    from ziro.engagement import get_engagement_state

    state = get_engagement_state()

    for run in doc.get("runs", []):
        tool_name = ((run.get("tool") or {}).get("driver") or {}).get("name", "unknown")
        rules_list = ((run.get("tool") or {}).get("driver") or {}).get("rules", []) or []
        rule_by_id = {r.get("id", ""): r for r in rules_list if isinstance(r, dict)}

        for result in run.get("results", []):
            if len(findings_imported) >= max_findings:
                break

            rule_id = result.get("ruleId", "")
            rule = rule_by_id.get(rule_id, {})
            level = (result.get("level") or rule.get("defaultConfiguration", {}).get("level") or "note").upper()

            # Map SARIF level to our severity
            severity_map = {
                "ERROR": "HIGH",
                "WARNING": "MEDIUM",
                "NOTE": "LOW",
                "NONE": "INFO",
            }
            severity = severity_map.get(level, "MEDIUM")

            if sev_filter and severity not in sev_filter:
                continue

            message = (result.get("message") or {}).get("text", "") or rule.get("shortDescription", {}).get("text", "")

            # Extract first location
            endpoint = ""
            locations = result.get("locations", [])
            if locations:
                phys = locations[0].get("physicalLocation", {}) or {}
                artifact = (phys.get("artifactLocation") or {}).get("uri", "")
                region = phys.get("region", {}) or {}
                line = region.get("startLine", 0)
                endpoint = f"{artifact}:{line}" if artifact else ""

            finding_id = f"sarif_{tool_name}_{rule_id}_{len(findings_imported)}"
            state.add_finding(
                id=finding_id,
                title=f"[{tool_name}] {rule_id}: {message[:150]}",
                severity=severity,
                vuln_type=rule_id.lower().replace(" ", "_"),
                endpoint=endpoint,
                status="unconfirmed",
                confidence=0.4,  # SAST alone — confidence boosted when dynamic validates
            )
            findings_imported.append(
                {
                    "id": finding_id,
                    "rule_id": rule_id,
                    "severity": severity,
                    "location": endpoint,
                    "tool": tool_name,
                }
            )

    return {
        "success": True,
        "sarif_file": sarif_path,
        "imported_count": len(findings_imported),
        "imported": findings_imported[:50],
        "note": (
            "Findings registered as UNCONFIRMED with confidence 0.4. Dynamic "
            "agents should now attempt to exploit each one against the running "
            "app to promote to CONFIRMED, or mark FALSE_POSITIVE if unreachable."
        ),
    }
