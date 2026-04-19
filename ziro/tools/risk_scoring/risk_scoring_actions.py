"""Risk scoring beyond raw CVSS — business impact, reachability, blast radius."""

from __future__ import annotations

from typing import Any, Literal

from ziro.tools.registry import register_tool


_SEVERITY_TO_CVSS = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0, "INFO": 0.5}


@register_tool(sandbox_execution=False)
def compute_risk_score(
    agent_state: Any,
    cvss_score: float,
    reachability: Literal["unauthenticated", "authenticated", "internal", "unreachable"] = "authenticated",
    data_sensitivity: Literal["none", "pii", "phi", "payment", "trade_secret", "credentials"] = "none",
    blast_radius: Literal["single_user", "single_tenant", "all_tenants", "infra"] = "single_user",
    business_criticality: Literal["low", "medium", "high", "critical"] = "medium",
    compliance_flags: list[str] | None = None,
    exploit_maturity: Literal["poc_theoretical", "working_poc", "weaponized", "in_the_wild"] = "working_poc",
) -> dict[str, Any]:
    """Compute an enriched risk score on top of raw CVSS.

    Returns a score 0-100, risk tier (CRITICAL/HIGH/MEDIUM/LOW), factor breakdown
    explaining how each input contributed, and a recommended remediation_priority
    (P0/P1/P2/P3).

    Use this for every finding before writing create_vulnerability_report —
    the enriched score tells clients 'fix this first' in a way CVSS alone cannot.
    """
    compliance_flags = compliance_flags or []

    # Base from CVSS (0-10 -> 0-35)
    base = min(cvss_score, 10.0) * 3.5

    reach_bonus = {
        "unauthenticated": 25,
        "authenticated": 12,
        "internal": 5,
        "unreachable": -10,
    }[reachability]

    data_bonus = {
        "none": 0,
        "pii": 10,
        "phi": 15,
        "payment": 15,
        "trade_secret": 12,
        "credentials": 18,
    }[data_sensitivity]

    blast_bonus = {
        "single_user": 0,
        "single_tenant": 5,
        "all_tenants": 18,
        "infra": 22,
    }[blast_radius]

    crit_bonus = {"low": 0, "medium": 3, "high": 6, "critical": 10}[business_criticality]

    exploit_bonus = {
        "poc_theoretical": -5,
        "working_poc": 0,
        "weaponized": 8,
        "in_the_wild": 15,
    }[exploit_maturity]

    compliance_bonus = len(compliance_flags) * 4  # PCI, HIPAA, SOC2 each add points

    score = base + reach_bonus + data_bonus + blast_bonus + crit_bonus + exploit_bonus + compliance_bonus
    score = max(0.0, min(100.0, score))

    if score >= 80:
        tier = "CRITICAL"
        priority = "P0"
    elif score >= 60:
        tier = "HIGH"
        priority = "P1"
    elif score >= 40:
        tier = "MEDIUM"
        priority = "P2"
    elif score >= 20:
        tier = "LOW"
        priority = "P3"
    else:
        tier = "INFO"
        priority = "P4"

    return {
        "success": True,
        "score": round(score, 1),
        "tier": tier,
        "remediation_priority": priority,
        "factors": {
            "cvss_base": round(base, 1),
            "reachability_bonus": reach_bonus,
            "data_sensitivity_bonus": data_bonus,
            "blast_radius_bonus": blast_bonus,
            "business_criticality_bonus": crit_bonus,
            "exploit_maturity_bonus": exploit_bonus,
            "compliance_bonus": compliance_bonus,
        },
        "rationale": (
            f"CVSS {cvss_score} -> base {base:.1f}; {reachability} reach (+{reach_bonus}); "
            f"{data_sensitivity} data (+{data_bonus}); {blast_radius} blast (+{blast_bonus}); "
            f"{business_criticality} criticality (+{crit_bonus}); {exploit_maturity} exploit (+{exploit_bonus})"
            + (f"; {len(compliance_flags)} compliance flags (+{compliance_bonus})" if compliance_bonus else "")
        ),
    }
