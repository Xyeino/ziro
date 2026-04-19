"""Quality + cost metrics — cost per finding, FP rate, scan efficiency."""

from __future__ import annotations

from typing import Any

from ziro.tools.registry import register_tool


@register_tool(sandbox_execution=False)
def compute_scan_metrics(agent_state: Any) -> dict[str, Any]:
    """Compute quality and cost metrics for the current scan.

    Returns:
    - total_findings, by_severity, by_status (confirmed/potential/fp/unreproduced)
    - total_llm_tokens (input + output), total_cost_usd
    - cost_per_confirmed_finding
    - fp_rate (false_positive / (confirmed + false_positive))
    - mean_iterations_per_agent
    - time_elapsed_seconds
    """
    findings_by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "UNKNOWN": 0}
    findings_by_status = {"confirmed": 0, "potential": 0, "unreproduced": 0, "false_positive": 0, "inconclusive": 0, "unconfirmed": 0}
    total_input_tokens = 0
    total_output_tokens = 0
    total_cost = 0.0
    total_iterations = 0
    agent_count = 0
    earliest_start: float | None = None

    # Engagement findings
    try:
        from ziro.engagement import get_engagement_state

        state = get_engagement_state()
        for f in state.findings.values():
            sev = (f.severity or "UNKNOWN").upper()
            findings_by_sev[sev] = findings_by_sev.get(sev, 0) + 1
            status = (f.status or "unconfirmed").lower()
            findings_by_status[status] = findings_by_status.get(status, 0) + 1
    except Exception:  # noqa: BLE001
        pass

    # Validator verdicts override
    try:
        import json as _json
        import os as _os

        verdict_path = "/workspace/validation/verdicts.jsonl"
        if _os.path.isfile(verdict_path):
            with open(verdict_path, encoding="utf-8") as f:
                for line in f:
                    try:
                        entry = _json.loads(line)
                        v = (entry.get("verdict") or "").lower()
                        if v == "false_positive":
                            findings_by_status["false_positive"] = findings_by_status.get("false_positive", 0) + 1
                    except Exception:  # noqa: BLE001
                        continue
    except Exception:  # noqa: BLE001
        pass

    # LLM cost + iterations
    try:
        from ziro.tools.agents_graph.agents_graph_actions import _agent_instances, _agent_states

        for aid, inst in _agent_instances.items():
            agent_count += 1
            if hasattr(inst, "llm") and hasattr(inst.llm, "_total_stats"):
                s = inst.llm._total_stats
                total_input_tokens += getattr(s, "input_tokens", 0) or 0
                total_output_tokens += getattr(s, "output_tokens", 0) or 0
                total_cost += getattr(s, "cost", 0.0) or 0.0

            state = _agent_states.get(aid)
            if state:
                total_iterations += getattr(state, "iteration", 0) or 0
                try:
                    from datetime import datetime

                    start_iso = getattr(state, "start_time", "")
                    if start_iso:
                        ts = datetime.fromisoformat(start_iso).timestamp()
                        if earliest_start is None or ts < earliest_start:
                            earliest_start = ts
                except Exception:  # noqa: BLE001
                    pass
    except Exception:  # noqa: BLE001
        pass

    total_findings = sum(findings_by_sev.values())
    confirmed = findings_by_status.get("confirmed", 0)
    fp = findings_by_status.get("false_positive", 0)

    fp_rate = 0.0
    if (confirmed + fp) > 0:
        fp_rate = fp / (confirmed + fp)

    cost_per_confirmed = 0.0
    if confirmed > 0:
        cost_per_confirmed = round(total_cost / confirmed, 4)

    time_elapsed = 0.0
    if earliest_start:
        import time as _time

        time_elapsed = round(_time.time() - earliest_start, 1)

    return {
        "success": True,
        "total_findings": total_findings,
        "by_severity": findings_by_sev,
        "by_status": findings_by_status,
        "cost": {
            "total_usd": round(total_cost, 4),
            "input_tokens": total_input_tokens,
            "output_tokens": total_output_tokens,
            "cost_per_confirmed_finding_usd": cost_per_confirmed,
        },
        "quality": {
            "confirmed": confirmed,
            "false_positive": fp,
            "fp_rate": round(fp_rate, 3),
        },
        "performance": {
            "agent_count": agent_count,
            "total_iterations": total_iterations,
            "mean_iterations_per_agent": (
                round(total_iterations / agent_count, 1) if agent_count else 0.0
            ),
            "time_elapsed_seconds": time_elapsed,
        },
    }
