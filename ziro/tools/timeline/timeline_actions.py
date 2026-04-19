"""Timeline / Gantt view of agent activity for panel visualization."""

from __future__ import annotations

from typing import Any

from ziro.tools.registry import register_tool


@register_tool(sandbox_execution=False)
def get_session_timeline(
    agent_state: Any,
    max_events: int = 500,
) -> dict[str, Any]:
    """Return per-agent activity timeline for Gantt-chart rendering.

    Pulls from tracer tool execution log + agent lifecycle events. Each row
    has start/end timestamps, agent_name, event_type (tool_exec / message /
    status_change), and details for hover tooltip.

    Panel frontend uses this to render Gantt chart with concurrent rows per
    agent, color-coded by event type.
    """
    events: list[dict[str, Any]] = []
    agents_seen: set[str] = set()

    try:
        from ziro.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if not tracer:
            return {"success": True, "events": [], "agents": []}

        # Pull tool executions from tracer
        try:
            execs = getattr(tracer, "tool_executions", None) or []
            if callable(execs):
                execs = execs()
            for ex in list(execs)[:max_events]:
                if not isinstance(ex, dict):
                    continue
                agent_id = ex.get("agent_id", "")
                agents_seen.add(agent_id)
                events.append({
                    "agent_id": agent_id,
                    "type": "tool_exec",
                    "tool_name": ex.get("tool_name", ""),
                    "status": ex.get("status", ""),
                    "start_ts": ex.get("started_at") or ex.get("start_time"),
                    "end_ts": ex.get("ended_at") or ex.get("end_time"),
                    "duration_ms": ex.get("duration_ms"),
                    "preview": str(ex.get("args", {}))[:100],
                })
        except Exception:
            pass

        # Pull agent status transitions from graph nodes
        try:
            from ziro.tools.agents_graph.agents_graph_actions import _agent_graph

            for aid, node in _agent_graph.get("nodes", {}).items():
                agents_seen.add(aid)
                events.append({
                    "agent_id": aid,
                    "type": "status",
                    "status": node.get("status", ""),
                    "name": node.get("name", ""),
                    "start_ts": node.get("created_at"),
                    "end_ts": node.get("finished_at"),
                })
        except Exception:
            pass
    except Exception:
        pass

    # Sort by start timestamp
    def _ts_key(e: dict[str, Any]) -> float:
        ts = e.get("start_ts")
        if ts is None:
            return 0.0
        if isinstance(ts, (int, float)):
            return float(ts)
        try:
            from datetime import datetime

            return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
        except Exception:
            return 0.0

    events.sort(key=_ts_key)

    return {
        "success": True,
        "event_count": len(events),
        "agents": sorted(agents_seen),
        "events": events[-max_events:],
    }
