"""Playbook tools — list / load structured attack playbooks."""

from __future__ import annotations

from typing import Any

from ziro.tools.registry import register_tool


@register_tool(sandbox_execution=False)
def list_available_playbooks(agent_state: Any) -> dict[str, Any]:
    """List all attack playbooks shipped with Ziro.

    Playbooks are structured YAML files defining phases, objectives, techniques,
    and sub-agent skill assignments for specific target types (web app, TMA,
    smart contract, AD, mobile, etc.). Use load_playbook to inject one into the
    current agent's context.
    """
    from ziro.playbooks import list_playbooks

    return {"success": True, "playbooks": list_playbooks()}


@register_tool(sandbox_execution=False)
def load_playbook(agent_state: Any, name: str) -> dict[str, Any]:
    """Load a playbook's full structure into the tool result.

    Returns the playbook as an XML block the agent can reference. Follow the
    phases in order; use sub_agents definitions to seed create_agent calls
    with the right skill bundle.
    """
    from ziro.playbooks import get_playbook

    pb = get_playbook(name)
    if not pb:
        from ziro.playbooks import list_playbooks

        return {
            "success": False,
            "error": f"Unknown playbook {name!r}",
            "available": [p["name"] for p in list_playbooks()],
        }

    return {
        "success": True,
        "playbook": pb.name,
        "description": pb.description,
        "target_types": pb.target_types,
        "phase_count": len(pb.phases),
        "xml_block": pb.to_prompt_block(),
        "phases": [
            {
                "name": p.name,
                "objective": p.objective,
                "timeout_minutes": p.timeout_minutes,
                "parallel": p.parallel,
                "technique_count": len(p.techniques),
                "sub_agent_count": len(p.sub_agents),
            }
            for p in pb.phases
        ],
    }
