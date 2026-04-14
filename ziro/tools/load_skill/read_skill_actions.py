from typing import Any

from ziro.tools.registry import register_tool


@register_tool(sandbox_execution=False)
def read_skill(agent_state: Any, skill: str) -> dict[str, Any]:
    """Read the full content of a single skill WITHOUT adding it to the agent's permanent context.

    Use this when you need one-off reference for a specific technique or payload list,
    but don't want to pay the recurring context cost of load_skill. The skill body is
    returned in the tool result for the current turn only — it will NOT be present in
    future turns unless you reload it.

    For specialist agents that will reference the skill repeatedly across many iterations,
    use load_skill instead to bake it into the system prompt.
    """
    try:
        from ziro.skills import get_skill_metadata, load_skill_body

        skill_name = (skill or "").strip()
        if not skill_name:
            return {
                "success": False,
                "error": "No skill name provided",
            }

        meta = get_skill_metadata(skill_name)
        if meta is None:
            from ziro.skills import get_all_skill_names

            available = sorted(get_all_skill_names())
            return {
                "success": False,
                "error": f"Unknown skill '{skill_name}'",
                "available_skills": available[:50],
            }

        body = load_skill_body(skill_name)
        if body is None:
            return {
                "success": False,
                "error": f"Skill '{skill_name}' exists in the index but its body could not be loaded",
            }

    except Exception as e:  # noqa: BLE001
        return {
            "success": False,
            "error": f"Failed to read skill: {e!s}",
        }
    else:
        return {
            "success": True,
            "skill": skill_name,
            "category": meta.category,
            "description": meta.description,
            "mitre_techniques": meta.mitre_techniques,
            "kill_chain_phases": meta.kill_chain_phases,
            "related_skills": meta.related_skills,
            "body": body,
            "note": (
                "This skill was read once — it is NOT loaded into your permanent context. "
                "If you will reference it across multiple iterations, call load_skill instead."
            ),
        }
