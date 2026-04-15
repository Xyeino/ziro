from typing import Any

from ziro.tools.registry import get_tool_names, get_tool_xml_schema, register_tool


@register_tool(sandbox_execution=False)
def read_tool_doc(agent_state: Any, tool_name: str) -> dict[str, Any]:
    """Read the full schema (with examples and details) for a single tool.

    The system prompt's tools_prompt is rendered in compact mode by default —
    examples and details are stripped to save ~14K tokens per LLM call. When
    you need the full reference for a specific tool (worked examples, edge
    cases, parameter details), call this tool with its name and the full
    schema is returned in the result.

    This is a one-off lookup — the full schema is NOT added to your permanent
    context. If you call read_tool_doc, look at the result, and then need it
    again later, call read_tool_doc again rather than relying on memory.
    """
    try:
        name = (tool_name or "").strip()
        if not name:
            return {"success": False, "error": "tool_name is required"}

        schema = get_tool_xml_schema(name)
        if schema is None:
            return {
                "success": False,
                "error": f"Unknown tool '{name}'",
                "available_tools": sorted(get_tool_names())[:80],
            }

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to read tool doc: {e!s}"}
    else:
        return {
            "success": True,
            "tool_name": name,
            "schema": schema,
            "note": (
                "Full schema with examples and details — NOT persisted to your "
                "system prompt. Call read_tool_doc again if you need to re-reference."
            ),
        }
