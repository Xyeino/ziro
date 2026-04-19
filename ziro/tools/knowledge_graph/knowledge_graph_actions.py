"""Knowledge graph mutation tools for agents."""

from __future__ import annotations

from typing import Any

from ziro.knowledge_graph import get_knowledge_graph
from ziro.tools.registry import register_tool


@register_tool(sandbox_execution=False)
def kg_add_node(
    agent_state: Any,
    node_id: str,
    kind: str,
    label: str = "",
    attrs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Add a node to the knowledge graph.

    kind: host / service / credential / finding / session / user / token / path
    """
    get_knowledge_graph().add_node(node_id, kind, label=label, **(attrs or {}))
    return {"success": True, "node_id": node_id}


@register_tool(sandbox_execution=False)
def kg_add_edge(
    agent_state: Any,
    source: str,
    target: str,
    kind: str,
    weight: float = 1.0,
    attrs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Add a directed edge to the knowledge graph.

    Standard edge kinds: hosts_service, runs_on, accessible_from, leaks,
    pivots_to, authenticates_with, grants_access, exploits, chains_to,
    owned_by, child_of, maps_to_cve.

    Use weight <1.0 for high-confidence/easy-exploit edges, >1.0 for
    difficult ones — shortest_path/attack_paths_to respect this.
    """
    get_knowledge_graph().add_edge(source, target, kind, weight=weight, **(attrs or {}))
    return {"success": True, "edge": f"{source} -[{kind}]-> {target}"}


@register_tool(sandbox_execution=False)
def kg_find_attack_paths(
    agent_state: Any,
    target_node: str,
    max_paths: int = 5,
    max_length: int = 8,
) -> dict[str, Any]:
    """Discover multi-hop attack paths ending at target_node.

    Ordered by total edge weight (cheapest first). Use to answer 'what
    chain of weaknesses leads to full compromise of target?' or 'which
    credential leak enables access to this resource?'.
    """
    kg = get_knowledge_graph()
    paths = kg.attack_paths_to(target_node, max_paths=max_paths, max_length=max_length)
    return {
        "success": True,
        "target": target_node,
        "paths_found": len(paths),
        "paths": paths,
    }


@register_tool(sandbox_execution=False)
def kg_shortest_path(
    agent_state: Any,
    source: str,
    target: str,
) -> dict[str, Any]:
    """Find shortest path between two nodes by edge weight."""
    kg = get_knowledge_graph()
    path = kg.shortest_path(source, target)
    if path is None:
        return {"success": True, "reachable": False, "path": None}
    return {
        "success": True,
        "reachable": True,
        "path": path,
        "length": len(path) - 1,
    }


@register_tool(sandbox_execution=False)
def kg_summary(agent_state: Any) -> dict[str, Any]:
    """Return graph statistics + a mermaid diagram for visualization."""
    kg = get_knowledge_graph()
    summary = kg.summary()
    summary["mermaid"] = kg.to_mermaid()
    return {"success": True, **summary}
