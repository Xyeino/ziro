"""Attack Graph — builds and maintains a strategic attack tree during scans.

The agent uses this to plan multi-step attack paths, track what has been
tried, and decide what to do next based on findings.
"""

import json
import logging
import threading
from datetime import UTC, datetime
from typing import Any

from ziro.tools.registry import register_tool

logger = logging.getLogger(__name__)

_graph_lock = threading.Lock()
_attack_graph: dict[str, Any] = {
    "nodes": {},  # id -> node
    "edges": [],  # (from_id, to_id, label)
}

# Node status progression
_VALID_STATUSES = {"planned", "in_progress", "success", "failed", "blocked", "skipped"}

# Node types
_VALID_TYPES = {
    "recon",           # Information gathering
    "enumerate",       # Service/user enumeration
    "vulnerability",   # Vulnerability identified
    "exploit",         # Exploit attempt
    "credential",      # Credential found
    "access",          # Access gained
    "pivot",           # Lateral movement
    "escalation",      # Privilege escalation
    "exfiltration",    # Data access proof
    "persistence",     # Maintaining access
}


@register_tool(sandbox_execution=False)
def add_attack_node(
    node_id: str,
    node_type: str,
    description: str,
    status: str = "planned",
    parent_id: str | None = None,
    target: str = "",
    technique: str = "",
    evidence: str = "",
    priority: int = 5,
) -> dict[str, Any]:
    """Add or update a node in the attack graph."""
    if not node_id or not node_id.strip():
        return {"success": False, "error": "node_id cannot be empty"}

    node_type = node_type.strip().lower()
    if node_type not in _VALID_TYPES:
        return {
            "success": False,
            "error": f"Invalid node_type: {node_type}. Must be one of: {', '.join(sorted(_VALID_TYPES))}",
        }

    status = status.strip().lower()
    if status not in _VALID_STATUSES:
        return {
            "success": False,
            "error": f"Invalid status: {status}. Must be one of: {', '.join(sorted(_VALID_STATUSES))}",
        }

    priority = max(1, min(10, priority))

    with _graph_lock:
        is_update = node_id in _attack_graph["nodes"]

        _attack_graph["nodes"][node_id] = {
            "id": node_id,
            "type": node_type,
            "description": description.strip(),
            "status": status,
            "target": target,
            "technique": technique,
            "evidence": evidence[:500] if evidence else "",
            "priority": priority,
            "created_at": (
                _attack_graph["nodes"].get(node_id, {}).get("created_at")
                or datetime.now(UTC).isoformat()
            ),
            "updated_at": datetime.now(UTC).isoformat(),
        }

        if parent_id and parent_id in _attack_graph["nodes"]:
            edge = (parent_id, node_id, f"{node_type}")
            if edge not in _attack_graph["edges"]:
                _attack_graph["edges"].append(edge)

    action = "Updated" if is_update else "Added"
    return {
        "success": True,
        "message": f"{action} node '{node_id}' ({node_type}: {status})",
        "node_id": node_id,
    }


@register_tool(sandbox_execution=False)
def get_attack_graph() -> dict[str, Any]:
    """Get the current attack graph state."""
    with _graph_lock:
        nodes = dict(_attack_graph["nodes"])
        edges = list(_attack_graph["edges"])

    # Compute stats
    by_status: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for node in nodes.values():
        s = node["status"]
        t = node["type"]
        by_status[s] = by_status.get(s, 0) + 1
        by_type[t] = by_type.get(t, 0) + 1

    # Build tree representation
    tree = _build_tree(nodes, edges)

    return {
        "success": True,
        "total_nodes": len(nodes),
        "stats_by_status": by_status,
        "stats_by_type": by_type,
        "tree": tree,
        "nodes": nodes,
        "edges": [(f, t, l) for f, t, l in edges],
    }


@register_tool(sandbox_execution=False)
def suggest_next_action() -> dict[str, Any]:
    """Analyze the attack graph and suggest the highest-priority next action."""
    with _graph_lock:
        nodes = dict(_attack_graph["nodes"])
        edges = list(_attack_graph["edges"])

    if not nodes:
        return {
            "success": True,
            "suggestion": "No attack graph yet. Start with recon — add nodes for port scanning, service enumeration, and web crawling.",
            "priority": "high",
        }

    # Find actionable nodes (planned or in_progress, sorted by priority)
    actionable = [
        n for n in nodes.values()
        if n["status"] in ("planned", "in_progress")
    ]
    actionable.sort(key=lambda x: (-x["priority"], x["created_at"]))

    # Find successful nodes that could enable new paths
    successes = [n for n in nodes.values() if n["status"] == "success"]

    # Check for unexploited opportunities
    suggestions = []

    # Credentials found but not used for lateral movement
    creds = [n for n in successes if n["type"] == "credential"]
    cred_targets = {e[1] for e in edges if any(c["id"] == e[0] for c in creds)}
    if creds and not any(n["type"] == "pivot" for n in nodes.values()):
        suggestions.append({
            "action": "Try lateral movement with found credentials",
            "reason": f"{len(creds)} credential(s) found but no pivot attempts",
            "priority": "high",
            "related_nodes": [c["id"] for c in creds],
        })

    # Vulnerabilities found but not exploited
    vulns = [n for n in successes if n["type"] == "vulnerability"]
    exploited = {e[1] for e in edges if any(v["id"] == e[0] for v in vulns) and nodes.get(e[1], {}).get("type") == "exploit"}
    unexploited = [v for v in vulns if v["id"] not in {e[0] for e in edges if nodes.get(e[1], {}).get("type") == "exploit"}]
    if unexploited:
        suggestions.append({
            "action": "Exploit confirmed vulnerabilities",
            "reason": f"{len(unexploited)} confirmed vuln(s) not yet exploited",
            "priority": "high",
            "related_nodes": [v["id"] for v in unexploited],
        })

    # Access gained but no privilege escalation attempted
    access_nodes = [n for n in successes if n["type"] == "access"]
    if access_nodes and not any(n["type"] == "escalation" for n in nodes.values()):
        suggestions.append({
            "action": "Attempt privilege escalation",
            "reason": f"{len(access_nodes)} access point(s) with no escalation attempts",
            "priority": "medium",
            "related_nodes": [a["id"] for a in access_nodes],
        })

    # Next planned action
    if actionable:
        next_node = actionable[0]
        suggestions.append({
            "action": f"Continue: {next_node['description']}",
            "reason": f"Highest priority planned action (priority {next_node['priority']})",
            "priority": "normal",
            "related_nodes": [next_node["id"]],
        })

    if not suggestions:
        # Check if everything is done
        all_terminal = all(n["status"] in ("success", "failed", "skipped") for n in nodes.values())
        if all_terminal:
            return {
                "success": True,
                "suggestion": "All attack paths explored. Consider finishing the scan.",
                "priority": "low",
                "stats": {"total": len(nodes), "success": len(successes), "failed": sum(1 for n in nodes.values() if n["status"] == "failed")},
            }

    return {
        "success": True,
        "suggestions": suggestions[:5],
        "actionable_count": len(actionable),
        "success_count": len(successes),
    }


def _build_tree(nodes: dict, edges: list) -> str:
    """Build a text tree representation of the attack graph."""
    # Find root nodes (no incoming edges)
    children_of: dict[str, list[str]] = {}
    has_parent = set()

    for from_id, to_id, _ in edges:
        children_of.setdefault(from_id, []).append(to_id)
        has_parent.add(to_id)

    roots = [nid for nid in nodes if nid not in has_parent]
    if not roots:
        roots = list(nodes.keys())[:1]

    lines = []
    visited = set()

    def _walk(nid: str, prefix: str = "", is_last: bool = True) -> None:
        if nid in visited:
            return
        visited.add(nid)

        node = nodes.get(nid, {})
        status_icon = {
            "planned": "○", "in_progress": "◐", "success": "●",
            "failed": "✗", "blocked": "◻", "skipped": "—",
        }.get(node.get("status", ""), "?")

        connector = "└── " if is_last else "├── "
        line = f"{prefix}{connector}{status_icon} [{node.get('type', '?')}] {node.get('description', nid)[:60]}"
        lines.append(line)

        children = children_of.get(nid, [])
        child_prefix = prefix + ("    " if is_last else "│   ")
        for i, child_id in enumerate(children):
            _walk(child_id, child_prefix, i == len(children) - 1)

    for i, root in enumerate(roots):
        _walk(root, "", i == len(roots) - 1)

    return "\n".join(lines) if lines else "(empty graph)"
