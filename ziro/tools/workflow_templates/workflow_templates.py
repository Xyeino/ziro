"""Workflow templates — YAML-declared multi-step plans with dependency chains.

Steps declare prerequisites; execute_workflow runs them in topological order
with fan-out on independent steps.
"""

from __future__ import annotations

import os
from typing import Any

import yaml

from ziro.tools.registry import register_tool


_BUILTIN_DIR = os.path.join(os.path.dirname(__file__), "builtin")


@register_tool(sandbox_execution=False)
def list_workflow_templates(agent_state: Any) -> dict[str, Any]:
    """List available workflow templates (builtin + user-contributed)."""
    available = []
    for src in (_BUILTIN_DIR, "/workspace/workflows"):
        if not os.path.isdir(src):
            continue
        for fname in sorted(os.listdir(src)):
            if fname.endswith((".yaml", ".yml")):
                path = os.path.join(src, fname)
                try:
                    with open(path, encoding="utf-8") as f:
                        doc = yaml.safe_load(f) or {}
                    available.append({
                        "name": doc.get("name", fname.rsplit(".", 1)[0]),
                        "description": doc.get("description", "")[:200],
                        "step_count": len(doc.get("steps", [])),
                        "path": path,
                    })
                except Exception:
                    continue
    return {"success": True, "templates": available, "count": len(available)}


@register_tool(sandbox_execution=False)
def load_workflow_template(
    agent_state: Any,
    template_name: str,
) -> dict[str, Any]:
    """Load a workflow template by name. Returns the full step DAG."""
    for src in (_BUILTIN_DIR, "/workspace/workflows"):
        if not os.path.isdir(src):
            continue
        for fname in os.listdir(src):
            if not fname.endswith((".yaml", ".yml")):
                continue
            path = os.path.join(src, fname)
            try:
                with open(path, encoding="utf-8") as f:
                    doc = yaml.safe_load(f) or {}
                if doc.get("name") == template_name or fname.rsplit(".", 1)[0] == template_name:
                    return {
                        "success": True,
                        "template": doc,
                        "path": path,
                        "execution_order": _topological_order(doc.get("steps", [])),
                    }
            except Exception:
                continue
    return {"success": False, "error": f"Template {template_name!r} not found"}


def _topological_order(steps: list[dict[str, Any]]) -> list[list[str]]:
    """Return parallel execution batches (each batch = independently runnable)."""
    by_id = {s["id"]: s for s in steps}
    pending = set(by_id.keys())
    completed: set[str] = set()
    batches: list[list[str]] = []

    while pending:
        runnable = [
            sid for sid in pending
            if set(by_id[sid].get("depends_on", []) or []).issubset(completed)
        ]
        if not runnable:
            # cycle / unresolved — bail with what we have
            batches.append(sorted(pending))
            break
        batches.append(sorted(runnable))
        for sid in runnable:
            pending.discard(sid)
            completed.add(sid)

    return batches
