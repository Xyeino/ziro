"""Operator approval queue — agent requests for sensitive actions.

Separate from command_safety (which is pattern-based on shell commands).
This is for higher-level 'agent wants to do X, does operator approve?'
moments (deploy sliver implant, delete persistence, submit finding to bug
bounty platform, etc.).
"""

from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any

from ziro.tools.registry import register_tool

_APPROVAL_DIR = "/workspace/.ziro-approvals"


def _path(aid: str) -> str:
    return os.path.join(_APPROVAL_DIR, f"{aid}.json")


def _write(aid: str, data: dict[str, Any]) -> None:
    os.makedirs(_APPROVAL_DIR, exist_ok=True)
    with open(_path(aid), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _read(aid: str) -> dict[str, Any] | None:
    if not os.path.isfile(_path(aid)):
        return None
    try:
        with open(_path(aid), encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return None


@register_tool(sandbox_execution=True)
def request_operator_approval(
    agent_state: Any,
    action: str,
    rationale: str,
    risk_level: str = "medium",
    details: dict[str, Any] | None = None,
    timeout_seconds: int = 600,
    poll_interval: float = 2.0,
) -> dict[str, Any]:
    """Request operator approval for a sensitive action. Blocks until decided or timeout.

    action: short label (deploy_implant, delete_persistence, exfil_evidence, ...)
    rationale: why you want to do this
    risk_level: low / medium / high / critical
    details: any additional context as dict (e.g., target_host, payload_preview)

    While blocked, the panel's /api/approvals endpoint shows the request.
    Operator hits approve/deny button; this tool unblocks with the result.

    Returns {approved: bool, reason, decided_by, decided_at}.
    """
    aid = f"req_{uuid.uuid4().hex[:10]}"
    agent_id = agent_state.agent_id if agent_state and hasattr(agent_state, "agent_id") else "unknown"

    state = {
        "id": aid,
        "status": "pending",
        "action": action,
        "rationale": rationale,
        "risk_level": risk_level.lower(),
        "details": details or {},
        "agent_id": agent_id,
        "created_at": time.time(),
        "decided_at": None,
        "decided_by": "",
        "approved": False,
        "operator_reason": "",
    }
    _write(aid, state)

    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        time.sleep(poll_interval)
        cur = _read(aid)
        if not cur or cur.get("status") == "pending":
            continue
        return {
            "success": True,
            "approval_id": aid,
            "approved": bool(cur.get("approved")),
            "reason": cur.get("operator_reason", ""),
            "decided_by": cur.get("decided_by", ""),
            "decided_at": cur.get("decided_at"),
            "duration_seconds": round(
                (cur.get("decided_at") or time.time()) - state["created_at"], 1
            ),
        }

    state["status"] = "timeout"
    _write(aid, state)
    return {
        "success": False,
        "approval_id": aid,
        "approved": False,
        "error": f"No operator response within {timeout_seconds}s. Default: deny.",
    }


@register_tool(sandbox_execution=False)
def list_pending_approvals(agent_state: Any) -> dict[str, Any]:
    """List all pending operator approval requests (for panel UI)."""
    if not os.path.isdir(_APPROVAL_DIR):
        return {"success": True, "pending": [], "count": 0}

    pending = []
    for fname in sorted(os.listdir(_APPROVAL_DIR)):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(_APPROVAL_DIR, fname), encoding="utf-8") as f:
                state = json.load(f)
            if state.get("status") == "pending":
                pending.append(state)
        except Exception:  # noqa: BLE001
            continue
    return {"success": True, "pending": pending, "count": len(pending)}
