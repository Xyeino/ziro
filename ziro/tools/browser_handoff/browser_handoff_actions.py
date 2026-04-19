"""Browser handoff — pause agent and request the operator to log in manually.

When the agent hits a login form it can't handle (2FA, SSO, CAPTCHA, WebAuthn,
magic link flow), it calls request_auth_handoff(url, reason). The panel UI
shows a modal with a live VNC view of the sandbox browser; the operator logs
in manually with their real credentials; Caido proxy captures the session
tokens during the handoff; agent resumes with authenticated context.

Creds never touch the LLM — only the resulting session token is extracted
from proxy history via record_credential post-handoff.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any

from ziro.tools.registry import register_tool


_HANDOFF_DIR = "/workspace/.ziro-handoffs"


def _state_file(handoff_id: str) -> str:
    return os.path.join(_HANDOFF_DIR, f"{handoff_id}.json")


def _write_state(handoff_id: str, state: dict[str, Any]) -> None:
    os.makedirs(_HANDOFF_DIR, exist_ok=True)
    with open(_state_file(handoff_id), "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def _read_state(handoff_id: str) -> dict[str, Any] | None:
    path = _state_file(handoff_id)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return None


@register_tool(sandbox_execution=True)
def request_auth_handoff(
    agent_state: Any,
    url: str,
    reason: str,
    expected_session_type: str = "http_cookie",
    timeout_seconds: int = 600,
    poll_interval: float = 2.0,
) -> dict[str, Any]:
    """Pause agent and request operator to manually authenticate in the sandbox browser.

    Writes a handoff request to /workspace/.ziro-handoffs/<id>.json which the
    panel picks up and shows a modal with a live browser view. Operator logs in,
    clicks Done. Panel writes status=completed to the state file. Agent unblocks
    and returns success.

    Blocks for up to timeout_seconds (default 10 min). Returns detail on what
    the operator did (session present, any cookies captured) so the agent can
    pick up the new authenticated context.

    Creds NEVER flow through the LLM — operator types them directly in the
    browser, Caido captures the resulting session token, agent reads the token
    from proxy history after unblock.

    reason: explain to the operator WHY you need auth (e.g., 'Need authenticated
    session to test horizontal IDOR on /api/orders').
    expected_session_type: http_cookie / bearer / jwt / oauth — helps panel UI
    show appropriate extraction instructions.
    """
    if not url or not reason:
        return {"success": False, "error": "Both url and reason are required"}

    handoff_id = f"handoff_{uuid.uuid4().hex[:10]}"
    aid = agent_state.agent_id if agent_state and hasattr(agent_state, "agent_id") else "unknown"

    request_state = {
        "id": handoff_id,
        "status": "pending",
        "agent_id": aid,
        "url": url,
        "reason": reason,
        "expected_session_type": expected_session_type,
        "created_at": time.time(),
        "completed_at": None,
        "operator_notes": "",
    }
    _write_state(handoff_id, request_state)

    # Poll for completion
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        time.sleep(poll_interval)
        current = _read_state(handoff_id)
        if not current:
            continue
        status = current.get("status", "pending")
        if status == "completed":
            return {
                "success": True,
                "handoff_id": handoff_id,
                "status": "completed",
                "operator_notes": current.get("operator_notes", ""),
                "completed_at": current.get("completed_at"),
                "duration_seconds": round(
                    (current.get("completed_at") or time.time()) - request_state["created_at"], 1
                ),
                "next_step": (
                    "Operator completed the login. Session tokens should now be in the Caido proxy history. "
                    "Call search_burp_proxy_history(host=...) to find the auth response with Set-Cookie "
                    "or Authorization header, then call record_credential to persist it in engagement state."
                ),
            }
        if status == "cancelled":
            return {
                "success": False,
                "handoff_id": handoff_id,
                "status": "cancelled",
                "error": "Operator cancelled the handoff",
                "operator_notes": current.get("operator_notes", ""),
            }

    # Timeout — mark abandoned
    request_state["status"] = "timeout"
    _write_state(handoff_id, request_state)
    return {
        "success": False,
        "handoff_id": handoff_id,
        "status": "timeout",
        "error": f"No operator response within {timeout_seconds}s. Proceed without authentication.",
    }


@register_tool(sandbox_execution=False)
def list_pending_handoffs(agent_state: Any) -> dict[str, Any]:
    """List all pending handoff requests (for panel UI and operator awareness)."""
    if not os.path.isdir(_HANDOFF_DIR):
        return {"success": True, "pending": [], "count": 0}

    pending: list[dict[str, Any]] = []
    for fname in os.listdir(_HANDOFF_DIR):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(_HANDOFF_DIR, fname), encoding="utf-8") as f:
                state = json.load(f)
            if state.get("status") == "pending":
                pending.append(state)
        except Exception:  # noqa: BLE001
            continue

    return {"success": True, "pending": pending, "count": len(pending)}
