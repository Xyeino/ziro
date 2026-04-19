"""Scan replay — step through historical scan events with scrubber position + bookmarks."""

from __future__ import annotations

import json
import os
from typing import Any

from ziro.tools.registry import register_tool


_REPLAY_DIR = "/workspace/.ziro-replay"


@register_tool(sandbox_execution=False)
def replay_list_scans(agent_state: Any) -> dict[str, Any]:
    """List all replayable scan sessions (from checkpoints + history)."""
    sessions = []
    try:
        from ziro.persistence import list_checkpoint_sessions

        sessions = list_checkpoint_sessions()
    except Exception:
        pass
    return {"success": True, "sessions": sessions, "count": len(sessions)}


@register_tool(sandbox_execution=False)
def replay_get_events(
    agent_state: Any,
    session_id: str,
    offset: int = 0,
    limit: int = 200,
) -> dict[str, Any]:
    """Load a window of events for replay scrubber.

    Returns tool executions + status transitions in chronological order,
    paginated so the panel can lazy-load large replays.
    """
    events: list[dict[str, Any]] = []
    try:
        from ziro.persistence import load_latest_checkpoint

        snap = load_latest_checkpoint(session_id) or {}
        # Each agent state has message history — reconstruct a timeline
        for aid, state in (snap.get("agent_states") or {}).items():
            for i, msg in enumerate((state.get("messages") or [])):
                events.append({
                    "agent_id": aid,
                    "agent_name": state.get("agent_name", ""),
                    "iteration": i,
                    "role": msg.get("role", ""),
                    "preview": (
                        msg.get("content", "")
                        if isinstance(msg.get("content"), str)
                        else str(msg.get("content"))[:200]
                    )[:500],
                })
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": str(e)}

    paged = events[offset : offset + limit]
    return {
        "success": True,
        "session_id": session_id,
        "total": len(events),
        "offset": offset,
        "limit": limit,
        "events": paged,
    }


@register_tool(sandbox_execution=False)
def replay_add_bookmark(
    agent_state: Any,
    session_id: str,
    position: int,
    label: str,
    note: str = "",
) -> dict[str, Any]:
    """Drop a bookmark at position for later jump-to during replay."""
    os.makedirs(_REPLAY_DIR, exist_ok=True)
    path = os.path.join(_REPLAY_DIR, f"{session_id}_bookmarks.json")
    bookmarks = []
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as f:
                bookmarks = json.load(f)
        except Exception:
            bookmarks = []

    bookmarks.append({"position": position, "label": label[:100], "note": note[:500]})

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(bookmarks, f, indent=2)
    except Exception as e:
        return {"success": False, "error": str(e)}

    return {"success": True, "session_id": session_id, "bookmarks": len(bookmarks)}


@register_tool(sandbox_execution=False)
def replay_list_bookmarks(
    agent_state: Any,
    session_id: str,
) -> dict[str, Any]:
    """List all bookmarks for a replay session."""
    path = os.path.join(_REPLAY_DIR, f"{session_id}_bookmarks.json")
    if not os.path.isfile(path):
        return {"success": True, "session_id": session_id, "bookmarks": []}
    try:
        with open(path, encoding="utf-8") as f:
            bookmarks = json.load(f)
    except Exception as e:
        return {"success": False, "error": str(e)}
    return {"success": True, "session_id": session_id, "bookmarks": bookmarks}
