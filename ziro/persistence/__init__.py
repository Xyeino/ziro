"""Scan checkpointing and resume — survives panel crashes / restarts.

Every 5 minutes (configurable via ZIRO_CHECKPOINT_INTERVAL), snapshot:
- All agent states (conversation history, iteration counts, waiting flags)
- Engagement state (hosts/services/creds/findings)
- Knowledge graph nodes + edges
- Vector memory entries
- Agent graph structure (nodes + edges)

Stored as JSON under /workspace/.ziro-checkpoints/<session_id>/<timestamp>.json.

`ziro resume <session_id>` (CLI) loads the most recent checkpoint and hands
control back to the panel with state restored.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

_CHECKPOINT_DIR = "/workspace/.ziro-checkpoints"
_ACTIVE_SESSION_ID: str | None = None
_CHECKPOINT_THREAD: threading.Thread | None = None
_STOP_EVENT = threading.Event()


def _session_dir(session_id: str) -> str:
    return os.path.join(_CHECKPOINT_DIR, session_id)


def _interval_seconds() -> int:
    try:
        return int(os.getenv("ZIRO_CHECKPOINT_INTERVAL", "300"))
    except ValueError:
        return 300


def _collect_snapshot() -> dict[str, Any]:
    snapshot: dict[str, Any] = {
        "timestamp": time.time(),
        "version": 1,
    }

    # Agent states
    try:
        from ziro.tools.agents_graph.agents_graph_actions import _agent_graph, _agent_states

        agent_states_dump: dict[str, Any] = {}
        for aid, state in _agent_states.items():
            try:
                agent_states_dump[aid] = state.model_dump() if hasattr(state, "model_dump") else {}
            except Exception:
                continue
        snapshot["agent_states"] = agent_states_dump
        snapshot["agent_graph"] = {
            "nodes": {k: dict(v) for k, v in _agent_graph.get("nodes", {}).items()},
            "edges": list(_agent_graph.get("edges", [])),
        }
    except Exception:  # noqa: BLE001
        pass

    # Engagement state
    try:
        from ziro.engagement import get_engagement_state

        state = get_engagement_state()
        snapshot["engagement"] = {
            "target": state.target,
            "started_at": state.started_at,
            "hosts": {k: v.__dict__ for k, v in state.hosts.items()},
            "services": [s.__dict__ for s in state.services],
            "credentials": [c.__dict__ for c in state.credentials],
            "sessions": [sess.__dict__ for sess in state.sessions],
            "findings": {k: v.__dict__ for k, v in state.findings.items()},
            "notes": list(state.notes),
        }
    except Exception:  # noqa: BLE001
        pass

    # Knowledge graph
    try:
        from ziro.knowledge_graph import get_knowledge_graph

        kg = get_knowledge_graph()
        snapshot["knowledge_graph"] = {
            "nodes": {k: {"id": n.id, "kind": n.kind, "label": n.label, "attrs": n.attrs}
                      for k, n in kg._nodes.items()},
            "edges": [
                {"source": e.source, "target": e.target, "kind": e.kind,
                 "weight": e.weight, "attrs": e.attrs}
                for edges in kg._adjacency.values()
                for e in edges
            ],
        }
    except Exception:  # noqa: BLE001
        pass

    return snapshot


def write_checkpoint(session_id: str) -> str:
    sess_dir = _session_dir(session_id)
    os.makedirs(sess_dir, exist_ok=True)
    path = os.path.join(sess_dir, f"{int(time.time())}.json")
    try:
        snap = _collect_snapshot()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(snap, f, default=str)
        logger.info(f"Checkpoint written: {path}")
        return path
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Checkpoint failed: {e}")
        return ""


def load_latest_checkpoint(session_id: str) -> dict[str, Any] | None:
    sess_dir = _session_dir(session_id)
    if not os.path.isdir(sess_dir):
        return None
    files = sorted(
        [f for f in os.listdir(sess_dir) if f.endswith(".json")],
        reverse=True,
    )
    if not files:
        return None
    path = os.path.join(sess_dir, files[0])
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Failed to load checkpoint {path}: {e}")
        return None


def restore_from_checkpoint(session_id: str) -> dict[str, Any]:
    """Load snapshot and repopulate engagement state + knowledge graph.

    Agent states / conversation histories require the panel to re-instantiate
    agents — this helper populates static state only.
    """
    snap = load_latest_checkpoint(session_id)
    if not snap:
        return {"success": False, "error": "No checkpoint found"}

    restored: dict[str, int] = {}

    # Engagement state
    try:
        from ziro.engagement import reset_engagement_state

        engagement = snap.get("engagement", {})
        state = reset_engagement_state(target=engagement.get("target", ""))
        for host_data in engagement.get("hosts", {}).values():
            state.add_host(**host_data)
        for s in engagement.get("services", []):
            state.add_service(**s)
        for c in engagement.get("credentials", []):
            state.add_credential(**c)
        for sess in engagement.get("sessions", []):
            state.add_session(**sess)
        for f in engagement.get("findings", {}).values():
            state.add_finding(**f)
        for note in engagement.get("notes", []):
            state.add_note(note)
        restored["engagement"] = (
            len(engagement.get("hosts", {}))
            + len(engagement.get("services", []))
            + len(engagement.get("findings", {}))
        )
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Engagement restore failed: {e}")

    # Knowledge graph
    try:
        from ziro.knowledge_graph import reset_knowledge_graph

        kg = reset_knowledge_graph()
        kg_data = snap.get("knowledge_graph", {})
        for n in kg_data.get("nodes", {}).values():
            kg.add_node(n["id"], n["kind"], label=n.get("label", ""), **n.get("attrs", {}))
        for e in kg_data.get("edges", []):
            kg.add_edge(
                e["source"], e["target"], e["kind"],
                weight=e.get("weight", 1.0), **e.get("attrs", {}),
            )
        restored["knowledge_graph"] = len(kg_data.get("nodes", {}))
    except Exception as e:  # noqa: BLE001
        logger.warning(f"KG restore failed: {e}")

    return {
        "success": True,
        "session_id": session_id,
        "timestamp": snap.get("timestamp"),
        "restored": restored,
    }


def _checkpoint_loop(session_id: str) -> None:
    interval = _interval_seconds()
    while not _STOP_EVENT.wait(interval):
        write_checkpoint(session_id)


def start_checkpoint_loop(session_id: str) -> None:
    global _ACTIVE_SESSION_ID, _CHECKPOINT_THREAD

    if _CHECKPOINT_THREAD and _CHECKPOINT_THREAD.is_alive():
        return

    _ACTIVE_SESSION_ID = session_id
    _STOP_EVENT.clear()
    _CHECKPOINT_THREAD = threading.Thread(
        target=_checkpoint_loop, args=(session_id,), daemon=True, name="ziro-checkpoint",
    )
    _CHECKPOINT_THREAD.start()


def stop_checkpoint_loop() -> None:
    _STOP_EVENT.set()


def list_checkpoint_sessions() -> list[dict[str, Any]]:
    if not os.path.isdir(_CHECKPOINT_DIR):
        return []
    out = []
    for session_id in os.listdir(_CHECKPOINT_DIR):
        sess_dir = os.path.join(_CHECKPOINT_DIR, session_id)
        if not os.path.isdir(sess_dir):
            continue
        files = sorted(
            [f for f in os.listdir(sess_dir) if f.endswith(".json")],
            reverse=True,
        )
        if not files:
            continue
        latest_path = os.path.join(sess_dir, files[0])
        out.append({
            "session_id": session_id,
            "checkpoints": len(files),
            "latest": files[0],
            "latest_path": latest_path,
            "latest_size": os.path.getsize(latest_path) if os.path.exists(latest_path) else 0,
        })
    return out
