"""Dry-run mode — record planned tool calls without executing side-effect ones."""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any


_DRY_RUN_LOG_FILE = "/workspace/.ziro-dryrun.jsonl"
_DRY_RUN_LOCK = threading.Lock()


# Tool names that are READ-ONLY and safe to actually execute even in dry-run
# (they just observe state, don't modify anything).
_SAFE_READ_ONLY_TOOLS = frozenset({
    "think",
    "view_agent_graph",
    "view_engagement_state",
    "list_requests",
    "view_request",
    "search_burp_proxy_history",
    "list_sitemap",
    "view_sitemap_entry",
    "get_engagement_package",
    "list_available_playbooks",
    "load_playbook",
    "list_payload_categories",
    "load_payload_list",
    "read_skill",
    "read_tool_doc",
    "list_installable_tools",
    "list_pending_handoffs",
    "list_findings_for_validation",
    "detect_lockfiles",
    "list_threat_actors",
})


def is_dry_run() -> bool:
    return os.getenv("ZIRO_DRY_RUN", "").strip().lower() in ("1", "true", "yes")


def log_planned_tool_call(tool_name: str, args: dict[str, Any]) -> None:
    """Append a planned tool call to the dry-run log."""
    entry = {
        "tool": tool_name,
        "args_preview": {
            k: (str(v)[:200] + "..." if isinstance(v, str) and len(str(v)) > 200 else v)
            for k, v in (args or {}).items()
        },
        "timestamp": time.time(),
    }
    with _DRY_RUN_LOCK:
        try:
            os.makedirs(os.path.dirname(_DRY_RUN_LOG_FILE), exist_ok=True)
            with open(_DRY_RUN_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:  # noqa: BLE001
            pass


def should_skip_execution(tool_name: str) -> bool:
    """Return True if a tool should NOT actually execute under dry-run.

    Read-only tools in _SAFE_READ_ONLY_TOOLS still run — the agent needs
    observation capability to plan. Everything else is logged and skipped.
    """
    if not is_dry_run():
        return False
    return tool_name not in _SAFE_READ_ONLY_TOOLS
