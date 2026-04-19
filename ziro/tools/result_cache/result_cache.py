"""Cache deterministic-ish tool results so repeated calls don't re-run the tool.

Opt-in per-tool-name. nmap/nuclei/subfinder against the same target produce
effectively-identical output within a scan session — caching saves time and
tokens (the result is not re-emitted in conversation history).

Cache is process-local (dict), keyed by (tool_name, sorted_args_json). TTL
configurable via ZIRO_TOOL_CACHE_TTL (default 1800s = 30 min).
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Any

_CACHE: dict[str, tuple[float, Any]] = {}
_LOCK = threading.Lock()

# Tools whose results are cached by default. Only read-ish, deterministic ones.
_CACHEABLE_TOOLS = frozenset({
    "discover_api_spec",
    "discover_graphql_endpoint",
    "detect_capabilities",
    "detect_lockfiles",
    "download_js_bundles",
    "analyze_js_file",
    "list_payload_categories",
    "list_threat_actors",
    "list_available_playbooks",
    "list_installable_tools",
    "list_personas",
})


def _ttl() -> int:
    try:
        return int(os.getenv("ZIRO_TOOL_CACHE_TTL", "1800"))
    except ValueError:
        return 1800


def _key(tool_name: str, args: dict[str, Any]) -> str:
    try:
        args_str = json.dumps(args, sort_keys=True, default=str)
    except Exception:
        args_str = str(args)
    return hashlib.blake2s(f"{tool_name}|{args_str}".encode(), digest_size=10).hexdigest()


def is_cacheable(tool_name: str) -> bool:
    if os.getenv("ZIRO_TOOL_CACHE", "1").strip().lower() in ("0", "false", "off"):
        return False
    return tool_name in _CACHEABLE_TOOLS


def cache_lookup(tool_name: str, args: dict[str, Any]) -> Any | None:
    if not is_cacheable(tool_name):
        return None
    k = _key(tool_name, args)
    ttl = _ttl()
    with _LOCK:
        entry = _CACHE.get(k)
        if not entry:
            return None
        ts, value = entry
        if time.time() - ts > ttl:
            _CACHE.pop(k, None)
            return None
        return value


def cache_store(tool_name: str, args: dict[str, Any], value: Any) -> None:
    if not is_cacheable(tool_name):
        return
    k = _key(tool_name, args)
    with _LOCK:
        _CACHE[k] = (time.time(), value)


def cache_clear() -> int:
    with _LOCK:
        n = len(_CACHE)
        _CACHE.clear()
        return n
