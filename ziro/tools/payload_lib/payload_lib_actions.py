"""Load battle-tested payload lists from the bundled library.

LLMs are notorious for inventing subtly-broken payloads (wrong quoting, missing
escape, ineffective encoding, etc.). This tool gives agents access to curated,
tested payload lists so they use known-working inputs instead of guessing.

Library lives in ziro/payloads/ — plain text files, one payload per line,
# comments stripped. Agents call load_payload_list(category=...) to get a
list of strings, then pass them to fuzz_request_parameter or iterate with
terminal_execute + curl.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

from ziro.tools.registry import register_tool
from ziro.utils.resource_paths import get_ziro_resource_path


def _payloads_dir() -> str:
    return str(get_ziro_resource_path("payloads"))


@lru_cache(maxsize=1)
def _list_categories() -> dict[str, str]:
    d = _payloads_dir()
    if not os.path.isdir(d):
        return {}
    out: dict[str, str] = {}
    for fname in sorted(os.listdir(d)):
        if fname.endswith(".txt"):
            name = fname[:-4]
            out[name] = os.path.join(d, fname)
    return out


def _load_file(path: str) -> list[str]:
    payloads: list[str] = []
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n").rstrip("\r")
            if not line.strip():
                continue
            if line.lstrip().startswith("#"):
                continue
            payloads.append(line)
    return payloads


@register_tool(sandbox_execution=False)
def load_payload_list(
    agent_state: Any,
    category: str,
    count: int = 50,
    offset: int = 0,
    contains: str = "",
) -> dict[str, Any]:
    """Load payloads from a category file in the Ziro payload library.

    Categories available: sql_injection, xss, ssrf, path_traversal, ssti,
    command_injection, xxe, open_redirect, nosql_injection. Call
    list_payload_categories first if unsure.

    - count: max number of payloads to return (default 50)
    - offset: skip first N payloads (useful for paging through a long list)
    - contains: case-insensitive substring filter (only return payloads
      containing this string — handy when you want, say, just the time-based
      SQL payloads or just the Apache-specific path traversal variants)
    """
    try:
        cats = _list_categories()
        if category not in cats:
            return {
                "success": False,
                "error": f"Unknown category '{category}'",
                "available": sorted(cats.keys()),
            }

        all_payloads = _load_file(cats[category])
        if contains:
            needle = contains.lower()
            all_payloads = [p for p in all_payloads if needle in p.lower()]

        slice_ = all_payloads[offset : offset + count]

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"load_payload_list failed: {e!s}"}
    else:
        return {
            "success": True,
            "category": category,
            "total_in_category": len(all_payloads),
            "returned": len(slice_),
            "offset": offset,
            "payloads": slice_,
            "note": (
                "These are battle-tested payloads. Feed directly to "
                "fuzz_request_parameter, or iterate with terminal_execute + curl. "
                "Do NOT modify them before testing — they work as-is against most targets."
            ),
        }


@register_tool(sandbox_execution=False)
def list_payload_categories(agent_state: Any) -> dict[str, Any]:
    """List all available payload categories with counts.

    Call this when you're not sure what payload lists exist. Cheap
    informational call — returns just the category names and how many
    payloads each contains.
    """
    try:
        cats = _list_categories()
        summary: list[dict[str, Any]] = []
        for name, path in cats.items():
            try:
                payloads = _load_file(path)
                summary.append({"category": name, "count": len(payloads), "file": path})
            except Exception:
                summary.append({"category": name, "count": 0, "file": path})

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"list_payload_categories failed: {e!s}"}
    else:
        return {
            "success": True,
            "categories": summary,
            "total_categories": len(summary),
            "total_payloads": sum(c["count"] for c in summary),
        }
