"""Sploitus exploit search — scrape public exploit databases by CVE/keyword."""

from __future__ import annotations

import re
from typing import Any

from ziro.tools.registry import register_tool


@register_tool(sandbox_execution=True)
def sploitus_search(
    agent_state: Any,
    query: str,
    max_results: int = 15,
    user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    timeout: float = 20.0,
) -> dict[str, Any]:
    """Search Sploitus for public exploits by CVE ID, product name, or keyword.

    Aggregates Exploit-DB, GitHub PoCs, Metasploit modules, Packet Storm, and
    more. Returns title, CVE list, source, published date, and URL for each hit.

    Use when SCA or CVE lookup surfaces a known CVE — this returns weaponized
    or PoC exploits ready to adapt. Do NOT run exploits against out-of-scope
    targets (RoE enforcement blocks that anyway).
    """
    if not query.strip():
        return {"success": False, "error": "query required"}

    try:
        import httpx

        url = "https://sploitus.com/search"
        payload = {
            "type": "exploits",
            "sort": "default",
            "query": query.strip(),
            "title": False,
            "offset": 0,
        }
        headers = {
            "User-Agent": user_agent,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            r = client.post(url, json=payload, headers=headers)

        if r.status_code != 200:
            return {
                "success": False,
                "error": f"Sploitus returned HTTP {r.status_code}",
                "hint": "Sploitus may have rate-limited; retry in a minute.",
            }

        try:
            data = r.json()
        except Exception:
            # HTML fallback — extract title/URL pairs
            return _html_fallback_parse(r.text, query, max_results)

        exploits = data.get("exploits", []) or []
        results: list[dict[str, Any]] = []
        for item in exploits[:max_results]:
            if not isinstance(item, dict):
                continue
            results.append(
                {
                    "title": (item.get("title") or "")[:250],
                    "id": item.get("id") or "",
                    "type": item.get("type") or "",
                    "source": item.get("source") or "",
                    "published": item.get("published") or "",
                    "score": item.get("score"),
                    "cve": item.get("cve") or "",
                    "url": item.get("href") or item.get("url") or "",
                    "tags": (item.get("tags") or [])[:8],
                }
            )

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"sploitus_search failed: {e!s}"}
    else:
        return {
            "success": True,
            "query": query,
            "count": len(results),
            "results": results,
            "note": "Review each URL; download PoC via scan_git_history/curl. Adapt to in-scope target only.",
        }


def _html_fallback_parse(html: str, query: str, max_results: int) -> dict[str, Any]:
    """Loose HTML scrape when JSON endpoint is unavailable."""
    hits: list[dict[str, Any]] = []
    for m in re.finditer(
        r'<a[^>]+href="([^"]+)"[^>]*class="[^"]*result[^"]*"[^>]*>([^<]+)</a>',
        html,
    ):
        href, title = m.group(1), m.group(2)
        hits.append({"title": title[:250], "url": href})
        if len(hits) >= max_results:
            break
    return {
        "success": True,
        "query": query,
        "count": len(hits),
        "results": hits,
        "source": "html_fallback",
    }
