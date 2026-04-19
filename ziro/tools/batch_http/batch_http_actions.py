"""Batched parallel HTTP requests — execute up to 50 curls as one tool call."""

from __future__ import annotations

import asyncio
from typing import Any

from ziro.tools.registry import register_tool


@register_tool(sandbox_execution=True)
async def batch_http_get(
    agent_state: Any,
    urls: list[str],
    user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    timeout: float = 10.0,
    concurrency: int = 10,
    follow_redirects: bool = False,
    return_body_preview: int = 200,
) -> dict[str, Any]:
    """Execute up to 50 parallel HTTP GETs as a single tool call.

    Replaces chains of individual terminal_execute + curl calls when the agent
    needs to probe many URLs quickly (recon sweeps, IDOR sweeps across user IDs,
    wordlist directory brute, shadow endpoint discovery).

    Returns per-URL status, size, final_url (after redirects), and a short body
    preview. Caps at 50 URLs per call to keep output manageable.
    """
    if not urls:
        return {"success": False, "error": "urls list cannot be empty"}
    urls = urls[:50]

    import httpx

    sem = asyncio.Semaphore(concurrency)
    results: list[dict[str, Any]] = []

    async def _fetch(url: str) -> dict[str, Any]:
        async with sem:
            try:
                async with httpx.AsyncClient(
                    follow_redirects=follow_redirects, verify=False, timeout=timeout
                ) as client:
                    r = await client.get(url, headers={"User-Agent": user_agent})
                    return {
                        "url": url,
                        "status": r.status_code,
                        "size": len(r.content),
                        "content_type": r.headers.get("content-type", ""),
                        "final_url": str(r.url),
                        "body_preview": r.text[:return_body_preview],
                    }
            except Exception as e:  # noqa: BLE001
                return {"url": url, "error": str(e)[:200]}

    results = await asyncio.gather(*(_fetch(u) for u in urls))

    # Group by status for the agent's convenience
    by_status: dict[str, int] = {}
    for r in results:
        status = str(r.get("status") or "err")
        by_status[status] = by_status.get(status, 0) + 1

    return {
        "success": True,
        "count": len(results),
        "by_status": by_status,
        "results": results,
    }
