"""Tools for semantic memory — store and search across scan observations."""

from __future__ import annotations

from typing import Any

from ziro.tools.registry import register_tool
from ziro.vector_memory import get_vector_store


@register_tool(sandbox_execution=False)
def memory_store(
    agent_state: Any,
    text: str,
    scope: str = "scan",
    scope_id: str = "default",
    attrs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Store an observation in semantic memory for later retrieval.

    scope: scan / task / subagent / finding — allows scoped search.
    scope_id: narrow identifier (e.g., scope='finding', scope_id='f_abc123').

    Use for things worth remembering across iterations:
    - unusual HTTP responses that didn't match a simple pattern
    - free-form observations ("this endpoint rate-limits after 5 req/s")
    - leaked hints from error messages
    """
    store = get_vector_store()
    eid = store.store(text, scope=scope, scope_id=scope_id, attrs=attrs)
    return {"success": True, "entry_id": eid, "total_entries": store.size()}


@register_tool(sandbox_execution=False)
def memory_search(
    agent_state: Any,
    query: str,
    scope: str = "",
    scope_id: str = "",
    top_k: int = 10,
    min_similarity: float = 0.15,
) -> dict[str, Any]:
    """Semantic search over stored observations.

    Returns most-similar entries with cosine similarity score. Use before
    repeating work — 'did I see something about JWT handling earlier?'
    """
    store = get_vector_store()
    hits = store.search(
        query, scope=scope, scope_id=scope_id, top_k=top_k, min_similarity=min_similarity
    )
    return {
        "success": True,
        "query": query,
        "hit_count": len(hits),
        "hits": hits,
    }
