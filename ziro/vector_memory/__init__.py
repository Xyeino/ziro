"""Lightweight vector memory store — semantic search over scan observations.

No external vector DB dependency. Uses:
- sentence-transformers if installed (best quality, ~100ms per embed)
- litellm embeddings API if LLM provider supports it
- Fallback: hashed character-n-gram sketch (fast, low quality but non-zero signal)

Storage is in-memory per process, JSONL backup to /workspace/.ziro-vectors/
so session persistence can reload.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class VectorEntry:
    id: str
    text: str
    embedding: list[float]
    scope: str  # scan / task / subagent / finding
    scope_id: str
    created_at: float
    attrs: dict[str, Any] = field(default_factory=dict)


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


class VectorStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: list[VectorEntry] = []
        self._embed_fn = self._select_embedder()
        self._persist_dir = "/workspace/.ziro-vectors"

    def _select_embedder(self):
        # Try sentence-transformers first
        try:
            from sentence_transformers import SentenceTransformer  # noqa

            model = SentenceTransformer("all-MiniLM-L6-v2")

            def _embed(text: str) -> list[float]:
                return model.encode(text, show_progress_bar=False).tolist()

            logger.info("VectorStore using sentence-transformers MiniLM-L6-v2")
            return _embed
        except Exception:
            pass

        # Fallback: litellm embeddings API
        try:
            import litellm

            from ziro.config.config import resolve_llm_config

            model_name, api_key, api_base = resolve_llm_config()

            def _embed(text: str) -> list[float]:
                try:
                    kwargs: dict[str, Any] = {"input": text[:8000]}
                    if api_key:
                        kwargs["api_key"] = api_key
                    # Use a generic embedding model; fall through to sketch on error
                    try:
                        r = litellm.embedding(model="text-embedding-3-small", **kwargs)
                        return r.data[0]["embedding"]
                    except Exception:
                        return _sketch_embed(text)
                except Exception:
                    return _sketch_embed(text)

            return _embed
        except Exception:
            return _sketch_embed

    def _persist_entry(self, entry: VectorEntry) -> None:
        try:
            os.makedirs(self._persist_dir, exist_ok=True)
            path = os.path.join(self._persist_dir, f"{entry.scope}.jsonl")
            with open(path, "a", encoding="utf-8") as f:
                f.write(
                    json.dumps(
                        {
                            "id": entry.id,
                            "text": entry.text,
                            "embedding": entry.embedding,
                            "scope": entry.scope,
                            "scope_id": entry.scope_id,
                            "created_at": entry.created_at,
                            "attrs": entry.attrs,
                        }
                    )
                    + "\n"
                )
        except Exception:  # noqa: BLE001
            pass

    def store(
        self,
        text: str,
        scope: str = "scan",
        scope_id: str = "default",
        entry_id: str = "",
        attrs: dict[str, Any] | None = None,
    ) -> str:
        eid = entry_id or hashlib.blake2s(
            f"{scope}|{scope_id}|{text[:200]}|{time.time()}".encode(), digest_size=8
        ).hexdigest()
        emb = self._embed_fn(text)
        entry = VectorEntry(
            id=eid,
            text=text[:2000],
            embedding=emb,
            scope=scope,
            scope_id=scope_id,
            created_at=time.time(),
            attrs=attrs or {},
        )
        with self._lock:
            self._entries.append(entry)
            self._persist_entry(entry)
        return eid

    def search(
        self,
        query: str,
        scope: str = "",
        scope_id: str = "",
        top_k: int = 10,
        min_similarity: float = 0.15,
    ) -> list[dict[str, Any]]:
        q_emb = self._embed_fn(query)
        with self._lock:
            candidates = self._entries
            if scope:
                candidates = [e for e in candidates if e.scope == scope]
            if scope_id:
                candidates = [e for e in candidates if e.scope_id == scope_id]
            scored = [
                (_cosine(q_emb, e.embedding), e)
                for e in candidates
            ]
        scored.sort(key=lambda r: -r[0])
        return [
            {
                "id": e.id,
                "text": e.text,
                "scope": e.scope,
                "scope_id": e.scope_id,
                "similarity": round(sim, 3),
                "attrs": e.attrs,
                "age_sec": round(time.time() - e.created_at, 0),
            }
            for sim, e in scored[:top_k]
            if sim >= min_similarity
        ]

    def size(self) -> int:
        with self._lock:
            return len(self._entries)


def _sketch_embed(text: str, dims: int = 128) -> list[float]:
    """Cheap character-n-gram hashing sketch. Low quality but non-zero."""
    vec = [0.0] * dims
    if not text:
        return vec
    text = text.lower()[:2000]
    # 3-gram hash features
    for i in range(len(text) - 2):
        gram = text[i : i + 3]
        h = int(hashlib.blake2s(gram.encode(), digest_size=4).hexdigest(), 16)
        idx = h % dims
        sign = 1.0 if (h >> 16) & 1 else -1.0
        vec[idx] += sign
    # Normalize
    norm = math.sqrt(sum(v * v for v in vec))
    if norm:
        vec = [v / norm for v in vec]
    return vec


_global_store: VectorStore | None = None
_store_lock = threading.Lock()


def get_vector_store() -> VectorStore:
    global _global_store
    with _store_lock:
        if _global_store is None:
            _global_store = VectorStore()
        return _global_store


def reset_vector_store() -> None:
    global _global_store
    with _store_lock:
        _global_store = None
