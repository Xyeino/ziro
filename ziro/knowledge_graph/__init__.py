"""Knowledge graph over scan findings — hosts, services, creds, vulns, sessions.

NetworkX-backed in-process graph mirroring the engagement state but with
typed edges enabling multi-hop attack path discovery via shortest-path.

Nodes:  Host, Service, Credential, Finding, Session, User, Token, Path
Edges:  hosts_service, runs_on, accessible_from, leaks, pivots_to,
        authenticates_with, exploits, chains_to, owned_by
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class GraphNode:
    id: str
    kind: str  # host / service / credential / finding / session / user / token / path
    label: str
    attrs: dict[str, Any]


@dataclass
class GraphEdge:
    source: str
    target: str
    kind: str
    attrs: dict[str, Any]
    weight: float = 1.0  # lower = preferred path


_EDGE_KINDS = frozenset({
    "hosts_service",       # host → service
    "runs_on",             # service → host
    "accessible_from",     # service/endpoint → network/internet
    "leaks",               # service/finding → credential/token
    "pivots_to",           # host → host
    "authenticates_with",  # session → credential
    "grants_access",       # credential → host/service
    "exploits",            # finding → service/host
    "chains_to",           # finding → finding
    "owned_by",            # resource → user
    "child_of",            # sub-finding → parent finding
    "maps_to_cve",         # finding → cve id
})


class KnowledgeGraph:
    """Thread-safe graph. Uses NetworkX if available, falls back to pure-dict adjacency."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._nodes: dict[str, GraphNode] = {}
        self._adjacency: dict[str, list[GraphEdge]] = {}
        self._reverse_adjacency: dict[str, list[GraphEdge]] = {}
        self._networkx = None
        try:
            import networkx as nx

            self._networkx = nx
            self._nx_graph = nx.DiGraph()
        except ImportError:
            self._nx_graph = None

    # ---- mutators ----

    def add_node(self, node_id: str, kind: str, label: str = "", **attrs: Any) -> None:
        with self._lock:
            node = GraphNode(id=node_id, kind=kind, label=label or node_id, attrs=attrs)
            self._nodes[node_id] = node
            self._adjacency.setdefault(node_id, [])
            self._reverse_adjacency.setdefault(node_id, [])
            if self._nx_graph is not None:
                self._nx_graph.add_node(node_id, kind=kind, label=label, **attrs)

    def add_edge(
        self,
        source: str,
        target: str,
        kind: str,
        weight: float = 1.0,
        **attrs: Any,
    ) -> None:
        if kind not in _EDGE_KINDS:
            logger.warning(f"Unknown edge kind {kind!r}; accepting anyway")
        with self._lock:
            edge = GraphEdge(source=source, target=target, kind=kind, weight=weight, attrs=attrs)
            self._adjacency.setdefault(source, []).append(edge)
            self._reverse_adjacency.setdefault(target, []).append(edge)
            if self._nx_graph is not None:
                self._nx_graph.add_edge(source, target, kind=kind, weight=weight, **attrs)

    # ---- queries ----

    def neighbors(self, node_id: str) -> list[GraphEdge]:
        with self._lock:
            return list(self._adjacency.get(node_id, []))

    def incoming(self, node_id: str) -> list[GraphEdge]:
        with self._lock:
            return list(self._reverse_adjacency.get(node_id, []))

    def shortest_path(self, source: str, target: str) -> list[str] | None:
        """Find shortest path from source to target by edge weight.

        Returns list of node IDs along the path, or None if unreachable.
        """
        with self._lock:
            if self._nx_graph is not None:
                try:
                    return self._networkx.shortest_path(
                        self._nx_graph, source=source, target=target, weight="weight"
                    )
                except Exception:
                    return None
            # Fallback: BFS
            if source not in self._nodes or target not in self._nodes:
                return None
            visited = {source: None}
            queue = [source]
            while queue:
                current = queue.pop(0)
                if current == target:
                    path = []
                    while current is not None:
                        path.append(current)
                        current = visited[current]
                    return list(reversed(path))
                for edge in self._adjacency.get(current, []):
                    if edge.target not in visited:
                        visited[edge.target] = current
                        queue.append(edge.target)
            return None

    def attack_paths_to(self, target: str, max_paths: int = 5, max_length: int = 8) -> list[dict[str, Any]]:
        """Find multi-hop attack paths that could lead to target.

        Walks incoming edges backwards from target, collecting all simple paths
        up to max_length. Returns paths ordered by total weight (shortest/lowest
        weight first).
        """
        with self._lock:
            if self._nx_graph is not None and target in self._nx_graph:
                paths = []
                for source in list(self._nx_graph.nodes):
                    if source == target:
                        continue
                    try:
                        # nx.all_simple_paths in a reverse graph
                        for p in self._networkx.all_simple_paths(
                            self._nx_graph, source=source, target=target, cutoff=max_length
                        ):
                            if len(p) > 1:
                                weight = sum(
                                    self._nx_graph[p[i]][p[i + 1]].get("weight", 1.0)
                                    for i in range(len(p) - 1)
                                )
                                paths.append({"path": p, "length": len(p), "weight": weight})
                    except Exception:
                        continue
                paths.sort(key=lambda r: (r["weight"], r["length"]))
                return paths[:max_paths]
            return []

    def summary(self) -> dict[str, Any]:
        with self._lock:
            by_kind: dict[str, int] = {}
            for n in self._nodes.values():
                by_kind[n.kind] = by_kind.get(n.kind, 0) + 1
            total_edges = sum(len(v) for v in self._adjacency.values())
            return {
                "total_nodes": len(self._nodes),
                "total_edges": total_edges,
                "node_counts_by_kind": by_kind,
                "using_networkx": self._nx_graph is not None,
            }

    def to_mermaid(self, max_nodes: int = 50) -> str:
        """Render small subset as mermaid flowchart for panel visualization."""
        lines = ["graph LR"]
        with self._lock:
            count = 0
            for node_id, node in list(self._nodes.items())[:max_nodes]:
                safe_id = node_id.replace("-", "_").replace(".", "_")
                safe_label = node.label.replace('"', "'")[:40]
                shape_open, shape_close = {
                    "host": ('["', '"]'),
                    "service": ('("', '")'),
                    "credential": ('{{"', '"}}'),
                    "finding": ('[/"', '"/]'),
                }.get(node.kind, ('["', '"]'))
                lines.append(f"    {safe_id}{shape_open}{safe_label}{shape_close}")
                count += 1
            for src_id, edges in self._adjacency.items():
                safe_src = src_id.replace("-", "_").replace(".", "_")
                for e in edges[:10]:
                    safe_tgt = e.target.replace("-", "_").replace(".", "_")
                    lines.append(f"    {safe_src} -->|{e.kind}| {safe_tgt}")
        return "\n".join(lines)


# Singleton per process
_global_graph: KnowledgeGraph | None = None
_global_lock = threading.Lock()


def get_knowledge_graph() -> KnowledgeGraph:
    global _global_graph
    with _global_lock:
        if _global_graph is None:
            _global_graph = KnowledgeGraph()
        return _global_graph


def reset_knowledge_graph() -> KnowledgeGraph:
    global _global_graph
    with _global_lock:
        _global_graph = KnowledgeGraph()
        return _global_graph
