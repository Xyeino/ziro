"""Runtime scope enforcement — blocks agent tool calls that target out-of-RoE hosts.

Loads the RoE allowlist from /workspace/engagement/<slug>/roe.json (produced by
create_roe). Every tool invocation that takes a URL/host/IP is gated: if the
target is not in scope, the call fails with a clear error instead of silently
hitting an out-of-scope system.

Enable via ZIRO_SCOPE_ENFORCE=1. Disabled by default so legacy behavior works.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


_ENGAGEMENT_DIR = "/workspace/engagement"


@dataclass
class ScopeDecision:
    in_scope: bool
    reason: str = ""
    target: str = ""


def _normalize_host(raw: str) -> str:
    """Extract the hostname/IP from a URL or pass through if already plain."""
    raw = (raw or "").strip()
    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
    else:
        # Might be "host:port" or bare host
        host = raw.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
    return host.lower()


def _host_matches_pattern(host: str, pattern: str) -> bool:
    """Match host against a pattern (exact, wildcard, CIDR, or regex-safe substring).

    Pattern forms:
    - 'example.com' — exact match + all subdomains
    - '*.example.com' — wildcard subdomains (not the apex)
    - '10.0.0.0/8' — CIDR range
    - '192.168.1.1' — exact IP
    - 'internal.corp' — treat as domain suffix
    """
    host = host.lower().strip(".")
    pattern = pattern.lower().strip().strip(".")

    if not host or not pattern:
        return False

    # CIDR match
    if "/" in pattern:
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            try:
                return ipaddress.ip_address(host) in network
            except ValueError:
                return False
        except ValueError:
            pass

    # Wildcard
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host.endswith("." + suffix)

    # Exact match
    if host == pattern:
        return True

    # Subdomain of pattern (e.g., api.example.com matches example.com)
    if host.endswith("." + pattern):
        return True

    return False


@lru_cache(maxsize=8)
def _load_roe_digest() -> dict[str, Any] | None:
    """Find and parse the latest roe.json in /workspace/engagement/."""
    if not os.path.isdir(_ENGAGEMENT_DIR):
        return None

    latest: tuple[float, str] | None = None
    for slug in os.listdir(_ENGAGEMENT_DIR):
        path = os.path.join(_ENGAGEMENT_DIR, slug, "roe.json")
        if os.path.isfile(path):
            mtime = os.path.getmtime(path)
            if latest is None or mtime > latest[0]:
                latest = (mtime, path)

    if not latest:
        return None

    try:
        with open(latest[1], encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Failed to load RoE digest: {e}")
        return None


def invalidate_roe_cache() -> None:
    _load_roe_digest.cache_clear()


def check_target_in_scope(target: str) -> ScopeDecision:
    """Check a URL/host/IP against the loaded RoE in_scope / out_of_scope lists."""
    if not target:
        return ScopeDecision(in_scope=True, reason="empty target")

    if os.getenv("ZIRO_SCOPE_ENFORCE", "").strip().lower() not in ("1", "true", "yes"):
        return ScopeDecision(in_scope=True, reason="enforcement disabled")

    digest = _load_roe_digest()
    if not digest:
        return ScopeDecision(
            in_scope=True,
            reason="no RoE loaded — enforcement no-op until create_roe is called",
        )

    host = _normalize_host(target)
    if not host:
        return ScopeDecision(in_scope=True, reason="could not parse target")

    out_of_scope = digest.get("out_of_scope", []) or []
    for pattern in out_of_scope:
        if _host_matches_pattern(host, pattern):
            return ScopeDecision(
                in_scope=False,
                reason=f"host {host!r} matches explicit out-of-scope pattern {pattern!r}",
                target=host,
            )

    in_scope = digest.get("in_scope", []) or []
    if not in_scope:
        # Empty in_scope list — defensive default is to allow everything
        return ScopeDecision(in_scope=True, reason="no in_scope patterns declared")

    for pattern in in_scope:
        if _host_matches_pattern(host, pattern):
            return ScopeDecision(in_scope=True, reason=f"matches in_scope {pattern!r}", target=host)

    return ScopeDecision(
        in_scope=False,
        reason=f"host {host!r} does not match any in_scope pattern; refusing to proceed",
        target=host,
    )


_URL_RE = re.compile(r"https?://[^\s'\"`<>]+")


def extract_targets_from_args(args: dict[str, Any]) -> list[str]:
    """Best-effort extraction of URL/host targets from arbitrary tool kwargs."""
    targets: list[str] = []
    priority_keys = (
        "url", "target", "target_url", "host", "hostname", "domain",
        "endpoint", "callback_host", "main_url", "base_url",
    )

    for key in priority_keys:
        if key in args and isinstance(args[key], str) and args[key].strip():
            targets.append(args[key])

    # Scan all string values for embedded URLs (command= fields, etc.)
    for v in args.values():
        if isinstance(v, str):
            for m in _URL_RE.finditer(v):
                targets.append(m.group(0))

    return targets


def evaluate_tool_invocation(tool_name: str, args: dict[str, Any]) -> ScopeDecision:
    """Evaluate whether a tool invocation violates RoE scope.

    Returns ScopeDecision(in_scope=False, ...) if ANY extracted target is
    out of scope. Tool caller should refuse to execute in that case.
    """
    # Tools that never touch the network — skip
    if tool_name in (
        "view_agent_graph", "create_note", "list_notes", "think",
        "create_roe", "create_conops", "create_opplan",
        "create_deconfliction_plan", "get_engagement_package",
        "load_payload_list", "list_payload_categories",
        "read_skill", "load_skill", "read_tool_doc",
        "agent_finish", "finish_scan", "wait_for_message",
        "send_message_to_agent", "update_todo", "mark_todo_done",
        "create_vulnerability_report", "capture_evidence",
        "list_findings_for_validation", "record_validation_verdict",
    ):
        return ScopeDecision(in_scope=True, reason="non-network tool")

    targets = extract_targets_from_args(args)
    if not targets:
        return ScopeDecision(in_scope=True, reason="no targets found in args")

    for target in targets:
        decision = check_target_in_scope(target)
        if not decision.in_scope:
            return decision

    return ScopeDecision(in_scope=True, reason="all targets pass")
