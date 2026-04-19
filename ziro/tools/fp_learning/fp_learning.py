"""False-positive learning — remember operator-marked FPs across scans.

When the operator marks a finding as FP, we compute its fingerprint (same algo
as dedupe) and store it in a persistent JSONL at ~/.ziro/fp_memory.jsonl.
Before creating a new vulnerability report, the agent can query this memory
to see if a similar pattern was previously dismissed and either skip reporting
or tag the finding with 'previously_marked_fp'.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from ziro.tools.registry import register_tool


def _memory_path() -> Path:
    home = Path(os.path.expanduser("~")) / ".ziro"
    home.mkdir(parents=True, exist_ok=True)
    return home / "fp_memory.jsonl"


def _append(entry: dict[str, Any]) -> None:
    path = _memory_path()
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _load_all() -> list[dict[str, Any]]:
    path = _memory_path()
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:  # noqa: BLE001
                    continue
    except Exception:  # noqa: BLE001
        return []
    return out


@register_tool(sandbox_execution=False)
def mark_as_false_positive(
    agent_state: Any,
    finding_id: str,
    title: str,
    vuln_type: str,
    endpoint: str = "",
    reason: str = "",
    target: str = "",
) -> dict[str, Any]:
    """Persist an FP marker so future scans can recognize this pattern.

    The operator calls this (via panel UI) when a finding is incorrect. Future
    scans that produce similar fingerprints will be auto-downgraded with a
    'previously_marked_fp' tag and can be silently dropped or included with a
    warning, per operator preference.
    """
    from ziro.llm.dedupe import compute_fingerprint

    fp = compute_fingerprint(
        {"title": title, "description": "", "endpoint": endpoint, "target": target}
    )
    entry = {
        "fingerprint": fp,
        "finding_id": finding_id,
        "title": title[:200],
        "vuln_type": vuln_type,
        "endpoint": endpoint,
        "target": target,
        "reason": reason[:500],
        "marked_at": time.time(),
    }
    _append(entry)
    return {"success": True, "fingerprint": fp, "persisted": True}


@register_tool(sandbox_execution=False)
def check_fp_memory(
    agent_state: Any,
    title: str,
    vuln_type: str = "",
    endpoint: str = "",
    target: str = "",
) -> dict[str, Any]:
    """Check if a candidate finding was previously marked as FP by the operator.

    Call BEFORE create_vulnerability_report to decide whether to suppress or
    proceed with a note. Returns match info with confidence.
    """
    from ziro.llm.dedupe import compute_fingerprint

    fp = compute_fingerprint(
        {"title": title, "description": "", "endpoint": endpoint, "target": target}
    )
    entries = _load_all()
    matches = [e for e in entries if e.get("fingerprint") == fp]
    return {
        "success": True,
        "is_known_fp": bool(matches),
        "fingerprint": fp,
        "match_count": len(matches),
        "matches": matches[:5],
        "guidance": (
            "Previously marked FP by operator. Consider skipping this finding OR "
            "include it in the report with a 'previously-dismissed' tag and your "
            "specific justification for why it's valid this time."
            if matches
            else "No prior FP record for this fingerprint."
        ),
    }
