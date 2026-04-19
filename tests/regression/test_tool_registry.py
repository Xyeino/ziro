"""Regression test — every release must keep the registered tool set stable or growing.

Catches silent tool registration regressions (a new version drops tools without
documenting it). Baseline is locked in .ziro-tool-baseline; update manually
when tools are intentionally removed.
"""

from __future__ import annotations

import os

import pytest


BASELINE_FILE = os.path.join(os.path.dirname(__file__), ".ziro-tool-baseline")


def _current_tools() -> set[str]:
    import ziro.tools  # noqa: F401
    from ziro.tools.registry import get_tool_names

    return set(get_tool_names())


def _baseline_tools() -> set[str]:
    if not os.path.isfile(BASELINE_FILE):
        return set()
    with open(BASELINE_FILE, encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip() and not line.startswith("#")}


def test_tool_set_does_not_shrink() -> None:
    """Current tool set must be a superset of baseline — tools shouldn't silently vanish."""
    baseline = _baseline_tools()
    if not baseline:
        pytest.skip("No baseline locked — run `pytest tests/regression --update-baseline` first")

    current = _current_tools()
    missing = baseline - current
    assert not missing, (
        f"{len(missing)} tool(s) removed vs baseline — "
        f"update tests/regression/.ziro-tool-baseline if intentional. Missing: {sorted(missing)}"
    )


def test_tool_count_minimum() -> None:
    """Sanity floor: at least 100 tools must be registered (v4.2.0+)."""
    current = _current_tools()
    assert len(current) >= 100, f"Tool count dropped below 100: got {len(current)}"


def test_no_duplicate_tool_names() -> None:
    """No two tools may share the same name."""
    import ziro.tools  # noqa: F401
    from ziro.tools.registry import get_tool_names

    names = get_tool_names()
    assert len(names) == len(set(names)), (
        f"Duplicate tool names detected: {[n for n in names if names.count(n) > 1]}"
    )


def test_core_tools_present() -> None:
    """Core infrastructure tools must always be registered."""
    current = _current_tools()
    required = {
        "create_roe",
        "create_conops",
        "create_opplan",
        "think",
        "terminal_execute",
        "python_action",
        "create_agent",
        "finish_scan",
        "create_vulnerability_report",
        "view_engagement_state",
        "load_skill",
        "validate_single_finding",
        "compute_risk_score",
        "map_to_compliance",
        "discover_exploit_chains",
        "kg_add_node",
        "kg_find_attack_paths",
        "memory_store",
        "memory_search",
        "generate_pdf_report",
        "compute_scan_metrics",
    }
    missing = required - current
    assert not missing, f"Core tools missing from registry: {sorted(missing)}"
