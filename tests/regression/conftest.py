"""Regression test configuration — supports --update-baseline to refresh locked tool set."""

from __future__ import annotations

import os

import pytest


BASELINE_FILE = os.path.join(os.path.dirname(__file__), ".ziro-tool-baseline")


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--update-baseline",
        action="store_true",
        default=False,
        help="Write current tool set to baseline file (tests/regression/.ziro-tool-baseline)",
    )


@pytest.fixture(scope="session", autouse=True)
def _maybe_update_baseline(request: pytest.FixtureRequest) -> None:
    if not request.config.getoption("--update-baseline"):
        return

    import ziro.tools  # noqa: F401
    from ziro.tools.registry import get_tool_names

    tools = sorted(get_tool_names())
    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        f.write("# Ziro tool baseline — regenerate via `pytest tests/regression --update-baseline`\n")
        f.write("# Regression tests verify no tools disappear between releases.\n")
        for t in tools:
            f.write(t + "\n")

    print(f"\n[update-baseline] Wrote {len(tools)} tools to {BASELINE_FILE}")
    pytest.exit(f"Baseline updated with {len(tools)} tools — re-run tests without --update-baseline.", returncode=0)
