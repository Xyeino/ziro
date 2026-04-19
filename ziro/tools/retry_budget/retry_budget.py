"""Agent-wide retry budget for tool failures.

Tracks consecutive tool failures per-agent. When budget is exhausted, the agent
is terminated cleanly so the parent is notified instead of the sub-agent
burning iterations on repeat failures.

Separate from LLM failure circuit breaker (which tracks LLM 400/500/timeout).
This tracks *tool* failures: SCOPE_VIOLATION, blocked commands, repeated 404s,
connection errors.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field


@dataclass
class _BudgetState:
    consecutive_failures: int = 0
    total_failures: int = 0
    last_failure_reason: str = ""


_STATES: dict[str, _BudgetState] = {}
_LOCK = threading.Lock()


def _get_max_failures() -> int:
    try:
        return int(os.getenv("ZIRO_TOOL_FAILURE_BUDGET", "15"))
    except ValueError:
        return 15


def record_failure(agent_id: str, reason: str = "") -> _BudgetState:
    with _LOCK:
        state = _STATES.setdefault(agent_id, _BudgetState())
        state.consecutive_failures += 1
        state.total_failures += 1
        state.last_failure_reason = reason or state.last_failure_reason
        return state


def record_success(agent_id: str) -> None:
    with _LOCK:
        state = _STATES.get(agent_id)
        if state and state.consecutive_failures:
            state.consecutive_failures = 0


def is_budget_exhausted(agent_id: str) -> tuple[bool, _BudgetState | None]:
    with _LOCK:
        state = _STATES.get(agent_id)
        if not state:
            return False, None
        return state.consecutive_failures >= _get_max_failures(), state


def reset_agent(agent_id: str) -> None:
    with _LOCK:
        _STATES.pop(agent_id, None)
