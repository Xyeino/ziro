"""Tests for executor async thread wrapping of sync tools."""

import asyncio
import threading

import pytest


@pytest.mark.asyncio
async def test_sync_tool_runs_in_thread() -> None:
    """Sync tool functions should be executed via asyncio.to_thread, not on the event loop."""
    from unittest.mock import patch

    call_thread_id = None

    def fake_sync_tool(value: str) -> str:
        nonlocal call_thread_id
        call_thread_id = threading.current_thread().ident
        return f"result: {value}"

    event_loop_thread_id = threading.current_thread().ident

    with (
        patch("ziro.tools.executor.get_tool_by_name", return_value=fake_sync_tool),
        patch("ziro.tools.executor.convert_arguments", return_value={"value": "test"}),
        patch("ziro.tools.executor.needs_agent_state", return_value=False),
    ):
        from ziro.tools.executor import _execute_tool_locally

        result = await _execute_tool_locally("fake_tool", None, value="test")

    assert result == "result: test"
    # Sync tool should have run in a different thread
    assert call_thread_id != event_loop_thread_id


@pytest.mark.asyncio
async def test_async_tool_runs_directly() -> None:
    """Async tool functions should be awaited directly, not wrapped in to_thread."""
    from unittest.mock import patch

    async def fake_async_tool(value: str) -> str:
        return f"async: {value}"

    with (
        patch("ziro.tools.executor.get_tool_by_name", return_value=fake_async_tool),
        patch("ziro.tools.executor.convert_arguments", return_value={"value": "hello"}),
        patch("ziro.tools.executor.needs_agent_state", return_value=False),
    ):
        from ziro.tools.executor import _execute_tool_locally

        result = await _execute_tool_locally("fake_async", None, value="hello")

    assert result == "async: hello"
