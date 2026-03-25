"""Tests for MemoryCompressor error fallback behavior."""

import os
from unittest.mock import patch

import pytest


def test_summarize_messages_error_returns_concatenation() -> None:
    """When LLM call fails, _summarize_messages should return concatenated originals."""
    with patch.dict(os.environ, {"ZIRO_LLM": "test-model"}):
        from ziro.llm.memory_compressor import _summarize_messages

    messages = [
        {"role": "user", "content": "First message"},
        {"role": "assistant", "content": "Second message"},
    ]

    with patch("ziro.llm.memory_compressor.litellm") as mock_litellm:
        mock_litellm.completion.side_effect = RuntimeError("LLM unavailable")
        with patch("ziro.llm.memory_compressor.resolve_llm_config", return_value=(None, None, None)):
            result = _summarize_messages(messages, "test-model", timeout=5)

    assert result["role"] == "user"
    assert "First message" in result["content"]
    assert "Second message" in result["content"]
    assert "context_summary" in result["content"]


def test_summarize_messages_empty_response_returns_originals() -> None:
    """When LLM returns empty summary, should still return usable content."""
    with patch.dict(os.environ, {"ZIRO_LLM": "test-model"}):
        from ziro.llm.memory_compressor import _summarize_messages

    messages = [
        {"role": "user", "content": "Important context"},
    ]

    mock_response = type("Response", (), {
        "choices": [type("Choice", (), {"message": type("Msg", (), {"content": ""})()})()]
    })()

    with patch("ziro.llm.memory_compressor.litellm") as mock_litellm:
        mock_litellm.completion.return_value = mock_response
        with patch("ziro.llm.memory_compressor.resolve_llm_config", return_value=(None, None, None)):
            result = _summarize_messages(messages, "test-model", timeout=5)

    assert result["role"] == "user"
    assert "Important context" in result["content"]


def test_summarize_messages_empty_list() -> None:
    """Empty message list should return a placeholder summary."""
    with patch.dict(os.environ, {"ZIRO_LLM": "test-model"}):
        from ziro.llm.memory_compressor import _summarize_messages

    result = _summarize_messages([], "test-model")
    assert result["role"] == "user"
    assert "No messages to summarize" in result["content"]
