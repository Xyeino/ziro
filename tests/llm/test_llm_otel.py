import litellm
import pytest

from ziro.llm.config import LLMConfig
from ziro.llm.llm import LLM


def test_llm_does_not_modify_litellm_callbacks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ZIRO_TELEMETRY", "1")
    monkeypatch.setenv("ZIRO_OTEL_TELEMETRY", "1")
    monkeypatch.setattr(litellm, "callbacks", ["custom-callback"])

    llm = LLM(LLMConfig(model_name="openai/gpt-5.4"), agent_name=None)

    assert llm is not None
    assert litellm.callbacks == ["custom-callback"]
