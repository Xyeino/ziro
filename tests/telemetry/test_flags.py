from ziro.telemetry.flags import is_otel_enabled, is_posthog_enabled


def test_flags_fallback_to_ziro_telemetry(monkeypatch) -> None:
    monkeypatch.delenv("ZIRO_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("ZIRO_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("ZIRO_TELEMETRY", "0")

    assert is_otel_enabled() is False
    assert is_posthog_enabled() is False


def test_otel_flag_overrides_global_telemetry(monkeypatch) -> None:
    monkeypatch.setenv("ZIRO_TELEMETRY", "0")
    monkeypatch.setenv("ZIRO_OTEL_TELEMETRY", "1")
    monkeypatch.delenv("ZIRO_POSTHOG_TELEMETRY", raising=False)

    assert is_otel_enabled() is True
    assert is_posthog_enabled() is False


def test_posthog_flag_overrides_global_telemetry(monkeypatch) -> None:
    monkeypatch.setenv("ZIRO_TELEMETRY", "0")
    monkeypatch.setenv("ZIRO_POSTHOG_TELEMETRY", "1")
    monkeypatch.delenv("ZIRO_OTEL_TELEMETRY", raising=False)

    assert is_otel_enabled() is False
    assert is_posthog_enabled() is True
