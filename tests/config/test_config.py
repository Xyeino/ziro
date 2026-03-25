"""Tests for Config save/load with --config override and corrupted config handling."""

import json
import logging

from ziro.config.config import Config


def test_save_respects_config_override(monkeypatch, tmp_path) -> None:
    """Config.save() should write to the override path, not the default."""
    override_path = tmp_path / "custom-config.json"
    monkeypatch.setattr(Config, "_config_file_override", override_path)

    result = Config.save({"env": {"ZIRO_LLM": "test-model"}})

    assert result is True
    assert override_path.exists()
    data = json.loads(override_path.read_text(encoding="utf-8"))
    assert data["env"]["ZIRO_LLM"] == "test-model"


def test_save_without_override_uses_default(monkeypatch, tmp_path) -> None:
    """Config.save() should write to default path when no override is set."""
    monkeypatch.setattr(Config, "_config_file_override", None)
    monkeypatch.setattr(Config, "config_dir", classmethod(lambda cls: tmp_path))

    result = Config.save({"env": {"ZIRO_LLM": "default-model"}})

    assert result is True
    default_path = tmp_path / "cli-config.json"
    assert default_path.exists()


def test_load_corrupted_config_warns(monkeypatch, tmp_path, caplog) -> None:
    """Config.load() should warn when config file is corrupted JSON."""
    config_path = tmp_path / "cli-config.json"
    config_path.write_text("{invalid json!!", encoding="utf-8")
    monkeypatch.setattr(Config, "_config_file_override", config_path)

    with caplog.at_level(logging.WARNING):
        result = Config.load()

    assert result == {}
    assert "corrupted" in caplog.text.lower()


def test_load_missing_config_returns_empty(monkeypatch, tmp_path) -> None:
    """Config.load() should return {} for non-existent config file."""
    monkeypatch.setattr(Config, "_config_file_override", tmp_path / "nonexistent.json")

    result = Config.load()

    assert result == {}


def test_save_current_uses_override(monkeypatch, tmp_path) -> None:
    """Config.save_current() should respect the config file override."""
    override_path = tmp_path / "custom.json"
    override_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(Config, "_config_file_override", override_path)
    monkeypatch.setenv("ZIRO_LLM", "my-model")

    Config.save_current()

    data = json.loads(override_path.read_text(encoding="utf-8"))
    assert data["env"]["ZIRO_LLM"] == "my-model"
