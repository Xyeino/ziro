import contextlib
import json
import os
from pathlib import Path
from typing import Any


ZIRO_API_BASE = "https://models.ziro.ai/api/v1"

# Prefix migration: ZIRO_* is canonical, ZIRO_* accepted as fallback
_LEGACY_PREFIX = "ZIRO_"
_CURRENT_PREFIX = "ZIRO_"


def _env_with_fallback(name: str, default: str | None = None) -> str | None:
    """Read env var with ZIRO_ prefix, falling back to ZIRO_ for compat."""
    upper = name.upper()
    # Try canonical ZIRO_ name first
    val = os.getenv(upper, None)
    if val is not None:
        return val
    # Fallback: if name starts with ZIRO_, try ZIRO_ equivalent
    if upper.startswith(_CURRENT_PREFIX):
        legacy = _LEGACY_PREFIX + upper[len(_CURRENT_PREFIX):]
        val = os.getenv(legacy, None)
        if val is not None:
            return val
    return default


class Config:
    """Configuration Manager for Ziro."""

    # LLM Configuration
    ziro_llm = None
    llm_api_key = None
    llm_api_base = None
    openai_api_base = None
    litellm_base_url = None
    ollama_api_base = None
    ziro_reasoning_effort = "high"
    ziro_llm_max_retries = "5"
    ziro_memory_compressor_timeout = "30"
    llm_timeout = "300"
    _LLM_CANONICAL_NAMES = (
        "ziro_llm",
        "llm_api_key",
        "llm_api_base",
        "openai_api_base",
        "litellm_base_url",
        "ollama_api_base",
        "ziro_reasoning_effort",
        "ziro_llm_max_retries",
        "ziro_memory_compressor_timeout",
        "llm_timeout",
    )

    # Tool & Feature Configuration
    perplexity_api_key = None
    ziro_disable_browser = "false"

    # Runtime Configuration
    ziro_image = "ghcr.io/xyeino/ziro-sandbox:0.1.13"
    ziro_runtime_backend = "docker"
    ziro_sandbox_execution_timeout = "120"
    ziro_sandbox_connect_timeout = "10"

    # Telemetry
    ziro_telemetry = "1"
    ziro_otel_telemetry = None
    ziro_posthog_telemetry = None
    traceloop_base_url = None
    traceloop_api_key = None
    traceloop_headers = None

    # Config file override (set via --config CLI arg)
    _config_file_override: Path | None = None

    @classmethod
    def _tracked_names(cls) -> list[str]:
        return [
            k
            for k, v in vars(cls).items()
            if not k.startswith("_") and k[0].islower() and (v is None or isinstance(v, str))
        ]

    @classmethod
    def tracked_vars(cls) -> list[str]:
        return [name.upper() for name in cls._tracked_names()]

    @classmethod
    def _llm_env_vars(cls) -> set[str]:
        return {name.upper() for name in cls._LLM_CANONICAL_NAMES}

    @classmethod
    def _llm_env_changed(cls, saved_env: dict[str, Any]) -> bool:
        for var_name in cls._llm_env_vars():
            current = os.getenv(var_name)
            if current is None:
                continue
            if saved_env.get(var_name) != current:
                return True
        return False

    @classmethod
    def get(cls, name: str) -> str | None:
        default = getattr(cls, name, None)
        return _env_with_fallback(name, default)

    @classmethod
    def config_dir(cls) -> Path:
        return Path.home() / ".ziro"

    @classmethod
    def config_file(cls) -> Path:
        if cls._config_file_override is not None:
            return cls._config_file_override
        return cls.config_dir() / "cli-config.json"

    @classmethod
    def load(cls) -> dict[str, Any]:
        path = cls.config_file()
        if not path.exists():
            return {}
        try:
            with path.open("r", encoding="utf-8") as f:
                data: dict[str, Any] = json.load(f)
                return data
        except json.JSONDecodeError:
            import logging

            logging.getLogger(__name__).warning(
                "Config file is corrupted and could not be parsed: %s. "
                "Using default settings. Consider deleting or fixing the file.",
                path,
            )
            return {}
        except OSError:
            return {}

    @classmethod
    def save(cls, config: dict[str, Any]) -> bool:
        try:
            config_path = cls.config_file()
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with config_path.open("w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
        except OSError:
            return False
        with contextlib.suppress(OSError):
            config_path.chmod(0o600)  # may fail on Windows
        return True

    @classmethod
    def apply_saved(cls, force: bool = False) -> dict[str, str]:
        saved = cls.load()
        env_vars = saved.get("env", {})
        if not isinstance(env_vars, dict):
            env_vars = {}
        cleared_vars = {
            var_name
            for var_name in cls.tracked_vars()
            if var_name in os.environ and os.environ.get(var_name) == ""
        }
        if cleared_vars:
            for var_name in cleared_vars:
                env_vars.pop(var_name, None)
            if cls._config_file_override is None:
                cls.save({"env": env_vars})
        if cls._llm_env_changed(env_vars):
            for var_name in cls._llm_env_vars():
                env_vars.pop(var_name, None)
            if cls._config_file_override is None:
                cls.save({"env": env_vars})
        applied = {}

        for var_name, var_value in env_vars.items():
            if var_name in cls.tracked_vars() and (force or var_name not in os.environ):
                os.environ[var_name] = var_value
                applied[var_name] = var_value

        return applied

    @classmethod
    def capture_current(cls) -> dict[str, Any]:
        env_vars = {}
        for var_name in cls.tracked_vars():
            value = os.getenv(var_name)
            if value:
                env_vars[var_name] = value
        return {"env": env_vars}

    @classmethod
    def save_current(cls) -> bool:
        existing = cls.load().get("env", {})
        merged = dict(existing)

        for var_name in cls.tracked_vars():
            value = os.getenv(var_name)
            if value is None:
                pass
            elif value == "":
                merged.pop(var_name, None)
            else:
                merged[var_name] = value

        return cls.save({"env": merged})


def apply_saved_config(force: bool = False) -> dict[str, str]:
    return Config.apply_saved(force=force)


def save_current_config() -> bool:
    return Config.save_current()


def resolve_llm_config() -> tuple[str | None, str | None, str | None]:
    """Resolve LLM model, api_key, and api_base based on ZIRO_LLM prefix.

    Returns:
        tuple: (model_name, api_key, api_base)
        - model_name: Original model name (ziro/ prefix preserved for display)
        - api_key: LLM API key
        - api_base: API base URL (auto-set to ZIRO_API_BASE for ziro/ models)
    """
    model = Config.get("ziro_llm")
    if not model:
        return None, None, None

    api_key = Config.get("llm_api_key")

    if model.startswith("ziro/"):
        api_base: str | None = ZIRO_API_BASE
    else:
        api_base = (
            Config.get("llm_api_base")
            or Config.get("openai_api_base")
            or Config.get("litellm_base_url")
            or Config.get("ollama_api_base")
        )

    return model, api_key, api_base
