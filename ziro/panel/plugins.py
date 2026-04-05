"""Plugin system — load custom scanning modules from ~/.ziro/plugins/

Each plugin is a Python file with a `run(target, config)` function.
Plugins are executed in the sandbox alongside built-in tools.

Example plugin (~/.ziro/plugins/custom_scanner.py):

    def run(target: str, config: dict) -> dict:
        import requests
        r = requests.get(f"{target}/custom-endpoint")
        return {
            "name": "Custom Scanner",
            "findings": [{"title": "Found custom issue", "severity": "medium"}],
        }
"""

import importlib.util
import logging
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

PLUGIN_DIR = Path.home() / ".ziro" / "plugins"


def _ensure_plugin_dir() -> None:
    PLUGIN_DIR.mkdir(parents=True, exist_ok=True)
    readme = PLUGIN_DIR / "README.md"
    if not readme.exists():
        readme.write_text(
            "# Ziro Plugins\\n\\n"
            "Place Python files here. Each must have a `run(target, config)` function.\\n\\n"
            "Example:\\n```python\\n"
            "def run(target: str, config: dict) -> dict:\\n"
            "    return {'name': 'My Plugin', 'findings': []}\\n"
            "```\\n"
        )


def list_plugins() -> list[dict[str, Any]]:
    """List available plugins."""
    _ensure_plugin_dir()
    plugins = []
    for f in PLUGIN_DIR.glob("*.py"):
        if f.name.startswith("_"):
            continue
        plugins.append({
            "name": f.stem,
            "path": str(f),
            "size": f.stat().st_size,
        })
    return plugins


def run_plugin(name: str, target: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute a plugin by name."""
    plugin_path = PLUGIN_DIR / f"{name}.py"
    if not plugin_path.exists():
        return {"error": f"Plugin '{name}' not found at {plugin_path}"}

    try:
        spec = importlib.util.spec_from_file_location(f"ziro_plugin_{name}", str(plugin_path))
        if not spec or not spec.loader:
            return {"error": f"Failed to load plugin '{name}'"}

        module = importlib.util.module_from_spec(spec)
        sys.modules[f"ziro_plugin_{name}"] = module
        spec.loader.exec_module(module)

        if not hasattr(module, "run"):
            return {"error": f"Plugin '{name}' has no run() function"}

        result = module.run(target, config or {})
        return {"success": True, "plugin": name, "result": result}
    except Exception as e:
        return {"error": f"Plugin '{name}' failed: {e}"}
    finally:
        sys.modules.pop(f"ziro_plugin_{name}", None)


_ensure_plugin_dir()
