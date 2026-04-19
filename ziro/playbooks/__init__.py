"""Attack playbooks — YAML phase/technique definitions for different target types."""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from ziro.utils.resource_paths import get_ziro_resource_path

logger = logging.getLogger(__name__)


@dataclass
class PlaybookPhase:
    name: str
    objective: str = ""
    timeout_minutes: int = 60
    parallel: bool = False
    techniques: list[dict[str, Any]] = field(default_factory=list)
    sub_agents: list[dict[str, Any]] = field(default_factory=list)
    deliverables: list[str] = field(default_factory=list)


@dataclass
class Playbook:
    name: str
    description: str = ""
    version: int = 1
    target_types: list[str] = field(default_factory=list)
    phases: list[PlaybookPhase] = field(default_factory=list)

    def to_prompt_block(self) -> str:
        lines = [
            f"<playbook name=\"{self.name}\" version=\"{self.version}\">",
            f"  <description>{self.description}</description>",
        ]
        for phase in self.phases:
            lines.append(f"  <phase name=\"{phase.name}\" timeout_minutes=\"{phase.timeout_minutes}\""
                         + (" parallel=\"true\"" if phase.parallel else "") + ">")
            if phase.objective:
                lines.append(f"    <objective>{phase.objective}</objective>")
            for t in phase.techniques:
                lines.append(f"    <technique>{t.get('description', '')}</technique>")
            for sa in phase.sub_agents:
                lines.append(f"    <sub_agent name=\"{sa.get('name', '')}\" skills=\"{','.join(sa.get('skills', []))}\"/>")
            lines.append("  </phase>")
        lines.append("</playbook>")
        return "\n".join(lines)


def _parse_yaml_minimal(text: str) -> dict[str, Any]:
    """Very small YAML-ish parser for our playbook format.

    Supports: scalar values, inline [lists], nested - item blocks, and key:
    indented blocks. Avoids a PyYAML dependency for a simple whitelist
    structure we control.
    """
    # Try real PyYAML first if available
    try:
        import yaml

        return yaml.safe_load(text) or {}
    except Exception:  # noqa: BLE001
        pass

    # Fallback: bare minimum. We control the files so this should rarely run.
    # Simple approach: require PyYAML. Raise a clear error.
    raise RuntimeError(
        "PyYAML required to parse playbooks. Install via `pip install PyYAML` "
        "or ensure the sandbox image includes it."
    )


def _playbook_from_dict(data: dict[str, Any]) -> Playbook:
    phases = []
    for p in data.get("phases", []) or []:
        phases.append(
            PlaybookPhase(
                name=p.get("name", "unnamed"),
                objective=p.get("objective", ""),
                timeout_minutes=int(p.get("timeout_minutes", 60)),
                parallel=bool(p.get("parallel", False)),
                techniques=list(p.get("techniques", []) or []),
                sub_agents=list(p.get("sub_agents", []) or []),
                deliverables=list(p.get("deliverables", []) or []),
            )
        )
    return Playbook(
        name=data.get("name", "unnamed"),
        description=data.get("description", ""),
        version=int(data.get("version", 1)),
        target_types=list(data.get("target_types", []) or []),
        phases=phases,
    )


@lru_cache(maxsize=1)
def _load_all_playbooks() -> dict[str, Playbook]:
    pb_dir = get_ziro_resource_path("playbooks")
    out: dict[str, Playbook] = {}
    if not pb_dir.exists():
        return out
    for path in pb_dir.glob("*.yaml"):
        try:
            data = _parse_yaml_minimal(path.read_text(encoding="utf-8"))
            pb = _playbook_from_dict(data)
            out[pb.name] = pb
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Failed to load playbook {path}: {e}")
    return out


def get_playbook(name: str) -> Playbook | None:
    return _load_all_playbooks().get(name)


def list_playbooks() -> list[dict[str, Any]]:
    return [
        {
            "name": pb.name,
            "description": pb.description,
            "version": pb.version,
            "target_types": pb.target_types,
            "phase_count": len(pb.phases),
        }
        for pb in _load_all_playbooks().values()
    ]


def invalidate_playbook_cache() -> None:
    _load_all_playbooks.cache_clear()
