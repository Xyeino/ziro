"""Threat actor profile loader for adversary emulation.

Profiles live as markdown files under ziro/skills/threat_actors/ with an
extended frontmatter schema describing a named threat group's TTPs,
preferred tooling, and operator style. When an agent is spawned with a
threat actor profile, the content is injected into its system prompt so
it emulates that adversary's TTPs during testing.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from ziro.utils.resource_paths import get_ziro_resource_path

logger = logging.getLogger(__name__)

_FRONTMATTER_PATTERN = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)


@dataclass
class ThreatActorProfile:
    name: str
    description: str = ""
    aliases: list[str] = field(default_factory=list)
    attribution: str = ""
    primary_motivation: list[str] = field(default_factory=list)
    sophistication: str = ""
    preferred_tools: list[str] = field(default_factory=list)
    tactics: dict[str, list[str]] = field(default_factory=dict)
    body: str = ""
    path: Path | None = None

    def all_techniques(self) -> set[str]:
        techniques: set[str] = set()
        for phase_techniques in self.tactics.values():
            techniques.update(phase_techniques)
        return techniques

    def summary(self) -> str:
        parts = [f"**{self.name}** — {self.description or '(no description)'}"]
        if self.attribution:
            parts.append(f"Attribution: {self.attribution}")
        if self.primary_motivation:
            parts.append(f"Motivation: {', '.join(self.primary_motivation)}")
        if self.aliases:
            parts.append(f"Aliases: {', '.join(self.aliases)}")
        return "\n".join(parts)


_TACTIC_KEYS = {
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
}


def _parse_frontmatter_block(raw: str) -> dict[str, object]:
    result: dict[str, object] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if value.startswith("[") and value.endswith("]"):
            items = [v.strip().strip("\"'") for v in value[1:-1].split(",")]
            result[key] = [i for i in items if i]
        else:
            result[key] = value.strip("\"'")
    return result


def _parse_profile(path: Path) -> ThreatActorProfile | None:
    try:
        content = path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError, UnicodeDecodeError) as e:
        logger.warning(f"Failed to read threat actor profile {path}: {e}")
        return None

    match = _FRONTMATTER_PATTERN.match(content)
    if not match:
        logger.warning(f"Threat actor profile {path} missing frontmatter")
        return None

    data = _parse_frontmatter_block(match.group(1))
    body = _FRONTMATTER_PATTERN.sub("", content).lstrip()

    name = str(data.get("name") or path.stem)
    description = str(data.get("description") or "")
    aliases_raw = data.get("aliases", [])
    aliases = list(aliases_raw) if isinstance(aliases_raw, list) else []

    motivation_raw = data.get("primary_motivation", [])
    if isinstance(motivation_raw, str):
        motivation = [motivation_raw]
    else:
        motivation = list(motivation_raw)

    sophistication = str(data.get("sophistication") or "")

    tools_raw = data.get("preferred_tools", [])
    preferred_tools = list(tools_raw) if isinstance(tools_raw, list) else []

    tactics: dict[str, list[str]] = {}
    for key in _TACTIC_KEYS:
        value = data.get(key, [])
        if isinstance(value, list):
            tactics[key] = [str(v) for v in value]
        elif isinstance(value, str) and value:
            tactics[key] = [value]

    return ThreatActorProfile(
        name=name,
        description=description,
        aliases=aliases,
        attribution=str(data.get("attribution") or ""),
        primary_motivation=motivation,
        sophistication=sophistication,
        preferred_tools=preferred_tools,
        tactics=tactics,
        body=body,
        path=path,
    )


@lru_cache(maxsize=1)
def _load_all_profiles() -> dict[str, ThreatActorProfile]:
    """Scan and cache all threat actor profiles, keyed by primary name and aliases."""
    profiles_dir = get_ziro_resource_path("skills") / "threat_actors"
    out: dict[str, ThreatActorProfile] = {}

    if not profiles_dir.exists():
        return out

    for file_path in profiles_dir.glob("*.md"):
        profile = _parse_profile(file_path)
        if not profile:
            continue
        out[profile.name] = profile
        for alias in profile.aliases:
            out.setdefault(alias, profile)

    return out


def invalidate_profiles_cache() -> None:
    _load_all_profiles.cache_clear()


def get_threat_actor(name: str | None) -> ThreatActorProfile | None:
    if not name:
        return None
    normalized = name.strip().lower().replace("-", "_").replace(" ", "_")
    profiles = _load_all_profiles()
    return profiles.get(normalized)


def list_threat_actors() -> list[str]:
    """Return the canonical names of registered profiles (without aliases)."""
    seen: set[str] = set()
    names: list[str] = []
    for profile in _load_all_profiles().values():
        if profile.name not in seen:
            names.append(profile.name)
            seen.add(profile.name)
    return sorted(names)


def render_threat_actor_prompt(profile: ThreatActorProfile) -> str:
    """Produce a system-prompt-ready adversary emulation block."""
    lines = [
        "# Adversary Emulation Mode",
        "",
        f"You are operating in **{profile.name}** emulation mode. You must mimic",
        f"this threat actor's tactics, techniques, and operator style for the duration",
        f"of this engagement. Every decision should answer: \"would {profile.name} do this?\"",
        "",
    ]

    if profile.description:
        lines.append(f"**Profile**: {profile.description}")
    if profile.attribution:
        lines.append(f"**Attribution**: {profile.attribution}")
    if profile.primary_motivation:
        lines.append(f"**Motivation**: {', '.join(profile.primary_motivation)}")
    if profile.sophistication:
        lines.append(f"**Sophistication**: {profile.sophistication}")
    if profile.aliases:
        lines.append(f"**Aliases**: {', '.join(profile.aliases)}")
    if profile.preferred_tools:
        lines.append(f"**Preferred tools**: {', '.join(profile.preferred_tools)}")

    if profile.tactics:
        lines.append("")
        lines.append("## TTPs by Kill Chain Phase (MITRE ATT&CK)")
        for phase, techniques in profile.tactics.items():
            if techniques:
                lines.append(f"- **{phase.replace('_', ' ').title()}**: {', '.join(techniques)}")

    if profile.body.strip():
        lines.append("")
        lines.append("## Operator Playbook")
        lines.append(profile.body.strip())

    lines.append("")
    lines.append("## Emulation Rules")
    lines.append("- Always prefer techniques from this profile over generic approaches")
    lines.append("- Flag deviations from the profile explicitly in your reasoning")
    lines.append("- Note any profile technique that is not applicable to this target")
    lines.append("- Do NOT simulate destructive impact actions against production targets")
    lines.append("- Document emulated TTPs in the final report for defensive mapping")

    return "\n".join(lines)
