import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from ziro.utils.resource_paths import get_ziro_resource_path

logger = logging.getLogger(__name__)

_EXCLUDED_CATEGORIES = {"scan_modes", "coordination"}
_FRONTMATTER_PATTERN = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)

# MITRE ATT&CK kill chain phases (TA* tactics).
# https://attack.mitre.org/tactics/enterprise/
KILL_CHAIN_PHASES = {
    "reconnaissance": "TA0043",
    "resource_development": "TA0042",
    "initial_access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege_escalation": "TA0004",
    "defense_evasion": "TA0005",
    "credential_access": "TA0006",
    "discovery": "TA0007",
    "lateral_movement": "TA0008",
    "collection": "TA0009",
    "command_and_control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}


@dataclass
class SkillMetadata:
    """Parsed frontmatter metadata for a skill file.

    Only the metadata is cached — full body is loaded on demand via load_skills().
    """

    name: str
    category: str
    description: str = ""
    path: Path | None = None
    mitre_techniques: list[str] = field(default_factory=list)
    kill_chain_phases: list[str] = field(default_factory=list)
    related_skills: list[str] = field(default_factory=list)

    def frontmatter_summary(self) -> str:
        """One-liner used for progressive disclosure — shown to agents before full read."""
        parts = [f"**{self.name}** ({self.category})"]
        if self.description:
            parts.append(f"— {self.description}")
        if self.kill_chain_phases:
            parts.append(f"[phase: {', '.join(self.kill_chain_phases)}]")
        if self.mitre_techniques:
            parts.append(f"[MITRE: {', '.join(self.mitre_techniques)}]")
        return " ".join(parts)


def _parse_frontmatter(content: str) -> dict[str, object]:
    """Parse the YAML-ish frontmatter block without a yaml dependency.

    Supports scalar values and inline JSON-style lists: `key: [a, b, c]`.
    """
    match = _FRONTMATTER_PATTERN.match(content)
    if not match:
        return {}

    raw = match.group(1)
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


def _read_skill_metadata(file_path: Path, category: str) -> SkillMetadata | None:
    try:
        content = file_path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError, UnicodeDecodeError) as e:
        logger.warning(f"Failed to read skill {file_path}: {e}")
        return None

    data = _parse_frontmatter(content)

    name = str(data.get("name") or file_path.stem)
    description = str(data.get("description") or "")

    raw_techniques = data.get("mitre_techniques", [])
    mitre_techniques = (
        list(raw_techniques) if isinstance(raw_techniques, list) else [str(raw_techniques)]
    )

    raw_phases = data.get("kill_chain_phases", [])
    if isinstance(raw_phases, str):
        # Accept single-value form `kill_chain_phases: initial_access`
        raw_phases = [raw_phases]
    kill_chain_phases = [p for p in raw_phases if p in KILL_CHAIN_PHASES]

    raw_related = data.get("related_skills", [])
    related_skills = list(raw_related) if isinstance(raw_related, list) else []

    return SkillMetadata(
        name=name,
        category=category,
        description=description,
        path=file_path,
        mitre_techniques=[t for t in mitre_techniques if t],
        kill_chain_phases=kill_chain_phases,
        related_skills=related_skills,
    )


@lru_cache(maxsize=1)
def _load_all_metadata() -> dict[str, SkillMetadata]:
    """Scan every skill file once and cache the metadata map {skill_name: SkillMetadata}."""
    skills_dir = get_ziro_resource_path("skills")
    metadata: dict[str, SkillMetadata] = {}

    if not skills_dir.exists():
        return metadata

    for category_dir in skills_dir.iterdir():
        if not category_dir.is_dir() or category_dir.name.startswith("__"):
            continue
        if category_dir.name in _EXCLUDED_CATEGORIES:
            continue

        for file_path in category_dir.glob("*.md"):
            skill_name = file_path.stem
            meta = _read_skill_metadata(file_path, category_dir.name)
            if meta:
                metadata[skill_name] = meta

    return metadata


def invalidate_metadata_cache() -> None:
    """Drop the cached metadata map — call after writing new skill files in tests."""
    _load_all_metadata.cache_clear()


def get_available_skills() -> dict[str, list[str]]:
    metadata = _load_all_metadata()
    categories: dict[str, list[str]] = {}
    for name, meta in metadata.items():
        categories.setdefault(meta.category, []).append(name)
    for cat in categories:
        categories[cat].sort()
    return categories


def get_all_skill_names() -> set[str]:
    return set(_load_all_metadata().keys())


def get_skill_metadata(skill_name: str) -> SkillMetadata | None:
    return _load_all_metadata().get(skill_name)


def get_skills_by_phase(phase: str) -> list[str]:
    """Return skill names whose frontmatter declares the given kill chain phase."""
    if phase not in KILL_CHAIN_PHASES:
        return []
    return sorted(
        name for name, meta in _load_all_metadata().items() if phase in meta.kill_chain_phases
    )


def get_skills_by_technique(technique_id: str) -> list[str]:
    """Return skill names whose frontmatter declares the given MITRE technique (e.g. T1190)."""
    technique_id = technique_id.strip().upper()
    return sorted(
        name for name, meta in _load_all_metadata().items() if technique_id in meta.mitre_techniques
    )


def validate_skill_names(skill_names: list[str]) -> dict[str, list[str]]:
    available_skills = get_all_skill_names()
    valid_skills = []
    invalid_skills = []

    for skill_name in skill_names:
        if skill_name in available_skills:
            valid_skills.append(skill_name)
        else:
            invalid_skills.append(skill_name)

    return {"valid": valid_skills, "invalid": invalid_skills}


def parse_skill_list(skills: str | None) -> list[str]:
    if not skills:
        return []
    return [s.strip() for s in skills.split(",") if s.strip()]


def validate_requested_skills(skill_list: list[str], max_skills: int = 5) -> str | None:
    if len(skill_list) > max_skills:
        return "Cannot specify more than 5 skills for an agent (use comma-separated format)"

    if not skill_list:
        return None

    validation = validate_skill_names(skill_list)
    if validation["invalid"]:
        available_skills = list(get_all_skill_names())
        return (
            f"Invalid skills: {validation['invalid']}. "
            f"Available skills: {', '.join(available_skills)}"
        )

    return None


def generate_skills_description() -> str:
    available_skills = get_available_skills()

    if not available_skills:
        return "No skills available"

    all_skill_names = get_all_skill_names()

    if not all_skill_names:
        return "No skills available"

    sorted_skills = sorted(all_skill_names)
    skills_str = ", ".join(sorted_skills)

    description = f"List of skills to load for this agent (max 5). Available skills: {skills_str}. "

    example_skills = sorted_skills[:2]
    if example_skills:
        example = f"Example: {', '.join(example_skills)} for specialized agent"
        description += example

    return description


def generate_skills_index(include_phase: bool = True) -> str:
    """Human-readable index of all skills with MITRE tags.

    Used by the progressive-disclosure system prompt so the agent sees WHAT
    skills exist without paying the context cost of their full bodies.
    """
    metadata = _load_all_metadata()
    if not metadata:
        return "No skills available"

    by_category: dict[str, list[SkillMetadata]] = {}
    for meta in metadata.values():
        by_category.setdefault(meta.category, []).append(meta)

    lines = ["# Available skills (index only — call read_skill to load full content)"]

    for category in sorted(by_category):
        lines.append(f"\n## {category}")
        for meta in sorted(by_category[category], key=lambda m: m.name):
            summary = f"- `{meta.name}`"
            if meta.description:
                summary += f" — {meta.description}"
            tags = []
            if include_phase and meta.kill_chain_phases:
                tags.append("phase: " + ",".join(meta.kill_chain_phases))
            if meta.mitre_techniques:
                tags.append("MITRE: " + ",".join(meta.mitre_techniques))
            if tags:
                summary += f"  _[{' · '.join(tags)}]_"
            lines.append(summary)

    return "\n".join(lines)


def _get_all_categories() -> dict[str, list[str]]:
    """Get all skill categories including internal ones (scan_modes, coordination)."""
    skills_dir = get_ziro_resource_path("skills")
    all_categories: dict[str, list[str]] = {}

    if not skills_dir.exists():
        return all_categories

    for category_dir in skills_dir.iterdir():
        if category_dir.is_dir() and not category_dir.name.startswith("__"):
            category_name = category_dir.name
            skills = []

            for file_path in category_dir.glob("*.md"):
                skill_name = file_path.stem
                skills.append(skill_name)

            if skills:
                all_categories[category_name] = sorted(skills)

    return all_categories


def load_skill_body(skill_name: str) -> str | None:
    """Load the body of a single skill (frontmatter stripped). Returns None if missing.

    Used by the read_skill tool for progressive disclosure — agents call this
    only when they decide they actually need the full content.
    """
    meta = get_skill_metadata(skill_name)
    if meta is None or meta.path is None:
        return None
    try:
        content = meta.path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError, UnicodeDecodeError) as e:
        logger.warning(f"Failed to read skill body for {skill_name}: {e}")
        return None
    return _FRONTMATTER_PATTERN.sub("", content).lstrip()


def load_skills(skill_names: list[str]) -> dict[str, str]:
    skill_content: dict[str, str] = {}
    skills_dir = get_ziro_resource_path("skills")

    all_categories = _get_all_categories()

    for skill_name in skill_names:
        try:
            skill_path = None

            if "/" in skill_name:
                skill_path = f"{skill_name}.md"
            else:
                for category, skills in all_categories.items():
                    if skill_name in skills:
                        skill_path = f"{category}/{skill_name}.md"
                        break

                if not skill_path:
                    root_candidate = f"{skill_name}.md"
                    if (skills_dir / root_candidate).exists():
                        skill_path = root_candidate

            if skill_path and (skills_dir / skill_path).exists():
                full_path = skills_dir / skill_path
                var_name = skill_name.split("/")[-1]
                content = full_path.read_text(encoding="utf-8")
                content = _FRONTMATTER_PATTERN.sub("", content).lstrip()
                skill_content[var_name] = content
                logger.info(f"Loaded skill: {skill_name} -> {var_name}")
            else:
                logger.warning(f"Skill not found: {skill_name}")

        except (FileNotFoundError, OSError, ValueError) as e:
            logger.warning(f"Failed to load skill {skill_name}: {e}")

    return skill_content
