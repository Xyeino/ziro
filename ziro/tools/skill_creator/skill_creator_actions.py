"""Skill creator — scaffold a new skill markdown file with frontmatter from a structured spec."""

from __future__ import annotations

import os
import re
from typing import Any

from ziro.tools.registry import register_tool


_SKILLS_ROOT = os.path.join(os.path.dirname(__file__), "..", "..", "skills")
_SKILLS_ROOT = os.path.abspath(_SKILLS_ROOT)


def _slugify(s: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9_]+", "_", s.strip())
    return s.lower().strip("_") or "skill"


@register_tool(sandbox_execution=False)
def create_skill(
    agent_state: Any,
    name: str,
    description: str,
    body: str,
    category: str = "vulnerabilities",
    mitre_techniques: list[str] | None = None,
    kill_chain_phases: list[str] | None = None,
    related_skills: list[str] | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Scaffold a new Ziro skill markdown file with frontmatter.

    Categories: vulnerabilities / frameworks / protocols / cloud / technologies
                / tooling / reconnaissance / analysis / scan_modes / threat_actors.

    The created skill is immediately discoverable by agents via load_skill /
    read_skill — no restart required.

    Writes to ziro/skills/<category>/<slug>.md.
    """
    category = (category or "vulnerabilities").strip().strip("/")
    cat_dir = os.path.join(_SKILLS_ROOT, category)
    if not os.path.isdir(cat_dir):
        return {
            "success": False,
            "error": f"Unknown category: {category}",
            "available": [d for d in os.listdir(_SKILLS_ROOT) if os.path.isdir(os.path.join(_SKILLS_ROOT, d))],
        }

    slug = _slugify(name)
    path = os.path.join(cat_dir, f"{slug}.md")
    if os.path.exists(path) and not overwrite:
        return {
            "success": False,
            "error": f"Skill already exists at {path} — pass overwrite=True to replace.",
        }

    # Build frontmatter
    def _yaml_list(items: list[str] | None) -> str:
        if not items:
            return "[]"
        return "[" + ", ".join(items) + "]"

    frontmatter = (
        "---\n"
        f"name: {slug}\n"
        f"description: {description.strip()}\n"
        f"mitre_techniques: {_yaml_list(mitre_techniques)}\n"
        f"kill_chain_phases: {_yaml_list(kill_chain_phases)}\n"
        f"related_skills: {_yaml_list(related_skills)}\n"
        "---\n\n"
    )

    # Write
    try:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(frontmatter)
            f.write(body.strip() + "\n")
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to write skill: {e!s}"}

    # Reload skill registry so agents pick it up
    try:
        from ziro.skills import reload_skills

        reload_skills()
    except Exception:
        pass

    return {
        "success": True,
        "path": path,
        "slug": slug,
        "category": category,
        "note": "Skill is now loadable via load_skill(skill_name=%r). Panel will show it after next agent iteration." % slug,
    }


@register_tool(sandbox_execution=False)
def list_skill_categories(agent_state: Any) -> dict[str, Any]:
    """List available skill categories."""
    if not os.path.isdir(_SKILLS_ROOT):
        return {"success": False, "error": "Skills root not found"}
    cats = []
    for d in sorted(os.listdir(_SKILLS_ROOT)):
        full = os.path.join(_SKILLS_ROOT, d)
        if os.path.isdir(full):
            n_skills = len([f for f in os.listdir(full) if f.endswith(".md")])
            cats.append({"name": d, "skill_count": n_skills})
    return {"success": True, "categories": cats}
