"""Tool creator — scaffold a new tool module + schema XML + registration entry."""

from __future__ import annotations

import os
import re
import textwrap
from typing import Any

from ziro.tools.registry import register_tool


_TOOLS_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _slugify(s: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9_]+", "_", s.strip())
    return s.lower().strip("_") or "new_tool"


@register_tool(sandbox_execution=False)
def create_tool(
    agent_state: Any,
    name: str,
    description: str,
    parameters: list[dict[str, Any]] | None = None,
    implementation_body: str = "",
    sandbox_execution: bool = True,
    agent_roles: list[str] | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Scaffold a new Ziro tool — implementation file + schema XML + init registration.

    parameters: list of dicts {name, type, required, description}
    implementation_body: Python code for the function body. Gets access to
      agent_state + typed args. Must return dict with "success" key.

    Creates directory ziro/tools/<slug>/ with:
    - <slug>_actions.py (decorator + function)
    - <slug>_actions_schema.xml
    - __init__.py (export)

    Appends `from .<slug> import *  # noqa: F403` to ziro/tools/__init__.py so
    the new tool is importable immediately.
    """
    slug = _slugify(name)
    parameters = parameters or []
    agent_roles = agent_roles or []
    pkg_dir = os.path.join(_TOOLS_ROOT, slug)

    if os.path.isdir(pkg_dir) and not overwrite:
        return {"success": False, "error": f"Tool package {slug} already exists. overwrite=True to replace."}

    os.makedirs(pkg_dir, exist_ok=True)

    # Build Python signature
    sig_parts = ["agent_state: Any"]
    for p in parameters:
        pname = p.get("name", "arg")
        ptype = p.get("type", "str")
        type_map = {
            "string": "str", "int": "int", "integer": "int",
            "number": "float", "boolean": "bool", "list": "list", "dict": "dict",
        }
        py_type = type_map.get(ptype, "Any")
        if not p.get("required", False):
            default_map = {"str": '""', "int": "0", "float": "0.0", "bool": "False",
                           "list": "None", "dict": "None", "Any": "None"}
            default = default_map.get(py_type, "None")
            sig_parts.append(f"{pname}: {py_type} = {default}")
        else:
            sig_parts.append(f"{pname}: {py_type}")
    sig = ",\n    ".join(sig_parts)

    # Decorator args
    decorator_args = [f"sandbox_execution={sandbox_execution}"]
    if agent_roles:
        decorator_args.append(f"agent_roles={agent_roles!r}")
    decorator = f"@register_tool({', '.join(decorator_args)})"

    # Body
    body = implementation_body.strip() or 'return {"success": True, "note": "stub — fill in implementation"}'
    indented_body = textwrap.indent(body, "    ")

    actions_code = f'''"""Auto-generated tool module for {slug}."""

from __future__ import annotations

from typing import Any

from ziro.tools.registry import register_tool


{decorator}
def {slug}(
    {sig},
) -> dict[str, Any]:
    """{description}"""
{indented_body}
'''

    with open(os.path.join(pkg_dir, f"{slug}_actions.py"), "w", encoding="utf-8", newline="\n") as f:
        f.write(actions_code)

    # Schema XML
    xml_params = []
    for p in parameters:
        pname = p.get("name", "arg")
        ptype = p.get("type", "string")
        required = str(p.get("required", False)).lower()
        pdesc = p.get("description", "")
        xml_params.append(
            f'      <parameter name="{pname}" type="{ptype}" required="{required}">'
            f"<description>{pdesc}</description></parameter>"
        )
    xml = (
        "<tools>\n"
        f'  <tool name="{slug}">\n'
        f"    <description>{description}</description>\n"
        "    <parameters>\n"
        + ("\n".join(xml_params) if xml_params else "") +
        ("\n" if xml_params else "") +
        "    </parameters>\n"
        "  </tool>\n"
        "</tools>\n"
    )
    with open(os.path.join(pkg_dir, f"{slug}_actions_schema.xml"), "w", encoding="utf-8", newline="\n") as f:
        f.write(xml)

    # __init__.py
    init_code = f'''from .{slug}_actions import {slug}

__all__ = ["{slug}"]
'''
    with open(os.path.join(pkg_dir, "__init__.py"), "w", encoding="utf-8", newline="\n") as f:
        f.write(init_code)

    # Register in tools/__init__.py
    tools_init = os.path.join(_TOOLS_ROOT, "__init__.py")
    try:
        with open(tools_init, encoding="utf-8") as f:
            init_content = f.read()
        import_line = f"from .{slug} import *  # noqa: F403"
        if import_line not in init_content:
            # Insert before `from .registry import`
            marker = "from .registry import ("
            if marker in init_content:
                updated = init_content.replace(marker, f"{import_line}\n{marker}", 1)
                with open(tools_init, "w", encoding="utf-8", newline="\n") as f:
                    f.write(updated)
            else:
                # Append
                with open(tools_init, "a", encoding="utf-8") as f:
                    f.write(f"\n{import_line}\n")
    except Exception as e:  # noqa: BLE001
        return {
            "success": True,
            "warning": f"Tool scaffolded but failed to auto-register in tools/__init__.py: {e!s}",
            "package_dir": pkg_dir,
            "slug": slug,
        }

    return {
        "success": True,
        "slug": slug,
        "package_dir": pkg_dir,
        "files_created": [
            f"{slug}_actions.py",
            f"{slug}_actions_schema.xml",
            "__init__.py",
        ],
        "note": "Registered in ziro/tools/__init__.py. Restart the panel or use importlib.reload to make the tool live.",
    }
