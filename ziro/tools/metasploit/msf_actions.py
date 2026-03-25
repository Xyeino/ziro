"""Metasploit Framework integration for Ziro.

Provides tools for searching modules, getting module info, and executing
modules via msfconsole in the sandbox terminal.
"""

import json
import logging
import re
from typing import Any

from ziro.tools.registry import register_tool

logger = logging.getLogger(__name__)

# Dangerous modules/actions that should never be auto-executed
_BLOCKED_PAYLOADS = frozenset({
    "cmd/unix/reverse_perl",
    "cmd/unix/reverse_bash",
    "windows/meterpreter/reverse_tcp",
    "windows/x64/meterpreter/reverse_tcp",
    "linux/x64/meterpreter/reverse_tcp",
})

_BLOCKED_POST_MODULES = frozenset({
    "post/multi/manage/shell_to_meterpreter",
    "post/windows/manage/enable_rdp",
    "post/linux/manage/adduser",
})

# Max output length to avoid flooding the LLM context
_MAX_OUTPUT_CHARS = 8000


def _sanitize_msf_command(command: str) -> str | None:
    """Validate and sanitize an msfconsole command. Returns error string if blocked."""
    stripped = command.strip().lower()

    # Block shell escapes
    if stripped.startswith("!") or stripped.startswith("shell"):
        return "Shell escapes are not allowed. Use terminal_execute for shell commands."

    # Block irb/script console
    if stripped in ("irb", "pry"):
        return "Interactive Ruby console is not allowed."

    # Block writing to disk outside workspace
    if re.search(r"set\s+spooldir\s+/(?!workspace)", stripped):
        return "Spool directory must be within /workspace."

    return None


def _build_rc_script(
    module_path: str,
    options: dict[str, str],
    action: str | None = None,
) -> str:
    """Build an msfconsole resource script for module execution."""
    lines = [f"use {module_path}"]

    for key, value in options.items():
        # Escape quotes in values
        safe_value = str(value).replace('"', '\\"')
        lines.append(f'set {key} "{safe_value}"')

    if action:
        lines.append(f"set ACTION {action}")

    # Check/run
    lines.append("check" if action is None else "run -j")
    lines.append("exit")

    return "\n".join(lines)


@register_tool(sandbox_execution=True)
def msf_search(
    query: str,
    module_type: str | None = None,
    platform: str | None = None,
    cve: str | None = None,
) -> dict[str, Any]:
    """Search Metasploit module database."""
    if not query or not query.strip():
        return {"success": False, "error": "Search query cannot be empty"}

    parts = [f"search {query.strip()}"]

    if module_type:
        allowed_types = {"exploit", "auxiliary", "post", "payload", "encoder", "nop", "evasion"}
        if module_type.lower() not in allowed_types:
            return {
                "success": False,
                "error": f"Invalid module_type. Must be one of: {', '.join(sorted(allowed_types))}",
            }
        parts[0] += f" type:{module_type.lower()}"

    if platform:
        parts[0] += f" platform:{platform.lower()}"

    if cve:
        cve_clean = cve.strip().upper()
        if not re.match(r"^CVE-\d{4}-\d+$", cve_clean):
            return {"success": False, "error": f"Invalid CVE format: {cve}. Expected CVE-YYYY-NNNNN"}
        parts[0] += f" cve:{cve_clean.replace('CVE-', '')}"

    command = parts[0]

    return {
        "success": True,
        "command": f"msfconsole -q -x '{command}; exit'",
        "instruction": (
            "Execute this command via terminal_execute to search the Metasploit module database. "
            "Parse the results table to identify relevant modules."
        ),
    }


@register_tool(sandbox_execution=True)
def msf_module_info(
    module_path: str,
) -> dict[str, Any]:
    """Get detailed info about a Metasploit module."""
    if not module_path or not module_path.strip():
        return {"success": False, "error": "module_path cannot be empty"}

    # Validate module path format
    path = module_path.strip()
    valid_prefixes = (
        "exploit/", "auxiliary/", "post/", "payload/",
        "encoder/", "nop/", "evasion/",
    )
    if not any(path.startswith(p) for p in valid_prefixes):
        return {
            "success": False,
            "error": f"Invalid module path. Must start with one of: {', '.join(valid_prefixes)}",
        }

    # Check blocked modules
    for blocked in _BLOCKED_POST_MODULES:
        if blocked in path:
            return {"success": False, "error": f"Module {path} is blocked for safety reasons."}

    return {
        "success": True,
        "command": f"msfconsole -q -x 'info {path}; exit'",
        "instruction": (
            "Execute this command via terminal_execute to get module details including "
            "options, targets, description, and references."
        ),
    }


@register_tool(sandbox_execution=True)
def msf_execute(
    module_path: str,
    options: str,
    action: str | None = None,
    check_only: bool = True,
) -> dict[str, Any]:
    """Execute a Metasploit module against a target.

    By default runs in check-only mode (vulnerability verification without exploitation).
    Set check_only=False to actually run the exploit — use with caution.
    """
    if not module_path or not module_path.strip():
        return {"success": False, "error": "module_path cannot be empty"}

    path = module_path.strip()

    # Validate module path
    valid_prefixes = ("exploit/", "auxiliary/", "post/", "evasion/")
    if not any(path.startswith(p) for p in valid_prefixes):
        return {
            "success": False,
            "error": f"Only exploit, auxiliary, post, and evasion modules can be executed. Got: {path}",
        }

    # Parse options JSON
    try:
        opts = json.loads(options) if isinstance(options, str) else options
        if not isinstance(opts, dict):
            return {"success": False, "error": "options must be a JSON object with key-value pairs"}
    except json.JSONDecodeError as e:
        return {"success": False, "error": f"Invalid JSON in options: {e}"}

    # Require RHOSTS/RHOST
    has_target = any(k.upper() in ("RHOSTS", "RHOST", "TARGET_URI") for k in opts)
    if not has_target and not path.startswith("post/"):
        return {"success": False, "error": "options must include RHOSTS or RHOST for the target"}

    # Block dangerous payloads
    payload = opts.get("PAYLOAD", opts.get("payload", ""))
    if payload and payload in _BLOCKED_PAYLOADS:
        return {
            "success": False,
            "error": f"Payload {payload} is blocked. Use a safer payload like cmd/unix/generic.",
        }

    # Block dangerous post modules
    for blocked in _BLOCKED_POST_MODULES:
        if blocked in path:
            return {"success": False, "error": f"Module {path} is blocked for safety reasons."}

    # Build resource script
    rc_content = _build_rc_script(path, opts, action=action)

    if check_only:
        # Override: only check, don't exploit
        rc_content = rc_content.replace("run -j", "check")

    # Escape for shell
    rc_escaped = rc_content.replace("'", "'\\''")

    return {
        "success": True,
        "mode": "check" if check_only else "exploit",
        "module": path,
        "options": opts,
        "command": f"echo '{rc_escaped}' > /tmp/msf_task.rc && msfconsole -q -r /tmp/msf_task.rc",
        "instruction": (
            f"Execute this command via terminal_execute (timeout=60). "
            f"Mode: {'CHECK ONLY — verifies vulnerability without exploitation' if check_only else 'EXPLOIT — will attempt exploitation'}. "
            f"Parse the output for [+] (success), [-] (failure), or [*] (info) markers."
        ),
        "warning": (
            "This will attempt actual exploitation. Ensure you have authorization."
            if not check_only
            else None
        ),
    }
