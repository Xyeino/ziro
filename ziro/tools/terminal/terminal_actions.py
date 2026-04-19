from typing import Any

from ziro.tools.registry import register_tool
from ziro.tools.safety import SafetyLevel, check_command_safety


@register_tool
def terminal_execute(
    command: str,
    is_input: bool = False,
    timeout: float | None = None,
    terminal_id: str | None = None,
    no_enter: bool = False,
) -> dict[str, Any]:
    # Safety gate — block destructive commands unless operator override is set.
    # Control key sequences (C-c, Enter, etc.) and is_input mode skip the check.
    if not is_input and command.strip():
        safety = check_command_safety(command)
        if safety.level == SafetyLevel.BLOCKED:
            return {
                "error": (
                    f"Command blocked by safety guardrail: {safety.reason}. "
                    f"Pattern matched: {safety.matched_pattern!r}. "
                    f"If this is intentional, set {safety.override_env}=1 in the "
                    f"panel environment and retry."
                ),
                "safety_level": "blocked",
                "safety_reason": safety.reason,
                "command": command,
                "terminal_id": terminal_id or "default",
                "content": "",
                "status": "blocked",
                "exit_code": None,
                "working_dir": None,
            }
        if safety.level == SafetyLevel.APPROVAL_REQUIRED:
            # In non-interactive scan mode this is effectively a block with a
            # softer message. Operator enables via env var (see safety module).
            return {
                "error": (
                    f"Command requires operator approval: {safety.reason}. "
                    f"To auto-approve this class of commands for the current scan, "
                    f"set {safety.override_env}=1 in the panel environment."
                ),
                "safety_level": "approval_required",
                "safety_reason": safety.reason,
                "command": command,
                "terminal_id": terminal_id or "default",
                "content": "",
                "status": "approval_required",
                "exit_code": None,
                "working_dir": None,
            }

    from .terminal_manager import get_terminal_manager

    manager = get_terminal_manager()

    try:
        return manager.execute_command(
            command=command,
            is_input=is_input,
            timeout=timeout,
            terminal_id=terminal_id,
            no_enter=no_enter,
        )
    except (ValueError, RuntimeError) as e:
        return {
            "error": str(e),
            "command": command,
            "terminal_id": terminal_id or "default",
            "content": "",
            "status": "error",
            "exit_code": None,
            "working_dir": None,
        }
