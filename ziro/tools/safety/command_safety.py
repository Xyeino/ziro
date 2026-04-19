"""Command safety guardrails for terminal execution.

Hard-blocks or requires approval for commands matching known destructive patterns.
Inspired by reference commandSafety.ts but expanded.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from enum import Enum


class SafetyLevel(Enum):
    SAFE = "safe"
    APPROVAL_REQUIRED = "approval_required"
    BLOCKED = "blocked"


@dataclass
class CommandSafetyResult:
    level: SafetyLevel
    reason: str = ""
    matched_pattern: str = ""
    override_env: str = ""


# HARD BLOCKS — these cannot run even with operator approval in non-interactive mode
_HARD_BLOCK_PATTERNS: list[tuple[str, str]] = [
    # Fork bombs
    (r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:?\s*&\s*\}\s*;?\s*:", "fork bomb"),
    (r"\$\(\s*\$\(\s*\$\(", "recursive command substitution bomb"),
    # Filesystem destruction on paths outside /workspace, /tmp
    (r"\brm\s+(?:-[a-zA-Z]*[rRfF][a-zA-Z]*\s+)+(?!/workspace|/tmp|/var/tmp|\./|[^/-])/?\s*(?:\*)?\s*$",
     "recursive delete of root / system path"),
    (r"\brm\s+-[rRfF]+\s+/\s*$", "rm -rf /"),
    (r"\brm\s+-[rRfF]+\s+/\*", "rm -rf /*"),
    (r"\brm\s+-[rRfF]+\s+~\s*$", "rm -rf ~"),
    (r"\brm\s+-[rRfF]+\s+\$HOME", "rm -rf $HOME"),
    # Disk / device writes
    (r"\bdd\s+(?:[^|&;]*\s+)?of=/dev/(?:sd[a-z]|nvme|hd[a-z]|vd[a-z]|xvd[a-z]|disk|loop)",
     "dd write to block device"),
    (r"\b(?:mkfs|mkfs\.[a-z0-9]+|mke2fs)\b\s+/dev/", "filesystem format of block device"),
    (r"\bshred\b\s+/dev/", "shred block device"),
    (r"\bwipefs\b.*\s+/dev/", "wipefs on device"),
    # Kernel / bootloader destruction
    (r"\bdd\s+(?:[^|&;]*\s+)?of=/boot", "dd overwrite bootloader"),
    (r"\b>\s*/dev/mem\b", "write to /dev/mem"),
    (r"\becho\s+[^|]*>\s*/proc/sysrq-trigger", "sysrq trigger"),
    # Kill everything / system shutdown
    (r"\bkill\s+-9\s+-1\b", "kill all processes"),
    (r"\bkill\s+-KILL\s+-1\b", "kill all processes"),
    (r"\b(?:halt|poweroff|shutdown\s+-h\s+now|init\s+0)\b(?!\s*[&;|]|\s+-h\s+\+[0-9]+)",
     "immediate shutdown"),
    (r"\bshutdown\s+-r\s+now\b", "immediate reboot"),
    (r"\breboot\b\s*(?:[&;]|$)", "immediate reboot"),
    # Fork bomb variants
    (r":\(\)\s*\{\s*:\|:&\s*\}", "fork bomb variant"),
    (r"\bpython3?\s+-c\s+['\"]\s*import\s+os\s*;\s*os\.fork\(\)\s*while", "python fork bomb"),
    # Tarpits on proc / tmpfs
    (r"\byes\s*>.*(?:/dev/full|/proc/)", "yes redirect to special"),
]

# APPROVAL REQUIRED — operator must explicitly OK these in interactive mode
_APPROVAL_PATTERNS: list[tuple[str, str]] = [
    # Persistent backdoors / reverse shells (allowed but approval-gated)
    (r"\bnc\s+(?:-[a-zA-Z]+\s+)*(?:-e|--exec)\b", "netcat reverse shell with -e"),
    (r"\bmkfifo\s+/tmp/[a-zA-Z0-9_-]+\s*;\s*cat", "mkfifo reverse shell"),
    (r"\bbash\s+-i\s+>&\s*/dev/tcp/", "bash reverse shell"),
    (r"\bpython3?\s+-c\s+['\"][^'\"]*socket[^'\"]*\.connect\(", "python reverse shell"),
    (r"\bperl\s+-e\s+['\"][^'\"]*socket[^'\"]*connect\(", "perl reverse shell"),
    (r"\bphp\s+-r\s+['\"][^'\"]*fsockopen", "php reverse shell"),
    (r"\bruby\s+-rsocket\s+-e\b", "ruby reverse shell"),
    (r"\bsocat\b.*\bexec:", "socat exec reverse shell"),
    # SSH / remote exec
    (r"\bssh\s+(?:[^-]\S*\s+)?-o\s+(?:Strict|UserKnownHosts)", "SSH with host key bypass"),
    (r"\bssh\s+[^-]\S+\s+.+", "outbound SSH connection"),
    (r"\bscp\s+[^-]\S+:\S+", "outbound SCP"),
    (r"\brsync\s+.*\s+\S+@\S+:", "outbound rsync"),
    # Privilege escalation attempts
    (r"\bsudo\s+-i\b", "sudo interactive shell"),
    (r"\bsu\s+-", "switch to root"),
    (r"\bsetuid\b|\bchmod\s+(?:\+s|[0-9]*[4567][0-9]{3})\s+", "setuid bit on file"),
    # Package install / system modification
    (r"\bapt(?:-get)?\s+(?:-y\s+)?(?:install|remove|purge|dist-upgrade)", "apt package modification"),
    (r"\byum\s+(?:install|remove)\b", "yum package modification"),
    (r"\bdnf\s+(?:install|remove)\b", "dnf package modification"),
    (r"\bpacman\s+-S\b", "pacman install"),
    (r"\bcurl\b.*\|\s*(?:sh|bash)\s*$", "curl | sh pattern"),
    (r"\bwget\b.*\|\s*(?:sh|bash)\s*$", "wget | sh pattern"),
    # Destructive git / repo operations
    (r"\bgit\s+push\s+(?:-f|--force)", "git force push"),
    (r"\bgit\s+reset\s+--hard", "git hard reset"),
    (r"\bgit\s+clean\s+-[fd]", "git clean"),
    # Mass file writes
    (r"\bfind\s+.*\s+-delete\b", "find with -delete"),
    (r"\bfind\s+.*\s+-exec\s+rm\b", "find -exec rm"),
    # Cron / systemd persistence (for red team engagements, needs RoE approval)
    (r"\bcrontab\s+-[erl]", "crontab modification"),
    (r"\bsystemctl\s+(?:enable|start|daemon-reload)\b", "systemctl service modification"),
]


def _match_any(command: str, patterns: list[tuple[str, str]]) -> tuple[str, str] | None:
    for pat, reason in patterns:
        try:
            if re.search(pat, command, re.IGNORECASE):
                return pat, reason
        except re.error:
            continue
    return None


def check_command_safety(
    command: str,
    *,
    override_env_var: str = "ZIRO_ALLOW_UNSAFE_COMMANDS",
    approval_env_var: str = "ZIRO_AUTO_APPROVE_COMMANDS",
) -> CommandSafetyResult:
    """Classify a shell command by safety level.

    - BLOCKED: hard-destructive patterns (rm -rf /, fork bombs, dd to /dev/sda, ...)
      Can be overridden only by setting ZIRO_ALLOW_UNSAFE_COMMANDS=1 explicitly.
    - APPROVAL_REQUIRED: potentially dangerous but sometimes legitimate on a pentest
      (reverse shells, package installs, ssh, crontab, git force-push). Allowed when
      ZIRO_AUTO_APPROVE_COMMANDS=1 or the operator confirms in interactive mode.
    - SAFE: default path.
    """
    command = command or ""
    if not command.strip():
        return CommandSafetyResult(SafetyLevel.SAFE)

    hard_match = _match_any(command, _HARD_BLOCK_PATTERNS)
    if hard_match:
        pat, reason = hard_match
        if os.getenv(override_env_var, "").strip().lower() in ("1", "true", "yes"):
            return CommandSafetyResult(
                SafetyLevel.APPROVAL_REQUIRED,
                reason=f"{reason} (override via {override_env_var})",
                matched_pattern=pat,
                override_env=override_env_var,
            )
        return CommandSafetyResult(
            SafetyLevel.BLOCKED,
            reason=reason,
            matched_pattern=pat,
            override_env=override_env_var,
        )

    approval_match = _match_any(command, _APPROVAL_PATTERNS)
    if approval_match:
        pat, reason = approval_match
        if os.getenv(approval_env_var, "").strip().lower() in ("1", "true", "yes"):
            return CommandSafetyResult(
                SafetyLevel.SAFE,
                reason=f"{reason} (auto-approved via {approval_env_var})",
                matched_pattern=pat,
            )
        return CommandSafetyResult(
            SafetyLevel.APPROVAL_REQUIRED,
            reason=reason,
            matched_pattern=pat,
            override_env=approval_env_var,
        )

    return CommandSafetyResult(SafetyLevel.SAFE)
