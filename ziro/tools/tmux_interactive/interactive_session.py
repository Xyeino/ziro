"""Persistent tmux pane for interactive security tools.

The existing TerminalSession in ziro.tools.terminal injects a PS1 marker into
bash to detect command completion. That model fails for interactive tools that
replace the shell entirely — msfconsole, sliver-client, sqlmap --wizard,
evil-winrm, hydra --pause, wpscan interactive — because once the tool is
running there is no PS1 to match and the session thinks the command is hanging.

InteractiveSession is a separate tmux pane that:
- Launches a long-running tool directly (no PS1 wrapping)
- Uses regex-based prompt detection so the agent knows when the tool is ready
  for input vs still processing
- Supports send-line, send-control-key, capture-buffer, wait-for-pattern, kill
- Lives for the entire scan, not per-command
- Lets the agent drive multi-stage workflows like human operators:
    > sliver
    > generate --http example.com --save /tmp/imp
    > mtls
    > use SESSION_NAME
    > execute-shell
    etc.
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import libtmux

logger = logging.getLogger(__name__)


# Well-known interactive tool prompt signatures. Agents can override via start().
KNOWN_PROMPTS: dict[str, str] = {
    "msfconsole": r"msf\d*(?:\s+[^>]+)?\s*>\s*$",
    "sliver": r"\[server\][^>]*>\s*$|sliver[^>]*>\s*$",
    "sqlmap": r"sqlmap>\s*$",
    "hydra": r"\[q/Q\]\s*>\s*$|hydra[^>]*>\s*$",
    "evil-winrm": r"\*Evil-WinRM\*\s+PS\s+[^>]+>\s*$",
    "python": r">>>\s*$|\.\.\.\s*$",
    "ipython": r"In\s*\[\d+\]:\s*$",
    "pdb": r"\(Pdb\)\s*$",
    "mysql": r"mysql>\s*$",
    "psql": r"\w+=[>#]\s*$",
    "redis": r"\d+\.\d+\.\d+\.\d+:\d+>\s*$",
    "mongo": r">\s*$",
    "ftp": r"ftp>\s*$",
    "telnet": r"\w+:[^$]*\$\s*$|login:\s*$|Password:\s*$",
    "smbclient": r"smb:\s*[^>]*>\s*$",
    "rlwrap": r"[>\$#]\s*$",
    "wpscan": r"wpscan>\s*$",
    "bash": r"[\$#]\s*$",
}


class InteractiveSession:
    POLL_INTERVAL = 0.3
    DEFAULT_WAIT_TIMEOUT = 30.0
    HISTORY_LIMIT = 20_000
    # Max bytes returned on a single capture — trims noisy tools like sqlmap
    MAX_CAPTURE = 16_000

    def __init__(
        self,
        name: str,
        command: str,
        work_dir: str = "/workspace",
        prompt_regex: str | None = None,
    ) -> None:
        self.name = name
        self.command = command
        self.work_dir = str(Path(work_dir).resolve())
        self.prompt_regex = prompt_regex or self._guess_prompt(command)
        self._prompt_re: re.Pattern[str] | None = None
        if self.prompt_regex:
            try:
                self._prompt_re = re.compile(self.prompt_regex, re.MULTILINE)
            except re.error as e:
                logger.warning(f"Invalid prompt regex {self.prompt_regex!r}: {e}")
                self._prompt_re = None

        self._tmux_session_name = f"ziro-int-{name}-{uuid.uuid4().hex[:6]}"
        self.server: libtmux.Server | None = None
        self._session: libtmux.Session | None = None
        self._pane: libtmux.Pane | None = None
        self._closed = False
        self._started_at = time.time()

        self._initialize()

    @staticmethod
    def _guess_prompt(command: str) -> str | None:
        """Map a launch command to a known prompt regex if it matches a known tool."""
        cmd_lower = command.strip().lower()
        # Match on the first whitespace-separated token
        first = cmd_lower.split()[0] if cmd_lower else ""
        # Also handle paths like /usr/bin/msfconsole
        first_basename = first.rsplit("/", 1)[-1] if "/" in first else first
        for tool_name, pattern in KNOWN_PROMPTS.items():
            if tool_name in first_basename or tool_name == first_basename:
                return pattern
        return None

    def _initialize(self) -> None:
        import libtmux  # deferred — only available inside the sandbox container

        self.server = libtmux.Server()
        self._session = self.server.new_session(
            session_name=self._tmux_session_name,
            start_directory=self.work_dir,
            kill_session=True,
            x=200,
            y=50,
        )
        self._session.set_option("history-limit", str(self.HISTORY_LIMIT))

        window = self._session.active_window
        self._pane = window.active_pane

        # Launch the command directly in the pane
        self._pane.send_keys(self.command, enter=True)
        logger.info(
            "Started interactive session %s (%s) in tmux %s",
            self.name,
            self.command,
            self._tmux_session_name,
        )

    def _capture_raw(self) -> str:
        if not self._pane:
            raise RuntimeError("Interactive session not initialized")
        lines = self._pane.cmd("capture-pane", "-J", "-pS", "-").stdout
        content = "\n".join(line.rstrip() for line in lines)
        if len(content) > self.MAX_CAPTURE:
            content = "[...truncated...]\n" + content[-self.MAX_CAPTURE:]
        return content

    def capture(self, lines: int | None = None) -> str:
        """Return the current pane buffer. Pass lines=N to trim to the last N lines."""
        content = self._capture_raw()
        if lines and lines > 0:
            all_lines = content.splitlines()
            return "\n".join(all_lines[-lines:])
        return content

    def is_at_prompt(self) -> bool:
        """True if the current buffer ends at the configured prompt pattern."""
        if not self._prompt_re:
            return False
        content = self._capture_raw()
        tail = "\n".join(content.splitlines()[-5:])
        return bool(self._prompt_re.search(tail))

    def wait_for_prompt(self, timeout: float | None = None) -> tuple[bool, str]:
        """Block until the configured prompt appears, or until timeout.

        Returns (hit_prompt, current_buffer).
        """
        deadline = time.time() + (timeout or self.DEFAULT_WAIT_TIMEOUT)
        while time.time() < deadline:
            if self.is_at_prompt():
                return True, self._capture_raw()
            time.sleep(self.POLL_INTERVAL)
        return False, self._capture_raw()

    def wait_for_pattern(
        self, pattern: str, timeout: float | None = None
    ) -> tuple[bool, str]:
        """Block until a custom regex appears anywhere in the buffer, or timeout."""
        try:
            compiled = re.compile(pattern, re.MULTILINE | re.DOTALL)
        except re.error as e:
            return False, f"Invalid pattern: {e}"

        deadline = time.time() + (timeout or self.DEFAULT_WAIT_TIMEOUT)
        while time.time() < deadline:
            content = self._capture_raw()
            if compiled.search(content):
                return True, content
            time.sleep(self.POLL_INTERVAL)
        return False, self._capture_raw()

    def send_line(
        self, text: str, wait_for_prompt: bool = True, timeout: float | None = None
    ) -> tuple[bool, str]:
        """Send a line of input (with Enter) and optionally wait for the prompt again.

        Returns (prompt_returned, buffer_after).
        """
        if not self._pane:
            raise RuntimeError("Interactive session not initialized")
        self._pane.send_keys(text, enter=True)
        time.sleep(self.POLL_INTERVAL)
        if wait_for_prompt:
            return self.wait_for_prompt(timeout)
        time.sleep(self.POLL_INTERVAL)
        return True, self._capture_raw()

    def send_key(self, key: str) -> str:
        """Send a raw key (e.g., C-c, Enter, Up) without adding Enter."""
        if not self._pane:
            raise RuntimeError("Interactive session not initialized")
        self._pane.send_keys(key, enter=False)
        time.sleep(self.POLL_INTERVAL)
        return self._capture_raw()

    def interrupt(self) -> str:
        """Send Ctrl+C to the pane."""
        return self.send_key("C-c")

    def is_alive(self) -> bool:
        if self._closed or not self._session or not self.server:
            return False
        try:
            return self._session.id in [s.id for s in self.server.sessions]
        except (AttributeError, OSError):
            return False

    def kill(self) -> None:
        if self._closed:
            return
        try:
            if self._session:
                self._session.kill()
        except (AttributeError, OSError) as e:
            logger.debug("Error killing interactive session %s: %s", self.name, e)
        self._closed = True
        self._session = None
        self._pane = None
        self.server = None

    def info(self) -> dict[str, object]:
        return {
            "name": self.name,
            "command": self.command,
            "prompt_regex": self.prompt_regex,
            "tmux_name": self._tmux_session_name,
            "alive": self.is_alive(),
            "uptime_sec": round(time.time() - self._started_at, 1),
            "at_prompt": self.is_at_prompt() if self.is_alive() else False,
        }
