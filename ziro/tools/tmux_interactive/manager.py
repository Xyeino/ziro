"""Per-agent manager for InteractiveSession instances."""

from __future__ import annotations

import atexit
import contextlib
import threading
from typing import Any

from ziro.tools.context import get_current_agent_id

from .interactive_session import InteractiveSession


class InteractiveSessionManager:
    MAX_SESSIONS_PER_AGENT = 8

    def __init__(self) -> None:
        self._by_agent: dict[str, dict[str, InteractiveSession]] = {}
        self._lock = threading.Lock()
        atexit.register(self._cleanup_all)

    def _agent_sessions(self) -> dict[str, InteractiveSession]:
        agent_id = get_current_agent_id()
        with self._lock:
            return self._by_agent.setdefault(agent_id, {})

    def list_sessions(self) -> list[dict[str, Any]]:
        sessions = self._agent_sessions()
        return [s.info() for s in sessions.values()]

    def get(self, name: str) -> InteractiveSession | None:
        return self._agent_sessions().get(name)

    def start(
        self,
        name: str,
        command: str,
        work_dir: str = "/workspace",
        prompt_regex: str | None = None,
    ) -> dict[str, Any]:
        sessions = self._agent_sessions()

        if name in sessions:
            existing = sessions[name]
            if existing.is_alive():
                return {
                    "success": False,
                    "error": f"Session '{name}' already exists and is alive",
                    "info": existing.info(),
                }
            # Prune a dead session slot
            del sessions[name]

        if len(sessions) >= self.MAX_SESSIONS_PER_AGENT:
            return {
                "success": False,
                "error": (
                    f"Reached {self.MAX_SESSIONS_PER_AGENT} interactive sessions for this agent. "
                    "Kill some before starting new ones."
                ),
            }

        try:
            session = InteractiveSession(
                name=name,
                command=command,
                work_dir=work_dir,
                prompt_regex=prompt_regex,
            )
        except Exception as e:  # noqa: BLE001
            return {"success": False, "error": f"Failed to start session: {e!s}"}

        with self._lock:
            self._by_agent.setdefault(get_current_agent_id(), {})[name] = session

        return {"success": True, "info": session.info()}

    def send(
        self,
        name: str,
        text: str,
        wait_for_prompt: bool = True,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        session = self.get(name)
        if session is None:
            return {"success": False, "error": f"No session named '{name}'"}
        if not session.is_alive():
            return {"success": False, "error": f"Session '{name}' is dead"}

        hit_prompt, buffer = session.send_line(
            text, wait_for_prompt=wait_for_prompt, timeout=timeout
        )
        return {
            "success": True,
            "at_prompt": hit_prompt,
            "buffer": buffer,
            "info": session.info(),
        }

    def send_key(self, name: str, key: str) -> dict[str, Any]:
        session = self.get(name)
        if session is None:
            return {"success": False, "error": f"No session named '{name}'"}
        if not session.is_alive():
            return {"success": False, "error": f"Session '{name}' is dead"}
        buffer = session.send_key(key)
        return {"success": True, "buffer": buffer, "info": session.info()}

    def read(self, name: str, lines: int | None = None) -> dict[str, Any]:
        session = self.get(name)
        if session is None:
            return {"success": False, "error": f"No session named '{name}'"}
        return {
            "success": True,
            "buffer": session.capture(lines=lines),
            "info": session.info(),
        }

    def wait_for(
        self, name: str, pattern: str | None = None, timeout: float | None = None
    ) -> dict[str, Any]:
        session = self.get(name)
        if session is None:
            return {"success": False, "error": f"No session named '{name}'"}

        if pattern:
            matched, buffer = session.wait_for_pattern(pattern, timeout=timeout)
        else:
            matched, buffer = session.wait_for_prompt(timeout=timeout)

        return {
            "success": True,
            "matched": matched,
            "buffer": buffer,
            "info": session.info(),
        }

    def kill(self, name: str) -> dict[str, Any]:
        sessions = self._agent_sessions()
        session = sessions.get(name)
        if session is None:
            return {"success": False, "error": f"No session named '{name}'"}
        session.kill()
        with self._lock:
            sessions.pop(name, None)
        return {"success": True, "killed": name}

    def kill_all(self) -> dict[str, Any]:
        sessions = self._agent_sessions()
        killed = []
        for name, session in list(sessions.items()):
            with contextlib.suppress(Exception):
                session.kill()
            killed.append(name)
        with self._lock:
            self._by_agent[get_current_agent_id()] = {}
        return {"success": True, "killed": killed}

    def _cleanup_all(self) -> None:
        with self._lock:
            for agent_sessions in self._by_agent.values():
                for session in agent_sessions.values():
                    with contextlib.suppress(Exception):
                        session.kill()
            self._by_agent.clear()


_manager: InteractiveSessionManager | None = None


def get_manager() -> InteractiveSessionManager:
    global _manager
    if _manager is None:
        _manager = InteractiveSessionManager()
    return _manager
