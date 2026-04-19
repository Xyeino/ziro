"""Out-of-band (OOB) interaction tools for blind vulnerability testing.

Wraps `interactsh-client` which is already in the sandbox image. Generates a
unique subdomain under oast.fun / oast.online / interact.sh, polls the
ProjectDiscovery interact server for any DNS/HTTP/SMTP callbacks.

Critical for blind SSRF, blind XXE, blind SQLi, OOB SSTI, blind RCE, etc.
"""

from __future__ import annotations

import json
import os
import shlex
import signal
import subprocess
import threading
import time
import uuid
from typing import Any

from ziro.tools.registry import register_tool


_OOB_STATE_DIR = "/workspace/.ziro-oob"
_LOCK = threading.Lock()
_RUNNING: dict[str, dict[str, Any]] = {}  # session_id -> state


def _state_file(session_id: str) -> str:
    return os.path.join(_OOB_STATE_DIR, f"{session_id}.json")


def _load_state(session_id: str) -> dict[str, Any] | None:
    path = _state_file(session_id)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return None


def _save_state(session_id: str, data: dict[str, Any]) -> None:
    os.makedirs(_OOB_STATE_DIR, exist_ok=True)
    with open(_state_file(session_id), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


@register_tool(sandbox_execution=True)
def start_oob_listener(
    agent_state: Any,
    server: str = "oast.fun",
    session_name: str = "",
) -> dict[str, Any]:
    """Start an interactsh-client session and return the unique callback URL.

    The returned URL (e.g. c0f5jn.oast.fun) can be embedded in blind SSRF/XXE/
    SQLi/SSTI payloads. Call poll_oob_interactions periodically to see which
    payloads actually triggered a callback.

    server: oast.fun (default), oast.online, oast.me, or interact.sh.
    """
    session_id = session_name.strip() or f"oob_{uuid.uuid4().hex[:8]}"

    # Launch interactsh-client in JSON-stream mode to a file we tail
    output_file = f"/tmp/interactsh_{session_id}.jsonl"
    cmd = [
        "interactsh-client",
        "-s", server,
        "-json",
        "-o", output_file,
        "-nc",  # no color
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid,
        )
    except FileNotFoundError:
        return {
            "success": False,
            "error": "interactsh-client not installed in sandbox",
            "install_hint": "install_tool_on_demand is not yet wired for interactsh — add to Dockerfile or use curl-based OOB.",
        }
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"failed to start interactsh-client: {e!s}"}

    # interactsh-client prints the callback domain to stdout on start
    callback_domain = ""
    for _ in range(30):  # wait up to 6s for startup
        line = proc.stdout.readline().decode(errors="replace").strip()
        if f".{server}" in line:
            # Extract like "c0f5jn.oast.fun"
            import re

            m = re.search(rf"([a-z0-9]+\.{re.escape(server)})", line)
            if m:
                callback_domain = m.group(1)
                break
        if proc.poll() is not None:
            break
        time.sleep(0.2)

    if not callback_domain:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            pass
        return {
            "success": False,
            "error": "Could not extract callback domain from interactsh-client output",
        }

    state = {
        "session_id": session_id,
        "pid": proc.pid,
        "callback_domain": callback_domain,
        "server": server,
        "output_file": output_file,
        "started_at": time.time(),
        "callbacks_seen": 0,
    }
    with _LOCK:
        _RUNNING[session_id] = state
    _save_state(session_id, state)

    return {
        "success": True,
        "session_id": session_id,
        "callback_domain": callback_domain,
        "callback_url_http": f"http://{callback_domain}/",
        "callback_url_https": f"https://{callback_domain}/",
        "dns_probe_name": f"probe.{callback_domain}",
        "usage": "Embed the callback_domain in blind payloads. Call poll_oob_interactions with session_id to see triggered callbacks.",
    }


@register_tool(sandbox_execution=True)
def poll_oob_interactions(
    agent_state: Any,
    session_id: str,
    wait_seconds: float = 0.0,
) -> dict[str, Any]:
    """Poll interactsh for any callbacks recorded against the listener.

    Returns list of callback events with protocol (DNS/HTTP/SMTP), source IP,
    timestamp, and raw request data. Use to confirm blind vulnerability
    triggered.

    wait_seconds: how long to wait for new callbacks. Default 0 = immediate check.
    """
    state = _load_state(session_id)
    if not state:
        return {"success": False, "error": f"Unknown session_id {session_id!r}"}

    if wait_seconds > 0:
        time.sleep(min(wait_seconds, 60))

    output_file = state.get("output_file", "")
    if not os.path.isfile(output_file):
        return {
            "success": True,
            "session_id": session_id,
            "callbacks": [],
            "count": 0,
            "note": "No output file yet — listener running but no callbacks recorded.",
        }

    callbacks: list[dict[str, Any]] = []
    try:
        with open(output_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    callbacks.append(
                        {
                            "protocol": event.get("protocol", ""),
                            "source_ip": event.get("remote-address", ""),
                            "timestamp": event.get("timestamp", ""),
                            "unique_id": event.get("unique-id", ""),
                            "raw_request_preview": (event.get("raw-request") or "")[:500],
                        }
                    )
                except Exception:  # noqa: BLE001
                    continue
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to read output: {e!s}"}

    # Update persistent state
    state["callbacks_seen"] = len(callbacks)
    _save_state(session_id, state)

    return {
        "success": True,
        "session_id": session_id,
        "callback_domain": state.get("callback_domain", ""),
        "count": len(callbacks),
        "callbacks": callbacks[-50:],
    }


@register_tool(sandbox_execution=True)
def stop_oob_listener(
    agent_state: Any,
    session_id: str,
) -> dict[str, Any]:
    """Stop the interactsh-client session and return the final callback count."""
    state = _load_state(session_id)
    if not state:
        return {"success": False, "error": f"Unknown session_id {session_id!r}"}

    pid = state.get("pid")
    try:
        if pid:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            time.sleep(0.3)
    except Exception:  # noqa: BLE001
        pass

    with _LOCK:
        _RUNNING.pop(session_id, None)

    return {
        "success": True,
        "session_id": session_id,
        "callbacks_seen": state.get("callbacks_seen", 0),
        "duration_seconds": round(time.time() - state.get("started_at", time.time()), 1),
    }
