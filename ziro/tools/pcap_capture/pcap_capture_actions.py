"""pcap capture wrapper around tcpdump running inside the sandbox."""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
import time
import uuid
from typing import Any

from ziro.tools.registry import register_tool


_PCAP_DIR = "/workspace/pcap"
_CAPTURE_REGISTRY: dict[str, dict[str, Any]] = {}


@register_tool(sandbox_execution=True)
def start_pcap_capture(
    agent_state: Any,
    interface: str = "any",
    filter_expr: str = "",
    max_packets: int = 5000,
    max_seconds: int = 300,
    name: str = "",
) -> dict[str, Any]:
    """Start tcpdump capture in the background; returns capture_id for later stop/read.

    interface: any / eth0 / lo / docker0
    filter_expr: BPF filter (e.g. "host 10.0.0.5 and port 443")
    max_packets: auto-stop after N packets
    max_seconds: auto-stop after N seconds

    Writes to /workspace/pcap/<name>.pcap. Call stop_pcap_capture to close.
    """
    os.makedirs(_PCAP_DIR, exist_ok=True)
    cap_id = name.strip() or f"cap_{uuid.uuid4().hex[:8]}"
    pcap_path = os.path.join(_PCAP_DIR, f"{cap_id}.pcap")

    cmd = [
        "tcpdump", "-i", interface, "-w", pcap_path,
        "-c", str(max_packets), "-G", str(max_seconds), "-W", "1", "-U",
    ]
    if filter_expr:
        cmd.extend(shlex.split(filter_expr))

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            preexec_fn=os.setsid,
        )
    except FileNotFoundError:
        return {"success": False, "error": "tcpdump not installed in sandbox"}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"failed to start tcpdump: {e!s}"}

    _CAPTURE_REGISTRY[cap_id] = {
        "pid": proc.pid,
        "path": pcap_path,
        "started_at": time.time(),
        "max_seconds": max_seconds,
        "filter": filter_expr,
        "interface": interface,
    }

    return {
        "success": True,
        "capture_id": cap_id,
        "pcap_path": pcap_path,
        "pid": proc.pid,
        "note": "Capture running. Call stop_pcap_capture(capture_id) to end early, or it auto-stops at max_packets/max_seconds.",
    }


@register_tool(sandbox_execution=True)
def stop_pcap_capture(
    agent_state: Any,
    capture_id: str,
) -> dict[str, Any]:
    """Stop a running tcpdump capture and return file stats."""
    entry = _CAPTURE_REGISTRY.get(capture_id)
    if not entry:
        return {"success": False, "error": f"Unknown capture_id {capture_id!r}"}

    pid = entry["pid"]
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
        time.sleep(0.5)
    except (ProcessLookupError, PermissionError):
        pass

    path = entry["path"]
    size = os.path.getsize(path) if os.path.exists(path) else 0
    _CAPTURE_REGISTRY.pop(capture_id, None)

    return {
        "success": True,
        "capture_id": capture_id,
        "pcap_path": path,
        "size_bytes": size,
        "duration_seconds": round(time.time() - entry["started_at"], 1),
        "note": (
            f"Analyze via: tshark -r {path} -q -z io,stat,1 | "
            f"terminal_execute, or use python tool with scapy.rdpcap()."
        ),
    }


@register_tool(sandbox_execution=True)
def list_pcap_captures(agent_state: Any) -> dict[str, Any]:
    """List active and on-disk pcap captures."""
    active = [
        {
            "capture_id": cid,
            "pid": e["pid"],
            "path": e["path"],
            "filter": e["filter"],
            "interface": e["interface"],
            "uptime_sec": round(time.time() - e["started_at"], 1),
        }
        for cid, e in _CAPTURE_REGISTRY.items()
    ]
    on_disk: list[dict[str, Any]] = []
    if os.path.isdir(_PCAP_DIR):
        for fname in sorted(os.listdir(_PCAP_DIR)):
            if fname.endswith(".pcap"):
                p = os.path.join(_PCAP_DIR, fname)
                on_disk.append({"path": p, "size_bytes": os.path.getsize(p)})

    return {"success": True, "active": active, "on_disk": on_disk}
