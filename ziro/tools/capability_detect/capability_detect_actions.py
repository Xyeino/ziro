"""Probe sandbox for installed tooling and produce a capabilities manifest.

Inspired by reference capability registry. Runs a single batched shell
probe listing ~60 common pentest binaries, parses what's present + versions,
and caches the manifest so every agent knows what's available without trying
and failing on missing tools.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from functools import lru_cache
from typing import Any

from ziro.tools.registry import register_tool


# Tool name -> version flag (None = just check existence)
_TOOLS_TO_CHECK: dict[str, tuple[str | None, str]] = {
    # Network / recon
    "nmap": ("--version", "Nmap"),
    "masscan": ("--version", "masscan"),
    "rustscan": ("--version", "rustscan"),
    "subfinder": ("--version", "subfinder"),
    "amass": ("--version", "amass"),
    "assetfinder": ("--version", "assetfinder"),
    "httpx": ("--version", "httpx"),
    "katana": ("--version", "katana"),
    "gospider": ("--version", "gospider"),
    "hakrawler": (None, "hakrawler"),
    "waybackurls": (None, "waybackurls"),
    "gau": (None, "gau"),
    "dalfox": ("--version", "dalfox"),
    "nuclei": ("-version", "nuclei"),
    "afrog": ("-V", "afrog"),
    "jaeles": ("--help", "jaeles"),
    "wafw00f": ("--version", "wafw00f"),
    "wpscan": ("--version", "wpscan"),
    "wapiti": ("--version", "wapiti"),
    # Web app
    "ffuf": ("--version", "ffuf"),
    "feroxbuster": ("--version", "feroxbuster"),
    "dirsearch": ("--version", "dirsearch"),
    "gobuster": ("--version", "gobuster"),
    "arjun": ("--version", "arjun"),
    "commix": ("--version", "commix"),
    "sqlmap": ("--version", "sqlmap"),
    "xsstrike": (None, "xsstrike"),
    "zaproxy": ("--version", "zaproxy"),
    "nikto": ("-Version", "nikto"),
    # Secrets
    "trufflehog": ("--version", "trufflehog"),
    "gitleaks": ("version", "gitleaks"),
    "semgrep": ("--version", "semgrep"),
    "bandit": ("--version", "bandit"),
    "trivy": ("--version", "trivy"),
    # Password / auth
    "hydra": ("-h", "hydra"),
    "medusa": ("-h", "medusa"),
    "hashcat": ("--version", "hashcat"),
    "john": ("--version", "john"),
    "cewl": ("--version", "cewl"),
    # Exploitation
    "msfconsole": ("--version", "msfconsole"),
    "msfvenom": ("--version", "msfvenom"),
    "searchsploit": ("-h", "searchsploit"),
    "evil-winrm": ("--version", "evil-winrm"),
    "impacket-GetNPUsers": (None, "impacket"),
    "impacket-psexec": (None, "impacket"),
    "responder": ("--version", "responder"),
    "crackmapexec": ("--version", "crackmapexec"),
    "netexec": ("--version", "netexec"),
    "bloodhound-python": (None, "bloodhound"),
    "sliver-client": (None, "sliver"),
    # Smart contracts
    "slither": ("--version", "slither"),
    "mythril": ("version", "mythril"),
    "echidna-test": ("--version", "echidna"),
    # Generic
    "curl": ("--version", "curl"),
    "wget": ("--version", "wget"),
    "jq": ("--version", "jq"),
    "openssl": ("version", "openssl"),
    "git": ("--version", "git"),
    "docker": ("--version", "docker"),
    "tcpdump": ("--version", "tcpdump"),
    "socat": ("-V", "socat"),
    "ncat": ("--version", "ncat"),
    # Browser automation
    "playwright": (None, "playwright"),
    "chromium": ("--version", "chromium"),
    # Useful Python packages (checked via python -c)
}


def _run_quick(cmd: str, timeout: float = 5.0) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        combined = (result.stdout or "") + (result.stderr or "")
        return True, combined[:500]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False, ""


@lru_cache(maxsize=1)
def _detect_all() -> dict[str, Any]:
    detected: dict[str, dict[str, Any]] = {}
    missing: list[str] = []

    for tool, (version_arg, display) in _TOOLS_TO_CHECK.items():
        path = shutil.which(tool)
        if not path:
            missing.append(tool)
            continue

        version_str = ""
        if version_arg:
            cmd = f"{tool} {version_arg}"
            ok, output = _run_quick(cmd, timeout=4.0)
            if ok and output:
                # Grab the first non-empty line, strip ANSI
                for line in output.split("\n"):
                    line = line.strip()
                    if line and not line.startswith("usage:"):
                        version_str = line[:120]
                        break

        detected[tool] = {
            "path": path,
            "display": display,
            "version": version_str,
        }

    return {
        "detected_count": len(detected),
        "missing_count": len(missing),
        "detected": detected,
        "missing": missing,
    }


def invalidate_capability_cache() -> None:
    _detect_all.cache_clear()


@register_tool(sandbox_execution=True)
def detect_capabilities(
    agent_state: Any,
    refresh: bool = False,
) -> dict[str, Any]:
    """Probe the sandbox for installed pentest tooling and return the manifest.

    Checks ~60 common tools (nmap, sqlmap, msfconsole, hashcat, trufflehog,
    sliver-client, slither, trivy, nuclei, ffuf, etc.) and returns what's
    present with versions. Cached per-process — pass refresh=true to re-probe.

    Agent should call this once at scan start, then reference the manifest
    before attempting to use tools so it doesn't waste iterations on missing
    binaries.
    """
    if refresh:
        invalidate_capability_cache()
    result = _detect_all()

    # Group by category for readable output
    categories = {
        "network": ["nmap", "masscan", "rustscan", "subfinder", "amass", "httpx",
                    "katana", "gospider", "gau", "waybackurls"],
        "web": ["ffuf", "feroxbuster", "dirsearch", "arjun", "sqlmap", "dalfox",
                "nuclei", "afrog", "wafw00f", "wpscan", "nikto"],
        "secrets": ["trufflehog", "gitleaks", "semgrep", "bandit", "trivy"],
        "password": ["hydra", "medusa", "hashcat", "john", "cewl"],
        "exploit": ["msfconsole", "msfvenom", "searchsploit", "sliver-client",
                    "evil-winrm", "crackmapexec", "netexec", "responder"],
        "smart_contract": ["slither", "mythril", "echidna-test"],
        "generic": ["curl", "wget", "jq", "openssl", "git", "docker", "tcpdump"],
    }

    by_category: dict[str, list[str]] = {}
    for cat, tools in categories.items():
        present = [t for t in tools if t in result["detected"]]
        by_category[cat] = present

    return {
        "success": True,
        "total_checked": len(_TOOLS_TO_CHECK),
        "detected_count": result["detected_count"],
        "missing_count": result["missing_count"],
        "by_category": by_category,
        "missing": result["missing"],
        "note": "Tools in `missing` are NOT available in this sandbox. Do not attempt to call them. If you need one, request its installation via an apt/pipx command (which will be gated by the command safety + approval system).",
    }
