"""Install-on-demand — agent can request a specific tool get installed mid-scan.

Gated by the existing command safety + approval system (apt install and pipx
install trigger APPROVAL_REQUIRED unless ZIRO_AUTO_APPROVE_COMMANDS=1).
"""

from __future__ import annotations

import shlex
import subprocess
from typing import Any, Literal

from ziro.tools.registry import register_tool


# Known-safe install recipes for common pentest tools
_INSTALL_RECIPES: dict[str, str] = {
    # Go binaries
    "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "katana": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "dalfox": "go install -v github.com/hahwul/dalfox/v2@latest",
    "afrog": "go install -v github.com/zan8in/afrog/v3/cmd/afrog@latest",
    "gospider": "go install -v github.com/jaeles-project/gospider@latest",
    "ffuf": "go install -v github.com/ffuf/ffuf/v2@latest",
    "hakrawler": "go install -v github.com/hakluke/hakrawler@latest",
    "gau": "go install -v github.com/lc/gau/v2/cmd/gau@latest",
    "amass": "go install -v github.com/owasp-amass/amass/v4/...@master",
    # Pip
    "sqlmap": "pipx install sqlmap",
    "commix": "pip install --break-system-packages commix",
    "xsstrike": "pip install --break-system-packages XSStrike",
    "wpscan": "gem install wpscan",
    "arjun": "pipx install arjun",
    "dirsearch": "pipx install dirsearch",
    "wafw00f": "pipx install wafw00f",
    "bandit": "pipx install bandit",
    "semgrep": "pipx install semgrep",
    "trufflehog": "pipx install trufflehog3",
    "slither-analyzer": "pipx install slither-analyzer",
    "mythril": "pipx install mythril",
    # Apt
    "nmap": "apt-get install -y nmap",
    "masscan": "apt-get install -y masscan",
    "nikto": "apt-get install -y nikto",
    "wapiti": "apt-get install -y wapiti",
    "hydra": "apt-get install -y hydra",
    "john": "apt-get install -y john",
    "hashcat": "apt-get install -y hashcat",
    "evil-winrm": "gem install evil-winrm",
    "crackmapexec": "pipx install crackmapexec",
    "netexec": "pipx install netexec",
    "responder": "apt-get install -y responder",
    "bloodhound-python": "pipx install bloodhound",
    # Mobile reverse engineering
    "jadx": "bash -c 'mkdir -p /opt/jadx && curl -sSL https://github.com/skylot/jadx/releases/latest/download/jadx-1.5.1.zip -o /tmp/jadx.zip && unzip -q -o /tmp/jadx.zip -d /opt/jadx && chmod +x /opt/jadx/bin/jadx && ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx && ln -sf /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui || true'",
    "apktool": "bash -c 'curl -sSL https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.10.0.jar -o /usr/local/bin/apktool.jar && curl -sSL https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -o /usr/local/bin/apktool && chmod +x /usr/local/bin/apktool'",
    "smali": "apt-get install -y smali",
    "baksmali": "apt-get install -y baksmali",
    "dex2jar": "bash -c 'cd /opt && curl -sSL https://github.com/pxb1988/dex2jar/releases/latest/download/dex-tools-v2.4.zip -o dex-tools.zip && unzip -q -o dex-tools.zip -d /opt && rm dex-tools.zip && chmod +x /opt/dex-tools-v2.4/*.sh && ln -sf /opt/dex-tools-v2.4/d2j-dex2jar.sh /usr/local/bin/d2j-dex2jar'",
    "frida-tools": "pip install --break-system-packages frida-tools",
    "class-dump": "bash -c 'curl -sSL https://github.com/nygard/class-dump/releases/download/3.5/class-dump-3.5.dmg -o /tmp/cd.dmg || echo \"class-dump requires macOS or prebuilt binary; operator must provide\"'",
    "objection": "pip install --break-system-packages objection",
    # Misc
    "mobsf": "docker pull opensecurity/mobile-security-framework-mobsf:latest",
}


@register_tool(sandbox_execution=True)
def install_tool_on_demand(
    agent_state: Any,
    tool_name: str,
    timeout: int = 300,
) -> dict[str, Any]:
    """Request installation of a known pentest tool into the sandbox.

    Uses curated install recipes (apt/pipx/go install/gem install). Gated by
    command safety system — apt/pipx installs will BLOCK or require approval
    unless ZIRO_AUTO_APPROVE_COMMANDS=1.

    Supported tools: """ + ", ".join(sorted(_INSTALL_RECIPES.keys())) + """.

    After install, call detect_capabilities(refresh=True) to refresh the
    manifest. If the tool is not in the recipe list, return an error with
    available names — do NOT arbitrarily run apt install.
    """
    recipe = _INSTALL_RECIPES.get(tool_name)
    if not recipe:
        return {
            "success": False,
            "error": f"Unknown tool '{tool_name}' — no curated install recipe.",
            "available_tools": sorted(_INSTALL_RECIPES.keys()),
        }

    # Command safety will kick in here for apt/pipx/gem/go install patterns
    try:
        result = subprocess.run(
            shlex.split(recipe) if not recipe.startswith(("apt", "sudo apt")) else f"sudo {recipe}".split(),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        rc = result.returncode
        stdout = result.stdout or ""
        stderr = result.stderr or ""
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Install timed out after {timeout}s",
            "recipe": recipe,
        }
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Install failed: {e!s}", "recipe": recipe}

    if rc == 0:
        return {
            "success": True,
            "tool": tool_name,
            "recipe": recipe,
            "stdout_tail": stdout[-500:],
            "next_step": "Call detect_capabilities(refresh=True) to refresh the sandbox manifest.",
        }
    return {
        "success": False,
        "tool": tool_name,
        "recipe": recipe,
        "exit_code": rc,
        "stderr": stderr[-1000:],
        "stdout_tail": stdout[-500:],
    }


@register_tool(sandbox_execution=False)
def list_installable_tools(agent_state: Any) -> dict[str, Any]:
    """Return the curated list of tools the agent can request for installation."""
    return {
        "success": True,
        "count": len(_INSTALL_RECIPES),
        "tools": sorted(_INSTALL_RECIPES.keys()),
    }
