"""Mobile app decompilation — APK via jadx/apktool, IPA via class-dump/otool."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import time
from typing import Any

from ziro.tools.registry import register_tool


_DECOMP_ROOT = "/workspace/mobile-projects"


def _run(cmd: str, timeout: int = 300, cwd: str | None = None) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=cwd,
        )
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except FileNotFoundError as e:
        return 127, "", f"binary not found: {e}"
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


def _slug(s: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in s)[:80]


@register_tool(sandbox_execution=True)
def decompile_apk(
    agent_state: Any,
    apk_path: str,
    method: str = "jadx",
    project_name: str = "",
    timeout: int = 600,
) -> dict[str, Any]:
    """Decompile an Android APK to source code.

    method:
      jadx    — decompile DEX to Java source (readable) + resources
      apktool — decompile to smali + resources (closer to bytecode)

    Output lands in /workspace/mobile-projects/<project_name>/<method>/.

    After decompilation, operator can browse/edit via the Code Workbench
    panel tab. Agent tools (read_workspace_file, search_workspace_files,
    etc.) work on the resulting tree.
    """
    if not os.path.isabs(apk_path):
        apk_path = os.path.join("/workspace", apk_path)
    if not os.path.isfile(apk_path):
        return {"success": False, "error": f"APK not found: {apk_path}"}

    basename = os.path.splitext(os.path.basename(apk_path))[0]
    name = _slug(project_name or basename) or "apk_project"
    project_dir = os.path.join(_DECOMP_ROOT, name)
    os.makedirs(project_dir, exist_ok=True)

    out_dir = os.path.join(project_dir, method)
    if os.path.exists(out_dir):
        shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(out_dir, exist_ok=True)

    if method == "jadx":
        cmd = f"jadx -d {shlex.quote(out_dir)} --show-bad-code {shlex.quote(apk_path)}"
    elif method == "apktool":
        cmd = f"apktool d -o {shlex.quote(out_dir)} -f {shlex.quote(apk_path)}"
    else:
        return {"success": False, "error": f"Unknown method: {method}. Use jadx or apktool."}

    t0 = time.time()
    rc, out, err = _run(cmd, timeout=timeout)
    duration = round(time.time() - t0, 1)

    if rc == 127:
        # Try to auto-install and retry once. Discover latest jadx version
        # dynamically rather than hardcoding (the asset name embeds the version,
        # so the path '/releases/latest/download/jadx-X.Y.Z.zip' won't auto-redirect
        # to the right file when X.Y.Z drifts).
        install_cmd = {
            "jadx": (
                "set -e; "
                'JADX_VER=$(curl -fsSL https://api.github.com/repos/skylot/jadx/releases/latest '
                '| grep \'"tag_name"\' | head -1 | sed -E \'s/.*"v?([^"]+)".*/\\1/\'); '
                "JADX_VER=${JADX_VER:-1.5.5}; "
                "mkdir -p /opt/jadx && "
                "curl -fsSL --retry 3 https://github.com/skylot/jadx/releases/download/v${JADX_VER}/jadx-${JADX_VER}.zip -o /tmp/jadx.zip && "
                "test -s /tmp/jadx.zip && "
                "unzip -q -o /tmp/jadx.zip -d /opt/jadx && "
                "chmod +x /opt/jadx/bin/jadx && "
                "ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx"
            ),
            "apktool": (
                "set -e; "
                "curl -fsSL --retry 3 https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.10.0.jar -o /usr/local/bin/apktool.jar && "
                "test -s /usr/local/bin/apktool.jar && "
                "curl -fsSL --retry 3 https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -o /usr/local/bin/apktool && "
                "chmod +x /usr/local/bin/apktool"
            ),
        }.get(method)

        if install_cmd:
            try:
                subprocess.run(
                    ["bash", "-c", install_cmd],
                    capture_output=True, text=True, timeout=180, check=False,
                )
                # Retry
                rc, out, err = _run(cmd, timeout=timeout)
            except Exception:  # noqa: BLE001
                pass

        if rc == 127:
            return {
                "success": False,
                "error": f"{method} not installed in sandbox and auto-install failed",
                "hint": (
                    f"Run install_tool_on_demand(tool_name={method!r}) manually, "
                    "or rebuild the sandbox image with the latest Dockerfile which "
                    "bakes jadx + apktool in."
                ),
            }

    # Scan result
    file_count = 0
    for _, _, files in os.walk(out_dir):
        file_count += len(files)

    if file_count == 0:
        return {
            "success": False,
            "error": f"{method} produced no output",
            "stdout_tail": out[-500:],
            "stderr_tail": err[-500:],
        }

    # Copy original APK alongside for reference
    apk_copy = os.path.join(project_dir, os.path.basename(apk_path))
    if not os.path.exists(apk_copy):
        try:
            shutil.copy2(apk_path, apk_copy)
        except Exception:
            pass

    # Try to detect AndroidManifest.xml for metadata
    manifest_info: dict[str, Any] = {}
    for candidate in (
        os.path.join(out_dir, "AndroidManifest.xml"),
        os.path.join(out_dir, "resources", "AndroidManifest.xml"),
    ):
        if os.path.isfile(candidate):
            try:
                with open(candidate, encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                import re
                pkg = re.search(r'package="([^"]+)"', content)
                ver = re.search(r'android:versionName="([^"]+)"', content)
                min_sdk = re.search(r'minSdkVersion="([^"]+)"', content)
                target_sdk = re.search(r'targetSdkVersion="([^"]+)"', content)
                manifest_info = {
                    "package": pkg.group(1) if pkg else "",
                    "version": ver.group(1) if ver else "",
                    "min_sdk": min_sdk.group(1) if min_sdk else "",
                    "target_sdk": target_sdk.group(1) if target_sdk else "",
                }
            except Exception:
                pass
            break

    return {
        "success": True,
        "project": name,
        "method": method,
        "project_dir": project_dir,
        "source_dir": out_dir,
        "file_count": file_count,
        "duration_seconds": duration,
        "manifest": manifest_info,
        "next_step": (
            f"Browse source via Code Workbench panel tab (project={name!r}) "
            "or call read_workspace_file / search_workspace_files to analyze."
        ),
    }


@register_tool(sandbox_execution=True)
def decompile_ipa(
    agent_state: Any,
    ipa_path: str,
    method: str = "auto",
    project_name: str = "",
    timeout: int = 600,
) -> dict[str, Any]:
    """Decompile an iOS IPA to Objective-C headers + Swift demangled symbols.

    method:
      class-dump — dump ObjC class interfaces from binary
      otool      — Mach-O inspection + load commands
      auto       — run class-dump then otool, produces richer output

    Also unzips the IPA to extract Payload/<AppName>.app/ tree for resource/
    plist inspection.
    """
    if not os.path.isabs(ipa_path):
        ipa_path = os.path.join("/workspace", ipa_path)
    if not os.path.isfile(ipa_path):
        return {"success": False, "error": f"IPA not found: {ipa_path}"}

    basename = os.path.splitext(os.path.basename(ipa_path))[0]
    name = _slug(project_name or basename) or "ipa_project"
    project_dir = os.path.join(_DECOMP_ROOT, name)
    os.makedirs(project_dir, exist_ok=True)

    # 1. Unzip
    unzip_dir = os.path.join(project_dir, "unzipped")
    if not os.path.isdir(unzip_dir):
        os.makedirs(unzip_dir, exist_ok=True)
        rc, out, err = _run(f"unzip -o -q {shlex.quote(ipa_path)} -d {shlex.quote(unzip_dir)}", timeout=120)
        if rc != 0 and rc != 127:
            return {"success": False, "error": f"unzip failed: {err[-300:]}"}

    # 2. Find Mach-O binary
    payload_dir = os.path.join(unzip_dir, "Payload")
    binary_path = ""
    app_bundle = ""
    if os.path.isdir(payload_dir):
        for entry in os.listdir(payload_dir):
            if entry.endswith(".app"):
                app_bundle = os.path.join(payload_dir, entry)
                app_name = entry[:-4]
                cand = os.path.join(app_bundle, app_name)
                if os.path.isfile(cand):
                    binary_path = cand
                break

    if not binary_path:
        return {
            "success": False,
            "error": "No Mach-O binary found in IPA Payload/",
            "project_dir": project_dir,
        }

    results: dict[str, Any] = {}

    # 3. class-dump
    if method in ("class-dump", "auto"):
        cd_out = os.path.join(project_dir, "class-dump")
        os.makedirs(cd_out, exist_ok=True)
        rc, out, err = _run(
            f"class-dump -H -o {shlex.quote(cd_out)} {shlex.quote(binary_path)}",
            timeout=timeout,
        )
        if rc == 127:
            results["class_dump"] = "not installed"
        elif rc != 0:
            results["class_dump"] = f"failed: {err[-300:]}"
        else:
            n = len([f for f in os.listdir(cd_out) if f.endswith(".h")])
            results["class_dump"] = f"{n} headers"
            results["class_dump_dir"] = cd_out

    # 4. otool metadata
    if method in ("otool", "auto"):
        rc, out, err = _run(f"otool -L {shlex.quote(binary_path)}", timeout=60)
        otool_out = os.path.join(project_dir, "otool.txt")
        if rc == 0:
            with open(otool_out, "w", encoding="utf-8") as f:
                f.write("=== otool -L (dylibs) ===\n" + out + "\n\n")
            rc2, out2, _ = _run(f"otool -hv {shlex.quote(binary_path)}", timeout=60)
            if rc2 == 0:
                with open(otool_out, "a", encoding="utf-8") as f:
                    f.write("=== otool -hv (header) ===\n" + out2 + "\n\n")
            rc3, out3, _ = _run(f"otool -L {shlex.quote(binary_path)} | head -20", timeout=60)
            results["otool_file"] = otool_out

    # 5. Info.plist
    info_plist = os.path.join(app_bundle, "Info.plist") if app_bundle else ""
    plist_data: dict[str, Any] = {}
    if info_plist and os.path.isfile(info_plist):
        rc, out, err = _run(f"plutil -convert xml1 -o - {shlex.quote(info_plist)}", timeout=30)
        if rc == 0:
            import re
            pkg = re.search(r"<key>CFBundleIdentifier</key>\s*<string>([^<]+)</string>", out)
            ver = re.search(r"<key>CFBundleShortVersionString</key>\s*<string>([^<]+)</string>", out)
            plist_data = {
                "bundle_id": pkg.group(1) if pkg else "",
                "version": ver.group(1) if ver else "",
            }

    return {
        "success": True,
        "project": name,
        "method": method,
        "project_dir": project_dir,
        "binary_path": binary_path,
        "app_bundle": app_bundle,
        "plist": plist_data,
        "decompile_results": results,
        "next_step": f"Browse via Code Workbench (project={name!r}).",
    }


@register_tool(sandbox_execution=False)
def list_mobile_projects(agent_state: Any) -> dict[str, Any]:
    """List decompiled mobile projects available in /workspace/mobile-projects/."""
    if not os.path.isdir(_DECOMP_ROOT):
        return {"success": True, "projects": [], "count": 0}

    projects = []
    for entry in sorted(os.listdir(_DECOMP_ROOT)):
        path = os.path.join(_DECOMP_ROOT, entry)
        if not os.path.isdir(path):
            continue
        methods = [
            d for d in os.listdir(path)
            if os.path.isdir(os.path.join(path, d)) and d in ("jadx", "apktool", "class-dump", "unzipped")
        ]
        total_size = 0
        try:
            for root, _, files in os.walk(path):
                for f in files:
                    try:
                        total_size += os.path.getsize(os.path.join(root, f))
                    except Exception:
                        pass
        except Exception:
            pass
        projects.append({
            "name": entry,
            "path": path,
            "methods": methods,
            "size_bytes": total_size,
        })

    return {"success": True, "projects": projects, "count": len(projects)}
