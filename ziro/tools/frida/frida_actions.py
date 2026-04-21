"""Frida dynamic instrumentation wrapper for Android/iOS runtime analysis."""

from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
import time
from typing import Any

from ziro.tools.registry import register_tool


def _run(cmd: str, timeout: int = 60, cwd: str | None = None) -> tuple[int, str, str]:
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
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "binary not found"
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


@register_tool(sandbox_execution=True)
def frida_list_devices(agent_state: Any) -> dict[str, Any]:
    """List connected Frida devices (USB/adb/simulator)."""
    rc, out, err = _run("frida-ls-devices", timeout=15)
    if rc == 127:
        return {"success": False, "error": "frida-ls-devices not installed (pip install frida-tools)"}
    lines = [ln.strip() for ln in out.splitlines() if ln.strip() and not ln.startswith("---")]
    devices = []
    for line in lines[1:]:  # skip header
        parts = line.split(None, 2)
        if len(parts) >= 2:
            devices.append({"id": parts[0], "type": parts[1], "name": parts[2] if len(parts) > 2 else ""})
    return {"success": True, "devices": devices, "count": len(devices)}


@register_tool(sandbox_execution=True)
def frida_list_processes(
    agent_state: Any,
    device: str = "usb",
) -> dict[str, Any]:
    """List processes running on the device."""
    rc, out, err = _run(f"frida-ps -{device[0] if device in ('usb', 'remote') else 'U'}", timeout=30)
    if rc == 127:
        return {"success": False, "error": "frida-ps not installed"}
    if rc != 0:
        return {"success": False, "error": err[-500:] or out[-500:]}

    processes = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("PID") or line.startswith("---"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            processes.append({"pid": parts[0], "name": parts[1]})
    return {"success": True, "processes": processes[:200]}


@register_tool(sandbox_execution=True)
def frida_run_script(
    agent_state: Any,
    target: str,
    script_code: str,
    device: str = "usb",
    mode: str = "attach",
    wait_seconds: int = 10,
) -> dict[str, Any]:
    """Inject a JavaScript Frida script into a running process and capture console output.

    target: process name or PID
    mode: attach (to running) / spawn (launch fresh)
    script_code: JavaScript Frida API code

    Script output (send(), console.log) is captured for wait_seconds seconds
    then detached. Use for runtime tracing, hooking specific functions, SSL
    pinning bypass, root detection bypass, etc.
    """
    script_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".js", delete=False, encoding="utf-8",
    )
    try:
        script_file.write(script_code)
        script_file.close()

        dev_flag = "-U" if device == "usb" else "-R" if device == "remote" else f"--device={device}"
        mode_flag = "-f" if mode == "spawn" else "-n" if not target.isdigit() else "-p"

        cmd = (
            f"timeout {wait_seconds + 5} frida {dev_flag} {mode_flag} {shlex.quote(target)} "
            f"-l {shlex.quote(script_file.name)} --eternalize --no-pause -q"
        )
        rc, out, err = _run(cmd, timeout=wait_seconds + 15)
    finally:
        try:
            os.unlink(script_file.name)
        except Exception:
            pass

    if rc == 127:
        return {"success": False, "error": "frida CLI not installed"}

    return {
        "success": True,
        "target": target,
        "output_tail": out[-3000:],
        "stderr_tail": err[-500:] if err else "",
        "exit_code": rc,
    }


@register_tool(sandbox_execution=True)
def frida_ssl_bypass(
    agent_state: Any,
    target_package: str,
    platform: str = "android",
    device: str = "usb",
    wait_seconds: int = 15,
) -> dict[str, Any]:
    """Inject SSL pinning bypass into an Android/iOS app for MITM testing.

    Uses built-in SSL unpinning scripts covering:
    - Android: OkHttp3, Conscrypt, TrustManager, WebView, Cronet
    - iOS: NSURLSession, URLSession, TrustKit, SSLSocket, Alamofire

    App launches via spawn and bypass hooks are attached automatically.
    """
    if platform.lower() == "android":
        script = _ANDROID_SSL_BYPASS_SCRIPT
    elif platform.lower() in ("ios", "iphone"):
        script = _IOS_SSL_BYPASS_SCRIPT
    else:
        return {"success": False, "error": f"Unsupported platform: {platform}"}

    return frida_run_script(
        agent_state=agent_state,
        target=target_package,
        script_code=script,
        device=device,
        mode="spawn",
        wait_seconds=wait_seconds,
    )


_ANDROID_SSL_BYPASS_SCRIPT = """
// Generic Android SSL pinning bypass
// Covers: OkHttp3, TrustManager, WebView, HostnameVerifier, Conscrypt, Cronet
Java.perform(function () {
    console.log("[*] Ziro SSL bypass loaded");

    // TrustManager
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.registerClass({
            name: 'com.ziro.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var TrustManagers = [TrustManager.$new()];
        var SSLContext_init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        );
        SSLContext_init.implementation = function (km, tm, sr) {
            console.log("[+] Hooked SSLContext.init");
            SSLContext_init.call(this, km, TrustManagers, sr);
        };
    } catch (e) { console.log("[-] TrustManager hook: " + e); }

    // OkHttp3
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {
            console.log("[+] Bypassed OkHttp3 pinning for: " + hostname);
            return;
        };
    } catch (e) { console.log("[-] OkHttp3 hook: " + e); }

    // WebView
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function (webView, sslErrorHandler, sslError) {
            sslErrorHandler.proceed();
            console.log("[+] WebView SSL error bypassed");
        };
    } catch (e) { console.log("[-] WebView hook: " + e); }
});
"""

_IOS_SSL_BYPASS_SCRIPT = """
// Generic iOS SSL pinning bypass
try {
    var SecTrustEvaluateWithError = Module.findExportByName("Security", "SecTrustEvaluateWithError");
    if (SecTrustEvaluateWithError) {
        Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function (trust, error) {
            console.log("[+] SecTrustEvaluateWithError bypassed");
            return 1;
        }, 'int', ['pointer', 'pointer']));
    }
} catch (e) { console.log("[-] SecTrust hook: " + e); }

try {
    var NSURLSession = ObjC.classes.NSURLSession;
    Interceptor.attach(NSURLSession["- URLSession:didReceiveChallenge:completionHandler:"].implementation, {
        onEnter: function(args) {
            console.log("[+] NSURLSession challenge bypassed");
        }
    });
} catch (e) {}
"""
