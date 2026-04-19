"""MobSF (Mobile Security Framework) wrapper — static analysis for APK / IPA / AAB / XAPK."""

from __future__ import annotations

import os
import time
from typing import Any

from ziro.tools.registry import register_tool


@register_tool(sandbox_execution=True)
def mobsf_static_scan(
    agent_state: Any,
    file_path: str,
    mobsf_url: str = "http://localhost:8000",
    api_key: str = "",
    poll_interval: float = 3.0,
    poll_timeout: int = 600,
) -> dict[str, Any]:
    """Upload an APK/IPA/AAB/XAPK/ZIP to MobSF and run static analysis.

    MobSF must be running at mobsf_url (default: http://localhost:8000).
    Set api_key via MOBSF_API_KEY env var or pass directly. Returns:
    - hash + app_name
    - findings count by severity (critical/high/medium)
    - trackers
    - permissions
    - secrets_found
    - domains (exfil-looking domains)

    Agent then pulls full report via mobsf_report(hash) if needed.
    """
    if not os.path.isabs(file_path):
        file_path = os.path.join("/workspace", file_path)
    if not os.path.isfile(file_path):
        return {"success": False, "error": f"File not found: {file_path}"}

    try:
        import httpx
    except ImportError:
        return {"success": False, "error": "httpx not installed"}

    key = api_key or os.getenv("MOBSF_API_KEY", "")
    if not key:
        return {"success": False, "error": "MOBSF_API_KEY not set — export it or pass api_key="}

    headers = {"Authorization": key, "X-Mobsf-Api-Key": key}
    mobsf_url = mobsf_url.rstrip("/")

    try:
        # 1. Upload
        with httpx.Client(timeout=120.0) as client:
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                r = client.post(f"{mobsf_url}/api/v1/upload", files=files, headers=headers)
            if r.status_code != 200:
                return {"success": False, "error": f"Upload failed HTTP {r.status_code}: {r.text[:500]}"}
            upload_data = r.json()
            file_hash = upload_data.get("hash", "")
            scan_type = upload_data.get("scan_type", "")

            if not file_hash:
                return {"success": False, "error": "MobSF upload returned no hash", "response": upload_data}

            # 2. Start scan
            r = client.post(
                f"{mobsf_url}/api/v1/scan",
                data={"hash": file_hash, "scan_type": scan_type, "file_name": os.path.basename(file_path)},
                headers=headers,
                timeout=120.0,
            )
            if r.status_code != 200:
                return {"success": False, "error": f"Scan start failed: {r.status_code} {r.text[:500]}"}

            # 3. Poll for report
            deadline = time.time() + poll_timeout
            report: dict[str, Any] = {}
            while time.time() < deadline:
                r = client.post(
                    f"{mobsf_url}/api/v1/report_json",
                    data={"hash": file_hash},
                    headers=headers,
                    timeout=60.0,
                )
                if r.status_code == 200 and r.json():
                    report = r.json()
                    break
                time.sleep(poll_interval)
            else:
                return {"success": False, "error": "Scan timed out", "hash": file_hash}

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"MobSF scan failed: {e!s}"}

    # Extract compact summary
    summary = {
        "hash": file_hash,
        "app_name": report.get("app_name", ""),
        "package": report.get("package_name", ""),
        "version_name": report.get("version_name", ""),
        "target_sdk": report.get("target_sdk", ""),
        "min_sdk": report.get("min_sdk", ""),
        "file_name": os.path.basename(file_path),
    }

    # Counts
    sec_score = report.get("security_score", 0)
    findings_by_sev = {
        "high": len([f for f in (report.get("code_analysis", {}).get("findings", {}) or {}).values()
                      if (f.get("metadata", {}) or {}).get("severity") == "high"]),
        "medium": len([f for f in (report.get("code_analysis", {}).get("findings", {}) or {}).values()
                       if (f.get("metadata", {}) or {}).get("severity") == "warning"]),
    }
    summary["security_score"] = sec_score
    summary["code_findings_by_severity"] = findings_by_sev

    summary["permissions_dangerous"] = [
        p for p, meta in (report.get("permissions", {}) or {}).items()
        if (meta or {}).get("status") == "dangerous"
    ][:30]

    summary["trackers"] = [
        t.get("name", "") for t in (report.get("trackers", {}).get("trackers", []) or [])
    ][:20]

    summary["secrets"] = (report.get("secrets", []) or [])[:20]
    summary["domains"] = list((report.get("domains", {}) or {}).keys())[:30]
    summary["urls"] = (report.get("urls", []) or [])[:30]
    summary["emails"] = (report.get("emails", []) or [])[:10]

    return {
        "success": True,
        "summary": summary,
        "full_report_endpoint": f"{mobsf_url}/static_analyzer/?hash={file_hash}",
    }


@register_tool(sandbox_execution=True)
def mobsf_report(
    agent_state: Any,
    file_hash: str,
    section: str = "full",
    mobsf_url: str = "http://localhost:8000",
    api_key: str = "",
) -> dict[str, Any]:
    """Fetch MobSF report JSON. section: full / code_analysis / permissions / urls / secrets."""
    try:
        import httpx
    except ImportError:
        return {"success": False, "error": "httpx not installed"}

    key = api_key or os.getenv("MOBSF_API_KEY", "")
    if not key:
        return {"success": False, "error": "MOBSF_API_KEY not set"}

    headers = {"Authorization": key, "X-Mobsf-Api-Key": key}
    try:
        with httpx.Client(timeout=60.0) as client:
            r = client.post(
                f"{mobsf_url.rstrip('/')}/api/v1/report_json",
                data={"hash": file_hash},
                headers=headers,
            )
        if r.status_code != 200:
            return {"success": False, "error": f"HTTP {r.status_code}"}
        report = r.json()
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": str(e)}

    if section == "full":
        return {"success": True, "report": report}
    if section in report:
        return {"success": True, "section": section, "data": report[section]}
    return {"success": True, "section": section, "data": None, "note": f"Section {section!r} not in report"}
