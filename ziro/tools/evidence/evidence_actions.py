"""Evidence capture tool — allows the agent to save proof artifacts for findings."""

from typing import Any

from ziro.tools.registry import register_tool


@register_tool(sandbox_execution=False)
def capture_evidence(
    evidence_type: str,
    content: str,
    vuln_id: str | None = None,
    description: str = "",
    url: str = "",
    method: str = "",
    status_code: int | None = None,
    command: str = "",
    exit_code: int | None = None,
) -> dict[str, Any]:
    """Capture evidence for a vulnerability finding."""
    from ziro.evidence import get_evidence_collector

    collector = get_evidence_collector()
    if not collector:
        return {"success": False, "error": "Evidence collector not initialized. Run a scan first."}

    evidence_type = evidence_type.strip().lower()

    if evidence_type == "http":
        if not url:
            return {"success": False, "error": "URL is required for HTTP evidence"}
        artifact_id = collector.capture_http(
            url=url,
            method=method or "GET",
            response_body=content,
            status_code=status_code,
            vuln_id=vuln_id,
            description=description,
        )
    elif evidence_type == "command":
        if not command:
            return {"success": False, "error": "Command is required for command evidence"}
        artifact_id = collector.capture_command(
            command=command,
            output=content,
            exit_code=exit_code,
            vuln_id=vuln_id,
            description=description,
        )
    elif evidence_type == "screenshot":
        artifact_id = collector.capture_screenshot(
            screenshot_b64=content,
            url=url,
            vuln_id=vuln_id,
            description=description,
        )
    else:
        return {
            "success": False,
            "error": f"Unknown evidence type: {evidence_type}. Use 'http', 'command', or 'screenshot'.",
        }

    return {
        "success": True,
        "artifact_id": artifact_id,
        "message": f"Evidence captured: {artifact_id}",
    }


@register_tool(sandbox_execution=False)
def list_evidence(
    vuln_id: str | None = None,
) -> dict[str, Any]:
    """List captured evidence artifacts, optionally filtered by vulnerability ID."""
    from ziro.evidence import get_evidence_collector

    collector = get_evidence_collector()
    if not collector:
        return {"success": False, "error": "Evidence collector not initialized."}

    if vuln_id:
        artifacts = collector.get_evidence_for_finding(vuln_id)
    else:
        artifacts = collector.get_all_artifacts()

    # Return summary without large content
    summaries = []
    for a in artifacts:
        summary: dict[str, Any] = {
            "id": a["id"],
            "type": a["type"],
            "vuln_id": a.get("vuln_id"),
            "description": a.get("description", ""),
            "timestamp": a.get("timestamp", ""),
        }
        if a["type"] == "http":
            req = a.get("request", {})
            resp = a.get("response", {})
            summary["url"] = req.get("url", "")
            summary["method"] = req.get("method", "")
            summary["status_code"] = resp.get("status_code")
        elif a["type"] == "command":
            summary["command"] = a.get("command", "")[:100]
        summaries.append(summary)

    return {
        "success": True,
        "total": len(summaries),
        "artifacts": summaries,
    }
