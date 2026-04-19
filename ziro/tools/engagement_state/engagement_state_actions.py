"""Tools for mutating the engagement state from agent decisions."""

from __future__ import annotations

from typing import Any

from ziro.engagement import get_engagement_state
from ziro.tools.registry import register_tool


@register_tool(sandbox_execution=False)
def record_host(
    agent_state: Any,
    host: str,
    ip: str = "",
    open_ports: list[int] | None = None,
    technologies: list[str] | None = None,
    waf: str = "",
    notes: str = "",
) -> dict[str, Any]:
    """Record a discovered host and its metadata into the engagement state.

    Call this for every new host discovered (recon subdomain enum, nmap scan,
    passive DNS, etc.) so the engagement_state block in the system prompt
    stays up to date for all future LLM calls.
    """
    state = get_engagement_state()
    state.add_host(
        host=host,
        ip=ip,
        open_ports=open_ports or [],
        technologies=technologies or [],
        waf=waf,
        notes=notes,
    )
    return {"success": True, "host": host, "total_hosts": len(state.hosts)}


@register_tool(sandbox_execution=False)
def record_service(
    agent_state: Any,
    host: str,
    port: int,
    protocol: str = "tcp",
    product: str = "",
    version: str = "",
    url: str = "",
    notes: str = "",
) -> dict[str, Any]:
    """Record a discovered service (nmap -sV output, httpx fingerprint, etc.)."""
    state = get_engagement_state()
    state.add_service(
        host=host, port=port, protocol=protocol,
        product=product, version=version, url=url, notes=notes,
    )
    return {"success": True, "total_services": len(state.services)}


@register_tool(sandbox_execution=False)
def record_credential(
    agent_state: Any,
    source: str,
    username: str = "",
    password: str = "",
    token: str = "",
    token_type: str = "",
    validated: bool = False,
    access_level: str = "",
    host: str = "",
) -> dict[str, Any]:
    """Record a discovered credential/token.

    Call this when you find creds in JS bundles, leaked configs, default passwords
    working, a successful auth response, etc. Set validated=true only after you've
    actually proven the credential works against its API.
    """
    state = get_engagement_state()
    state.add_credential(
        source=source, username=username, password=password,
        token=token, token_type=token_type, validated=validated,
        access_level=access_level, host=host,
    )
    return {"success": True, "total_credentials": len(state.credentials)}


@register_tool(sandbox_execution=False)
def record_session(
    agent_state: Any,
    host: str,
    session_type: str,
    identifier: str = "",
    expires_at: str = "",
) -> dict[str, Any]:
    """Record an active session (HTTP cookie, SSH handle, C2 implant, etc.)."""
    state = get_engagement_state()
    aid = agent_state.agent_id if agent_state and hasattr(agent_state, "agent_id") else "unknown"
    state.add_session(agent_id=aid, host=host, session_type=session_type,
                      identifier=identifier, expires_at=expires_at)
    return {"success": True, "total_sessions": len(state.sessions)}


@register_tool(sandbox_execution=False)
def record_finding(
    agent_state: Any,
    finding_id: str,
    title: str,
    severity: str,
    vuln_type: str,
    endpoint: str = "",
    status: str = "unconfirmed",
    confidence: float = 0.0,
) -> dict[str, Any]:
    """Record a discovered finding into the engagement state for quick reference.

    This is DIFFERENT from create_vulnerability_report. create_vulnerability_report
    produces the full client-facing report. record_finding is just a state-machine
    entry visible in every LLM call's engagement_state block so agents know what's
    already been found without re-scanning.

    status: unconfirmed / potential / confirmed / false_positive
    """
    state = get_engagement_state()
    state.add_finding(
        id=finding_id, title=title, severity=severity, vuln_type=vuln_type,
        endpoint=endpoint, status=status, confidence=confidence,
    )
    return {"success": True, "total_findings": len(state.findings)}


@register_tool(sandbox_execution=False)
def view_engagement_state(agent_state: Any, include_notes: bool = False) -> dict[str, Any]:
    """Return the current engagement state as a summary + XML block.

    The XML block is the same one injected into the system prompt. Call this
    when you want a fresh snapshot mid-turn.
    """
    state = get_engagement_state()
    return {
        "success": True,
        "summary": state.summary(),
        "xml": state.to_prompt_block(compact=not include_notes),
    }
