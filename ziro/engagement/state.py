"""Typed engagement state — structured facts about the target, injected into LLM context.

Typed state container pattern for agent context enrichment. The model sees an up-to-date XML
block with every known host, service, credential, session, and finding on every
LLM call, instead of having to reconstruct context from raw tool output.

Mutated by tools (capture_evidence, create_vulnerability_report, recon tools),
read by LLM.build_messages via a new <engagement_state> block in the system prompt.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Host:
    host: str
    ip: str = ""
    open_ports: list[int] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    waf: str = ""
    notes: str = ""


@dataclass
class Service:
    host: str
    port: int
    protocol: str = "tcp"
    product: str = ""
    version: str = ""
    url: str = ""
    notes: str = ""


@dataclass
class Credential:
    source: str  # where it came from: "leaked in JS", "default", "recovered from response", ...
    username: str = ""
    password: str = ""
    token: str = ""
    token_type: str = ""  # jwt, bearer, session_cookie, api_key, ...
    validated: bool = False
    access_level: str = ""  # "user", "admin", "service_role", "read-only", ...
    host: str = ""


@dataclass
class Session:
    agent_id: str
    host: str
    session_type: str  # "http_cookie", "ssh", "c2_implant", "authenticated_api"
    expires_at: str = ""
    identifier: str = ""


@dataclass
class Finding:
    id: str
    title: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    vuln_type: str  # sqli / xss / ssrf / auth_bypass / ...
    endpoint: str = ""
    status: str = "unconfirmed"  # unconfirmed / potential / confirmed / false_positive
    confidence: float = 0.0


class EngagementState:
    """Thread-safe typed state container for a single scan."""

    def __init__(self, target: str = "") -> None:
        self._lock = threading.RLock()
        self.target = target
        self.started_at = datetime.now(timezone.utc).isoformat()

        self.hosts: dict[str, Host] = {}         # keyed by host name
        self.services: list[Service] = []
        self.credentials: list[Credential] = []
        self.sessions: list[Session] = []
        self.findings: dict[str, Finding] = {}   # keyed by finding id
        self.flag_attempts: list[dict[str, Any]] = []  # for CTF-style engagements
        self.notes: list[str] = []               # free-form agent observations

    # ---- mutators ----

    def add_host(
        self,
        host: str,
        *,
        ip: str = "",
        open_ports: list[int] | None = None,
        technologies: list[str] | None = None,
        waf: str = "",
        notes: str = "",
    ) -> None:
        with self._lock:
            existing = self.hosts.get(host)
            if existing is None:
                self.hosts[host] = Host(
                    host=host,
                    ip=ip,
                    open_ports=list(open_ports or []),
                    technologies=list(technologies or []),
                    waf=waf,
                    notes=notes,
                )
            else:
                if ip:
                    existing.ip = ip
                if open_ports:
                    existing.open_ports = sorted(set(existing.open_ports) | set(open_ports))
                if technologies:
                    existing.technologies = list(set(existing.technologies) | set(technologies))
                if waf:
                    existing.waf = waf
                if notes:
                    existing.notes = (existing.notes + "\n" + notes).strip() if existing.notes else notes

    def add_service(self, **kwargs: Any) -> None:
        with self._lock:
            svc = Service(**kwargs)
            # dedupe by host+port+protocol
            for existing in self.services:
                if (
                    existing.host == svc.host
                    and existing.port == svc.port
                    and existing.protocol == svc.protocol
                ):
                    if svc.product:
                        existing.product = svc.product
                    if svc.version:
                        existing.version = svc.version
                    if svc.url:
                        existing.url = svc.url
                    return
            self.services.append(svc)

    def add_credential(self, **kwargs: Any) -> None:
        with self._lock:
            cred = Credential(**kwargs)
            self.credentials.append(cred)

    def add_session(self, **kwargs: Any) -> None:
        with self._lock:
            self.sessions.append(Session(**kwargs))

    def add_finding(self, **kwargs: Any) -> None:
        with self._lock:
            finding = Finding(**kwargs)
            self.findings[finding.id] = finding

    def update_finding_status(self, finding_id: str, status: str, confidence: float = 0.0) -> bool:
        with self._lock:
            f = self.findings.get(finding_id)
            if not f:
                return False
            f.status = status
            if confidence:
                f.confidence = confidence
            return True

    def add_note(self, note: str) -> None:
        with self._lock:
            if note and note.strip():
                self.notes.append(note.strip())

    # ---- prompt block ----

    def to_prompt_block(self, compact: bool = True) -> str:
        """Render as <engagement_state> XML injected into the system prompt."""
        with self._lock:
            lines = [
                "<engagement_state>",
                f"<target>{self.target}</target>",
                f"<started>{self.started_at}</started>",
            ]

            if self.hosts:
                lines.append("<hosts>")
                for h in self.hosts.values():
                    bits = [f'host="{h.host}"']
                    if h.ip:
                        bits.append(f'ip="{h.ip}"')
                    if h.waf:
                        bits.append(f'waf="{h.waf}"')
                    if h.open_ports:
                        bits.append(f'ports="{",".join(map(str, h.open_ports))}"')
                    if h.technologies:
                        bits.append(f'tech="{",".join(h.technologies[:8])}"')
                    lines.append(f"  <host {' '.join(bits)}/>")
                lines.append("</hosts>")

            if self.services:
                lines.append("<services>")
                for s in self.services[:40]:
                    bits = [f'{s.host}:{s.port}/{s.protocol}']
                    if s.product:
                        bits.append(f'{s.product} {s.version}'.strip())
                    if s.url:
                        bits.append(s.url)
                    lines.append(f"  - {' | '.join(bits)}")
                lines.append("</services>")

            if self.credentials:
                lines.append("<credentials>")
                for c in self.credentials[:30]:
                    bits = []
                    if c.username:
                        bits.append(f"user={c.username}")
                    if c.password:
                        # Mask mid for short passwords
                        masked = c.password if len(c.password) < 8 else c.password[:3] + "***" + c.password[-2:]
                        bits.append(f"pass={masked}")
                    if c.token_type:
                        bits.append(f"token_type={c.token_type}")
                    if c.access_level:
                        bits.append(f"access={c.access_level}")
                    if c.validated:
                        bits.append("VALIDATED")
                    bits.append(f'source="{c.source}"')
                    lines.append(f"  - {' '.join(bits)}")
                lines.append("</credentials>")

            if self.sessions:
                lines.append("<active_sessions>")
                for sess in self.sessions[:20]:
                    lines.append(
                        f"  - agent={sess.agent_id} host={sess.host} type={sess.session_type}"
                        + (f" id={sess.identifier}" if sess.identifier else "")
                    )
                lines.append("</active_sessions>")

            if self.findings:
                lines.append("<findings>")
                # Sort by severity for the prompt
                sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
                sorted_findings = sorted(
                    self.findings.values(),
                    key=lambda f: (sev_rank.get(f.severity.upper(), 9), f.id),
                )
                for f in sorted_findings[:30]:
                    status_marker = f.status.upper()
                    lines.append(
                        f"  [{f.severity.upper()}] [{status_marker}] "
                        f"{f.vuln_type} @ {f.endpoint or '-'} — {f.title[:100]}"
                    )
                lines.append("</findings>")

            if self.notes and not compact:
                lines.append("<notes>")
                for n in self.notes[-10:]:
                    lines.append(f"  - {n[:200]}")
                lines.append("</notes>")

            lines.append("</engagement_state>")
            return "\n".join(lines)

    # ---- summary ----

    def summary(self) -> dict[str, int]:
        with self._lock:
            return {
                "hosts": len(self.hosts),
                "services": len(self.services),
                "credentials": len(self.credentials),
                "validated_credentials": sum(1 for c in self.credentials if c.validated),
                "sessions": len(self.sessions),
                "findings": len(self.findings),
                "critical_findings": sum(
                    1 for f in self.findings.values() if f.severity.upper() == "CRITICAL"
                ),
                "high_findings": sum(
                    1 for f in self.findings.values() if f.severity.upper() == "HIGH"
                ),
            }


# Singleton per process — fine because scans don't overlap in one process
_global_state: EngagementState | None = None
_state_lock = threading.Lock()


def get_engagement_state() -> EngagementState:
    global _global_state
    with _state_lock:
        if _global_state is None:
            _global_state = EngagementState()
        return _global_state


def reset_engagement_state(target: str = "") -> EngagementState:
    global _global_state
    with _state_lock:
        _global_state = EngagementState(target=target)
        return _global_state
