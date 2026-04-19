"""Engagement planning tools — Rules of Engagement, ConOps, OPPLAN, Deconfliction.

Decepticon has a dedicated 'Soundwave' agent that generates an engagement package
before any recon or exploit activity begins. Ziro doesn't need a separate agent
for this — the root agent can produce the same artifacts directly via these
tools, then reference them throughout the scan and include them in the final
report. The tools write to /workspace/engagement/ inside the sandbox so the
documents travel with the deliverables.
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from typing import Any

from ziro.tools.registry import register_tool


_ENGAGEMENT_DIR = "/workspace/engagement"


def _sanitize_slug(name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", name.strip().lower()).strip("-")
    return slug or "engagement"


def _ensure_dir() -> str:
    os.makedirs(_ENGAGEMENT_DIR, exist_ok=True)
    return _ENGAGEMENT_DIR


def _write(path: str, content: str) -> str:
    abs_path = os.path.join(_ensure_dir(), path)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(content)
    return abs_path


def _read(path: str) -> str | None:
    abs_path = os.path.join(_ENGAGEMENT_DIR, path)
    if not os.path.exists(abs_path):
        return None
    with open(abs_path, encoding="utf-8") as f:
        return f.read()


@register_tool(sandbox_execution=True, agent_roles=["root"])
def create_roe(
    agent_state: Any,
    engagement_name: str,
    client_name: str,
    authorized_by: str,
    in_scope: list[str],
    out_of_scope: list[str],
    allowed_techniques: list[str] | None = None,
    forbidden_techniques: list[str] | None = None,
    testing_window_start: str = "",
    testing_window_end: str = "",
    notification_channel: str = "",
    emergency_contact: str = "",
    destructive_actions_allowed: bool = False,
    data_exfiltration_allowed: bool = False,
    social_engineering_allowed: bool = False,
    production_allowed: bool = True,
    third_party_infrastructure_notice: str = "",
) -> dict[str, Any]:
    """Draft the formal Rules of Engagement document for this scan.

    The RoE is the authoritative scope and authorization statement. Every
    subsequent tool call by any agent should be validated against it. Produces
    a markdown document at /workspace/engagement/roe.md and a machine-readable
    JSON digest at /workspace/engagement/roe.json that the orchestrator can
    consult on every tool invocation.
    """
    try:
        allowed_techniques = allowed_techniques or []
        forbidden_techniques = forbidden_techniques or []

        digest = {
            "engagement_name": engagement_name,
            "client_name": client_name,
            "authorized_by": authorized_by,
            "created_at": datetime.now(UTC).isoformat(),
            "in_scope": in_scope,
            "out_of_scope": out_of_scope,
            "allowed_techniques": allowed_techniques,
            "forbidden_techniques": forbidden_techniques,
            "testing_window": {
                "start": testing_window_start,
                "end": testing_window_end,
            },
            "notification_channel": notification_channel,
            "emergency_contact": emergency_contact,
            "destructive_actions_allowed": destructive_actions_allowed,
            "data_exfiltration_allowed": data_exfiltration_allowed,
            "social_engineering_allowed": social_engineering_allowed,
            "production_allowed": production_allowed,
            "third_party_infrastructure_notice": third_party_infrastructure_notice,
        }

        slug = _sanitize_slug(engagement_name)

        def _bullet(items: list[str]) -> str:
            return "\n".join(f"- {i}" for i in items) if items else "- _none_"

        md = f"""# Rules of Engagement — {engagement_name}

**Client**: {client_name}
**Authorized by**: {authorized_by}
**Created**: {digest["created_at"]}
**Testing window**: {testing_window_start or "TBD"} → {testing_window_end or "TBD"}

---

## In Scope

{_bullet(in_scope)}

## Out of Scope

{_bullet(out_of_scope)}

## Allowed Techniques

{_bullet(allowed_techniques) if allowed_techniques else "- All standard pentest techniques except those explicitly forbidden below"}

## Forbidden Techniques

{_bullet(forbidden_techniques) if forbidden_techniques else "- (none explicitly listed — see defaults)"}

## Destructive & Sensitive Actions

- **Destructive actions**: {"ALLOWED" if destructive_actions_allowed else "FORBIDDEN — no data destruction, service disruption, or irreversible changes"}
- **Data exfiltration**: {"ALLOWED — exfiltrate to agreed storage only, delete after report" if data_exfiltration_allowed else "FORBIDDEN — evidence screenshots and hashes only"}
- **Social engineering**: {"ALLOWED — coordinate timing with client" if social_engineering_allowed else "FORBIDDEN — no phishing, vishing, or impersonation"}
- **Production systems**: {"IN SCOPE — operate with extreme care" if production_allowed else "FORBIDDEN — staging and test environments only"}

## Communication

- **Notification channel**: {notification_channel or "_TBD_"}
- **Emergency contact**: {emergency_contact or "_TBD_"}

## Third-Party Infrastructure

{third_party_infrastructure_notice or "_No third-party services in scope. If discovered during testing, STOP and notify the emergency contact before proceeding._"}

## Default Forbidden Actions (unless explicitly overridden above)

- Denial of service attacks (TCP/UDP floods, resource exhaustion)
- Destructive database or filesystem operations
- Credential dumping from systems outside the tester's own session
- Pivoting to non-scope networks
- Exfiltrating PII, PHI, payment card data, or other regulated information
- Phishing or social engineering of client staff or third parties
- Any action that could cause downtime during business hours
- Deploying persistent backdoors or implants not approved by the client
- Tampering with logs or audit trails to hide tester activity beyond standard pentest tradecraft
- Publishing findings, screenshots, or IOCs outside the agreed reporting channel
"""

        md_path = _write(f"{slug}/roe.md", md)
        json_path = _write(f"{slug}/roe.json", json.dumps(digest, indent=2))

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to create RoE: {e!s}"}
    else:
        return {
            "success": True,
            "markdown_path": md_path,
            "json_path": json_path,
            "engagement_slug": slug,
            "digest": digest,
        }


@register_tool(sandbox_execution=True, agent_roles=["root"])
def create_conops(
    agent_state: Any,
    engagement_name: str,
    mission_statement: str,
    primary_objectives: list[str],
    success_criteria: list[str],
    threat_actor_profile: str = "",
    testing_approach: str = "",
    assumed_starting_point: str = "external",
    kill_chain_focus: list[str] | None = None,
) -> dict[str, Any]:
    """Draft the Concept of Operations — mission, objectives, adversary model, approach.

    The ConOps answers "what are we simulating, why, and how" in a way the
    client can read. Writes to /workspace/engagement/<slug>/conops.md.
    """
    try:
        kill_chain_focus = kill_chain_focus or []
        slug = _sanitize_slug(engagement_name)

        md = f"""# Concept of Operations — {engagement_name}

**Generated**: {datetime.now(UTC).isoformat()}

## Mission Statement

{mission_statement}

## Primary Objectives

{chr(10).join(f"1. {o}" for o in primary_objectives) if primary_objectives else "_TBD_"}

## Success Criteria

{chr(10).join(f"- {c}" for c in success_criteria) if success_criteria else "_TBD_"}

## Threat Actor Profile

{threat_actor_profile or "_No specific adversary emulated — generic attacker model. Override by setting ZIRO_THREAT_ACTOR or passing threat_actor in create_agent._"}

## Starting Posture

- **Assumed starting point**: {assumed_starting_point}
- **Testing approach**: {testing_approach or "Black-box with no prior knowledge of internals"}

## Kill Chain Focus

{chr(10).join(f"- {p.replace('_', ' ').title()}" for p in kill_chain_focus) if kill_chain_focus else "- All phases from reconnaissance through impact"}

## Out-of-Scope Reminder

See the [Rules of Engagement](./roe.md) for the authoritative scope and prohibited actions.
"""

        path = _write(f"{slug}/conops.md", md)

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to create ConOps: {e!s}"}
    else:
        return {"success": True, "path": path, "engagement_slug": slug}


@register_tool(sandbox_execution=True, agent_roles=["root"])
def create_opplan(
    agent_state: Any,
    engagement_name: str,
    phases: list[dict[str, Any]],
    estimated_duration: str = "",
    required_tools: list[str] | None = None,
    risk_considerations: list[str] | None = None,
    rollback_procedures: str = "",
) -> dict[str, Any]:
    """Draft the Operations Plan (OPPLAN) — phased execution plan with agents and tools.

    The OPPLAN is the tester's playbook. Each phase entry should include:
      {
        "name": "Phase 1 — External Recon",
        "objective": "Map attack surface without alerting defenders",
        "agents": ["Recon Agent"],
        "skills": ["passive_osint_apis", "graphql_introspection"],
        "techniques": ["T1590", "T1589"],
        "duration": "1-2 hours",
        "deliverables": ["subdomain_list.txt", "endpoint_inventory.json"]
      }
    """
    try:
        required_tools = required_tools or []
        risk_considerations = risk_considerations or []
        slug = _sanitize_slug(engagement_name)

        phase_blocks = []
        for i, p in enumerate(phases, start=1):
            name = p.get("name", f"Phase {i}")
            objective = p.get("objective", "_TBD_")
            agents = p.get("agents", []) or []
            skills = p.get("skills", []) or []
            techniques = p.get("techniques", []) or []
            duration = p.get("duration", "")
            deliverables = p.get("deliverables", []) or []

            phase_blocks.append(
                f"""### {name}

**Objective**: {objective}

- **Agents**: {', '.join(agents) if agents else '_default root agent_'}
- **Skills**: {', '.join(f"`{s}`" for s in skills) if skills else '_default_'}
- **MITRE techniques**: {', '.join(techniques) if techniques else '_mixed_'}
- **Estimated duration**: {duration or '_open-ended_'}
- **Deliverables**: {', '.join(f"`{d}`" for d in deliverables) if deliverables else '_none declared_'}
"""
            )

        md = f"""# Operations Plan — {engagement_name}

**Generated**: {datetime.now(UTC).isoformat()}
**Estimated total duration**: {estimated_duration or '_TBD_'}

## Phases

{chr(10).join(phase_blocks) if phase_blocks else "_No phases declared_"}

## Required Tools

{chr(10).join(f"- `{t}`" for t in required_tools) if required_tools else "_Standard Ziro toolkit_"}

## Risk Considerations

{chr(10).join(f"- {r}" for r in risk_considerations) if risk_considerations else "_None specific to this engagement_"}

## Rollback & Cleanup

{rollback_procedures or "_Delete all created artifacts at end of engagement. Remove any persistence mechanisms, test accounts, and uploaded files. Document final state for client handover._"}

## Authoritative References

- [Rules of Engagement](./roe.md)
- [Concept of Operations](./conops.md)
- [Deconfliction Plan](./deconfliction.md)
"""

        path = _write(f"{slug}/opplan.md", md)
        json_path = _write(
            f"{slug}/opplan.json",
            json.dumps(
                {
                    "engagement_name": engagement_name,
                    "phases": phases,
                    "required_tools": required_tools,
                    "risk_considerations": risk_considerations,
                    "generated_at": datetime.now(UTC).isoformat(),
                },
                indent=2,
            ),
        )

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to create OPPLAN: {e!s}"}
    else:
        return {
            "success": True,
            "markdown_path": path,
            "json_path": json_path,
            "phase_count": len(phases),
        }


@register_tool(sandbox_execution=True, agent_roles=["root"])
def create_deconfliction_plan(
    agent_state: Any,
    engagement_name: str,
    concurrent_operations: list[str] | None = None,
    blue_team_contacts: list[str] | None = None,
    ioc_notification_plan: str = "",
    test_artifact_tagging: str = "",
    pause_conditions: list[str] | None = None,
) -> dict[str, Any]:
    """Draft the Deconfliction Plan — how to coordinate with blue team and avoid confusion.

    Produces /workspace/engagement/<slug>/deconfliction.md covering how tester
    activity is distinguished from real incidents and how to stop on request.
    """
    try:
        concurrent_operations = concurrent_operations or []
        blue_team_contacts = blue_team_contacts or []
        pause_conditions = pause_conditions or [
            "Active incident response detected on in-scope systems",
            "Client requests pause via the notification channel",
            "Unintended production impact observed",
            "Out-of-scope system inadvertently touched",
        ]

        slug = _sanitize_slug(engagement_name)

        md = f"""# Deconfliction Plan — {engagement_name}

**Generated**: {datetime.now(UTC).isoformat()}

## Concurrent Operations

{chr(10).join(f"- {c}" for c in concurrent_operations) if concurrent_operations else "_None known_"}

## Blue Team Contacts

{chr(10).join(f"- {c}" for c in blue_team_contacts) if blue_team_contacts else "_Use the notification channel from the RoE_"}

## IOC Notification Plan

{ioc_notification_plan or "_All test traffic originates from the sandbox container's egress IP. All test payloads embed the ZIRO-TEST marker in the User-Agent header and payload comments where feasible. Share egress IP and marker with blue team before testing begins._"}

## Test Artifact Tagging

{test_artifact_tagging or '''Every persistence mechanism, uploaded file, created account, and credential
drop carries the tag `ZIRO-TEST-<engagement_slug>` in its name or first comment
line. The tester maintains a running inventory in /workspace/engagement/artifacts.log
and removes every tagged artifact before end-of-engagement handover.'''}

## Pause Conditions

{chr(10).join(f"- {p}" for p in pause_conditions)}

When any pause condition triggers, the root agent MUST:

1. Stop all active tool invocations (Ctrl+C in interactive sessions, cancel_current_execution on sub-agents)
2. Snapshot current state (agent graph, tool history, partial deliverables)
3. Message the notification channel with the reason and timestamp
4. Wait for explicit client approval before resuming
"""

        path = _write(f"{slug}/deconfliction.md", md)

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to create deconfliction plan: {e!s}"}
    else:
        return {"success": True, "path": path, "engagement_slug": slug}


@register_tool(sandbox_execution=True, agent_roles=["root"])
def get_engagement_package(agent_state: Any, engagement_slug: str) -> dict[str, Any]:
    """Read the full engagement package back into the agent's context.

    Returns RoE, ConOps, OPPLAN, and Deconfliction Plan content if they exist.
    Use this at the start of each phase to re-verify scope and objectives,
    or when a sub-agent needs to see the authoritative boundaries before acting.
    """
    try:
        slug = _sanitize_slug(engagement_slug)
        package = {
            "roe_md": _read(f"{slug}/roe.md"),
            "roe_json": _read(f"{slug}/roe.json"),
            "conops_md": _read(f"{slug}/conops.md"),
            "opplan_md": _read(f"{slug}/opplan.md"),
            "opplan_json": _read(f"{slug}/opplan.json"),
            "deconfliction_md": _read(f"{slug}/deconfliction.md"),
        }
        missing = [k for k, v in package.items() if v is None]

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to read engagement package: {e!s}"}
    else:
        return {
            "success": True,
            "engagement_slug": slug,
            "package": package,
            "missing": missing,
        }
