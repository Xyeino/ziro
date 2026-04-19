"""
Ziro Web Panel — FastAPI backend serving the React frontend
and exposing scan data from the Tracer.
"""

import asyncio
import html
import json
import warnings

# Suppress noisy warnings from litellm/ChatGPT provider
warnings.filterwarnings("ignore", message=".*PydanticSerializationUnexpectedValue.*")
warnings.filterwarnings("ignore", message=".*LiteLLM.*")
import logging

# Suppress litellm info/debug noise
logging.getLogger("LiteLLM").setLevel(logging.WARNING)
logging.getLogger("litellm").setLevel(logging.WARNING)
import re
import shutil
import sqlite3
import subprocess
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ziro.panel.recon import get_recon_session, start_recon
from ziro.telemetry.tracer import Tracer, get_global_tracer, set_global_tracer
from ziro.tools.agents_graph.agents_graph_actions import (
    _agent_graph,
    _agent_states,
)
from ziro.tools.attack_graph.attack_graph_actions import _attack_graph
from ziro.tools.todo.todo_actions import _todos_storage

logger = logging.getLogger(__name__)

app = FastAPI(title="Ziro Panel API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = Path(__file__).parent / "frontend"
FRONTEND_DIST = FRONTEND_DIR / "dist"


def _ensure_frontend_built() -> bool:
    """Auto-install deps and build frontend if dist/ is missing. Returns True if ready."""
    if FRONTEND_DIST.exists() and (FRONTEND_DIST / "index.html").exists():
        return True

    if not FRONTEND_DIR.exists() or not (FRONTEND_DIR / "package.json").exists():
        logger.error("Frontend source not found at %s", FRONTEND_DIR)
        return False

    npm = shutil.which("npm")
    npx = shutil.which("npx")
    if not npm or not npx:
        logger.error(
            "Node.js/npm not found. Install Node.js 20+ to build the panel frontend, "
            "or run 'npm run build' manually in %s",
            FRONTEND_DIR,
        )
        return False

    try:
        logger.info("Installing frontend dependencies...")
        subprocess.run(
            [npm, "install"],
            cwd=str(FRONTEND_DIR),
            check=True,
            capture_output=True,
            text=True,
        )
        logger.info("Building frontend...")
        subprocess.run(
            [npx, "vite", "build"],
            cwd=str(FRONTEND_DIR),
            check=True,
            capture_output=True,
            text=True,
        )
        logger.info("Frontend built successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error("Frontend build failed: %s\n%s", e, e.stderr)
        return False
    except Exception as e:
        logger.error("Frontend build error: %s", e)
        return False


# --- API Routes ---


@app.get("/api/status")
async def get_status() -> dict[str, Any]:
    """Overall scan status."""
    tracer = get_global_tracer()
    if not tracer:
        return {"status": "idle", "message": "No active scan"}

    metadata = tracer.run_metadata
    vuln_count = len(tracer.vulnerability_reports)
    severity_counts: dict[str, int] = {}
    for v in tracer.vulnerability_reports:
        sev = v.get("severity", "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "status": metadata.get("status", "unknown"),
        "run_id": tracer.run_id,
        "run_name": tracer.run_name,
        "start_time": tracer.start_time,
        "end_time": tracer.end_time,
        "targets": metadata.get("targets", []),
        "vulnerability_count": vuln_count,
        "severity_counts": severity_counts,
    }


@app.get("/api/vulnerabilities")
async def get_vulnerabilities() -> list[dict[str, Any]]:
    """All vulnerability reports."""
    tracer = get_global_tracer()
    if not tracer:
        return []
    return tracer.vulnerability_reports


@app.get("/api/agents")
async def get_agents() -> dict[str, Any]:
    """Agent graph — nodes, edges, states."""
    agents_list = []
    for agent_id, node in _agent_graph.get("nodes", {}).items():
        state = _agent_states.get(agent_id)
        agent_info = {
            "id": agent_id,
            "name": node.get("name", "Unknown"),
            "task": node.get("task", ""),
            "status": node.get("status", "unknown"),
            "parent_id": node.get("parent_id"),
            "created_at": node.get("created_at"),
            "finished_at": node.get("finished_at"),
            "agent_type": node.get("agent_type", ""),
        }
        if state:
            graph_status = node.get("status", "unknown")
            is_done = state.completed or graph_status in ("completed", "finished")
            # Override status if agent is done but graph node hasn't been updated
            if is_done and graph_status == "running":
                agent_info["status"] = "completed"
            agent_info.update({
                "iteration": state.iteration,
                "max_iterations": state.max_iterations,
                "progress": (
                    100 if is_done
                    else round(state.iteration / state.max_iterations * 100)
                    if state.max_iterations > 0
                    else 0
                ),
                "completed": state.completed or is_done,
                "errors": state.errors,
                "actions_count": len(state.actions_taken),
                "observations_count": len(state.observations),
            })
        agents_list.append(agent_info)

    return {
        "agents": agents_list,
        "edges": _agent_graph.get("edges", []),
    }


@app.get("/api/agent-events")
async def get_agent_events(since_index: int = 0) -> dict[str, Any]:
    """Live feed of agent activity for TUI display.

    Builds a unified event feed from agent state messages (raw, unstripped)
    and tool executions interleaved chronologically.
    """
    tracer = get_global_tracer()
    events: list[dict[str, Any]] = []

    # Build feed from agent state messages (these keep full content, unlike
    # tracer.chat_messages which are cleaned/stripped of tool XML).
    all_messages: list[dict[str, Any]] = []
    for agent_id, state in _agent_states.items():
        node = _agent_graph.get("nodes", {}).get(agent_id, {})
        agent_name = node.get("name", agent_id)
        for msg in state.messages:
            content = msg.get("content", "")
            if isinstance(content, list):
                # Multi-part content (anthropic format)
                text_parts = [p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text"]
                content = "\n".join(text_parts)
            if not isinstance(content, str):
                content = str(content) if content else ""
            # Skip system/inherited context noise
            if "<inherited_context_from_parent>" in content or "<agent_delegation>" in content:
                continue
            # Truncate very long messages but keep enough to be useful
            if len(content) > 1000:
                content = content[:1000] + "..."
            all_messages.append({
                "agent_id": agent_id,
                "agent_name": agent_name,
                "role": msg.get("role", ""),
                "content": content,
            })

    # Apply since_index and build events
    for msg in all_messages[since_index:]:
        events.append({
            "type": "message",
            "agent_id": msg["agent_id"],
            "agent_name": msg["agent_name"],
            "role": msg["role"],
            "content": msg["content"],
            "timestamp": "",
            "index": since_index + len(events),
        })

    # Current streaming content
    streaming: dict[str, Any] = {}
    if tracer:
        for aid, content in tracer.streaming_content.items():
            node = _agent_graph.get("nodes", {}).get(aid, {})
            streaming[aid] = {
                "agent_name": node.get("name", aid),
                "content": content[-2000:] if len(content) > 2000 else content,
            }

    # Tool executions — return recent ones with timestamps
    tool_events: list[dict[str, Any]] = []
    if tracer:
        sorted_tools = sorted(
            tracer.tool_executions.values(),
            key=lambda t: t.get("started_at", ""),
        )
        for tex in sorted_tools[-100:]:
            agent_id = tex.get("agent_id", "")
            node = _agent_graph.get("nodes", {}).get(agent_id, {})
            # Summarize result
            result_data = tex.get("result", {})
            result_summary = ""
            if isinstance(result_data, dict):
                result_summary = str(result_data.get("content", "") or result_data.get("message", "") or result_data.get("output", ""))
            elif isinstance(result_data, str):
                result_summary = result_data
            if len(result_summary) > 500:
                result_summary = result_summary[:500] + "..."

            tool_events.append({
                "execution_id": tex.get("execution_id"),
                "agent_id": agent_id,
                "agent_name": node.get("name", agent_id),
                "tool_name": tex.get("tool_name", ""),
                "status": tex.get("status", ""),
                "started_at": tex.get("started_at", ""),
                "completed_at": tex.get("completed_at"),
                "args_summary": _summarize_args(tex.get("args", {})),
                "result_summary": result_summary,
            })

    # Agent thinking blocks from latest messages
    thinking: dict[str, Any] = {}
    for agent_id, state in _agent_states.items():
        node = _agent_graph.get("nodes", {}).get(agent_id, {})
        agent_name = node.get("name", agent_id)
        for msg in reversed(state.messages[-5:]):
            blocks = msg.get("thinking_blocks")
            if blocks:
                for block in reversed(blocks):
                    text = block.get("thinking", "")
                    if text:
                        thinking[agent_id] = {
                            "agent_name": agent_name,
                            "thinking": text[-1500:] if len(text) > 1500 else text,
                        }
                        break
            if agent_id in thinking:
                break

    return {
        "events": events,
        "total_messages": len(all_messages),
        "streaming": streaming,
        "tool_events": tool_events,
        "thinking": thinking,
    }


def _summarize_args(args: dict[str, Any]) -> str:
    """Short summary of tool args for display."""
    if not args:
        return ""
    parts = []
    for k, v in list(args.items())[:3]:
        sv = str(v)
        if len(sv) > 80:
            sv = sv[:77] + "..."
        parts.append(f"{k}={sv}")
    return ", ".join(parts)


@app.get("/api/recon-results")
async def get_recon_results() -> dict[str, Any]:
    """Parsed recon data for Target Overview display.

    First tries pre-scan recon results. If not available, extracts
    recon-like data from agent messages and tool results (live scan).
    """
    tracer = get_global_tracer()
    if not tracer or not tracer.scan_config:
        return {}

    recon = tracer.scan_config.get("recon_results")

    if recon:
        # Pre-scan recon data available
        step1 = recon.get("step_1", {})
        step2 = recon.get("step_2", {})
        step3 = recon.get("step_3", {})

        nmap_raw = _filter_shell_prompts(step2.get("nmap_output", ""))
        ports = _parse_nmap_ports(nmap_raw)
        httpx_raw = _filter_shell_prompts(step1.get("httpx_output", ""))
        httpx_info = _parse_httpx_output(httpx_raw)
        nuclei_raw = _filter_shell_prompts(step3.get("nuclei_output", ""))

        # Get IP info — from recon or fetch live
        ip_info = step1.get("ip_info", {})
        if not ip_info:
            # Try to resolve domain and get IP info live
            try:
                import socket
                import requests as _req
                domain = re.sub(r"^https?://", "", tracer.scan_config.get("targets", [{}])[0].get("original", "")).split("/")[0].split(":")[0]
                if domain:
                    ip = socket.gethostbyname(domain)
                    resp = _req.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,hosting", timeout=5)
                    if resp.ok:
                        d = resp.json()
                        if d.get("status") == "success":
                            ip_info = {"ip": ip, "country": d.get("country", ""), "region": d.get("regionName", ""),
                                       "city": d.get("city", ""), "isp": d.get("isp", ""), "org": d.get("org", ""),
                                       "asn": d.get("as", ""), "hosting": d.get("hosting", False)}
            except Exception:
                pass

        return {
            "subdomains": _filter_subdomain_list(step1.get("subdomains", [])),
            "httpx_output": httpx_raw,
            "httpx_info": httpx_info,
            "nmap_output": nmap_raw,
            "ports": ports,
            "nuclei_output": nuclei_raw,
            "findings_count": step3.get("findings_count", 0),
            "ip_info": ip_info,
            "endpoints": step2.get("endpoints", [])[:30],
            "api_endpoints": step2.get("api_endpoints", []),
            "auth_endpoints": step2.get("auth_endpoints", []),
            "graphql": step2.get("graphql", {}),
        }

    # Fallback: extract recon data from agent messages/tool results
    return _extract_recon_from_agents()


def _extract_recon_from_agents() -> dict[str, Any]:
    """Scan agent messages for recon-like data (nmap, subdomains, httpx, etc.)."""
    subdomains: set[str] = set()
    nmap_lines: list[str] = []
    httpx_lines: list[str] = []
    nuclei_lines: list[str] = []
    ports: list[dict[str, str]] = []
    httpx_info: dict[str, Any] = {}

    # Get target domain for subdomain matching
    tracer = get_global_tracer()
    target = ""
    if tracer and tracer.scan_config:
        targets = tracer.scan_config.get("targets", [])
        if targets:
            target = targets[0].get("original", "")
    domain = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]

    # Scan all agent messages for tool results containing recon data
    for agent_id, state in _agent_states.items():
        for msg in state.messages:
            content = msg.get("content", "")
            if isinstance(content, list):
                text_parts = [
                    p.get("text", "") for p in content
                    if isinstance(p, dict) and p.get("type") == "text"
                ]
                content = "\n".join(text_parts)
            if not isinstance(content, str) or not content:
                continue

            # Filter shell prompts
            content = _filter_shell_prompts(content)

            for line in content.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue

                # Detect nmap port output: "80/tcp open http"
                port_m = re.match(r"(\d+/\w+)\s+(open|filtered)\s+(.+)", stripped)
                if port_m:
                    nmap_lines.append(stripped)
                    port_entry = {
                        "port": port_m.group(1),
                        "state": port_m.group(2),
                        "service": port_m.group(3).strip(),
                    }
                    if port_entry not in ports:
                        ports.append(port_entry)
                    continue

                # Detect httpx output: "https://example.com [200] [title] ..."
                httpx_m = re.match(r"https?://\S+.*\[\d{3}\]", stripped)
                if httpx_m:
                    httpx_lines.append(stripped)
                    if not httpx_info:
                        httpx_info = _parse_httpx_output(stripped)
                    continue

                # Detect nuclei findings: "[template-id] [severity] ..."
                nuclei_m = re.match(r"\[[\w-]+\]\s*\[(info|low|medium|high|critical)\]", stripped, re.IGNORECASE)
                if nuclei_m:
                    nuclei_lines.append(stripped)
                    continue

                # Detect subdomains: lines that look like "subdomain.domain.tld"
                if domain and domain in stripped:
                    # Could be a subdomain line
                    sub_m = re.match(r"^([\w.-]+\." + re.escape(domain) + r")$", stripped)
                    if sub_m:
                        subdomains.add(sub_m.group(1))

    # Also check tool execution results for nmap/httpx data
    if tracer:
        for tex in tracer.tool_executions.values():
            result_data = tex.get("result", {})
            if not isinstance(result_data, dict):
                continue
            content = str(result_data.get("content", "") or result_data.get("output", "") or "")
            if not content:
                continue
            content = _filter_shell_prompts(content)
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                port_m = re.match(r"(\d+/\w+)\s+(open|filtered)\s+(.+)", stripped)
                if port_m:
                    nmap_lines.append(stripped)
                    port_entry = {"port": port_m.group(1), "state": port_m.group(2), "service": port_m.group(3).strip()}
                    if port_entry not in ports:
                        ports.append(port_entry)
                httpx_m = re.match(r"https?://\S+.*\[\d{3}\]", stripped)
                if httpx_m:
                    httpx_lines.append(stripped)
                    if not httpx_info:
                        httpx_info = _parse_httpx_output(stripped)

    # Also check attack graph for discovered info
    for node in _attack_graph.get("nodes", {}).values():
        node_target = node.get("target", "")
        if domain and domain in node_target:
            sub = re.sub(r"^https?://", "", node_target).split("/")[0].split(":")[0]
            if sub and sub != domain and "." in sub:
                subdomains.add(sub)

    nmap_raw = "\n".join(nmap_lines)
    httpx_raw = "\n".join(httpx_lines)
    nuclei_raw = "\n".join(nuclei_lines)

    # Only return if we found something
    if not subdomains and not ports and not httpx_info and not nuclei_raw:
        return {}

    return {
        "subdomains": _filter_subdomain_list(sorted(subdomains)),
        "httpx_output": httpx_raw,
        "httpx_info": httpx_info,
        "nmap_output": nmap_raw,
        "ports": ports,
        "nuclei_output": nuclei_raw,
        "findings_count": len(nuclei_lines),
        "ip_info": {},
    }


@app.get("/api/todos")
async def get_todos() -> dict[str, Any]:
    """All agent todos from _todos_storage."""
    all_todos: list[dict[str, Any]] = []
    for agent_id, todos in _todos_storage.items():
        node = _agent_graph.get("nodes", {}).get(agent_id, {})
        agent_name = node.get("name", agent_id)
        for todo_id, todo in todos.items():
            all_todos.append({
                "id": todo_id,
                "agent_id": agent_id,
                "agent_name": agent_name,
                **todo,
            })
    # Sort: in_progress first, then pending, then done
    status_order = {"in_progress": 0, "pending": 1, "done": 2}
    priority_order = {"critical": 0, "high": 1, "normal": 2, "low": 3}
    all_todos.sort(key=lambda t: (
        status_order.get(t.get("status", "pending"), 1),
        priority_order.get(t.get("priority", "normal"), 2),
    ))
    return {"todos": all_todos, "total": len(all_todos)}


# In-memory screenshot store: list of {url, timestamp, status_code, title, technologies}
_screenshots: list[dict[str, Any]] = []


@app.get("/api/screenshots")
async def get_screenshots() -> dict[str, Any]:
    """Screenshots / web probes of discovered subdomains and targets."""
    tracer = get_global_tracer()
    if not tracer or not tracer.scan_config:
        return {"screenshots": []}

    recon = tracer.scan_config.get("recon_results", {})
    step1 = recon.get("step_1", {})
    subdomains = _filter_subdomain_list(step1.get("subdomains", []))
    httpx_raw = _filter_shell_prompts(step1.get("httpx_output", ""))

    # Parse each httpx line into a screenshot-like card
    cards: list[dict[str, Any]] = []
    seen_urls: set[str] = set()

    for line in httpx_raw.splitlines():
        line = line.strip()
        if not line:
            continue
        url_match = re.match(r"(https?://\S+)", line)
        if not url_match:
            continue
        url = url_match.group(1)
        if url in seen_urls:
            continue
        seen_urls.add(url)

        brackets = re.findall(r"\[([^\]]+)\]", line)
        status = None
        title = ""
        techs: list[str] = []
        for val in brackets:
            if re.match(r"^\d{3}$", val):
                status = int(val)
            elif status and not title:
                title = val
            elif "," in val:
                techs = [t.strip() for t in val.split(",")]
            elif val.lower() not in ("http", "https"):
                techs.append(val)

        cards.append({
            "url": url,
            "status_code": status,
            "title": title,
            "technologies": techs,
            "alive": status is not None and status < 500,
            "screenshot": None,  # Will be filled below
        })

    # Also add subdomains not found in httpx as "unprobed"
    for sub in subdomains:
        urls = [f"https://{sub}", f"http://{sub}"]
        if not any(u in seen_urls for u in urls):
            cards.append({
                "url": f"https://{sub}",
                "status_code": None,
                "title": "",
                "technologies": [],
                "alive": None,
                "screenshot": None,
            })

    # Attach real screenshots from recon data
    screenshots_data = step1.get("screenshots", {})
    if screenshots_data:
        for card in cards:
            b64 = screenshots_data.get(card["url"], "")
            if b64:
                card["screenshot"] = b64

    return {"screenshots": cards, "total": len(cards)}


@app.get("/api/mitre")
async def get_mitre_mapping() -> dict[str, Any]:
    """MITRE ATT&CK mapping — placeholder; the real mapping is done client-side from vulns."""
    return {"hits": [], "coverage": 0, "total_techniques": 0}


@app.get("/api/http-logs")
async def get_http_logs() -> dict[str, Any]:
    """HTTP request log — placeholder; the real data comes from /api/agent-events tool_events."""
    return {"logs": [], "total": 0}


@app.get("/api/roi-scores")
async def get_roi_scores() -> dict[str, Any]:
    """ROI scoring for subdomains/targets based on recon data."""
    tracer = get_global_tracer()
    if not tracer or not tracer.scan_config:
        return {"scores": []}

    recon = tracer.scan_config.get("recon_results", {})
    step1 = recon.get("step_1", {})
    step2 = recon.get("step_2", {})
    step3 = recon.get("step_3", {})

    subdomains = _filter_subdomain_list(step1.get("subdomains", []))
    httpx_raw = _filter_shell_prompts(step1.get("httpx_output", ""))
    nuclei_raw = _filter_shell_prompts(step3.get("nuclei_output", ""))
    nmap_raw = _filter_shell_prompts(step2.get("nmap_output", ""))

    # Parse httpx lines into per-URL info
    url_info: dict[str, dict[str, Any]] = {}
    for line in httpx_raw.splitlines():
        line = line.strip()
        url_match = re.match(r"(https?://\S+)", line)
        if not url_match:
            continue
        url = url_match.group(1)
        domain = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
        brackets = re.findall(r"\[([^\]]+)\]", line)
        status = None
        techs: list[str] = []
        for val in brackets:
            if re.match(r"^\d{3}$", val):
                status = int(val)
            elif val.lower() not in ("http", "https"):
                techs.append(val)
        url_info[domain] = {"status": status, "techs": techs, "url": url}

    # Count nuclei findings per domain
    nuclei_hits: dict[str, int] = {}
    for line in nuclei_raw.splitlines():
        for sub in subdomains:
            if sub in line:
                nuclei_hits[sub] = nuclei_hits.get(sub, 0) + 1

    scores: list[dict[str, Any]] = []
    for sub in subdomains:
        score = 0
        factors: list[str] = []
        info = url_info.get(sub, {})

        # Factor: alive
        if info.get("status"):
            score += 20
            factors.append("alive")
            # 200 OK = more content = more attack surface
            if info["status"] == 200:
                score += 10
                factors.append("200 OK")

        # Factor: technologies detected (more = more surface)
        tech_count = len(info.get("techs", []))
        if tech_count > 0:
            score += min(tech_count * 5, 20)
            factors.append(f"{tech_count} techs")

        # Factor: no WAF/CDN = easier target
        techs_lower = [t.lower() for t in info.get("techs", [])]
        has_waf = any(w in " ".join(techs_lower) for w in ["waf", "cloudflare", "guard", "firewall", "cdn"])
        if not has_waf and info.get("status"):
            score += 15
            factors.append("no WAF")
        elif has_waf:
            score -= 10
            factors.append("WAF detected")

        # Factor: nuclei findings
        n_hits = nuclei_hits.get(sub, 0)
        if n_hits > 0:
            score += min(n_hits * 10, 30)
            factors.append(f"{n_hits} findings")

        # Factor: open non-standard ports
        for line in nmap_raw.splitlines():
            if sub in line or (not any(s in line for s in subdomains)):
                m = re.match(r"(\d+)/", line.strip())
                if m and m.group(1) not in ("80", "443"):
                    score += 5
                    factors.append(f"port {m.group(1)}")

        score = max(0, min(100, score))
        priority = "critical" if score >= 70 else "high" if score >= 50 else "medium" if score >= 30 else "low"

        scores.append({
            "subdomain": sub,
            "score": score,
            "priority": priority,
            "factors": factors,
            "url": info.get("url", f"https://{sub}"),
            "status_code": info.get("status"),
            "nuclei_findings": n_hits,
        })

    scores.sort(key=lambda x: x["score"], reverse=True)
    return {"scores": scores, "total": len(scores)}


def _filter_shell_prompts(text: str) -> str:
    """Remove shell prompt lines like [ZIRO_0]$ ... from raw output."""
    if not text:
        return ""
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        # Skip shell prompts
        if re.match(r"\[ZIRO_\d+\]\$", stripped):
            continue
        # Skip lines that are just the prompt with no output
        if stripped.startswith("[ZIRO_") and "$" in stripped:
            # Extract content after prompt if any
            after = re.sub(r"^\[ZIRO_\d+\]\$\s*", "", stripped)
            if after and not after.startswith(("subfinder", "httpx", "nmap", "nuclei", "echo", "head", "Command still")):
                lines.append(after)
            continue
        # Skip sandbox error messages
        if "A command is already running" in stripped:
            continue
        if "is_input=true" in stripped:
            continue
        if stripped and stripped != "$":
            lines.append(line)
    return "\n".join(lines).strip()


def _filter_subdomain_list(subdomains: list) -> list:
    """Remove shell prompts, commands, and malformed entries from subdomain list."""
    clean = []
    seen: set[str] = set()
    for s in subdomains:
        if not isinstance(s, str):
            continue
        # Split on literal \n that may be embedded in crt.sh results
        for part in s.replace("\\n", "\n").split("\n"):
            part = part.strip().lower()
            if not part or part in seen:
                continue
            # Skip shell prompts
            if re.match(r"\[ZIRO_\d+\]\$", part) or ("[ZIRO_" in part and "$" in part):
                continue
            # Skip command lines
            if part.startswith(("subfinder ", "httpx ", "nmap ", "nuclei ", "echo ", "head ", "command still")):
                continue
            # Skip pipe operators
            if " | " in part and ("head" in part or "dev/null" in part):
                continue
            # Skip if contains backslash, space, or is too long
            if "\\" in part or " " in part or len(part) > 200:
                continue
            # Must look like a domain (has dot, no special chars)
            if "." not in part or any(c in part for c in ("$", "[", "]", "(", ")", "{", "}", "|", ";", ">", "<")):
                continue
            seen.add(part)
            clean.append(part)
    return clean


def _parse_nmap_ports(nmap_output: str) -> list[dict[str, str]]:
    """Extract open ports from nmap output."""
    ports = []
    for line in nmap_output.splitlines():
        m = re.match(r"(\d+/\w+)\s+(open|filtered)\s+(.+)", line.strip())
        if m:
            ports.append({
                "port": m.group(1),
                "state": m.group(2),
                "service": m.group(3).strip(),
            })
    return ports


def _parse_httpx_output(httpx_output: str) -> dict[str, Any]:
    """Extract structured info from httpx probe output."""
    info: dict[str, Any] = {}
    if not httpx_output:
        return info

    for line in httpx_output.splitlines():
        line = line.strip()
        if not line:
            continue
        # httpx outputs like: https://example.com [200] [title] [server] [tech1,tech2]
        # Parse bracketed segments
        url_match = re.match(r"(https?://\S+)", line)
        if url_match:
            info["url"] = url_match.group(1)

        brackets = re.findall(r"\[([^\]]+)\]", line)
        for i, val in enumerate(brackets):
            if re.match(r"^\d{3}$", val):
                info["status_code"] = int(val)
            elif i == 1 and "status_code" in info:
                info["title"] = val
            elif val.lower() in ("http", "https"):
                continue
            elif "," in val and any(w in val.lower() for w in ("guard", "cloud", "waf", "cdn", "hsts", "nginx", "apache")):
                info["technologies"] = [t.strip() for t in val.split(",")]
            elif any(w in val.lower() for w in ("nginx", "apache", "iis", "cloudflare", "guard", "litespeed")):
                if "server" not in info:
                    info["server"] = val
                else:
                    info.setdefault("technologies", []).append(val)

    return info


@app.get("/api/attack-graph")
async def get_attack_graph() -> dict[str, Any]:
    """Attack graph nodes and edges. Always merges agent-created + auto-generated nodes."""
    existing_nodes = list(_attack_graph.get("nodes", {}).values())
    existing_edges = list(_attack_graph.get("edges", []))

    # Always auto-generate to fill in agent/tool nodes
    auto = _auto_generate_attack_graph()
    auto_nodes = auto.get("nodes", [])
    auto_edges = auto.get("edges", [])

    # Merge: existing first (they have priority), then auto-generated with unique IDs
    existing_ids = {n.get("id") for n in existing_nodes}
    merged_nodes = list(existing_nodes)
    for n in auto_nodes:
        if n.get("id") not in existing_ids:
            merged_nodes.append(n)
            existing_ids.add(n.get("id"))

    existing_edge_set = {(e[0], e[1]) if isinstance(e, list) else (e.get("source"), e.get("target")) for e in existing_edges}
    merged_edges = list(existing_edges)
    for e in auto_edges:
        key = (e[0], e[1]) if isinstance(e, list) else (e.get("source"), e.get("target"))
        if key not in existing_edge_set:
            merged_edges.append(e)

    return {"nodes": merged_nodes, "edges": merged_edges}


def _auto_generate_attack_graph() -> dict[str, Any]:
    """Build an attack graph from tracer data, vulns, agents, and tool executions."""
    tracer = get_global_tracer()
    nodes: list[dict[str, Any]] = []
    edges: list[list[str]] = []
    node_ids: set[str] = set()

    # Get target info
    target = ""
    if tracer and tracer.scan_config:
        targets = tracer.scan_config.get("targets", [])
        if targets:
            target = targets[0].get("original", "")

    if not target and not _agent_states:
        return {"nodes": [], "edges": []}

    # Root node: target
    root_id = "target-root"
    nodes.append({
        "id": root_id,
        "type": "recon",
        "description": target or "Target",
        "status": "success",
        "target": target,
        "technique": "",
        "evidence": "",
        "priority": 1,
    })
    node_ids.add(root_id)

    # Agent nodes — each agent as an activity node
    agent_parent = root_id
    for agent_id, node_data in _agent_graph.get("nodes", {}).items():
        name = node_data.get("name", agent_id)
        task = node_data.get("task", "")
        status = node_data.get("status", "unknown")
        state = _agent_states.get(agent_id)

        # Determine node type from task/name
        task_lower = (task + " " + name).lower()
        if any(w in task_lower for w in ("recon", "discover", "enum", "subdomain", "scan")):
            ntype = "recon"
        elif any(w in task_lower for w in ("vuln", "exploit", "inject", "xss", "sql", "attack", "test")):
            ntype = "vulnerability"
        elif any(w in task_lower for w in ("auth", "login", "credential", "password", "brute")):
            ntype = "credential"
        elif any(w in task_lower for w in ("access", "priv", "escal")):
            ntype = "access"
        elif any(w in task_lower for w in ("business", "logic", "race", "workflow")):
            ntype = "exploit"
        else:
            ntype = "enumerate"

        status_map = {"running": "in_progress", "completed": "success", "finished": "success", "error": "failed", "waiting": "planned"}
        a_id = f"agent-{agent_id}"
        nodes.append({
            "id": a_id,
            "type": ntype,
            "description": f"{name}: {task[:80]}" if task else name,
            "status": status_map.get(status, "in_progress"),
            "target": target,
            "technique": name,
            "evidence": f"{state.iteration}/{state.max_iterations} iterations" if state else "",
            "priority": 2,
        })
        node_ids.add(a_id)

        # Edge from root to agent (or from parent agent)
        parent = node_data.get("parent_id")
        parent_node = f"agent-{parent}" if parent and f"agent-{parent}" in node_ids else root_id
        edges.append([parent_node, a_id, "spawns"])

    # Tool execution nodes — group by tool name, link to agent
    if tracer:
        tool_groups: dict[str, dict[str, Any]] = {}
        for tex in tracer.tool_executions.values():
            tool_name = tex.get("tool_name", "")
            agent_id = tex.get("agent_id", "")
            if not tool_name:
                continue
            key = f"{agent_id}-{tool_name}"
            if key not in tool_groups:
                tool_groups[key] = {"tool_name": tool_name, "agent_id": agent_id, "count": 0, "status": "completed"}
            tool_groups[key]["count"] += 1
            if tex.get("status") == "running":
                tool_groups[key]["status"] = "running"

        for key, tg in tool_groups.items():
            t_id = f"tool-{key}"
            tool_lower = tg["tool_name"].lower()
            if any(w in tool_lower for w in ("nmap", "scan", "port")):
                ttype = "recon"
            elif any(w in tool_lower for w in ("nuclei", "vuln", "exploit")):
                ttype = "vulnerability"
            elif any(w in tool_lower for w in ("browser", "navigate", "click")):
                ttype = "exploit"
            elif any(w in tool_lower for w in ("subfinder", "dns", "httpx")):
                ttype = "enumerate"
            elif any(w in tool_lower for w in ("credential", "brute", "auth")):
                ttype = "credential"
            else:
                ttype = "enumerate"

            status_map2 = {"running": "in_progress", "completed": "success", "error": "failed"}
            nodes.append({
                "id": t_id,
                "type": ttype,
                "description": f"{tg['tool_name']} (×{tg['count']})",
                "status": status_map2.get(tg["status"], "success"),
                "target": target,
                "technique": tg["tool_name"],
                "evidence": f"Called {tg['count']} times",
                "priority": 3,
            })
            node_ids.add(t_id)

            parent_a = f"agent-{tg['agent_id']}"
            if parent_a in node_ids:
                edges.append([parent_a, t_id, "uses"])
            else:
                edges.append([root_id, t_id, "uses"])

    # Vulnerability nodes
    if tracer:
        for i, v in enumerate(tracer.vulnerability_reports):
            v_id = f"vuln-{i}"
            sev = v.get("severity", "info").lower()
            nodes.append({
                "id": v_id,
                "type": "vulnerability",
                "description": v.get("title", "Finding"),
                "status": "success",
                "target": v.get("target", "") or v.get("endpoint", ""),
                "technique": v.get("cve", "") or v.get("cwe", ""),
                "evidence": (v.get("poc_script_code", "") or "")[:200],
                "priority": {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(sev, 4),
            })
            node_ids.add(v_id)
            edges.append([root_id, v_id, sev])

    return {"nodes": nodes, "edges": edges}


@app.get("/api/tools")
async def get_tool_executions() -> list[dict[str, Any]]:
    """Tool execution history."""
    tracer = get_global_tracer()
    if not tracer:
        return []
    return [
        {
            "execution_id": eid,
            "agent_id": ex.get("agent_id"),
            "tool_name": ex.get("tool_name"),
            "status": ex.get("status"),
            "started_at": ex.get("started_at"),
            "completed_at": ex.get("completed_at"),
        }
        for eid, ex in tracer.tool_executions.items()
    ]


@app.get("/api/scan-results")
async def get_scan_results() -> dict[str, Any]:
    """Final scan results and summary."""
    tracer = get_global_tracer()
    if not tracer:
        return {"completed": False}
    return {
        "completed": bool(tracer.scan_results),
        "results": tracer.scan_results,
        "final_report": tracer.final_scan_result,
    }


@app.get("/api/llm-stats")
async def get_llm_stats() -> dict[str, Any]:
    """LLM usage statistics."""
    tracer = get_global_tracer()
    if not tracer:
        return {}
    try:
        return tracer.get_total_llm_stats()
    except Exception:
        return {}


@app.get("/api/scan-config")
async def get_scan_config() -> dict[str, Any]:
    """Current scan configuration."""
    tracer = get_global_tracer()
    if not tracer or not tracer.scan_config:
        return {}
    return tracer.scan_config


# --- Report generation ---


@app.get("/api/report")
async def generate_report(format: str = "html") -> Any:
    """Generate a pentest report in HTML (rendered in browser) or downloadable HTML file."""
    tracer = get_global_tracer()
    if not tracer:
        raise HTTPException(status_code=404, detail="No scan data available")

    metadata = tracer.run_metadata
    vulns = tracer.vulnerability_reports
    targets = metadata.get("targets", [])
    target_str = targets[0].get("original", "Unknown") if targets else "Unknown"

    # Severity stats
    sev_counts: dict[str, int] = {}
    for v in vulns:
        s = v.get("severity", "info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    # Recon data
    recon = tracer.scan_config.get("recon_results", {}) if tracer.scan_config else {}
    step1 = recon.get("step_1", {})
    step2 = recon.get("step_2", {})
    subdomains = _filter_subdomain_list(step1.get("subdomains", []))
    nmap_raw = _filter_shell_prompts(step2.get("nmap_output", ""))
    ports = _parse_nmap_ports(nmap_raw)
    httpx_info = _parse_httpx_output(_filter_shell_prompts(step1.get("httpx_output", "")))

    # Agents
    agents_list = []
    for aid, node in _agent_graph.get("nodes", {}).items():
        state = _agent_states.get(aid)
        agents_list.append({
            "name": node.get("name", aid),
            "task": node.get("task", ""),
            "status": node.get("status", "unknown"),
            "iterations": state.iteration if state else 0,
        })

    # Attack graph
    attack_nodes = list(_attack_graph.get("nodes", {}).values())

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    esc = html.escape

    # Build vulnerability rows
    vuln_rows = ""
    sev_colors = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#3b82f6", "info": "#8b8b8b"}
    for i, v in enumerate(vulns, 1):
        sev = v.get("severity", "info").lower()
        color = sev_colors.get(sev, "#888")
        vuln_rows += f"""
        <div class="vuln-card" style="border-left: 4px solid {color};">
            <div class="vuln-header">
                <span class="sev-badge" style="background:{color}20;color:{color};border:1px solid {color}40;">{esc(sev.upper())}</span>
                <span class="vuln-title">{esc(v.get('title', 'Untitled'))}</span>
                {f'<span class="cvss">CVSS: {v["cvss"]}</span>' if v.get('cvss') else ''}
            </div>
            {f'<div class="vuln-target">{esc(v.get("target", "") or v.get("endpoint", ""))}</div>' if v.get('target') or v.get('endpoint') else ''}
            {f'<p class="vuln-desc">{esc(v.get("description", ""))}</p>' if v.get('description') else ''}
            {f'<div class="section-sub"><strong>Impact:</strong> {esc(v.get("impact", ""))}</div>' if v.get('impact') else ''}
            {f'<div class="section-sub"><strong>Technical Analysis:</strong> {esc(v.get("technical_analysis", ""))}</div>' if v.get('technical_analysis') else ''}
            {f'<div class="poc-section"><div class="poc-label">Proof of Concept</div><pre class="poc-code">{esc(v.get("poc_script_code", ""))}</pre></div>' if v.get('poc_script_code') else ''}
            {f'<div class="section-sub remediation"><strong>Remediation:</strong> {esc(v.get("remediation_steps", ""))}</div>' if v.get('remediation_steps') else ''}
            {f'<div class="cve-info">CVE: {esc(v.get("cve", ""))} | CWE: {esc(v.get("cwe", ""))}</div>' if v.get('cve') or v.get('cwe') else ''}
        </div>"""

    # Port rows
    port_rows = ""
    for p in ports:
        port_rows += f'<tr><td class="mono">{esc(p["port"])}</td><td><span class="state-{p["state"]}">{esc(p["state"])}</span></td><td>{esc(p["service"])}</td></tr>'

    # Agent rows
    agent_rows = ""
    status_colors = {"running": "#22c55e", "completed": "#3b82f6", "finished": "#3b82f6", "error": "#ef4444", "waiting": "#eab308"}
    for a in agents_list:
        sc = status_colors.get(a["status"], "#888")
        agent_rows += f'<tr><td>{esc(a["name"])}</td><td style="max-width:400px;">{esc(a["task"][:120])}</td><td><span style="color:{sc};">{esc(a["status"])}</span></td><td>{a["iterations"]}</td></tr>'

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ziro Pentest Report — {esc(target_str)}</title>
<style>
  :root {{ --bg: #0a0a0a; --card: #111; --border: #222; --text: #e0e0e0; --muted: #888; --accent: #a855f7; }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ background:var(--bg); color:var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; line-height:1.6; }}
  .container {{ max-width:1000px; margin:0 auto; padding:40px 24px; }}
  .header {{ text-align:center; margin-bottom:48px; padding-bottom:32px; border-bottom:1px solid var(--border); }}
  .header h1 {{ font-size:28px; color:#f2f2f2; margin-bottom:8px; }}
  .header .subtitle {{ color:var(--accent); font-size:14px; letter-spacing:2px; text-transform:uppercase; }}
  .meta {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:16px; margin:24px 0; }}
  .meta-item {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:16px; }}
  .meta-item .label {{ font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:1px; }}
  .meta-item .value {{ font-size:18px; font-weight:600; color:#f2f2f2; margin-top:4px; }}
  .section {{ margin:32px 0; }}
  .section h2 {{ font-size:20px; color:#f2f2f2; margin-bottom:16px; padding-bottom:8px; border-bottom:1px solid var(--border); }}
  .section h3 {{ font-size:16px; color:#d4d4d4; margin:16px 0 8px; }}
  .summary-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:16px 0; }}
  .summary-box {{ text-align:center; padding:16px; border-radius:8px; border:1px solid var(--border); }}
  .summary-box .num {{ font-size:32px; font-weight:700; }}
  .summary-box .lbl {{ font-size:11px; color:var(--muted); text-transform:uppercase; margin-top:4px; }}
  .vuln-card {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:20px; margin:12px 0; }}
  .vuln-header {{ display:flex; align-items:center; gap:12px; margin-bottom:8px; }}
  .sev-badge {{ font-size:11px; font-weight:600; padding:3px 10px; border-radius:4px; letter-spacing:0.5px; }}
  .vuln-title {{ font-size:16px; font-weight:600; color:#f2f2f2; }}
  .cvss {{ font-size:12px; color:var(--muted); margin-left:auto; }}
  .vuln-target {{ font-size:13px; color:var(--accent); font-family:monospace; margin-bottom:8px; }}
  .vuln-desc {{ font-size:13px; color:#bbb; margin:8px 0; }}
  .section-sub {{ font-size:13px; color:#aaa; margin:8px 0; }}
  .remediation {{ color:#86efac; }}
  .poc-section {{ margin:12px 0; }}
  .poc-label {{ font-size:11px; color:var(--accent); text-transform:uppercase; letter-spacing:1px; margin-bottom:6px; }}
  .poc-code {{ background:#0d0d0d; border:1px solid var(--border); border-radius:6px; padding:12px; font-size:12px; color:#86efac; overflow-x:auto; white-space:pre-wrap; }}
  .cve-info {{ font-size:12px; color:var(--muted); margin-top:8px; }}
  table {{ width:100%; border-collapse:collapse; }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid var(--border); font-size:13px; }}
  th {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:1px; background:var(--card); }}
  .mono {{ font-family:monospace; color:var(--accent); }}
  .state-open {{ color:#22c55e; }}
  .state-filtered {{ color:#eab308; }}
  .chip {{ display:inline-block; background:#1a1a1a; border:1px solid #333; padding:4px 10px; border-radius:4px; font-size:12px; font-family:monospace; margin:3px; color:#d4d4d4; }}
  .footer {{ text-align:center; margin-top:48px; padding-top:24px; border-top:1px solid var(--border); color:var(--muted); font-size:12px; }}
  @media print {{
    body {{ background:#fff; color:#111; }}
    .vuln-card, .meta-item, th {{ background:#f9f9f9; border-color:#ddd; }}
    .poc-code {{ background:#f0f0f0; color:#1a5a1a; }}
  }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="subtitle">Penetration Test Report</div>
    <h1>ZIRO Security Assessment</h1>
    <p style="color:var(--muted);font-size:13px;">Target: <strong style="color:var(--accent);">{esc(target_str)}</strong> &mdash; Generated: {now}</p>
    <p style="color:var(--muted);font-size:12px;margin-top:4px;">Run: {esc(tracer.run_name or 'N/A')} &mdash; Status: {esc(metadata.get('status', 'unknown'))}</p>
  </div>

  <div class="section">
    <h2>Executive Summary</h2>
    <div class="summary-grid">
      <div class="summary-box"><div class="num" style="color:#ef4444">{sev_counts.get('critical', 0)}</div><div class="lbl">Critical</div></div>
      <div class="summary-box"><div class="num" style="color:#f97316">{sev_counts.get('high', 0)}</div><div class="lbl">High</div></div>
      <div class="summary-box"><div class="num" style="color:#eab308">{sev_counts.get('medium', 0)}</div><div class="lbl">Medium</div></div>
      <div class="summary-box"><div class="num" style="color:#3b82f6">{sev_counts.get('low', 0)}</div><div class="lbl">Low</div></div>
    </div>
    <p style="color:#bbb;font-size:14px;margin-top:12px;">
      Total of <strong>{len(vulns)}</strong> vulnerabilities discovered across <strong>{len(subdomains) or 1}</strong> target(s)
      using <strong>{len(agents_list)}</strong> AI agents with {len(attack_nodes)} attack graph nodes.
    </p>
  </div>

  <div class="section">
    <h2>Target Overview</h2>
    <div class="meta">
      <div class="meta-item"><div class="label">Target</div><div class="value" style="font-size:14px;font-family:monospace;">{esc(target_str)}</div></div>
      <div class="meta-item"><div class="label">Server</div><div class="value" style="font-size:14px;">{esc(httpx_info.get('server', 'N/A'))}</div></div>
      <div class="meta-item"><div class="label">HTTP Status</div><div class="value" style="font-size:14px;">{httpx_info.get('status_code', 'N/A')}</div></div>
      <div class="meta-item"><div class="label">Open Ports</div><div class="value">{len(ports)}</div></div>
    </div>
    {"<h3>Subdomains</h3><div>" + "".join(f'<span class="chip">{esc(s)}</span>' for s in subdomains) + "</div>" if subdomains else ""}
  </div>

  {"<div class='section'><h2>Network Services</h2><table><tr><th>Port</th><th>State</th><th>Service</th></tr>" + port_rows + "</table></div>" if ports else ""}

  <div class="section">
    <h2>Vulnerabilities ({len(vulns)})</h2>
    {vuln_rows if vuln_rows else '<p style="color:var(--muted);">No vulnerabilities discovered.</p>'}
  </div>

  <div class="section">
    <h2>AI Agents ({len(agents_list)})</h2>
    <table>
      <tr><th>Agent</th><th>Task</th><th>Status</th><th>Iterations</th></tr>
      {agent_rows}
    </table>
  </div>

  <div class="footer">
    <p>Generated by <strong>ZIRO</strong> Autonomous Penetration Testing Platform</p>
    <p>{now}</p>
  </div>
</div>
</body>
</html>"""

    if format == "download":
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".html", mode="w", encoding="utf-8")
        tmp.write(report_html)
        tmp.close()
        return FileResponse(
            tmp.name,
            media_type="text/html",
            filename=f"ziro-report-{target_str.replace('/', '_').replace(':', '_')}.html",
        )

    return HTMLResponse(content=report_html)


# --- Scan management ---

_scan_thread: threading.Thread | None = None
_scan_failed: bool = False


class CreateScanRequest(BaseModel):
    target: str
    task_name: str = ""
    instruction: str = ""
    scan_mode: str = "deep"
    red_team: bool = False
    zeroday: bool = False
    infra_mode: bool = False
    smart_contract: bool = False
    auto_risk_filter: bool = True
    credentials: list[dict[str, str]] = []
    request_headers: list[dict[str, str]] = []
    business_context: str = ""
    testing_scope: str = ""
    critical_assets: str = ""
    known_issues: str = ""
    compliance_requirements: str = ""
    recon_id: str = ""
    threat_actor: str = ""  # empty = no adversary emulation; names: apt29, apt28, lazarus, fin7, scattered_spider


@app.post("/api/scans")
async def create_scan(req: CreateScanRequest) -> dict[str, Any]:
    """Start a new penetration test scan."""
    global _scan_thread

    global _scan_failed
    if _scan_thread and _scan_thread.is_alive() and not _scan_failed:
        raise HTTPException(status_code=409, detail="A scan is already running")
    _scan_failed = False

    # Build instruction from all context fields
    parts = []

    # Role-based persona
    persona = _panel_settings.get("persona", "red_team")
    if persona == "blue_team":
        parts.append(
            "<role>BLUE TEAM DEFENDER</role>\n"
            "You are a defensive security analyst. Your goal is to:\n"
            "1. Identify vulnerabilities from a defender's perspective\n"
            "2. For EVERY finding, provide DETAILED remediation steps\n"
            "3. Prioritize findings by business risk, not just CVSS\n"
            "4. Suggest WAF rules, CSP policies, input validation code\n"
            "5. Recommend security architecture improvements\n"
            "6. Generate a remediation roadmap with priorities\n"
            "Still test actively, but focus output on HOW TO FIX, not just what's broken."
        )
    elif persona == "red_team":
        parts.append(
            "<role>RED TEAM ATTACKER</role>\n"
            "You are an offensive security specialist. Your goal is maximum impact:\n"
            "- Chain vulnerabilities into attack paths\n"
            "- Prove impact with data extraction, not just detection\n"
            "- Think like a real adversary — what would a hacker do next?\n"
            "- Escalate: low finding → chain → critical impact"
        )
    elif persona == "bug_bounty":
        parts.append(
            "<role>BUG BOUNTY HUNTER</role>\n"
            "You are a professional bug bounty hunter. Focus on:\n"
            "- HIGH IMPACT findings only (Critical/High severity)\n"
            "- Unique, creative vulnerabilities that automated scanners miss\n"
            "- Business logic flaws, race conditions, IDOR, auth bypasses\n"
            "- Write reports in bug bounty format: Summary → Steps to Reproduce → Impact → PoC\n"
            "- Skip low-hanging fruit (missing headers, info disclosure) unless chained\n"
            "- Focus on money: payment manipulation, balance bypass, gift card abuse"
        )

    # Ultra Mode: an external framework-style structured methodology
    if _panel_settings.get("ultra_mode"):
        parts.append(
            "<critical>\n"
            "ULTRA MODE — SHANNON METHODOLOGY ENABLED\n"
            "You are operating as a team of specialized security agents. Follow this structured pipeline EXACTLY.\n"
            "An incomplete analysis is a FAILED analysis. Finding one flaw is merely the first data point.\n"
            "Your mission is ONLY complete when EVERY potential attack vector has been systematically analyzed.\n"
            "USE HYPOTHESIS-DRIVEN TESTING: for each endpoint, form a hypothesis about what vulnerability\n"
            "might exist, design a minimal experiment to test it, analyze the result, then move to the next.\n"
            "Do NOT blindly run scanners — THINK about what could be vulnerable and WHY, then prove it.\n"
            "</critical>\n\n"

            "<methodology>\n"
            "PHASE 1: SPAWN MANY SPECIALIZED SUB-AGENTS\n"
            "Create as many sub-agents as needed. More agents = more coverage. Minimum 5, aim for 8-15.\n"
            "Each agent focuses on ONE specific task. Suggested agents:\n\n"

            "CORE AGENTS (always create these):\n"
            "- Injection Agent — SQLi, NoSQLi, command injection, SSTI, path traversal, XXE on all params\n"
            "- XSS Agent — reflected, stored, DOM-based XSS. Test CSP bypasses, encoding mismatches\n"
            "- Auth Agent — authentication bypass, JWT manipulation, session fixation, brute-force\n"
            "- SSRF Agent — server-side request forgery, cloud metadata, internal services\n"
            "- AuthZ Agent — IDOR on every endpoint, privilege escalation, missing access controls\n\n"

            "ADDITIONAL AGENTS (create based on target):\n"
            "- Recon Agent — deep crawling with katana, JS analysis, hidden endpoint discovery\n"
            "- Browser Agent — browser-driven testing, form submission, JS-heavy app interaction\n"
            "- API Fuzzer Agent — parameter fuzzing with arjun, type confusion, boundary values\n"
            "- Business Logic Agent — race conditions, state machine abuse, payment manipulation\n"
            "- Infrastructure Agent — port scanning, service exploitation, CVE checking\n"
            "- Proxy Analysis Agent — analyze all captured HTTP traffic for tokens, secrets, patterns\n"
            "- Secret Scanner Agent — JS source analysis, leaked API keys, source maps, .env files\n"
            "- WAF Bypass Agent — test bypass techniques specific to detected WAF vendor\n"
            "- Cache/Smuggling Agent — cache poisoning, HTTP request smuggling, 403 bypass\n\n"

            "IMPORTANT: Do NOT limit yourself to predefined agents. Create ANY agent you need.\n"
            "You can create agents with ANY name and ANY task. Examples:\n"
            "- 'POST /api/users Fuzzer' — test all parameters on one specific endpoint\n"
            "- 'GraphQL Introspection & Mutation Tester' — deep GraphQL analysis\n"
            "- 'Payment Flow Race Condition' — concurrent payment testing\n"
            "- 'JWT Token Manipulation' — test all JWT attack vectors\n"
            "- '/admin Panel Access Tester' — test admin bypass techniques\n"
            "- 'File Upload Exploitation' — test upload endpoint for webshell\n"
            "- 'Redis/Database Direct Access' — test exposed database services\n"
            "- 'API v1 vs v2 Comparison' — find differences between API versions\n"
            "- 'Cookie/Session Analyzer' — test session management\n"
            "- 'Telegram Bot API Tester' — test bot-specific endpoints\n\n"
            "CREATE ONE AGENT PER DISCOVERED API ENDPOINT when there are many endpoints.\n"
            "CREATE ONE AGENT PER VULNERABILITY TYPE when testing a specific area.\n"
            "CREATE FOLLOW-UP AGENTS: when an agent finds something, spawn a new one to go deeper.\n"
            "Each sub-agent should run MULTIPLE tools and spend significant time testing.\n"
            "There is NO LIMIT on how many agents you can create. More agents = better coverage.\n"
            "</methodology>\n\n"

            "<exploitation_protocol>\n"
            "PHASE 2: EXPLOITATION (for each confirmed vulnerability)\n"
            "Follow 4-stage OWASP workflow:\n"
            "  Stage 1: CONFIRMATION — Inject error chars, boolean conditions, time delays\n"
            "  Stage 2: FINGERPRINTING — Extract DB version, user, table names\n"
            "  Stage 3: DATA EXTRACTION — Extract first 5 rows from sensitive tables\n"
            "  Stage 4: IMPACT PROOF — Full database dump or RCE if possible\n\n"

            "PROOF OF IMPACT LEVELS:\n"
            "  Level 1: Injection point confirmed (error messages, timing)\n"
            "  Level 2: Query structure manipulated (UNION works, ORDER BY confirms columns)\n"
            "  Level 3: Data extraction PROVEN (actual data retrieved) ← MINIMUM for EXPLOITED\n"
            "  Level 4: Critical impact (admin credentials, RCE achieved)\n\n"

            "BYPASS EXHAUSTION PROTOCOL:\n"
            "  You CANNOT classify as false positive until you have tried:\n"
            "  - At least 8-10 distinct bypass techniques per vulnerability\n"
            "  - URL encoding, double encoding, unicode normalization\n"
            "  - Comment variations (/**/, --, #, %00)\n"
            "  - Case manipulation, null bytes, newline injection\n"
            "  - WAF-specific bypasses (chunked encoding, HTTP parameter pollution)\n"
            "  Only after ALL bypasses fail → classify as FALSE POSITIVE with documentation.\n"
            "</exploitation_protocol>\n\n"

            "<deliverable_requirements>\n"
            "EVERY vulnerability MUST include:\n"
            "- Exact reproduction steps (curl commands, not descriptions)\n"
            "- Expected response showing proof of exploitation\n"
            "- Impact classification: EXPLOITED / POTENTIAL / FALSE POSITIVE\n"
            "- CVSS score estimate\n"
            "- Remediation recommendation\n\n"

            "Use TodoWrite to create a task for EACH vulnerability. Mark in_progress when testing,\n"
            "completed when proven or classified. DO NOT call finish_scan until ALL tasks are completed.\n"
            "</deliverable_requirements>"
        )

    # Red Team mode: inject adversarial testing instructions
    if req.red_team:
        parts.append(
            "RED TEAM MODE ENABLED — Act as an experienced adversary performing a real-world attack simulation.\n"
            "Go beyond discovery: actively test and exploit found vulnerabilities to prove impact.\n"
            "Focus on:\n"
            "- Exploit testing: attempt to actually exploit discovered vulnerabilities (SQLi, XSS, RCE, SSRF, etc.)\n"
            "- Race conditions: test concurrent request attacks on critical operations (payments, transfers, balance changes)\n"
            "- Authentication bypass: test broken auth, session fixation, JWT manipulation, OAuth flaws\n"
            "- Business logic abuse: test price manipulation, coupon stacking, workflow bypasses, IDOR\n"
            "- Privilege escalation: test horizontal and vertical privilege escalation paths\n"
            "- Chain attacks: combine multiple low-severity findings into high-impact attack chains\n"
            "- PROXY ANALYSIS: Use search_burp_proxy_history() to inspect all captured HTTP traffic. "
            "Look for auth tokens, session cookies, CSRF tokens, API keys in requests. "
            "Use repeat_request() to replay requests with modified parameters.\n"
            "Provide concrete proof-of-concept for each finding with reproducible steps.\n"
            "This is an authorized penetration test — test aggressively but responsibly.\n\n"
            "AVAILABLE SCANNERS: nuclei, afrog (CEL-based PoC engine), feroxbuster (directory brute-force), "
            "nmap, sqlmap, dalfox (XSS), XSStrike (advanced XSS with WAF bypass), arjun (parameter discovery), "
            "katana (crawler), nikto, wapiti, trivy (container security). "
            "For race conditions: use vegeta for HTTP load testing at constant rate "
            "(e.g. 'echo \"POST https://target/api/transfer\" | vegeta attack -rate=50/s -duration=2s | vegeta report'). "
            "Use the right tool for each task.\n\n"
            "CRITICAL — DO NOT FINISH EARLY:\n"
            "- You MUST exhaust ALL attack vectors before calling finish_scan\n"
            "- Each subagent must run MULTIPLE tools, not just one\n"
            "- If a subagent finds nothing with one approach, try 2-3 alternative approaches\n"
            "- Run at least: nmap full port scan, nuclei+afrog, feroxbuster, sqlmap on found params, "
            "XSStrike/dalfox on inputs, arjun for hidden params, katana for JS crawling\n"
            "- Analyze ALL proxy traffic with search_burp_proxy_history()\n"
            "- Check for IDOR on every authenticated endpoint\n"
            "- Test race conditions on state-changing operations\n"
            "- DO NOT call finish_scan until you have tested every discovered endpoint thoroughly\n\n"

            "ATTACK CHAIN METHODOLOGY (multi-step exploitation):\n"
            "Do NOT stop at single-step vulns. Build CHAINS:\n"
            "1. RECON → find endpoint → find parameter → test injection\n"
            "2. If injection works → enumerate database → extract credentials\n"
            "3. Use credentials → access admin panel → find file upload\n"
            "4. Upload webshell → achieve RCE → read /etc/passwd\n"
            "5. Check sudo/SUID → escalate to root → full compromise\n"
            "Each step PROVES the next. Document the full chain.\n"
            "A 5-step chain proving RCE is worth 100x more than 5 separate low findings.\n\n"

            "DETERMINISTIC VALIDATION:\n"
            "Every finding MUST be PROVEN, not theorized:\n"
            "- PROVEN: You extracted actual data, executed a command, or modified state\n"
            "- NOT PROVEN: You saw an error message that might indicate a vuln\n"
            "- Include the EXACT curl command or tool output that proves exploitation\n"
            "- Include the EXACT response showing the impact\n"
            "- If you cannot REPRODUCE it, it is NOT a finding\n"
            "- 'The parameter appears vulnerable' is NOT acceptable — show the extracted data\n\n"
            "JAVASCRIPT SOURCE ANALYSIS (semi-white-box):\n"
            "- Download and analyze ALL JS bundles from the target (use curl + grep or katana -jc)\n"
            "- Search for: API keys, JWT tokens, AWS credentials, Firebase configs, hardcoded passwords\n"
            "- Extract hidden API endpoints from JS code (fetch/axios/XMLHttpRequest calls)\n"
            "- Check for source maps (.map files) — if found, download and analyze original source code\n"
            "- Look for commented-out code, debug endpoints, admin routes in JS\n"
            "- Parse webpack chunks for internal service URLs and environment configs\n"
            "- Check for exposed .env values baked into JS bundles (process.env.*, import.meta.env.*)\n\n"

            "OSINT (passive intelligence):\n"
            "- Use google_dork() tool to find exposed files, admin panels, git repos\n"
            "- Use check_breaches() to find if domain/emails appear in data breaches\n"
            "- Use osint_recon() for CT logs, robots.txt, security.txt, DNS intel\n"
            "- Check for leaked credentials that could grant access\n\n"

            "WEBSOCKET TESTING:\n"
            "- Check for WebSocket endpoints (ws:// or wss://) in JS files and proxy traffic\n"
            "- Test origin validation: connect from unauthorized origin\n"
            "- Test authentication: connect without auth token\n"
            "- Test injection: send malicious payloads through WS messages\n"
            "- Test authorization: access other users' channels/rooms\n"
            "- Test rate limiting: flood messages to check for DoS\n"
            "- Use python_action with websocket-client library for WS testing\n\n"

            "ANOMALY DETECTION:\n"
            "- Compare response sizes across similar endpoints — outliers indicate issues\n"
            "- Compare response times — unusually slow responses may indicate injection success\n"
            "- Look for response patterns: same status code but different body = parameter influence\n"
            "- Test same endpoint with different users — different response sizes = data leak\n"
            "- Send identical requests N times — inconsistent responses = race condition\n\n"

            "SELF-CORRECTION PROTOCOL:\n"
            "When a tool call fails or returns an error:\n"
            "1. DO NOT give up. Read the error message carefully.\n"
            "2. Analyze WHY it failed (wrong syntax? auth needed? WAF blocked? wrong path?)\n"
            "3. Try a DIFFERENT approach — at least 3 alternative techniques:\n"
            "   - Different tool (sqlmap instead of manual injection)\n"
            "   - Different encoding (URL encode, double encode, base64)\n"
            "   - Different endpoint (try similar paths)\n"
            "   - Different method (POST instead of GET)\n"
            "   - Different payload (adapt based on error message)\n"
            "4. If tool times out, try with shorter timeout or simpler payload\n"
            "5. If WAF blocks, try bypass techniques from the bypass exhaustion protocol\n"
            "6. ONLY mark as failed after 3+ different approaches have been tried\n\n"

            "ANTI-LOOP (task tree):\n"
            "Track what you have already tested. Before each action:\n"
            "- Check: have I tested THIS endpoint with THIS technique before?\n"
            "- If yes: skip and move to the NEXT untested endpoint or technique\n"
            "- Use TodoWrite to track: create a todo for each endpoint/technique combination\n"
            "- Mark tested combinations as completed\n"
            "- Never repeat the exact same request with the exact same payload twice\n"
            "- Progress through: all endpoints × all techniques systematically\n\n"

            "AUTO-EVIDENCE COLLECTION:\n"
            "For EVERY vulnerability found, immediately collect:\n"
            "1. Full curl command that reproduces the issue\n"
            "2. Complete HTTP response showing the impact\n"
            "3. Screenshot if it's a visual/browser issue (use browser_action screenshot)\n"
            "4. Affected endpoint + method + parameters\n"
            "5. Severity + CVSS estimate + business impact\n"
            "Store all evidence in the vulnerability report (poc_script_code field).\n"
            "Evidence is non-negotiable — every finding must be fully documented.\n\n"

            "WEB SEARCH FOR CVE INTELLIGENCE:\n"
            "Use web_search tool and cve_lookup tool together:\n"
            "- When you identify a technology + version, IMMEDIATELY search for CVEs\n"
            "- Search: '{technology} {version} exploit CVE PoC'\n"
            "- Check cve_lookup for CISA KEV (actively exploited) entries\n"
            "- If PoC exists on GitHub (trickest/cve), try to adapt and execute it\n"
            "- Cross-reference findings with knowledge base patterns\n\n"

            "=== ADVANCED ATTACK TECHNIQUES ===\n\n"

            "1. SINGLE-PACKET RACE CONDITIONS:\n"
            "Send 20-30 identical requests simultaneously to exploit TOCTOU flaws.\n"
            "Use nuclei with race condition templates: nuclei -u TARGET -t http/race/ -race-count 30\n"
            "Or use Python with threading:\n"
            "  import requests, concurrent.futures\n"
            "  def send(): return requests.post(url, json=payload)\n"
            "  with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:\n"
            "      results = list(ex.map(lambda _: send(), range(30)))\n"
            "Target: payments, balance transfers, coupon redemption, vote/like endpoints, \n"
            "gift purchases, any state-changing operation. Check if action executed multiple times.\n\n"

            "2. MULTI-STEP STATE MACHINE FUZZING:\n"
            "For multi-step processes (checkout, registration, password reset, 2FA):\n"
            "- Skip steps: go directly to step 3 without completing step 1-2\n"
            "- Repeat steps: submit step 2 twice\n"
            "- Reverse order: send step 3 before step 1\n"
            "- Modify step data: change order total between step 2 and step 3\n"
            "- Replay: capture step 2 response token, replay it after step flow completes\n"
            "- Parallel steps: send step 2 and step 3 simultaneously\n"
            "This catches logic bypasses that single-request testing misses.\n\n"

            "3. HTTP PARAMETER POLLUTION (HPP):\n"
            "Send same parameter twice: ?user_id=victim&user_id=attacker\n"
            "Test on EVERY parameter that controls access:\n"
            "- GET: ?id=1&id=2 (some backends take first, some take last)\n"
            "- POST JSON: {\"id\": 1, \"id\": 2} or {\"id\": [1, 2]}\n"
            "- Headers: two Authorization headers, two Cookie headers\n"
            "- Path: /api/users/1/../2 (path traversal in routing)\n"
            "Breaks access control when frontend validates first but backend uses last.\n\n"

            "4. SEMANTIC RESPONSE ANALYSIS:\n"
            "Don't just check status codes. Analyze CONTENT changes:\n"
            "- Send normal request → record response body (baseline)\n"
            "- Send injected request → compare response body\n"
            "- If 'balance: 100' changes to 'balance: 0' → IMPACT PROVEN\n"
            "- If response size differs by >10% → parameter has influence\n"
            "- If response contains your input echoed → potential XSS/injection\n"
            "- If response contains data from OTHER users → IDOR confirmed\n"
            "- If response time differs by >2x → potential blind injection\n"
            "Compare responses programmatically, don't rely on error messages.\n\n"

            "5. SUBDOMAIN TAKEOVER:\n"
            "For each subdomain, check if CNAME points to unclaimed resource:\n"
            "- dig CNAME subdomain.target.com\n"
            "- If CNAME points to *.herokuapp.com, *.s3.amazonaws.com, *.github.io, \n"
            "  *.azurewebsites.net, *.cloudfront.net — check if the resource exists\n"
            "- If resource returns 404/NoSuchBucket/There isn't a GitHub Pages site → TAKEOVER possible\n"
            "- This is typically Critical severity — attacker can serve content on victim's subdomain\n\n"

            "6. HTTP/2 SPECIFIC ATTACKS:\n"
            "If target supports HTTP/2:\n"
            "- H2 request smuggling: send conflicting Content-Length and Transfer-Encoding\n"
            "- H2 pseudo-header injection: inject via :authority, :path headers\n"
            "- H2→H1 downgrade smuggling: frontend speaks H2, backend speaks H1\n"
            "- Test with: curl --http2 -H 'Transfer-Encoding: chunked' TARGET\n"
            "- HPACK bomb: send headers that decompress to huge size\n\n"

            "7. WEB CACHE POISONING:\n"
            "Test if responses are cached with injected content:\n"
            "- Send: curl -H 'X-Forwarded-Host: evil.com' TARGET/page\n"
            "- Then visit TARGET/page normally — if evil.com appears, cache is poisoned\n"
            "- Try headers: X-Forwarded-Host, X-Original-URL, X-Rewrite-URL, X-Forwarded-Scheme\n"
            "- Also try: X-Forwarded-Port, X-Forwarded-Prefix\n"
            "- Check Vary header to understand cache key\n"
            "- Cache poisoning = stored XSS equivalent (affects ALL users)\n\n"

            "8. REGEX DoS (ReDoS):\n"
            "For input fields with pattern validation (email, URL, search):\n"
            "- Send catastrophic backtracking payloads:\n"
            "  Email: 'a' * 50 + '@' + 'a' * 50 (50 a's @ 50 a's)\n"
            "  URL: 'http://' + 'a' * 100 + '.com'\n"
            "  Search: '(' * 50 + ')' * 50\n"
            "- If response time >5 seconds → ReDoS confirmed\n"
            "- If server becomes unresponsive → Critical DoS\n"
            "9. BOLA/IDOR SYSTEMATIC TESTING:\n"
            "For EVERY authenticated endpoint:\n"
            "- Change user ID/UUID in path: /api/users/123 → /api/users/124\n"
            "- Change object references in body: {\"order_id\": 100} → {\"order_id\": 101}\n"
            "- Test with different auth tokens (user A's token on user B's data)\n"
            "- Test with NO auth token at all\n"
            "- Test with expired/invalid token\n"
            "- Enumerate IDs: sequential (1,2,3), UUIDs (if predictable), email-based\n"
            "BOLA is the #1 API vulnerability. Test EVERY endpoint.\n\n"

            "10. PII/SENSITIVE DATA DETECTION:\n"
            "In EVERY API response, check for:\n"
            "- Leaked emails, phone numbers, addresses in responses that shouldn't have them\n"
            "- Password hashes, tokens, API keys in response bodies\n"
            "- More data returned than requested (overfetching)\n"
            "- Internal IDs, database columns, debug info\n"
            "- Other users' data mixed into responses\n"
            "- Credit card numbers, SSN patterns, IBAN numbers\n"
            "Flag any PII exposure as a finding.\n\n"

            "11. 403 BYPASS TECHNIQUES:\n"
            "When endpoint returns 403 Forbidden, try:\n"
            "- Path: /admin → //admin, /./admin, /admin/, /admin/., /admin..;/\n"
            "- Headers: X-Original-URL: /admin, X-Rewrite-URL: /admin\n"
            "- Headers: X-Forwarded-For: 127.0.0.1, X-Real-IP: 127.0.0.1\n"
            "- Method: GET → POST, PUT, PATCH, OPTIONS, TRACE\n"
            "- Case: /Admin, /ADMIN, /aDmIn\n"
            "- Encoding: /%61dmin, /admin%00, /admin%20\n"
            "Try ALL techniques — 403 is often bypassable.\n\n"

            "12. HTTP REQUEST SMUGGLING:\n"
            "Test CL.TE and TE.CL desync:\n"
            "- Send conflicting Content-Length and Transfer-Encoding headers\n"
            "- Check if frontend and backend interpret request boundary differently\n"
            "- Use: smuggler tool or manual curl with chunked encoding\n\n"

            "13. CLOUD BUCKET ENUMERATION:\n"
            "Check for exposed cloud storage:\n"
            "- S3: https://{target}.s3.amazonaws.com, https://s3.amazonaws.com/{target}\n"
            "- Azure: https://{target}.blob.core.windows.net\n"
            "- GCP: https://storage.googleapis.com/{target}\n"
            "- If accessible: list objects, check for sensitive files, test write permissions\n\n"

            "REMEDIATION GUIDANCE:\n"
            "For EVERY vulnerability, include a fix recommendation:\n"
            "- SQLi → Use parameterized queries/prepared statements\n"
            "- XSS → Context-aware output encoding + CSP header\n"
            "- SSRF → Whitelist allowed URLs + block internal IPs\n"
            "- IDOR → Implement object-level authorization checks\n"
            "- Auth bypass → Validate session on every request\n"
            "- CORS → Strict origin whitelist, no wildcard\n"
            "- Missing headers → Add HSTS, CSP, X-Frame-Options, X-Content-Type\n"
            "- Race condition → Database-level locks or unique constraints\n"
            "Include specific code examples when possible.\n"
            "14. CUSTOM TEMPLATE GENERATION:\n"
            "When you find a vulnerability pattern, use generate_nuclei_template() to create\n"
            "a custom scanner template. Then run it against ALL similar endpoints.\n"
            "Example: found IDOR on /api/users/1 → generate template → scan /api/users/{1..100}\n"
            "This turns a single finding into systematic coverage.\n"
            "=== MYTHOS METHODOLOGY (hypothesis-driven testing) ===\n\n"

            "DO NOT just run scanners blindly. Follow the scientific method:\n\n"

            "STEP 1: PRIORITIZE TARGETS (1-5 scale)\n"
            "Before testing, rank every endpoint/parameter by vulnerability likelihood:\n"
            "  5 = Handles user input directly (search, file upload, login, payment)\n"
            "  4 = Processes data with state changes (database writes, balance updates)\n"
            "  3 = Returns user-specific data (profile, orders, settings)\n"
            "  2 = Static content with minimal input (about page, docs)\n"
            "  1 = No attack surface (health check, favicon, static assets)\n"
            "START with priority 5 endpoints. Skip 1-2 unless everything else is tested.\n\n"

            "STEP 2: HYPOTHESIZE before each test\n"
            "For each endpoint, THINK before testing:\n"
            "  'This endpoint takes user_id as a parameter and returns user data.\n"
            "   Hypothesis: IDOR — changing user_id will return other users data.\n"
            "   Experiment: send request with user_id=1, then user_id=2, compare responses.\n"
            "   Expected if vulnerable: different user data in response.'\n"
            "Write your hypothesis BEFORE running the test. This prevents random scanning.\n\n"

            "STEP 3: EXPERIMENT with precision\n"
            "Design the MINIMAL test to prove/disprove your hypothesis:\n"
            "  - Don't run nuclei on everything. Test ONE specific thing.\n"
            "  - Send ONE crafted request. Analyze the response carefully.\n"
            "  - Compare: baseline response vs injected response\n"
            "  - Look for: status code change, response size change, content change, timing change\n"
            "  - If no change: hypothesis rejected. Move to next.\n"
            "  - If change detected: dig deeper with follow-up experiments.\n\n"

            "STEP 4: VERIFY findings with a validation pass\n"
            "After finding a vulnerability:\n"
            "  1. Can you reproduce it 3 times consistently?\n"
            "  2. Does it work from a different session/IP?\n"
            "  3. What is the REAL impact (not theoretical)?\n"
            "  4. Generate a clean PoC that anyone can run\n"
            "  5. Ask yourself: 'If I were a security reviewer, would I accept this finding?'\n"
            "If any answer is no — it's not a confirmed finding.\n\n"

            "STEP 5: CHAIN discoveries\n"
            "After confirming a vulnerability, ask:\n"
            "  'What can I do WITH this access that I couldn't do before?'\n"
            "  - SQLi → can I read credentials? → can I login as admin?\n"
            "  - SSRF → can I reach internal services? → can I read cloud metadata?\n"
            "  - XSS → can I steal session cookies? → can I act as the victim?\n"
            "  - IDOR → can I access admin endpoints? → can I modify data?\n"
            "Each chain step is a NEW hypothesis to test.\n\n"

            "STEP 6: SPAWN VALIDATION AGENT\n"
            "When you have findings, create a sub-agent with this specific task:\n"
            "  'Validate these findings. For each one: reproduce it independently,\n"
            "   confirm the impact is real, rate severity accurately, and filter out\n"
            "   any false positives or low-impact issues.'\n"
            "This second pass catches mistakes and strengthens the report.\n\n"

            "=== SMART PAYLOAD GENERATION ===\n"
            "Do NOT use generic payloads. Adapt based on target:\n"
            "- Analyze error messages to understand backend (MySQL vs PostgreSQL vs MongoDB)\n"
            "- Check WAF vendor and use vendor-specific bypass payloads\n"
            "- Study response patterns: what chars are filtered? What encoding is accepted?\n"
            "- For SQLi: if MySQL → use /*!50000*/ comments. If PostgreSQL → use $$ dollar quoting\n"
            "- For XSS: if CSP blocks inline → try event handlers. If filter strips <script> → use <img onerror>\n"
            "- For SSRF: if IP blocked → try DNS rebinding, decimal IP, IPv6 mapped\n"
            "- Build payloads incrementally: test single char → test short payload → build full exploit\n\n"

            "=== VULNERABILITY CORRELATION ===\n"
            "After finding vulnerabilities, look for CHAINS that multiply impact:\n"
            "- XSS + no HttpOnly cookie + no CSP = Session Hijacking (Critical)\n"
            "- IDOR + admin email exposed = Account Takeover\n"
            "- SSRF + cloud metadata = AWS key theft → full infrastructure compromise\n"
            "- Open redirect + OAuth = Authentication bypass\n"
            "- Info disclosure + credential stuffing = Mass account compromise\n"
            "- Race condition + payment endpoint = Financial loss\n"
            "Always report the CHAIN, not individual findings. Chains get higher severity.\n\n"

            "=== GRAPHQL DEEP TESTING ===\n"
            "If GraphQL endpoint found:\n"
            "- Batching attacks: send array of queries [{query1},{query2},...] to bypass rate limits\n"
            "- Nested query DoS: {user{friends{friends{friends...}}}} — test depth limits\n"
            "- Field suggestion abuse: send typo field → check if server suggests real field names\n"
            "- Mutation fuzzing: test every mutation with invalid/unexpected input types\n"
            "- Introspection even if disabled: try __schema via aliases, fragments, GET params\n"
            "- Authorization per-field: query field A (allowed) + field B (restricted) in same query\n"
            "- Type confusion: send String where Int expected, Array where Object expected\n\n"

            "=== MOBILE API TESTING ===\n"
            "Test endpoints with mobile User-Agent — some APIs return MORE data to mobile clients:\n"
            "- Set User-Agent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)'\n"
            "- Also try: app-specific headers like X-App-Version, X-Platform: ios/android\n"
            "- Compare response sizes: mobile vs desktop — if mobile gets more fields = info leak\n"
            "- Test API versioning: /api/v1 vs /api/v2 vs /api/mobile — different access controls\n"
            "- Check for hidden mobile-only endpoints: /api/mobile/, /m/api/, /app/api/\n\n"

            "=== RESPONSE DIFFING ===\n"
            "Automatically compare responses to find anomalies:\n"
            "- Same endpoint, with auth vs without auth: size difference = data exposure\n"
            "- Same endpoint, user A vs user B token: content difference = IDOR\n"
            "- Same request repeated 10x: inconsistent responses = race condition or caching issue\n"
            "- Same endpoint, different HTTP methods: GET vs POST vs PUT = method override vuln\n"
            "- Baseline request vs injected request: any change in body = parameter influence\n"
            "Use python_action to automate: send both requests, compare response.text lengths.\n"
            "=== MOBILE APP TESTING ===\n"
            "When target is a mobile app or Telegram Mini App:\n"
            "- Intercept all API calls from the app via Caido proxy\n"
            "- Analyze: authentication tokens (JWT, session), API versioning, hidden endpoints\n"
            "- Test certificate pinning bypass (if app uses pinning)\n"
            "- Check for hardcoded secrets in app bundle/JS\n"
            "- Test deeplinks/universal links for open redirect or auth bypass\n"
            "- Check if app trusts user-controlled data (initData, WebView bridges)\n"
            "- For Telegram Mini Apps specifically:\n"
            "  - Validate initData signature verification on server side\n"
            "  - Test if bot_id can be manipulated\n"
            "  - Check if user data (user.id, user.first_name) is trusted without verification\n"
            "  - Test replay attacks with old initData\n"
            "  - Check authorization between different users/bots\n\n"

            "=== THREAT MODELING (STRIDE) ===\n"
            "Before attacking, build a threat model:\n"
            "- SPOOFING: Can an attacker impersonate another user/service?\n"
            "- TAMPERING: Can request data be modified in transit? (params, headers, body)\n"
            "- REPUDIATION: Are actions logged? Can attacker deny their actions?\n"
            "- INFORMATION DISCLOSURE: What data leaks through errors, headers, APIs?\n"
            "- DENIAL OF SERVICE: Can attacker exhaust resources? (ReDoS, infinite loops, large uploads)\n"
            "- ELEVATION OF PRIVILEGE: Can user become admin? Can guest access auth endpoints?\n"
            "Use this framework to identify attack vectors BEFORE scanning.\n"
            "Create a todo item for each STRIDE category and test systematically.\n\n"

            "=== EXPLOIT CHAINING WITH APPROVAL ===\n"
            "For multi-step exploit chains:\n"
            "1. Document each step BEFORE executing\n"
            "2. Show the full chain plan: Step 1 → Step 2 → ... → Impact\n"
            "3. Execute step by step, confirming each works before proceeding\n"
            "4. If any step fails, try alternative paths\n"
            "5. Record EVERY step with exact commands and responses\n"
            "Chains should be reproducible — another tester can follow your steps.\n\n"

            "=== BUSINESS LOGIC TESTING ===\n"
            "Dedicated testing for business logic flaws:\n"
            "- Price manipulation: change price in request body, apply negative discounts\n"
            "- Coupon/promo abuse: reuse codes, stack discounts, apply to excluded items\n"
            "- Quantity manipulation: order -1 items, 0 items, MAX_INT items\n"
            "- Workflow bypass: skip payment step, skip verification, skip terms acceptance\n"
            "- Race conditions on: balance transfers, limited stock purchases, vote/like\n"
            "- Currency/unit confusion: send cents where dollars expected\n"
            "- Referral abuse: self-referral, circular referral chains\n"
            "- Free trial abuse: re-register, manipulate trial dates\n"
            "- Loyalty points: negative redemption, point injection, overflow\n"
            "Create a dedicated sub-agent for business logic if the target has e-commerce/financial features.\n\n"

            "=== POC VALIDATION PROTOCOL ===\n"
            "After ALL testing is complete, spawn a VALIDATION AGENT with task:\n"
            "'Review all findings. For each vulnerability:\n"
            " 1. Reproduce it independently using only the PoC provided\n"
            " 2. Confirm the severity rating is accurate\n"
            " 3. Verify the impact is real (not theoretical)\n"
            " 4. Check for false positives — remove any unconfirmed findings\n"
            " 5. Ensure PoC commands are clean and copy-pasteable\n"
            " 6. Add CVSS score if missing'\n"
            "This validation pass is MANDATORY for Ultra Mode.\n\n"

            "=== SWARM COORDINATION ===\n"
            "When running many agents in parallel:\n"
            "- Assign clear non-overlapping scope to each agent\n"
            "- Agent A tests /api/users/*, Agent B tests /api/orders/*, etc.\n"
            "- Share findings between agents: if A finds auth bypass, B should test with it\n"
            "- Root agent acts as COORDINATOR: reviews sub-agent findings, identifies gaps,\n"
            "  spawns new agents for untested areas\n"
            "- After all sub-agents finish, root agent should:\n"
            "  1. Consolidate all findings\n"
            "  2. Build correlation chains\n"
            "  3. Spawn validation agent\n"
            "  4. Generate final report\n"
            "=== END ADVANCED TECHNIQUES ==="
        )

    if req.zeroday:
        parts.append(
            "ZERO-DAY HUNTER MODE ENABLED — Focus on discovering unknown and unpatched vulnerabilities.\n\n"
            "Strategy:\n"
            "1. TECHNOLOGY FINGERPRINTING: Identify exact versions of all frameworks, libraries, CMS, plugins, "
            "and server software. Use HTTP headers, error pages, JS files, meta tags, and /robots.txt.\n\n"
            "2. CVE RESEARCH: For each identified technology and version, use the cve_lookup tool to search NVD "
            "for known CVEs. Check if the target runs vulnerable versions. Focus on CVEs from 2024-2026 with "
            "public exploits.\n\n"
            "3. DEEP PARAMETER FUZZING: Systematically fuzz ALL input parameters:\n"
            "   - URL params, POST body fields, JSON properties, HTTP headers (Host, X-Forwarded-For, Referer)\n"
            "   - Test type confusion: send arrays where strings expected, negative numbers for quantities\n"
            "   - Boundary values: empty strings, very long strings (10000+ chars), special chars, null bytes\n"
            "   - Polyglot payloads that trigger multiple vulnerability classes simultaneously\n\n"
            "4. LOGIC ANALYSIS: Look for logic flaws that no scanner can find:\n"
            "   - State machine violations (skip steps in multi-step workflows)\n"
            "   - Time-of-check-to-time-of-use (TOCTOU) race conditions\n"
            "   - Integer overflow/underflow in financial calculations\n"
            "   - Implicit trust between microservices (SSRF chains)\n"
            "   - GraphQL introspection, batching attacks, nested query DoS\n\n"
            "5. NOVEL ATTACK VECTORS: Try unconventional approaches:\n"
            "   - HTTP request smuggling (CL.TE, TE.CL)\n"
            "   - Cache poisoning and cache deception\n"
            "   - WebSocket hijacking and injection\n"
            "   - Prototype pollution in JS-heavy apps\n"
            "   - Server-side template injection (SSTI) via unusual injection points\n"
            "   - DNS rebinding if internal services are accessible\n\n"
            "For each finding, provide:\n"
            "- Exact reproduction steps\n"
            "- Impact analysis (what an attacker could achieve)\n"
            "- Whether this is a known CVE or a potentially novel vulnerability\n"
            "- CVSS score estimate\n\n"
            "PROXY ANALYSIS: Use search_burp_proxy_history() and view_request() to inspect all HTTP traffic. "
            "Analyze request/response patterns, look for hidden parameters, debug endpoints, "
            "version headers, stack traces in error responses.\n\n"
            "SCANNERS: Use afrog for CEL-based PoC testing alongside nuclei. "
            "Use feroxbuster for recursive directory brute-forcing. "
            "Use katana for JS-aware crawling to discover hidden endpoints.\n\n"
            "CRITICAL — BE THOROUGH:\n"
            "- Do NOT stop after first pass. Run multiple tools on every endpoint.\n"
            "- Fuzz EVERY parameter with multiple payload types (SQLi, XSS, SSTI, command injection)\n"
            "- Check every endpoint for IDOR by changing IDs/UUIDs\n"
            "- Test type confusion on every JSON field\n"
            "- Look for hidden API endpoints via JS analysis (katana + gospider)\n"
            "- Cross-reference found technologies with cve_lookup for EVERY component"
        )

    if req.infra_mode:
        parts.append(
            "INFRASTRUCTURE PENTEST MODE — Target is a server/IP. Focus on OS and service-level vulnerabilities.\n\n"

            "PHASE 1: FULL RECONNAISSANCE\n"
            "- Run nmap FULL port scan: nmap -p- -sV -sC -O --script=vuln TARGET\n"
            "  This scans ALL 65535 ports with version detection, OS detection, and vuln scripts\n"
            "- For each open service, use cve_lookup to find CVEs for that exact version\n"
            "- Check Shodan data if available in recon results\n\n"

            "PHASE 2: SERVICE-SPECIFIC EXPLOITATION\n"
            "For each discovered service, run targeted attacks:\n\n"

            "SSH (port 22):\n"
            "- hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 ssh://TARGET\n"
            "- Try common credentials: root/root, admin/admin, root/toor, admin/password\n"
            "- Check for weak SSH keys, SSH agent forwarding, known_hosts leaks\n"
            "- Test SSH version for CVEs (libssh auth bypass, etc.)\n\n"

            "FTP (port 21):\n"
            "- Test anonymous login: ftp TARGET → user: anonymous\n"
            "- hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://TARGET\n"
            "- Check for writable directories, config file exposure\n\n"

            "MySQL/PostgreSQL (port 3306/5432):\n"
            "- hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://TARGET\n"
            "- Test default credentials: root/(empty), root/root, postgres/postgres\n"
            "- If access gained: enumerate databases, extract sensitive data\n\n"

            "Redis (port 6379):\n"
            "- redis-cli -h TARGET INFO → check if no auth required\n"
            "- If open: CONFIG GET dir, CONFIG SET dir /var/www/html, write webshell\n\n"

            "HTTP/HTTPS (80/443/8080/8443):\n"
            "- Full web app scan as normal (nuclei, feroxbuster, etc.)\n"
            "- Check for management panels: /manager, /admin, /phpmyadmin, /wp-admin\n"
            "- Check server-status, server-info, .env, .git exposure\n\n"

            "SMB (port 445):\n"
            "- enum4linux -a TARGET\n"
            "- smbclient -L //TARGET -N (anonymous listing)\n"
            "- Check for EternalBlue (MS17-010) if Windows\n\n"

            "PHASE 3: POST-EXPLOITATION (if access gained)\n"
            "- whoami, id, uname -a → identify user and OS\n"
            "- sudo -l → check sudo privileges\n"
            "- find / -perm -4000 2>/dev/null → SUID binaries\n"
            "- cat /etc/crontab, ls -la /etc/cron.* → cron jobs\n"
            "- Check for Docker: docker ps, /var/run/docker.sock\n"
            "- Check for Kubernetes: kubectl get pods, check service account tokens\n"
            "- Network enumeration: ip a, netstat -tlnp, arp -a → find pivot targets\n"
            "- Check cloud metadata: curl http://169.254.169.254/latest/meta-data/\n"
            "  If AWS: extract IAM credentials, check S3 buckets\n\n"

            "PHASE 4: PRIVILEGE ESCALATION\n"
            "- Use linpeas.sh or manual checks for privesc vectors\n"
            "- Kernel exploits: check kernel version → searchsploit linux kernel <version>\n"
            "- Writable /etc/passwd or /etc/shadow\n"
            "- Docker group membership → docker escape\n"
            "- Capabilities: getcap -r / 2>/dev/null\n"
            "- PATH hijacking, library injection\n\n"

            "TOOLS: nmap, hydra, enum4linux, smbclient, redis-cli, searchsploit, "
            "metasploit (msfconsole), nikto, nuclei, feroxbuster, sqlmap, netcat.\n"
            "For each finding, provide: exact commands used, output received, impact assessment."
        )

    if req.smart_contract:
        parts.append(
            "SMART CONTRACT AUDIT MODE — Target is a Solidity/EVM smart contract.\n\n"

            "PHASE 1: CODE ACQUISITION\n"
            "- If target is contract address: fetch verified source from Etherscan/BSCScan API\n"
            "  curl 'https://api.etherscan.io/api?module=contract&action=getsourcecode&address=ADDRESS'\n"
            "- If target is GitHub repo: clone and analyze all .sol files\n"
            "- Identify: Solidity version, compiler settings, dependencies (OpenZeppelin, etc.)\n\n"

            "PHASE 2: STATIC ANALYSIS\n"
            "Run automated tools on the source code:\n"
            "- slither . --print human-summary — overview of contract structure\n"
            "- slither . --detect all — run all 92+ vulnerability detectors\n"
            "- slither . --print contract-summary — functions, modifiers, state variables\n"
            "- myth analyze CONTRACT.sol — symbolic execution for deep bugs\n"
            "Parse and analyze ALL findings from both tools.\n\n"

            "PHASE 3: MANUAL AI ANALYSIS\n"
            "Read the contract code and check for:\n"
            "- REENTRANCY: external calls before state updates? Missing ReentrancyGuard?\n"
            "- ACCESS CONTROL: missing onlyOwner/onlyRole? Public functions that should be restricted?\n"
            "- INTEGER OVERFLOW/UNDERFLOW: unchecked math? Using Solidity <0.8.0 without SafeMath?\n"
            "- FLASH LOAN VECTORS: price oracles manipulable in single tx? Spot price used?\n"
            "- FRONT-RUNNING (MEV): can miners/validators profit from tx ordering?\n"
            "- ORACLE MANIPULATION: single oracle source? TWAP vs spot price?\n"
            "- DELEGATECALL: delegatecall to user-controlled address? Storage collision risk?\n"
            "- SELFDESTRUCT: can contract be destroyed? Remaining funds handled?\n"
            "- TIMESTAMP DEPENDENCE: using block.timestamp for critical logic?\n"
            "- TX.ORIGIN: using tx.origin for auth instead of msg.sender?\n"
            "- UNCHECKED RETURNS: external call return values ignored?\n"
            "- DENIAL OF SERVICE: unbounded loops? Gas griefing? Pull-over-push violated?\n"
            "- STORAGE COLLISION: proxy pattern with conflicting storage slots?\n"
            "- SIGNATURE REPLAY: missing nonce/chainId in signed messages?\n"
            "- ERC20/721 COMPLIANCE: missing events? Non-standard behavior?\n\n"

            "PHASE 4: ECONOMIC ANALYSIS\n"
            "- Token economics: can supply be inflated? Can tokens be minted without limit?\n"
            "- Liquidity pool: sandwich attack possible? Slippage manipulation?\n"
            "- Governance: flash loan governance attack? Vote manipulation?\n"
            "- Fee extraction: can fees be set to 100%? Fee bypass possible?\n\n"

            "PHASE 5: REPORT\n"
            "For each finding provide:\n"
            "- Vulnerability type and severity (Critical/High/Medium/Low/Informational)\n"
            "- Affected function and line number\n"
            "- Proof of concept (Solidity test or transaction steps)\n"
            "- Recommended fix with code example\n"
            "- Impact: what can attacker gain? How much funds at risk?\n\n"

            "TOOLS: slither, mythril (myth), solc, forge (Foundry), cast (Etherscan interaction).\n"
            "Use slither as primary scanner, mythril for deep symbolic analysis."
        )

    if req.instruction:
        parts.append(
            "=== USER INSTRUCTIONS (CRITICAL — FOLLOW THESE) ===\n"
            + req.instruction
            + "\n=== END USER INSTRUCTIONS ==="
        )
        logger.info("User instruction injected (%d chars)", len(req.instruction))
    if req.business_context:
        parts.append(f"Business context: {req.business_context}")
    if req.testing_scope:
        parts.append(f"Testing scope: {req.testing_scope}")
    if req.critical_assets:
        parts.append(f"Critical assets: {req.critical_assets}")
    if req.known_issues:
        parts.append(f"Known issues: {req.known_issues}")
    if req.compliance_requirements:
        parts.append(f"Compliance: {req.compliance_requirements}")
    if req.credentials:
        cred_lines = [f"  {c.get('username', '')}:{c.get('password', '')}" for c in req.credentials]
        parts.append("Credentials:\n" + "\n".join(cred_lines))
    if req.request_headers:
        hdr_lines = [f"  {h.get('name', '')}: {h.get('value', '')}" for h in req.request_headers]
        parts.append("Custom headers:\n" + "\n".join(hdr_lines))

    combined_instruction = "\n\n".join(parts)

    from ziro.interface.utils import generate_run_name, infer_target_type

    try:
        target_type, target_dict = infer_target_type(req.target)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid target: {req.target}")

    target_info = {
        "type": target_type,
        "details": target_dict,
        "original": req.target,
    }

    run_name = generate_run_name([target_info])

    scan_config = {
        "scan_id": run_name,
        "targets": [target_info],
        "user_instructions": combined_instruction,
        "run_name": run_name,
    }

    # Store custom headers and credentials in scan_config for tools to use
    if req.request_headers:
        scan_config["custom_headers"] = {
            h.get("name", ""): h.get("value", "")
            for h in req.request_headers if h.get("name")
        }
    if req.credentials:
        scan_config["credentials"] = req.credentials

    # Inject recon results if available
    if req.recon_id:
        recon_session = get_recon_session(req.recon_id)
        if recon_session and recon_session.results:
            recon_summary = recon_session.results.get("step_5", {}).get("summary", "") or recon_session.results.get("step_4", {}).get("summary", "")
            if recon_summary:
                scan_config["recon_summary"] = recon_summary
                scan_config["recon_results"] = recon_session.results

    def run_scan() -> None:
        global _scan_failed
        import asyncio as _asyncio

        from ziro.agents.ZiroAgent import ZiroAgent
        from ziro.llm.config import LLMConfig

        tracer = Tracer(run_name)
        tracer.set_scan_config(scan_config)
        set_global_tracer(tracer)

        # ZIRO_THREAT_ACTOR env var overrides request field when set
        import os as _os

        _ta = (req.threat_actor or _os.getenv("ZIRO_THREAT_ACTOR") or "").strip() or None
        llm_config = LLMConfig(
            scan_mode=req.scan_mode, interactive=True, threat_actor=_ta
        )
        agent_config = {
            "llm_config": llm_config,
            "max_iterations": 300,
        }

        # Auto-start checkpoint loop so the scan can be resumed if panel crashes
        try:
            from ziro.persistence import start_checkpoint_loop

            start_checkpoint_loop(run_name or "default")
        except Exception:
            pass

        async def _run() -> None:
            agent = ZiroAgent(agent_config)
            await agent.execute_scan(scan_config)

        loop = _asyncio.new_event_loop()
        _asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_run())
        except Exception as e:
            logger.error("Scan failed: %s", e)
            _scan_failed = True
        finally:
            loop.close()
            # Save scan to history + learn patterns
            try:
                _save_scan_to_history(tracer)
            except Exception:
                pass
            try:
                from ziro.panel.knowledge import learn_from_scan
                techs = []
                if tracer.scan_config:
                    recon = tracer.scan_config.get("recon_results", {})
                    s1 = recon.get("step_1", {})
                    httpx_info = s1.get("httpx_info", {}) if isinstance(s1, dict) else {}
                    techs = httpx_info.get("technologies", []) if isinstance(httpx_info, dict) else []
                target_str = tracer.scan_config.get("targets", [{}])[0].get("original", "") if tracer.scan_config else ""
                learn_from_scan(target_str, techs, tracer.vulnerability_reports)
            except Exception:
                pass

    _scan_thread = threading.Thread(target=run_scan, daemon=True)
    _scan_thread.start()

    return {
        "status": "started",
        "run_name": run_name,
        "target": req.target,
    }


@app.delete("/api/scans")
async def stop_scan() -> dict[str, str]:
    """Stop the running scan and clean up all resources."""
    # Cleanup runtime (Docker containers)
    try:
        from ziro.runtime import cleanup_runtime

        cleanup_runtime()
    except Exception:
        pass

    # Kill ziro containers by name
    try:
        result = subprocess.run(
            ["docker", "ps", "-q", "--filter", "name=ziro-scan-"],
            capture_output=True, text=True, timeout=5,
        )
        ids = result.stdout.strip().split()
        if ids:
            subprocess.run(["docker", "rm", "-f", *ids], capture_output=True, timeout=15)
    except Exception:
        pass

    # Close browsers
    try:
        from ziro.tools.browser.tab_manager import _browser_tab_manager

        _browser_tab_manager.close_all()
    except Exception:
        pass

    # Cleanup tracer
    tracer = get_global_tracer()
    if tracer:
        tracer.cleanup()

    return {"status": "stopped"}


class SendMessageRequest(BaseModel):
    agent_id: str = ""
    message: str


@app.get("/api/checkpoints")
async def list_checkpoints() -> dict[str, Any]:
    """List available scan checkpoint sessions for resume."""
    try:
        from ziro.persistence import list_checkpoint_sessions

        return {"sessions": list_checkpoint_sessions()}
    except Exception as e:
        return {"sessions": [], "error": str(e)}


@app.post("/api/checkpoints/save")
async def save_checkpoint(body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Force-write a checkpoint now (operator click from panel)."""
    session_id = (body or {}).get("session_id", "default")
    try:
        from ziro.persistence import write_checkpoint

        path = write_checkpoint(session_id)
        return {"status": "ok" if path else "failed", "path": path}
    except Exception as e:
        return {"status": "failed", "error": str(e)}


@app.post("/api/checkpoints/restore")
async def restore_checkpoint(body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Restore engagement state + knowledge graph from latest checkpoint."""
    session_id = (body or {}).get("session_id", "default")
    try:
        from ziro.persistence import restore_from_checkpoint

        return restore_from_checkpoint(session_id)
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/api/approvals")
async def list_approvals_endpoint() -> dict[str, Any]:
    """List pending operator approval requests for panel UI."""
    import json as _json
    import os as _os

    approval_dir = "/workspace/.ziro-approvals"
    if not _os.path.isdir(approval_dir):
        return {"pending": [], "count": 0}
    pending = []
    for fname in sorted(_os.listdir(approval_dir)):
        if not fname.endswith(".json"):
            continue
        try:
            with open(_os.path.join(approval_dir, fname), encoding="utf-8") as f:
                st = _json.load(f)
            if st.get("status") == "pending":
                pending.append(st)
        except Exception:
            continue
    return {"pending": pending, "count": len(pending)}


@app.post("/api/approval-decide/{approval_id}")
async def decide_approval(approval_id: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Operator approves/denies a pending request."""
    import json as _json
    import os as _os
    import time as _time

    path = f"/workspace/.ziro-approvals/{approval_id}.json"
    if not _os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Approval request not found")
    try:
        with open(path, encoding="utf-8") as f:
            state = _json.load(f)
    except Exception:
        raise HTTPException(status_code=500, detail="Corrupt approval state")

    approved = bool((body or {}).get("approved", False))
    reason = (body or {}).get("reason", "")[:500]
    decided_by = (body or {}).get("decided_by", "operator")[:100]

    state["status"] = "approved" if approved else "denied"
    state["approved"] = approved
    state["operator_reason"] = reason
    state["decided_by"] = decided_by
    state["decided_at"] = _time.time()

    with open(path, "w", encoding="utf-8") as f:
        _json.dump(state, f, indent=2)

    return {"status": state["status"], "approval_id": approval_id}


@app.get("/api/llm-debug/{agent_id}")
async def get_llm_debug(agent_id: str) -> dict[str, Any]:
    """Inspect last N messages an agent has seen — debug why it made a decision."""
    state = _agent_states.get(agent_id)
    if not state:
        raise HTTPException(status_code=404, detail="Agent not found")

    messages = state.messages[-30:]
    return {
        "agent_id": agent_id,
        "agent_name": getattr(state, "agent_name", ""),
        "iteration": state.iteration,
        "waiting": state.waiting_for_input,
        "completed": state.completed,
        "llm_failed": getattr(state, "llm_failed", False),
        "consecutive_llm_failures": getattr(state, "consecutive_llm_failures", 0),
        "messages_preview": [
            {
                "role": m.get("role", "?"),
                "content_preview": (
                    m.get("content", "")
                    if isinstance(m.get("content"), str)
                    else str(m.get("content"))[:500]
                )[:2000],
                "has_thinking": bool(m.get("thinking_blocks")),
            }
            for m in messages
        ],
    }


@app.get("/api/metrics", response_class=PlainTextResponse)
async def prometheus_metrics() -> str:
    """Prometheus text-format metrics endpoint.

    Exposes ziro_active_scans, ziro_findings_total, ziro_findings_confirmed_total,
    ziro_llm_cost_usd_total, ziro_llm_tokens_total (labeled by kind), and
    ziro_tool_executions_total (labeled by tool, status).
    """
    lines: list[str] = []

    # Active scans = agents not completed
    active = sum(1 for s in _agent_states.values() if not s.completed)
    lines += [
        "# HELP ziro_active_scans Number of agents currently running",
        "# TYPE ziro_active_scans gauge",
        f"ziro_active_scans {active}",
    ]

    # Findings
    try:
        from ziro.engagement import get_engagement_state

        st = get_engagement_state()
        total = len(st.findings)
        confirmed = sum(1 for f in st.findings.values() if f.status == "confirmed")
        by_sev: dict[str, int] = {}
        for f in st.findings.values():
            by_sev[f.severity or "UNKNOWN"] = by_sev.get(f.severity or "UNKNOWN", 0) + 1
        lines += [
            "# HELP ziro_findings_total Total findings in engagement state",
            "# TYPE ziro_findings_total gauge",
            f"ziro_findings_total {total}",
            "# HELP ziro_findings_confirmed_total Confirmed findings in engagement state",
            "# TYPE ziro_findings_confirmed_total gauge",
            f"ziro_findings_confirmed_total {confirmed}",
            "# HELP ziro_findings_by_severity Findings by severity label",
            "# TYPE ziro_findings_by_severity gauge",
        ]
        for sev, n in by_sev.items():
            lines.append(f'ziro_findings_by_severity{{severity="{sev}"}} {n}')
    except Exception:
        pass

    # LLM cost / tokens
    total_cost = 0.0
    total_input = 0
    total_output = 0
    total_cached = 0
    try:
        from ziro.tools.agents_graph.agents_graph_actions import _agent_instances

        for inst in _agent_instances.values():
            if hasattr(inst, "llm") and hasattr(inst.llm, "_total_stats"):
                s = inst.llm._total_stats
                total_cost += getattr(s, "cost", 0.0) or 0.0
                total_input += getattr(s, "input_tokens", 0) or 0
                total_output += getattr(s, "output_tokens", 0) or 0
                total_cached += getattr(s, "cached_tokens", 0) or 0
    except Exception:
        pass

    lines += [
        "# HELP ziro_llm_cost_usd_total Cumulative LLM cost in USD this process",
        "# TYPE ziro_llm_cost_usd_total counter",
        f"ziro_llm_cost_usd_total {total_cost}",
        "# HELP ziro_llm_tokens_total Cumulative LLM tokens by kind",
        "# TYPE ziro_llm_tokens_total counter",
        f'ziro_llm_tokens_total{{kind="input"}} {total_input}',
        f'ziro_llm_tokens_total{{kind="output"}} {total_output}',
        f'ziro_llm_tokens_total{{kind="cached"}} {total_cached}',
    ]

    # Tool executions counts
    try:
        tracer = get_global_tracer()
        if tracer and hasattr(tracer, "tool_execution_counts"):
            counts = tracer.tool_execution_counts or {}
            lines += [
                "# HELP ziro_tool_executions_total Cumulative tool executions",
                "# TYPE ziro_tool_executions_total counter",
            ]
            for (tool, status), n in counts.items():
                lines.append(
                    f'ziro_tool_executions_total{{tool="{tool}",status="{status}"}} {n}'
                )
    except Exception:
        pass

    return "\n".join(lines) + "\n"


@app.get("/api/cost-breakdown")
async def get_cost_breakdown() -> dict[str, Any]:
    """Per-agent LLM cost + token totals for live cost tracker in panel header."""
    rows = []
    totals = {"input_tokens": 0, "output_tokens": 0, "cached_tokens": 0, "cost": 0.0}
    for agent_id, state in _agent_states.items():
        node = _agent_graph.get("nodes", {}).get(agent_id, {})
        llm_stats = getattr(state, "_llm_stats", None)
        # Fall back: try to pull from agent_instance.llm.total_stats
        if llm_stats is None:
            try:
                from ziro.tools.agents_graph.agents_graph_actions import _agent_instances

                inst = _agent_instances.get(agent_id)
                if inst and hasattr(inst, "llm") and hasattr(inst.llm, "_total_stats"):
                    s = inst.llm._total_stats
                    llm_stats = {
                        "input_tokens": getattr(s, "input_tokens", 0),
                        "output_tokens": getattr(s, "output_tokens", 0),
                        "cached_tokens": getattr(s, "cached_tokens", 0),
                        "cost": getattr(s, "cost", 0.0),
                    }
            except Exception:
                llm_stats = {}
        if not llm_stats:
            continue
        rows.append(
            {
                "agent_id": agent_id,
                "agent_name": node.get("name", ""),
                "status": node.get("status", ""),
                **llm_stats,
            }
        )
        for k in ("input_tokens", "output_tokens", "cached_tokens"):
            totals[k] += int(llm_stats.get(k, 0) or 0)
        totals["cost"] += float(llm_stats.get("cost", 0.0) or 0.0)

    return {
        "totals": totals,
        "by_agent": sorted(rows, key=lambda r: -float(r.get("cost", 0))),
    }


@app.post("/api/scan/pause")
async def pause_scan(body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Pause all running agents — they finish their current iteration and wait for resume."""
    from datetime import datetime, timezone

    target_agent_id = (body or {}).get("agent_id", "")
    paused: list[str] = []
    for aid, state in _agent_states.items():
        if target_agent_id and aid != target_agent_id:
            continue
        if not state.waiting_for_input and not state.completed:
            state.waiting_for_input = True
            state.waiting_start_time = datetime.now(timezone.utc)
            paused.append(aid)
            node = _agent_graph.get("nodes", {}).get(aid)
            if node:
                node["status"] = "waiting"
                node["waiting_reason"] = "operator_pause"
    return {"status": "paused", "agent_ids": paused, "count": len(paused)}


@app.post("/api/scan/resume")
async def resume_scan(body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Resume paused agents. Optionally pass {message, agent_id} to inject operator guidance."""
    target_agent_id = (body or {}).get("agent_id", "")
    message = (body or {}).get("message", "").strip()
    resumed: list[str] = []
    for aid, state in _agent_states.items():
        if target_agent_id and aid != target_agent_id:
            continue
        if state.waiting_for_input:
            if message:
                state.add_message("user", message)
            state.resume_from_waiting()
            resumed.append(aid)
            node = _agent_graph.get("nodes", {}).get(aid)
            if node:
                node["status"] = "running"
                node.pop("waiting_reason", None)
    try:
        tracer = get_global_tracer()
        if tracer:
            for aid in resumed:
                tracer.update_agent_status(aid, "running")
    except Exception:
        pass
    return {
        "status": "resumed",
        "agent_ids": resumed,
        "count": len(resumed),
        "message_injected": bool(message),
    }


@app.get("/api/openapi.json", include_in_schema=False)
async def ziro_openapi_spec() -> dict[str, Any]:
    """Expose the panel API as OpenAPI 3.1 spec for external integrators.

    FastAPI generates this automatically; we just tag it as a stable public
    endpoint with custom info. Use with openapi-generator to build typed
    client libraries for Python/TypeScript/Go/Ruby.
    """
    spec = app.openapi()
    spec["info"] = {
        "title": "Ziro Panel API",
        "version": "1.0.0",
        "description": (
            "Public HTTP API for the Ziro pentest agent panel. Use these endpoints "
            "to kick off scans, send messages to running agents, read engagement "
            "state, and integrate Ziro with CI/CD or custom dashboards."
        ),
        "contact": {"url": "https://github.com/Xyeino/ziro"},
    }
    return spec


@app.get("/api/handoffs")
async def list_handoffs() -> dict[str, Any]:
    """List pending browser handoff requests for the panel UI modal."""
    import json as _json
    import os as _os

    handoff_dir = "/workspace/.ziro-handoffs"
    if not _os.path.isdir(handoff_dir):
        return {"pending": [], "count": 0}

    pending = []
    for fname in sorted(_os.listdir(handoff_dir)):
        if not fname.endswith(".json"):
            continue
        try:
            with open(_os.path.join(handoff_dir, fname), encoding="utf-8") as f:
                state = _json.load(f)
            if state.get("status") == "pending":
                pending.append(state)
        except Exception:
            continue

    return {"pending": pending, "count": len(pending)}


@app.post("/api/handoff-complete/{handoff_id}")
async def complete_handoff(handoff_id: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Operator marks a handoff completed — agent unblocks on next poll."""
    import json as _json
    import os as _os
    import time as _time

    handoff_dir = "/workspace/.ziro-handoffs"
    path = _os.path.join(handoff_dir, f"{handoff_id}.json")
    if not _os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Handoff not found")

    try:
        with open(path, encoding="utf-8") as f:
            state = _json.load(f)
    except Exception:
        raise HTTPException(status_code=500, detail="Corrupt handoff state")

    action = (body or {}).get("action", "complete")
    notes = (body or {}).get("notes", "")[:500]

    if action == "cancel":
        state["status"] = "cancelled"
    else:
        state["status"] = "completed"
    state["completed_at"] = _time.time()
    state["operator_notes"] = notes

    with open(path, "w", encoding="utf-8") as f:
        _json.dump(state, f, indent=2)

    return {"status": state["status"], "handoff_id": handoff_id}


@app.post("/api/agent-message")
async def send_agent_message(req: SendMessageRequest) -> dict[str, Any]:
    """Send a user message to an agent (default: root agent)."""
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    # Find target agent
    target_id = req.agent_id
    if not target_id:
        # Find root agent (no parent)
        for aid, node in _agent_graph.get("nodes", {}).items():
            if not node.get("parent_id"):
                target_id = aid
                break
        if not target_id and _agent_states:
            target_id = next(iter(_agent_states))

    if not target_id or target_id not in _agent_states:
        raise HTTPException(status_code=404, detail="Agent not found")

    state = _agent_states[target_id]

    # 1. Put the message into the agent message queue so _check_agent_messages
    #    picks it up on the next iteration. Previously the panel wrote directly
    #    to state.messages, which the agent loop's _check_agent_messages never
    #    saw — meaning the graph node status, tracer status, and UI were never
    #    updated from 'waiting' to 'running'. The user saw a frozen "ожидающий"
    #    panel even when the agent was actually processing the message.
    from ziro.tools.agents_graph.agents_graph_actions import send_user_message_to_agent

    send_result = send_user_message_to_agent(target_id, req.message.strip())
    if not send_result.get("success"):
        # Fallback: direct state mutation if the queue-based path failed
        state.add_message("user", req.message.strip())

    # 2. Resume the agent state if it's waiting or completed.
    if state.waiting_for_input:
        state.resume_from_waiting()
    elif state.completed or state.stop_requested:
        state.completed = False
        state.stop_requested = False
        state.waiting_for_input = False
        state.final_result = None
        logger.info("Resuming completed agent %s with new message", target_id)

    # 3. Update the graph node + tracer so the UI reflects 'running' immediately
    #    instead of staying stuck on 'waiting'/'completed'.
    try:
        with _agent_graph.get("_lock", __import__("threading").Lock()):
            pass
    except Exception:
        pass

    node = _agent_graph.get("nodes", {}).get(target_id)
    if node and node.get("status") in ("waiting", "completed", "stopped", "finished"):
        node["status"] = "running"

    try:
        tracer = get_global_tracer()
        if tracer:
            tracer.update_agent_status(target_id, "running")
    except Exception:
        pass

    return {"status": "sent", "agent_id": target_id, "message": req.message.strip()}


@app.get("/api/browser-view")
async def get_browser_view() -> dict[str, Any]:
    """Get the current browser screenshot from active agent browser sessions."""
    screenshots: dict[str, Any] = {}

    for agent_id, state in _agent_states.items():
        node = _agent_graph.get("nodes", {}).get(agent_id, {})
        agent_name = node.get("name", agent_id)

        # Check agent's last messages for browser screenshots
        for msg in reversed(state.messages[-10:]):
            content = msg.get("content", "")
            if isinstance(content, str) and "screenshot" in content.lower():
                # The browser_action tool returns screenshot as base64 in results
                pass

            # Check if content is a list (multi-part with images)
            if isinstance(content, list):
                for part in content:
                    if isinstance(part, dict):
                        if part.get("type") == "image":
                            source = part.get("source", {})
                            if source.get("type") == "base64":
                                screenshots[agent_id] = {
                                    "agent_name": agent_name,
                                    "screenshot": source.get("data", ""),
                                    "media_type": source.get("media_type", "image/png"),
                                }
                                break
            if agent_id in screenshots:
                break

    # Also check tool executions for browser_action screenshots
    tracer = get_global_tracer()
    if tracer:
        for tex in reversed(list(tracer.tool_executions.values())[-50:]):
            if tex.get("tool_name") in ("browser_action", "browser_launch"):
                agent_id = tex.get("agent_id", "")
                result = tex.get("result", {})
                if isinstance(result, dict) and result.get("screenshot"):
                    node = _agent_graph.get("nodes", {}).get(agent_id, {})
                    screenshots[agent_id] = {
                        "agent_name": node.get("name", agent_id),
                        "screenshot": result["screenshot"],
                        "media_type": "image/png",
                        "url": result.get("url", ""),
                        "title": result.get("title", ""),
                    }

    return {"browsers": screenshots, "total": len(screenshots)}


# --- Human assist requests (captcha, manual intervention) ---

_human_assist_requests: list[dict[str, Any]] = []


@app.get("/api/assist-requests")
async def get_assist_requests() -> dict[str, Any]:
    """Get pending human-assist requests (captcha, manual actions)."""
    return {"requests": _human_assist_requests, "total": len(_human_assist_requests)}


@app.post("/api/assist-resolve")
async def resolve_assist_request(req: dict[str, Any]) -> dict[str, Any]:
    """Mark an assist request as resolved (human completed the action)."""
    request_id = req.get("request_id", "")
    for ar in _human_assist_requests:
        if ar["id"] == request_id:
            ar["status"] = "resolved"
            # Resume the agent
            agent_id = ar.get("agent_id", "")
            if agent_id and agent_id in _agent_states:
                _agent_states[agent_id].add_message(
                    "user",
                    "Human operator has resolved the captcha/challenge. "
                    "You can continue your work. The browser should now have access."
                )
            return {"status": "resolved", "request_id": request_id}
    return {"status": "not_found"}


def add_assist_request(
    agent_id: str, assist_type: str, message: str,
    url: str = "", screenshot: str = "",
) -> str:
    """Add a human-assist request (called from tools when captcha detected)."""
    import uuid

    req_id = f"assist-{uuid.uuid4().hex[:8]}"
    node = _agent_graph.get("nodes", {}).get(agent_id, {})
    _human_assist_requests.append({
        "id": req_id,
        "agent_id": agent_id,
        "agent_name": node.get("name", agent_id),
        "type": assist_type,
        "message": message,
        "url": url,
        "screenshot": screenshot,
        "status": "pending",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return req_id


# --- Scan History (SQLite) ---

_history_db = Path.home() / ".ziro" / "scan_history.db"


def _init_history_db() -> None:
    _history_db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_history_db))
    conn.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_name TEXT, target TEXT, status TEXT, scan_mode TEXT,
        vuln_count INTEGER DEFAULT 0, critical INTEGER DEFAULT 0,
        high INTEGER DEFAULT 0, medium INTEGER DEFAULT 0, low INTEGER DEFAULT 0,
        started_at TEXT, ended_at TEXT, duration_seconds INTEGER DEFAULT 0,
        total_tokens INTEGER DEFAULT 0, cost REAL DEFAULT 0,
        agent_count INTEGER DEFAULT 0, tool_calls INTEGER DEFAULT 0,
        report_html TEXT DEFAULT '', findings_json TEXT DEFAULT '[]',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS scan_templates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT, target TEXT, scan_mode TEXT, notes TEXT,
        headers_json TEXT DEFAULT '[]', credentials_json TEXT DEFAULT '[]',
        business_context TEXT DEFAULT '', testing_scope TEXT DEFAULT '',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.commit()
    conn.close()


_init_history_db()


def _save_scan_to_history(tracer: Any) -> None:
    """Save completed scan to history DB."""
    try:
        metadata = tracer.run_metadata
        vulns = tracer.vulnerability_reports
        sev = {}
        for v in vulns:
            s = v.get("severity", "info").lower()
            sev[s] = sev.get(s, 0) + 1

        stats = {}
        try:
            stats = tracer.get_total_llm_stats()
        except Exception:
            pass

        conn = sqlite3.connect(str(_history_db))
        conn.execute(
            "INSERT INTO scans (run_name, target, status, vuln_count, critical, high, medium, low, "
            "started_at, ended_at, total_tokens, cost, agent_count, findings_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                tracer.run_name,
                metadata.get("targets", [{}])[0].get("original", "") if metadata.get("targets") else "",
                metadata.get("status", "unknown"),
                len(vulns),
                sev.get("critical", 0), sev.get("high", 0), sev.get("medium", 0), sev.get("low", 0),
                tracer.start_time, tracer.end_time,
                stats.get("total_tokens", 0),
                stats.get("total", {}).get("cost", 0),
                len(_agent_graph.get("nodes", {})),
                json.dumps([{"title": v.get("title", ""), "severity": v.get("severity", ""), "target": v.get("target", "")} for v in vulns]),
            ),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning("Failed to save scan to history: %s", e)


@app.get("/api/history")
async def get_scan_history() -> dict[str, Any]:
    """Get past scan results."""
    try:
        conn = sqlite3.connect(str(_history_db))
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 50").fetchall()
        conn.close()
        return {"scans": [dict(r) for r in rows], "total": len(rows)}
    except Exception:
        return {"scans": [], "total": 0}


@app.get("/api/history/diff")
async def diff_scans(scan_a: int, scan_b: int) -> dict[str, Any]:
    """Compare two scans — show new/fixed/unchanged vulnerabilities."""
    try:
        conn = sqlite3.connect(str(_history_db))
        conn.row_factory = sqlite3.Row
        a = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_a,)).fetchone()
        b = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_b,)).fetchone()
        conn.close()

        if not a or not b:
            return {"error": "Scan not found"}

        a_findings = {f["title"] for f in json.loads(a["findings_json"] or "[]")}
        b_findings = {f["title"] for f in json.loads(b["findings_json"] or "[]")}

        new_vulns = b_findings - a_findings
        fixed_vulns = a_findings - b_findings
        unchanged = a_findings & b_findings

        return {
            "scan_a": {"id": a["id"], "target": a["target"], "date": a["started_at"], "vuln_count": a["vuln_count"]},
            "scan_b": {"id": b["id"], "target": b["target"], "date": b["started_at"], "vuln_count": b["vuln_count"]},
            "new": sorted(new_vulns),
            "fixed": sorted(fixed_vulns),
            "unchanged": sorted(unchanged),
            "summary": f"+{len(new_vulns)} new, -{len(fixed_vulns)} fixed, {len(unchanged)} unchanged",
        }
    except Exception as e:
        return {"error": str(e)}


# --- Security Score ---

@app.get("/api/security-score")
async def get_security_score() -> dict[str, Any]:
    """Calculate A-F security score based on findings."""
    tracer = get_global_tracer()
    if not tracer:
        return {"grade": "?", "score": 0, "breakdown": {}}

    vulns = tracer.vulnerability_reports
    if not vulns:
        return {"grade": "A+", "score": 100, "breakdown": {"message": "No vulnerabilities found"}}

    # Scoring: start at 100, deduct per vulnerability
    score = 100
    deductions = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        sev = v.get("severity", "info").lower()
        if sev == "critical":
            score -= 25
            deductions["critical"] += 1
        elif sev == "high":
            score -= 15
            deductions["high"] += 1
        elif sev == "medium":
            score -= 8
            deductions["medium"] += 1
        elif sev == "low":
            score -= 3
            deductions["low"] += 1

    score = max(0, score)

    # Grade mapping
    if score >= 95:
        grade = "A+"
    elif score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"

    grade_color = {"A+": "#22c55e", "A": "#22c55e", "B": "#3b82f6", "C": "#eab308", "D": "#f97316", "F": "#ef4444"}.get(grade, "#888")

    return {
        "grade": grade,
        "score": score,
        "color": grade_color,
        "total_vulns": len(vulns),
        "breakdown": deductions,
    }


# --- Scan Templates ---

@app.get("/api/templates")
async def get_templates() -> dict[str, Any]:
    try:
        conn = sqlite3.connect(str(_history_db))
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM scan_templates ORDER BY id DESC").fetchall()
        conn.close()
        return {"templates": [dict(r) for r in rows]}
    except Exception:
        return {"templates": []}


@app.post("/api/templates")
async def save_template(req: dict[str, Any]) -> dict[str, Any]:
    try:
        conn = sqlite3.connect(str(_history_db))
        conn.execute(
            "INSERT INTO scan_templates (name, target, scan_mode, notes, headers_json, credentials_json, business_context, testing_scope) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (req.get("name", ""), req.get("target", ""), req.get("scan_mode", "standard"),
             req.get("notes", ""), json.dumps(req.get("headers", [])), json.dumps(req.get("credentials", [])),
             req.get("business_context", ""), req.get("testing_scope", "")),
        )
        conn.commit()
        conn.close()
        return {"status": "saved"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.delete("/api/templates/{template_id}")
async def delete_template(template_id: int) -> dict[str, str]:
    try:
        conn = sqlite3.connect(str(_history_db))
        conn.execute("DELETE FROM scan_templates WHERE id = ?", (template_id,))
        conn.commit()
        conn.close()
    except Exception:
        pass
    return {"status": "deleted"}


# --- Export: Markdown + JSON ---

@app.get("/api/report/markdown")
async def export_markdown() -> Any:
    """Export findings as Markdown."""
    tracer = get_global_tracer()
    if not tracer:
        raise HTTPException(status_code=404, detail="No scan data")

    vulns = tracer.vulnerability_reports
    target = tracer.scan_config.get("targets", [{}])[0].get("original", "?") if tracer.scan_config else "?"
    lines = [f"# Ziro Security Report — {target}\n", f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"]
    lines.append(f"**Vulnerabilities:** {len(vulns)}\n")

    for i, v in enumerate(vulns, 1):
        sev = v.get("severity", "info").upper()
        lines.append(f"\n## {i}. [{sev}] {v.get('title', 'Untitled')}\n")
        if v.get("target"):
            lines.append(f"**Target:** `{v['target']}`\n")
        if v.get("cvss"):
            lines.append(f"**CVSS:** {v['cvss']}")
        if v.get("cve"):
            lines.append(f" | **CVE:** {v['cve']}")
        if v.get("cwe"):
            lines.append(f" | **CWE:** {v['cwe']}")
        lines.append("\n")
        if v.get("description"):
            lines.append(f"\n{v['description']}\n")
        if v.get("poc_script_code"):
            lines.append(f"\n```\n{v['poc_script_code']}\n```\n")
        if v.get("remediation_steps"):
            lines.append(f"\n**Remediation:** {v['remediation_steps']}\n")

    content = "\n".join(lines)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".md", mode="w", encoding="utf-8")
    tmp.write(content)
    tmp.close()
    return FileResponse(tmp.name, media_type="text/markdown", filename=f"ziro-report-{target.replace('/', '_')}.md")


@app.get("/api/report/json")
async def export_json() -> Any:
    """Export findings as JSON."""
    tracer = get_global_tracer()
    if not tracer:
        raise HTTPException(status_code=404, detail="No scan data")

    data = {
        "tool": "ziro",
        "version": "1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": tracer.scan_config.get("targets", [{}])[0].get("original", "") if tracer.scan_config else "",
        "vulnerabilities": tracer.vulnerability_reports,
        "summary": {
            "total": len(tracer.vulnerability_reports),
            "by_severity": {},
        },
    }
    for v in tracer.vulnerability_reports:
        s = v.get("severity", "info").lower()
        data["summary"]["by_severity"][s] = data["summary"]["by_severity"].get(s, 0) + 1

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w", encoding="utf-8")
    tmp.write(json.dumps(data, indent=2, default=str))
    tmp.close()
    return FileResponse(tmp.name, media_type="application/json", filename="ziro-findings.json")


# --- Telegram Notifications ---

@app.post("/api/notify/telegram")
async def send_telegram_notification(req: dict[str, Any]) -> dict[str, Any]:
    """Send a notification to Telegram."""
    bot_token = get_api_key("telegram_bot")
    chat_id = get_api_key("telegram_chat")
    if not bot_token or not chat_id:
        return {"status": "error", "message": "Set telegram_bot and telegram_chat in Settings"}

    message = req.get("message", "")
    if not message:
        # Auto-generate from current scan
        tracer = get_global_tracer()
        if tracer:
            vulns = tracer.vulnerability_reports
            target = tracer.scan_config.get("targets", [{}])[0].get("original", "?") if tracer.scan_config else "?"
            sev = {}
            for v in vulns:
                s = v.get("severity", "info").lower()
                sev[s] = sev.get(s, 0) + 1
            message = (
                f"🔍 Ziro Scan Complete: {target}\n"
                f"🔴 Critical: {sev.get('critical', 0)} | 🟠 High: {sev.get('high', 0)} | "
                f"🟡 Medium: {sev.get('medium', 0)} | 🔵 Low: {sev.get('low', 0)}\n"
                f"Total: {len(vulns)} vulnerabilities"
            )

    import requests as _req
    try:
        resp = _req.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={"chat_id": chat_id, "text": message, "parse_mode": "HTML"},
            timeout=10,
        )
        return {"status": "sent" if resp.ok else "error", "response": resp.text[:200]}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# --- Compliance Mapping (OWASP Top 10) ---

OWASP_TOP_10 = {
    "A01": {"name": "Broken Access Control", "patterns": ["idor", "authz", "authorization", "privilege", "access control", "insecure direct"]},
    "A02": {"name": "Cryptographic Failures", "patterns": ["crypto", "ssl", "tls", "certificate", "encryption", "cleartext", "hash"]},
    "A03": {"name": "Injection", "patterns": ["sqli", "sql injection", "xss", "command injection", "ssti", "xxe", "ldap", "nosql"]},
    "A04": {"name": "Insecure Design", "patterns": ["business logic", "race condition", "design flaw"]},
    "A05": {"name": "Security Misconfiguration", "patterns": ["misconfig", "default", "header", "cors", "directory listing", "verbose error"]},
    "A06": {"name": "Vulnerable Components", "patterns": ["cve-", "outdated", "vulnerable version", "component"]},
    "A07": {"name": "Auth Failures", "patterns": ["authentication", "brute force", "credential", "session", "jwt", "password", "login"]},
    "A08": {"name": "Software & Data Integrity", "patterns": ["deserialization", "integrity", "supply chain"]},
    "A09": {"name": "Logging & Monitoring", "patterns": ["logging", "monitoring", "audit"]},
    "A10": {"name": "SSRF", "patterns": ["ssrf", "server-side request", "internal"]},
}


@app.get("/api/compliance")
async def get_compliance() -> dict[str, Any]:
    """Map vulnerabilities to OWASP Top 10."""
    tracer = get_global_tracer()
    if not tracer:
        return {"owasp": {}, "total_mapped": 0}

    mapping: dict[str, list[dict[str, str]]] = {k: [] for k in OWASP_TOP_10}

    for v in tracer.vulnerability_reports:
        text = f"{v.get('title', '')} {v.get('description', '')} {v.get('cwe', '')}".lower()
        for code, info in OWASP_TOP_10.items():
            if any(p in text for p in info["patterns"]):
                mapping[code].append({"title": v.get("title", ""), "severity": v.get("severity", "")})

    result = {}
    total = 0
    for code, info in OWASP_TOP_10.items():
        vulns = mapping[code]
        result[code] = {"name": info["name"], "vulns": vulns, "count": len(vulns)}
        total += len(vulns)

    return {"owasp": result, "total_mapped": total}


# --- Plugins ---


@app.get("/api/plugins")
async def get_plugins() -> dict[str, Any]:
    from ziro.panel.plugins import list_plugins
    return {"plugins": list_plugins()}


@app.post("/api/plugins/{name}/run")
async def run_plugin(name: str, req: dict[str, Any] = {}) -> dict[str, Any]:
    from ziro.panel.plugins import run_plugin as _run
    target = req.get("target", "")
    if not target:
        tracer = get_global_tracer()
        if tracer and tracer.scan_config:
            targets = tracer.scan_config.get("targets", [])
            if targets:
                target = targets[0].get("original", "")
    return _run(name, target, req.get("config", {}))


# --- Knowledge Graph ---


@app.get("/api/knowledge")
async def get_knowledge() -> dict[str, Any]:
    """Get knowledge base summary."""
    from ziro.panel.knowledge import get_knowledge_summary
    return get_knowledge_summary()


@app.get("/api/knowledge/patterns")
async def get_knowledge_patterns(tech: str = "") -> dict[str, Any]:
    """Get vulnerability patterns for given technologies."""
    from ziro.panel.knowledge import get_patterns_for_tech
    technologies = [t.strip() for t in tech.split(",") if t.strip()]
    patterns = get_patterns_for_tech(technologies) if technologies else []
    return {"patterns": patterns, "technologies": technologies}


# --- OpenAPI/Swagger Import ---


@app.post("/api/import/openapi")
async def import_openapi(req: dict[str, Any]) -> dict[str, Any]:
    """Import OpenAPI/Swagger spec and extract endpoints for testing."""
    spec_url = req.get("url", "")
    spec_json = req.get("spec", {})

    if spec_url:
        try:
            import requests as _req
            resp = _req.get(spec_url, timeout=15)
            resp.raise_for_status()
            if spec_url.endswith(".yaml") or spec_url.endswith(".yml"):
                import yaml
                spec_json = yaml.safe_load(resp.text)
            else:
                spec_json = resp.json()
        except Exception as e:
            return {"error": f"Failed to fetch spec: {e}", "endpoints": []}

    if not spec_json:
        return {"error": "No spec provided. Send {url: '...'} or {spec: {...}}", "endpoints": []}

    # Parse OpenAPI 3.x or Swagger 2.x
    endpoints: list[dict[str, Any]] = []
    base_url = ""

    # OpenAPI 3.x
    servers = spec_json.get("servers", [])
    if servers:
        base_url = servers[0].get("url", "")

    # Swagger 2.x
    if not base_url:
        host = spec_json.get("host", "")
        base_path = spec_json.get("basePath", "")
        schemes = spec_json.get("schemes", ["https"])
        if host:
            base_url = f"{schemes[0]}://{host}{base_path}"

    paths = spec_json.get("paths", {})
    for path, methods in paths.items():
        for method, details in methods.items():
            if method.lower() in ("get", "post", "put", "patch", "delete", "options", "head"):
                params = []
                for p in details.get("parameters", []):
                    params.append({
                        "name": p.get("name", ""),
                        "in": p.get("in", ""),
                        "required": p.get("required", False),
                        "type": p.get("schema", {}).get("type", p.get("type", "")),
                    })

                # Request body (OpenAPI 3.x)
                req_body = details.get("requestBody", {})
                body_schema = {}
                if req_body:
                    content = req_body.get("content", {})
                    for content_type, schema_info in content.items():
                        body_schema = schema_info.get("schema", {})
                        break

                endpoints.append({
                    "method": method.upper(),
                    "path": path,
                    "url": f"{base_url}{path}" if base_url else path,
                    "summary": details.get("summary", ""),
                    "parameters": params,
                    "body_schema": body_schema,
                    "auth_required": bool(details.get("security")),
                    "tags": details.get("tags", []),
                })

    return {
        "endpoints": endpoints,
        "total": len(endpoints),
        "base_url": base_url,
        "title": spec_json.get("info", {}).get("title", ""),
        "version": spec_json.get("info", {}).get("version", ""),
    }


# --- TOTP/2FA Support ---


@app.post("/api/totp/generate")
async def generate_totp(req: dict[str, Any]) -> dict[str, Any]:
    """Generate TOTP code from a secret key."""
    secret = req.get("secret", "")
    if not secret:
        return {"error": "No TOTP secret provided"}

    try:
        import hmac
        import struct
        import time as _time
        import base64

        # TOTP generation (RFC 6238)
        secret_bytes = base64.b32decode(secret.upper().replace(" ", ""), casefold=True)
        counter = int(_time.time()) // 30
        counter_bytes = struct.pack(">Q", counter)
        hmac_hash = hmac.new(secret_bytes, counter_bytes, "sha1").digest()
        offset = hmac_hash[-1] & 0x0F
        code = struct.unpack(">I", hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF
        totp = str(code % 1000000).zfill(6)
        remaining = 30 - (int(_time.time()) % 30)

        return {"code": totp, "remaining_seconds": remaining, "valid_until": int(_time.time()) + remaining}
    except Exception as e:
        return {"error": f"TOTP generation failed: {e}"}


# --- Translations (i18n) ---


@app.get("/api/i18n/{lang}")
async def get_translations(lang: str = "en") -> dict[str, Any]:
    from ziro.panel.i18n import TRANSLATIONS
    return TRANSLATIONS.get(lang, TRANSLATIONS["en"])


# --- Evidence Collector ---

@app.get("/api/evidence/download")
async def download_evidence() -> Any:
    """Download all scan evidence as ZIP archive."""
    import zipfile

    tracer = get_global_tracer()
    if not tracer:
        raise HTTPException(status_code=404, detail="No scan data")

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    tmp.close()

    target = ""
    if tracer.scan_config and tracer.scan_config.get("targets"):
        target = tracer.scan_config["targets"][0].get("original", "unknown")

    with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED) as zf:
        # Vulnerabilities JSON
        zf.writestr("findings.json", json.dumps(tracer.vulnerability_reports, indent=2, default=str))

        # Individual vulnerability files with PoC
        for i, v in enumerate(tracer.vulnerability_reports):
            sev = v.get("severity", "info").upper()
            title = re.sub(r"[^a-zA-Z0-9_-]", "_", v.get("title", "finding")[:50])
            content = f"# [{sev}] {v.get('title', '')}\n\n"
            content += f"**Target:** {v.get('target', '')}\n"
            content += f"**Endpoint:** {v.get('endpoint', '')}\n"
            if v.get("cvss"):
                content += f"**CVSS:** {v['cvss']}\n"
            if v.get("cve"):
                content += f"**CVE:** {v['cve']}\n"
            content += f"\n## Description\n{v.get('description', 'N/A')}\n"
            content += f"\n## Impact\n{v.get('impact', 'N/A')}\n"
            content += f"\n## Technical Analysis\n{v.get('technical_analysis', 'N/A')}\n"
            if v.get("poc_script_code"):
                content += f"\n## Proof of Concept\n```\n{v['poc_script_code']}\n```\n"
            if v.get("remediation_steps"):
                content += f"\n## Remediation\n{v['remediation_steps']}\n"
            zf.writestr(f"vulnerabilities/{i+1:02d}_{title}.md", content)

        # Tool execution log
        tool_log = []
        for eid, tex in tracer.tool_executions.items():
            tool_log.append({
                "id": eid,
                "agent_id": tex.get("agent_id"),
                "tool": tex.get("tool_name"),
                "status": tex.get("status"),
                "started": tex.get("started_at"),
                "args": tex.get("args", {}),
            })
        zf.writestr("tool_executions.json", json.dumps(tool_log, indent=2, default=str))

        # Agent states
        agents_data = {}
        for aid, node in _agent_graph.get("nodes", {}).items():
            state = _agent_states.get(aid)
            agents_data[aid] = {
                "name": node.get("name"),
                "task": node.get("task"),
                "status": node.get("status"),
                "iterations": state.iteration if state else 0,
            }
        zf.writestr("agents.json", json.dumps(agents_data, indent=2, default=str))

        # Scan config
        if tracer.scan_config:
            zf.writestr("scan_config.json", json.dumps(tracer.scan_config, indent=2, default=str))

        # Attack graph
        zf.writestr("attack_graph.json", json.dumps({
            "nodes": list(_attack_graph.get("nodes", {}).values()),
            "edges": list(_attack_graph.get("edges", [])),
        }, indent=2, default=str))

    filename = f"ziro-evidence-{target.replace('/', '_').replace(':', '_')}.zip"
    return FileResponse(tmp.name, media_type="application/zip", filename=filename)


# --- Action Recording (for playback) ---

_action_log: list[dict[str, Any]] = []


@app.get("/api/actions")
async def get_action_log() -> dict[str, Any]:
    """Get recorded agent actions for playback timeline."""
    # Auto-build from tool executions if _action_log is empty
    if not _action_log:
        tracer = get_global_tracer()
        if tracer:
            for tex in sorted(tracer.tool_executions.values(), key=lambda t: t.get("started_at", "")):
                agent_id = tex.get("agent_id", "")
                node = _agent_graph.get("nodes", {}).get(agent_id, {})
                result_data = tex.get("result", {})
                result_preview = ""
                if isinstance(result_data, dict):
                    result_preview = str(result_data.get("content", "") or result_data.get("message", ""))[:200]
                _action_log.append({
                    "timestamp": tex.get("started_at", ""),
                    "agent_id": agent_id,
                    "agent_name": node.get("name", agent_id),
                    "type": tex.get("tool_name", ""),
                    "details": _summarize_args(tex.get("args", {})),
                    "result": result_preview,
                    "status": tex.get("status", ""),
                    "duration_ms": 0,
                })

    return {
        "actions": _action_log[-500:],
        "total": len(_action_log),
        "duration_seconds": 0,
    }


def record_action(agent_id: str, action_type: str, details: str, screenshot: str = "") -> None:
    """Record an agent action for playback. Called from tools."""
    node = _agent_graph.get("nodes", {}).get(agent_id, {})
    _action_log.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "agent_name": node.get("name", agent_id),
        "type": action_type,
        "details": details[:500],
        "screenshot": screenshot[:100] + "..." if len(screenshot) > 100 else screenshot,
    })


# --- Settings (API keys) ---

_settings_file = Path.home() / ".ziro" / "settings.json"
_api_keys: dict[str, str] = {}
_panel_settings: dict[str, Any] = {"ultra_mode": False, "language": "en", "rpm_limit": 0, "persona": "red_team"}


def _load_settings() -> None:
    """Load all settings from disk."""
    global _api_keys, _panel_settings
    # Migrate from old api-keys.json
    old_file = Path.home() / ".ziro" / "api-keys.json"
    if old_file.exists() and not _settings_file.exists():
        try:
            _api_keys = json.loads(old_file.read_text())
            _save_settings()
        except (json.JSONDecodeError, OSError):
            pass

    if _settings_file.exists():
        try:
            data = json.loads(_settings_file.read_text())
            _api_keys = data.get("api_keys", data if "ultra_mode" not in data else {})
            _panel_settings = data.get("settings", {"ultra_mode": False})
        except (json.JSONDecodeError, OSError):
            pass


def _save_settings() -> None:
    """Save all settings to disk."""
    _settings_file.parent.mkdir(parents=True, exist_ok=True)
    _settings_file.write_text(json.dumps({
        "api_keys": _api_keys,
        "settings": _panel_settings,
    }, indent=2))


def _load_api_keys() -> dict[str, str]:
    if not _api_keys:
        _load_settings()
    return _api_keys


def _save_api_keys() -> None:
    _save_settings()


def get_api_key(service: str) -> str:
    """Get an API key by service name. Used by recon and tools."""
    if not _api_keys:
        _load_api_keys()
    return _api_keys.get(service, "")


# Load on startup
_load_settings()


# Available API services with descriptions
API_SERVICES = [
    {"id": "shodan", "name": "Shodan", "desc": "IP/port/service intelligence", "url": "https://account.shodan.io", "free": "100 req/month"},
    {"id": "censys", "name": "Censys", "desc": "Internet-wide scanning data (ID:SECRET format)", "url": "https://search.censys.io/account/api", "free": "250 req/month"},
    {"id": "securitytrails", "name": "SecurityTrails", "desc": "DNS history, subdomain data", "url": "https://securitytrails.com/app/signup", "free": "50 req/month"},
    {"id": "virustotal", "name": "VirusTotal", "desc": "Domain/IP reputation, subdomains", "url": "https://www.virustotal.com/gui/join-us", "free": "500 req/day"},
    {"id": "github", "name": "GitHub Token", "desc": "Subfinder GitHub source (PAT, no scopes)", "url": "https://github.com/settings/tokens", "free": "Unlimited"},
    {"id": "perplexity", "name": "Perplexity", "desc": "AI web search for agents", "url": "https://www.perplexity.ai/settings/api", "free": "Pay-per-use"},
    {"id": "binaryedge", "name": "BinaryEdge", "desc": "Internet scanning, subdomain data", "url": "https://app.binaryedge.io/sign-up", "free": "250 req/month"},
    {"id": "fullhunt", "name": "FullHunt", "desc": "Attack surface intelligence", "url": "https://fullhunt.io/sign-up", "free": "100 req/month"},
    {"id": "telegram_bot", "name": "Telegram Bot Token", "desc": "Bot token for scan notifications", "url": "https://t.me/BotFather", "free": "Free"},
    {"id": "telegram_chat", "name": "Telegram Chat ID", "desc": "Chat/group ID for notifications", "url": "https://t.me/userinfobot", "free": "Free"},
]


@app.get("/api/settings")
async def get_settings() -> dict[str, Any]:
    """Get current API keys (masked) and available services."""
    masked = {}
    for k, v in _api_keys.items():
        if v:
            masked[k] = v[:4] + "..." + v[-4:] if len(v) > 10 else "***"
        else:
            masked[k] = ""
    return {
        "keys": masked,
        "services": API_SERVICES,
        "configured_count": sum(1 for v in _api_keys.values() if v),
        "ultra_mode": _panel_settings.get("ultra_mode", False),
        "language": _panel_settings.get("language", "en"),
        "rpm_limit": _panel_settings.get("rpm_limit", 0),
        "persona": _panel_settings.get("persona", "red_team"),
    }


@app.post("/api/settings")
async def update_settings(req: dict[str, Any]) -> dict[str, Any]:
    """Update API keys and settings."""
    keys = req.get("keys", {})
    for service_id, value in keys.items():
        if isinstance(value, str):
            value = value.strip()
            if value and not value.endswith("..."):
                _api_keys[service_id] = value
            elif not value:
                _api_keys.pop(service_id, None)

    # Update ultra_mode if provided
    if "ultra_mode" in req:
        _panel_settings["ultra_mode"] = bool(req["ultra_mode"])
    if "language" in req:
        _panel_settings["language"] = req["language"] if req["language"] in ("en", "ru") else "en"
    if "rpm_limit" in req:
        rpm = int(req["rpm_limit"]) if str(req["rpm_limit"]).isdigit() else 0
        _panel_settings["rpm_limit"] = rpm
    if "persona" in req:
        _panel_settings["persona"] = req["persona"] if req["persona"] in ("red_team", "blue_team", "bug_bounty") else "red_team"
        # Apply to running rate limiter
        try:
            from ziro.llm.llm import _RateLimiter
            _RateLimiter.set_rpm(rpm)
        except Exception:
            pass

    _save_settings()
    return {
        "status": "saved",
        "configured_count": sum(1 for v in _api_keys.values() if v),
        "ultra_mode": _panel_settings.get("ultra_mode", False),
    }


# --- Distributed Scanning ---

@app.get("/api/sandbox/info")
async def get_sandbox_info() -> dict[str, Any]:
    """Get info about running sandbox containers."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=ziro-scan-", "--format", "{{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}"],
            capture_output=True, text=True, timeout=5,
        )
        containers = []
        for line in result.stdout.strip().split("\n"):
            if line.strip():
                parts = line.split("\t")
                containers.append({
                    "id": parts[0] if len(parts) > 0 else "",
                    "name": parts[1] if len(parts) > 1 else "",
                    "status": parts[2] if len(parts) > 2 else "",
                    "ports": parts[3] if len(parts) > 3 else "",
                })
        return {"containers": containers, "count": len(containers)}
    except Exception:
        return {"containers": [], "count": 0}


# --- WebSocket (real-time collaborative updates) ---

_ws_clients: list[WebSocket] = []


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    """Real-time updates via WebSocket. Replaces polling for connected clients."""
    await ws.accept()
    _ws_clients.append(ws)
    try:
        while True:
            # Send updates every 2 seconds
            try:
                tracer = get_global_tracer()
                status_data = {}
                if tracer:
                    metadata = tracer.run_metadata
                    vuln_count = len(tracer.vulnerability_reports)
                    sev_counts: dict[str, int] = {}
                    for v in tracer.vulnerability_reports:
                        s = v.get("severity", "info").lower()
                        sev_counts[s] = sev_counts.get(s, 0) + 1
                    status_data = {
                        "type": "status",
                        "status": metadata.get("status", "unknown"),
                        "vuln_count": vuln_count,
                        "severity_counts": sev_counts,
                        "agent_count": len(_agent_graph.get("nodes", {})),
                        "tool_count": len(tracer.tool_executions),
                    }
                    # Check for new vulns
                    latest_vulns = tracer.vulnerability_reports[-3:] if tracer.vulnerability_reports else []
                    if latest_vulns:
                        status_data["latest_vulns"] = [
                            {"title": v.get("title", ""), "severity": v.get("severity", "")}
                            for v in latest_vulns
                        ]

                await ws.send_json(status_data)
                await asyncio.sleep(2)
            except Exception:
                break
    except WebSocketDisconnect:
        pass
    finally:
        if ws in _ws_clients:
            _ws_clients.remove(ws)


async def _broadcast_ws(data: dict[str, Any]) -> None:
    """Send data to all connected WebSocket clients."""
    for ws in list(_ws_clients):
        try:
            await ws.send_json(data)
        except Exception:
            if ws in _ws_clients:
                _ws_clients.remove(ws)


# --- Reconnaissance ---


class CreateReconRequest(BaseModel):
    target: str


@app.post("/api/recon")
async def start_recon_endpoint(req: CreateReconRequest) -> dict[str, Any]:
    """Start pre-scan reconnaissance."""
    session = start_recon(req.target)
    return {"recon_id": session.recon_id, "status": "started"}


@app.get("/api/recon/{recon_id}/status")
async def get_recon_status(recon_id: str, since_index: int = 0) -> dict[str, Any]:
    """Poll recon progress. Use since_index to get only new logs."""
    session = get_recon_session(recon_id)
    if not session:
        raise HTTPException(status_code=404, detail="Recon session not found")

    logs = [
        {"timestamp": l.timestamp, "step": l.step, "message": l.message}
        for l in session.logs[since_index:]
    ]

    return {
        "recon_id": session.recon_id,
        "status": session.status,
        "current_step": session.current_step,
        "logs": logs,
        "total_logs": len(session.logs),
        "scan_progress": session.scan_progress,
        "scan_total": session.scan_total,
        "results": {
            k: {kk: vv for kk, vv in v.items() if kk != "summary"}
            if isinstance(v, dict) else v
            for k, v in session.results.items()
        },
        "docker_available": session.docker_available,
    }


# --- Serve built frontend ---


def mount_static_files() -> None:
    """Mount the built frontend if dist/ exists."""
    if FRONTEND_DIST.exists() and (FRONTEND_DIST / "index.html").exists():
        app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="static")


# Deferred mount — called after _ensure_frontend_built() in main.py
# mount_static_files()


# --- Runner ---


_cleanup_done = False


def _cleanup_all() -> None:
    """Kill Docker containers, browser instances, and scan threads on shutdown."""
    global _cleanup_done
    if _cleanup_done:
        return
    _cleanup_done = True

    logger.info("Cleaning up all resources...")

    # 1. Cleanup Docker runtime via Python API (if initialized)
    try:
        from ziro.runtime import cleanup_runtime

        cleanup_runtime()
    except Exception as e:
        logger.debug("Runtime cleanup: %s", e)

    # 2. Force-kill ALL ziro Docker containers by name pattern (catches leaked ones)
    try:
        result = subprocess.run(
            ["docker", "ps", "-q", "--filter", "name=ziro-scan-"],
            capture_output=True, text=True, timeout=5,
        )
        container_ids = result.stdout.strip().split()
        if container_ids:
            logger.info("Force-removing %d ziro containers...", len(container_ids))
            subprocess.run(
                ["docker", "rm", "-f", *container_ids],
                capture_output=True, timeout=15,
            )
    except Exception as e:
        logger.debug("Docker force-cleanup: %s", e)

    # 3. Close all Playwright browser contexts
    try:
        from ziro.tools.browser.tab_manager import _browser_tab_manager

        _browser_tab_manager.close_all()
    except Exception as e:
        logger.debug("Browser cleanup: %s", e)

    # 4. Force-close Playwright browser + event loop
    try:
        from ziro.tools.browser.browser_instance import _state
        import contextlib

        if _state.browser is not None:
            with contextlib.suppress(Exception):
                if _state.event_loop and not _state.event_loop.is_closed():
                    future = asyncio.run_coroutine_threadsafe(
                        _state.browser.close(), _state.event_loop
                    )
                    future.result(timeout=5)
            _state.browser = None

        if _state.playwright is not None:
            with contextlib.suppress(Exception):
                if _state.event_loop and not _state.event_loop.is_closed():
                    future = asyncio.run_coroutine_threadsafe(
                        _state.playwright.stop(), _state.event_loop
                    )
                    future.result(timeout=5)
            _state.playwright = None
    except Exception as e:
        logger.debug("Playwright cleanup: %s", e)

    # 5. Kill any orphaned browser processes (Chromium + Firefox/Camoufox)
    for pattern in ["chromium.*headless", "camoufox", "firefox.*headless"]:
        try:
            subprocess.run(
                ["pkill", "-f", pattern],
                capture_output=True, timeout=5,
            )
        except Exception:
            pass

    # 6. Stop Telegram bot
    try:
        from ziro.panel.telegram_bot import stop_telegram_bot
        stop_telegram_bot()
    except Exception:
        pass

    # 7. Cleanup tracer
    tracer = get_global_tracer()
    if tracer:
        try:
            tracer.cleanup()
        except Exception:
            pass

    logger.info("Cleanup complete.")


async def run_panel(host: str = "0.0.0.0", port: int = 8420) -> None:
    """Start the panel server."""
    import signal

    import uvicorn

    mount_static_files()

    # Start Telegram bot if configured
    try:
        from ziro.panel.telegram_bot import start_telegram_bot, stop_telegram_bot

        start_telegram_bot(panel_port=port)
    except Exception:
        pass

    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config)

    # Register cleanup for Ctrl+C and normal exit
    import atexit

    atexit.register(_cleanup_all)

    original_sigint = signal.getsignal(signal.SIGINT)
    original_sigterm = signal.getsignal(signal.SIGTERM)

    def _shutdown_handler(signum: int, frame: Any) -> None:
        logger.info("Shutdown signal received, cleaning up...")
        _cleanup_all()
        # Re-raise to let uvicorn shut down
        if signum == signal.SIGINT and callable(original_sigint):
            original_sigint(signum, frame)
        elif signum == signal.SIGTERM and callable(original_sigterm):
            original_sigterm(signum, frame)
        else:
            raise SystemExit(0)

    signal.signal(signal.SIGINT, _shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)

    try:
        await server.serve()
    finally:
        _cleanup_all()
