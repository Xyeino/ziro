"""Live Dashboard Server — real-time scan monitoring via WebSocket.

Runs a lightweight FastAPI server alongside the main scan process.
Clients connect via WebSocket to receive live updates about:
- Agent activity (spawn, complete, errors)
- Tool executions
- Vulnerability findings
- Attack graph changes
- Scan progress

Usage:
    ZIRO_DASHBOARD=1 ziro scan ...
    Then open http://localhost:7878 in a browser.
"""

import asyncio
import json
import logging
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_dashboard_instance: "DashboardServer | None" = None


class DashboardServer:
    """WebSocket-based live dashboard for scan monitoring."""

    def __init__(self, host: str = "127.0.0.1", port: int = 7878):
        self.host = host
        self.port = port
        self._clients: set[Any] = set()
        self._event_buffer: list[dict[str, Any]] = []
        self._max_buffer = 500
        self._server_thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._app: Any = None

    def start(self) -> None:
        """Start the dashboard server in a background thread."""
        self._server_thread = threading.Thread(
            target=self._run_server,
            daemon=True,
            name="ziro-dashboard",
        )
        self._server_thread.start()
        logger.info("Dashboard started at http://%s:%d", self.host, self.port)

    def _run_server(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._serve())

    async def _serve(self) -> None:
        try:
            from fastapi import FastAPI, WebSocket, WebSocketDisconnect
            from fastapi.responses import HTMLResponse
            import uvicorn
        except ImportError:
            logger.warning("FastAPI/uvicorn not installed — dashboard unavailable")
            return

        app = FastAPI(title="Ziro Dashboard")
        self._app = app

        @app.get("/", response_class=HTMLResponse)
        async def index() -> str:
            return _DASHBOARD_HTML

        @app.get("/api/state")
        async def state() -> dict[str, Any]:
            return self._get_full_state()

        @app.get("/api/events")
        async def events() -> list[dict[str, Any]]:
            return list(self._event_buffer)

        @app.websocket("/ws")
        async def websocket_endpoint(ws: WebSocket) -> None:
            await ws.accept()
            self._clients.add(ws)
            try:
                # Send current state on connect
                await ws.send_json({
                    "type": "init",
                    "state": self._get_full_state(),
                    "events": self._event_buffer[-50:],
                })
                # Keep alive and wait for disconnect
                while True:
                    await ws.receive_text()
            except WebSocketDisconnect:
                pass
            finally:
                self._clients.discard(ws)

        config = uvicorn.Config(
            app,
            host=self.host,
            port=self.port,
            log_level="warning",
            access_log=False,
        )
        server = uvicorn.Server(config)
        await server.serve()

    def broadcast(self, event_type: str, data: dict[str, Any]) -> None:
        """Broadcast an event to all connected WebSocket clients."""
        event = {
            "type": event_type,
            "timestamp": datetime.now(UTC).isoformat(),
            "data": data,
        }

        # Buffer events
        self._event_buffer.append(event)
        if len(self._event_buffer) > self._max_buffer:
            self._event_buffer = self._event_buffer[-self._max_buffer:]

        # Send to connected clients
        if self._loop and self._clients:
            asyncio.run_coroutine_threadsafe(
                self._broadcast_to_clients(event),
                self._loop,
            )

    async def _broadcast_to_clients(self, event: dict[str, Any]) -> None:
        disconnected = set()
        for client in self._clients:
            try:
                await client.send_json(event)
            except Exception:
                disconnected.add(client)
        self._clients -= disconnected

    def _get_full_state(self) -> dict[str, Any]:
        """Get the full current state for the dashboard."""
        state: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "agents": {},
            "findings": [],
            "attack_graph": {"nodes": {}, "edges": []},
            "scope": {},
        }

        try:
            from ziro.telemetry.tracer import get_global_tracer
            tracer = get_global_tracer()
            if tracer:
                state["agents"] = tracer.agents
                state["findings"] = [
                    {
                        "id": r.get("id"),
                        "title": r.get("title"),
                        "severity": r.get("severity"),
                        "target": r.get("target"),
                        "timestamp": r.get("timestamp"),
                    }
                    for r in tracer.vulnerability_reports
                ]
                state["run_metadata"] = tracer.run_metadata
        except ImportError:
            pass

        try:
            from ziro.tools.attack_graph.attack_graph_actions import _attack_graph, _graph_lock
            with _graph_lock:
                state["attack_graph"] = {
                    "nodes": dict(_attack_graph["nodes"]),
                    "edges": list(_attack_graph["edges"]),
                }
        except ImportError:
            pass

        try:
            from ziro.scope import get_scope_guard
            guard = get_scope_guard()
            if guard:
                state["scope"] = guard.summary()
        except ImportError:
            pass

        return state


def get_dashboard() -> "DashboardServer | None":
    return _dashboard_instance


def start_dashboard(host: str = "127.0.0.1", port: int = 7878) -> DashboardServer:
    global _dashboard_instance  # noqa: PLW0603
    if _dashboard_instance is None:
        _dashboard_instance = DashboardServer(host, port)
        _dashboard_instance.start()
    return _dashboard_instance


_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ziro Dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'JetBrains Mono', 'Fira Code', monospace; background: #0a0a0f; color: #e0e0e0; }
  .header { background: #12121a; padding: 16px 24px; border-bottom: 1px solid #2a2a3a; display: flex; align-items: center; gap: 16px; }
  .header h1 { font-size: 18px; color: #7c3aed; }
  .status { font-size: 12px; padding: 4px 12px; border-radius: 12px; }
  .status.connected { background: #065f46; color: #6ee7b7; }
  .status.disconnected { background: #7f1d1d; color: #fca5a5; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; padding: 16px; }
  .panel { background: #12121a; border: 1px solid #2a2a3a; border-radius: 8px; padding: 16px; }
  .panel h2 { font-size: 14px; color: #a78bfa; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 1px; }
  .finding { padding: 8px 12px; margin: 4px 0; border-radius: 4px; font-size: 13px; }
  .finding.critical { background: #450a0a; border-left: 3px solid #ef4444; }
  .finding.high { background: #431407; border-left: 3px solid #f97316; }
  .finding.medium { background: #422006; border-left: 3px solid #eab308; }
  .finding.low { background: #052e16; border-left: 3px solid #22c55e; }
  .finding.info { background: #0c1f3d; border-left: 3px solid #3b82f6; }
  .event { padding: 6px 0; border-bottom: 1px solid #1a1a2a; font-size: 12px; }
  .event .time { color: #6b7280; }
  .event .type { color: #a78bfa; font-weight: bold; }
  .agent { padding: 6px 12px; margin: 4px 0; border-radius: 4px; font-size: 13px; background: #1a1a2a; }
  .agent.running { border-left: 3px solid #3b82f6; }
  .agent.completed { border-left: 3px solid #22c55e; }
  .agent.error { border-left: 3px solid #ef4444; }
  .stats { display: flex; gap: 16px; flex-wrap: wrap; }
  .stat { text-align: center; }
  .stat .value { font-size: 28px; font-weight: bold; color: #7c3aed; }
  .stat .label { font-size: 11px; color: #6b7280; }
  #events { max-height: 400px; overflow-y: auto; }
  .full-width { grid-column: 1 / -1; }
</style>
</head>
<body>
<div class="header">
  <h1>ZIRO</h1>
  <span>Live Dashboard</span>
  <span id="ws-status" class="status disconnected">Disconnected</span>
</div>
<div class="grid">
  <div class="panel">
    <h2>Scan Stats</h2>
    <div class="stats" id="stats">
      <div class="stat"><div class="value" id="stat-findings">0</div><div class="label">Findings</div></div>
      <div class="stat"><div class="value" id="stat-agents">0</div><div class="label">Agents</div></div>
      <div class="stat"><div class="value" id="stat-events">0</div><div class="label">Events</div></div>
    </div>
  </div>
  <div class="panel">
    <h2>Agents</h2>
    <div id="agents"></div>
  </div>
  <div class="panel">
    <h2>Findings</h2>
    <div id="findings"></div>
  </div>
  <div class="panel">
    <h2>Live Events</h2>
    <div id="events"></div>
  </div>
</div>
<script>
let ws;
let eventCount = 0;

function connect() {
  ws = new WebSocket(`ws://${location.host}/ws`);

  ws.onopen = () => {
    document.getElementById('ws-status').className = 'status connected';
    document.getElementById('ws-status').textContent = 'Connected';
  };

  ws.onclose = () => {
    document.getElementById('ws-status').className = 'status disconnected';
    document.getElementById('ws-status').textContent = 'Disconnected';
    setTimeout(connect, 2000);
  };

  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.type === 'init') {
      renderState(msg.state);
      msg.events.forEach(addEvent);
    } else {
      addEvent(msg);
      if (msg.type === 'finding.created') updateFindings(msg.data);
      if (msg.type === 'agent.started' || msg.type === 'agent.completed') fetchState();
    }
  };
}

function renderState(state) {
  const findings = state.findings || [];
  document.getElementById('stat-findings').textContent = findings.length;
  document.getElementById('stat-agents').textContent = Object.keys(state.agents || {}).length;

  const findingsEl = document.getElementById('findings');
  findingsEl.innerHTML = findings.map(f =>
    `<div class="finding ${f.severity}">${f.severity.toUpperCase()} — ${f.title}</div>`
  ).join('') || '<div style="color:#6b7280">No findings yet</div>';

  const agentsEl = document.getElementById('agents');
  const agents = Object.values(state.agents || {});
  agentsEl.innerHTML = agents.map(a =>
    `<div class="agent ${a.status || 'running'}">${a.name || a.id} — ${(a.task || '').slice(0, 60)}</div>`
  ).join('') || '<div style="color:#6b7280">No agents yet</div>';
}

function addEvent(evt) {
  eventCount++;
  document.getElementById('stat-events').textContent = eventCount;
  const el = document.getElementById('events');
  const time = evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : '';
  const div = document.createElement('div');
  div.className = 'event';
  div.innerHTML = `<span class="time">${time}</span> <span class="type">${evt.type}</span> ${JSON.stringify(evt.data || {}).slice(0, 100)}`;
  el.prepend(div);
  while (el.children.length > 100) el.removeChild(el.lastChild);
}

function updateFindings(data) {
  if (!data || !data.report) return;
  const r = data.report;
  const el = document.getElementById('findings');
  const div = document.createElement('div');
  div.className = `finding ${r.severity || 'info'}`;
  div.textContent = `${(r.severity || 'INFO').toUpperCase()} — ${r.title || 'Untitled'}`;
  el.prepend(div);
  const count = parseInt(document.getElementById('stat-findings').textContent) + 1;
  document.getElementById('stat-findings').textContent = count;
}

function fetchState() {
  fetch('/api/state').then(r => r.json()).then(renderState).catch(() => {});
}

connect();
</script>
</body>
</html>"""
