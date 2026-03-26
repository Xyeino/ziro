---
name: caido
description: Caido lightweight web security proxy — intercept, replay, and automate HTTP requests via CLI and API.
---

# Caido CLI Playbook

Official docs:
- https://docs.caido.io/
- https://docs.caido.io/reference/cli.html
- https://docs.caido.io/reference/api.html

Canonical syntax:
`caido [command] [options]`

High-signal flags:
- `caido listen -p <port>` start the proxy listener on a specific port
- `caido replay` send a saved request and display the response
- `caido export` export project data (requests, findings)
- `--host <addr>` bind address for the proxy (default 127.0.0.1)
- `--port <port>` proxy port (default 8080)
- `--upstream-proxy <url>` chain through an upstream proxy
- `--no-browser` start without auto-opening the browser
- `--data-path <path>` custom data directory for project files
- `--api-host <addr>` GraphQL API bind address
- `--api-port <port>` GraphQL API port
- `--log-level debug|info|warn|error` set log verbosity

Agent-safe baseline for automation:
`caido --host 127.0.0.1 --port 8090 --no-browser --log-level info --data-path /tmp/caido_project`

Common patterns:
- Start proxy in headless mode:
  `caido --host 127.0.0.1 --port 8090 --no-browser`
- Start with upstream proxy chain (e.g., through Burp):
  `caido --port 8090 --upstream-proxy http://127.0.0.1:8080 --no-browser`
- Use Caido GraphQL API for automation:
  `curl -X POST http://127.0.0.1:8090/api/graphql -H "Content-Type: application/json" -d '{"query":"{ requests { edges { node { id method url } } } }"}'`
- Export intercepted requests:
  `curl -X POST http://127.0.0.1:8090/api/graphql -H "Content-Type: application/json" -d '{"query":"{ requests(first: 100) { edges { node { id method url requestRaw responseRaw } } } }"}'`
- Configure scope via API (limit what gets intercepted):
  Scope rules are configured through the web UI at `http://127.0.0.1:8090` or via GraphQL mutations.
- Automate request replay:
  Use the GraphQL API to fetch a request by ID, modify parameters, and send it.
- Run with custom data path for isolated projects:
  `caido --port 8090 --no-browser --data-path /tmp/project_a`

Workflow integration:
- Use Caido as the proxy target for other tools: set `http_proxy=http://127.0.0.1:8090` for CLI tools.
- Route browser traffic through Caido for manual testing while logging all requests for later analysis.
- Use the GraphQL API to build custom automation workflows (fuzzing, parameter tampering).
- Export request/response pairs for offline analysis or reporting.
- Pair with `wafw00f` to identify WAFs before proxying traffic.

Sandbox safety:
- Always bind to `127.0.0.1` (not `0.0.0.0`) to prevent external access.
- Use `--no-browser` in automated/headless environments.
- Set `--data-path` to a temporary directory to isolate project data.
- Use `--log-level warn` in production pipelines to reduce log noise.
- The GraphQL API should only be exposed on localhost.
- Stop the proxy when done to free the port.

Failure recovery:
- If port is already in use, change `--port` to an alternate (e.g., 8091, 8092).
- If API queries fail, verify Caido is running and check `--api-port`.
- If TLS interception fails, ensure the Caido CA certificate is installed/trusted.
- If upstream proxy fails, verify the upstream is reachable before chaining.
