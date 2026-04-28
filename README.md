```
     _______ _____ _____   ____
    |___  / |_   _|  __ \ / __ \
       / /  | | | |__) | |  | |
      / /   | | |  _  /| |  | |
     / /__ _| |_| | \ \| |__| |
    /_____|_____|_|  \_\\____/
```

**AI-powered autonomous penetration testing agent.** Point it at a target — multi-agent swarm finds, validates, and reports vulnerabilities. **145 registered tools**, knowledge graph + vector memory, Code Workbench with mobile decompile pipeline, OpenAI-compatible LLM routing.

[![License](https://img.shields.io/badge/License-Apache%202.0-3b82f6?style=flat-square)](LICENSE)
[![Tools](https://img.shields.io/badge/Tools-145-a855f7?style=flat-square)](#tools)
[![Sandbox](https://img.shields.io/badge/Sandbox-Docker-2496ED?style=flat-square&logo=docker)](#install)

---

## Server install (Linux, recommended)

Tested on Ubuntu 24.04. Should work on any Debian/Ubuntu derivative with Python 3.12+.

### 1. System dependencies

```bash
# Python + git + curl
sudo apt update
sudo apt install -y python3.12 python3.12-venv python3-pip git curl unzip

# Docker (sandbox runtime)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Java JRE (for jadx — Android APK decompilation)
sudo apt install -y default-jre-headless

# Node.js 20 LTS (panel frontend) — apt source has it on Ubuntu 24+
# If apt is slow/unavailable, use the binary tarball:
curl -fsSL https://nodejs.org/dist/v20.18.0/node-v20.18.0-linux-x64.tar.xz \
  -o /tmp/node.tar.xz
sudo tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1
rm /tmp/node.tar.xz
node --version   # should print v20.x
```

### 2. Ziro itself

```bash
curl -sSL https://raw.githubusercontent.com/Xyeino/ziro/master/scripts/install.sh | bash
source ~/.bashrc
ziro --version
```

The installer creates `~/.ziro/venv` and adds `~/.ziro/bin` to your PATH.

### 3. Mobile reverse-engineering tools (optional, for APK/IPA workflows)

```bash
# jadx — Java decompiler
JADX_VER=$(curl -fsSL https://api.github.com/repos/skylot/jadx/releases/latest \
  | grep '"tag_name"' | head -1 | sed -E 's/.*"v?([^"]+)".*/\1/')
sudo mkdir -p /opt/jadx
curl -fsSL "https://github.com/skylot/jadx/releases/download/v${JADX_VER}/jadx-${JADX_VER}.zip" -o /tmp/jadx.zip
sudo unzip -q -o /tmp/jadx.zip -d /opt/jadx
sudo chmod +x /opt/jadx/bin/jadx
sudo ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx
rm /tmp/jadx.zip

# apktool — smali / resources
sudo curl -fsSL https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.10.0.jar \
  -o /usr/local/bin/apktool.jar
sudo curl -fsSL https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool \
  -o /usr/local/bin/apktool
sudo chmod +x /usr/local/bin/apktool

jadx --version && apktool --version
```

Skip this section if you only test web targets.

### 4. Pull the sandbox image

```bash
docker pull ghcr.io/xyeino/ziro-sandbox:latest
# ~6 GB compressed, ~19 GB unpacked. Make sure you have ~25 GB free.
```

### 5. Configure your LLM

Ziro uses LiteLLM under the hood, so any OpenAI-compatible endpoint works.

**Direct OpenAI / Anthropic / xAI:**
```bash
export ZIRO_LLM='openai/gpt-5.4'
export LLM_API_KEY='sk-...'
```

**OpenAI-compatible router (e.g. KRouter, OpenRouter, together.ai, your own):**
```bash
export ZIRO_LLM='openai/cx/gpt-5.4'           # model name as the router exposes it
export LLM_API_KEY='sk-...'
export LLM_API_BASE='https://api.krouter.net/v1'   # router base URL
```

Discover available models:
```bash
curl -H "Authorization: Bearer $LLM_API_KEY" "$LLM_API_BASE/models" | jq '.data[].id'
```

**Local Ollama:**
```bash
export ZIRO_LLM='openai/llama3.1:70b'
export LLM_API_BASE='http://localhost:11434/v1'
export LLM_API_KEY='ollama'
```

### 6. Run as a service

```bash
sudo tee /etc/systemd/system/ziro.service > /dev/null <<'EOF'
[Unit]
Description=Ziro panel
After=docker.service network.target
Requires=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=/root
Environment="ZIRO_LLM=openai/gpt-5.4"
Environment="LLM_API_KEY=sk-..."
Environment="LLM_API_BASE=https://api.openai.com/v1"
Environment="ZIRO_SCOPE_ENFORCE=1"
ExecStart=/root/.ziro/venv/bin/ziro --panel --panel-port 8420
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# First start: precompile frontend (one-off, ~2 min)
cd ~/.ziro/venv/lib/python3.12/site-packages/ziro/panel/frontend
npm install
npx vite build
cd ~

sudo systemctl daemon-reload
sudo systemctl enable --now ziro
sudo systemctl status ziro --no-pager
```

Open `http://<server-ip>:8420` in a browser. Default page: **Overview**.

For HTTPS + auth, put nginx / Caddy / Traefik in front — sample Caddy config in [`deploy/caddy/`](deploy/caddy/).

---

## Quick scan from CLI

```bash
# Web target
ziro --target https://your-app.com

# Local codebase (white-box)
ziro --target ./app-directory

# GitHub repo (clone + scan)
ziro --target https://github.com/org/repo

# With instructions
ziro --target https://your-app.com \
  --instruction "Test authenticated flows. Credentials in /tmp/creds.txt"

# Headless (CI mode — no TUI)
ziro -n --target ./app -m quick
```

---

## What it does

Multi-agent swarm. Root agent orchestrates phase-specialised sub-agents:

1. **Phase 0 — Planning** — Rules of Engagement, Concept of Operations, OPPLAN
2. **Phase 1 — Reconnaissance** — surface mapping, tech fingerprinting, API discovery
3. **Phase 2 — Vulnerability Discovery** — OWASP Top 10 + framework-specific
4. **Phase 3 — Exploitation** — working PoCs for confirmed findings
5. **Phase 4 — Chaining** — combine findings (SSRF + leaked token = cloud takeover)
6. **Phase 5 — Validation** — re-execute every PoC, drop FPs, score risk
7. **Phase 6 — Reporting** — PDF + JSON + markdown deliverables

Findings land in `~/.ziro/runs/<run-name>/` — vulnerability reports, HTTP evidence, reproduction scripts, PDF report.

---

## Tools (highlights)

| Category | Examples |
|---|---|
| **Recon** | nmap, subfinder, httpx, katana, gospider, dalfox, afrog, ffuf |
| **Static analysis** | semgrep, bandit, slither, mythril, halmos, echidna, trufflehog |
| **Dynamic** | Browser handoff, Caido proxy, batch HTTP fuzzing, OOB interactsh |
| **Mobile** | MobSF, Frida (SSL pinning bypass), jadx, apktool, class-dump, otool |
| **Cloud** | AWS IAM enum, S3 misconfig, IMDS SSRF, privilege escalation paths |
| **Smart contracts** | Slither, Mythril, Echidna fuzzing, Halmos symbolic execution |
| **Intelligence** | Knowledge graph + Dijkstra attack paths, vector memory, exploit chain auto-discovery |
| **Reporting** | PDF reports (ReportLab), OWASP/CWE/MITRE/PCI/SOC2/HIPAA/GDPR mapping |
| **Auto-remediation** | LLM fix generator + GitHub PR autofix |

Full list: `curl http://localhost:8420/api/tools/registry`.

---

## Panel features

The web panel at `http://localhost:8420` includes:

- **Overview** — dense single-page dashboard (active agents, findings, cost, runtime)
- **Code Workbench** — Monaco editor + AI task pane for any workspace file. Built-in mobile decompile: upload APK/IPA → auto-decompile → browse Java sources → ask AI to audit
- **Live Traffic** — WebSocket stream of every proxy request as it's captured
- **Engagement** — typed state viewer (hosts/services/credentials/findings/notes)
- **Approvals** — operator approval queue for sensitive actions
- **Cost** — per-agent LLM token + USD breakdown
- **Checkpoints** — save/restore scan sessions (auto-snapshot every 5 min)
- **LLM Debug** — inspect any agent's last 30 messages for diagnostics

---

## Configuration reference

| Env var | Default | Purpose |
|---|---|---|
| `ZIRO_LLM` | _(required)_ | Model id, e.g. `openai/gpt-5.4` |
| `LLM_API_KEY` | _(required)_ | API key |
| `LLM_API_BASE` | provider default | Custom endpoint (KRouter, OpenRouter, Ollama, etc.) |
| `ZIRO_PERSONA` | — | webapp / api / cloud / mobile / red_team |
| `ZIRO_THREAT_ACTOR` | — | apt29 / apt28 / lazarus / fin7 / scattered_spider |
| `ZIRO_SCOPE_ENFORCE` | `0` | `1` blocks any tool call outside Rules of Engagement |
| `ZIRO_DRY_RUN` | `0` | Plan-only mode, no side effects |
| `ZIRO_RPM_LIMIT` | — | Cap LLM requests per minute |
| `ZIRO_CHECKPOINT_INTERVAL` | `300` | Seconds between scan checkpoints |
| `ZIRO_TOOL_CACHE_TTL` | `1800` | Tool result cache TTL |
| `ZIRO_IMAGE` | `ghcr.io/xyeino/ziro-sandbox:latest` | Docker image to spawn for sandboxes |
| `ZIRO_SANDBOX_ISOLATION` | — | `loopback` binds tool server to 127.0.0.1 only |

---

## Alternative deployments

### Docker Compose (panel only)

```bash
docker run -d --name ziro \
  -p 8420:8420 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v ziro-workspace:/workspace \
  -e ZIRO_LLM=openai/gpt-5.4 \
  -e LLM_API_KEY=sk-... \
  ghcr.io/xyeino/ziro-sandbox:latest \
  ziro --panel --panel-port 8420
```

### Kubernetes (Helm)

```bash
kubectl create secret generic ziro-llm --from-literal=LLM_API_KEY='sk-...'
helm install ziro ./deploy/helm/ziro \
  --set llm.model='openai/gpt-5.4' \
  --set llm.existingSecret=ziro-llm
kubectl port-forward svc/ziro 8420:8420
```

### AWS ECS Fargate (Terraform)

```hcl
module "ziro" {
  source      = "github.com/Xyeino/ziro//deploy/terraform/modules/ziro"
  llm_model   = "openai/gpt-5.4"
  llm_api_key = var.openai_api_key
}
```

### Observability (optional)

```bash
docker compose -f deploy/observability/docker-compose.yml up -d
# Grafana at :3000 with preloaded "Ziro Overview" dashboard
# Prometheus scrapes /api/metrics every 15 s
```

---

## CI/CD

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - run: pip install git+https://github.com/Xyeino/ziro.git
      - run: ziro -n -t ./ --scan-mode quick
        env:
          ZIRO_LLM: ${{ secrets.ZIRO_LLM }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
```

---

## Troubleshooting

**`ziro: command not found`**
```bash
echo 'export PATH="$HOME/.ziro/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

**`Frontend build failed. Make sure Node.js 20+ is installed`**
Install Node 20 via the binary tarball in step 1 — `apt install nodejs` on older Ubuntu pulls Node 18.

**`Tool 'detect_capabilities' not found`** (or any other tool)
Sandbox image is older than your panel install. Pull fresh:
```bash
docker pull ghcr.io/xyeino/ziro-sandbox:latest
docker rm -f $(docker ps -aq --filter 'name=ziro-scan-')
sudo systemctl restart ziro
```

**`Tool server not initialized`**
Sandbox container failed entrypoint. Check container logs:
```bash
docker ps -a --filter 'name=ziro-scan-'
docker logs <container-id> 2>&1 | tail -40
```

**`Decompile failed: jadx not installed`**
jadx isn't on the panel host. Install it via section 3 above.

**`No space left on device` during pull**
Sandbox image is ~19 GB. Either free space or move Docker root:
```bash
sudo systemctl stop docker
sudo mv /var/lib/docker /opt/docker-data
sudo tee /etc/docker/daemon.json <<'EOF'
{"data-root": "/opt/docker-data"}
EOF
sudo systemctl start docker
```

**Panel API returns empty / 405 on POST**
Endpoint mismatch between client and server — the canonical scan endpoint is `POST /api/scans` (plural), not `/api/scan/start`.

---

## Security caveats

- **Only test targets you own or have explicit permission to test.** Unauthorized testing is illegal in most jurisdictions.
- The sandbox runs commands as `pentester` user inside Docker but has full network access to anything reachable from the host. Use `ZIRO_SCOPE_ENFORCE=1` to block out-of-RoE tool calls at runtime.
- The panel binds to `0.0.0.0:8420` by default. Put it behind a reverse proxy with auth before exposing to the internet.
- LLM API keys appear in agent logs — make sure log files are mode `600` and not on a shared mount.

---

## Architecture

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for directory layout, tool registration pattern, skill format, and panel API reference.

```
ziro/
├── agents/              # Agent loop + state
├── engagement/          # Typed engagement state machine
├── knowledge_graph/     # NetworkX graph + attack path discovery
├── vector_memory/       # Semantic memory store
├── llm/                 # LiteLLM wrapper + dedupe + memory compressor
├── panel/               # FastAPI backend + React/Tailwind/Monaco frontend
├── payloads/            # 600+ payload corpus across 9 categories
├── personas/            # 8 agent personas
├── persistence/         # Scan checkpoint / resume
├── playbooks/           # YAML attack playbooks
├── runtime/             # Docker sandbox + tool server bridge
├── scope/               # RoE middleware
├── skills/              # 70+ skills with MITRE tagging
├── threat_actors/       # 5 threat actor profiles
└── tools/               # 145 registered tools
```

---

## License

[Apache 2.0](LICENSE) — fork it, ship it, sell it. Just don't blame me when the LLM bills come in.
