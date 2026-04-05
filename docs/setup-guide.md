# Ziro Setup Guide

## Quick Start

```bash
# 1. Clone and install
git clone <repo-url> && cd ziro
poetry install

# 2. Set your LLM provider
export ZIRO_LLM="chatgpt/gpt-5.4"          # ChatGPT subscription (free API calls)
# or
export ZIRO_LLM="anthropic/claude-sonnet-4-20250514"
export LLM_API_KEY="sk-ant-..."

# 3. Build frontend & launch panel
cd ziro/panel/frontend && npm install && npx vite build && cd ../../..
poetry run ziro --panel
```

Panel opens at **http://localhost:8420**

---

## LLM Providers

Ziro uses [LiteLLM](https://docs.litellm.ai/) — any provider works:

| Provider | ZIRO_LLM value | API Key |
|---|---|---|
| ChatGPT (subscription) | `chatgpt/gpt-5.4` | None (OAuth login) |
| ChatGPT Pro | `chatgpt/gpt-5.4-pro` | None (OAuth login) |
| Anthropic Claude | `anthropic/claude-sonnet-4-20250514` | `LLM_API_KEY` |
| OpenAI API | `openai/gpt-4o` | `LLM_API_KEY` |
| Ollama (local) | `ollama/llama3` | None |

**ChatGPT mode**: First scan will show a device code — open the link, enter code, authorize. Token saves automatically.

---

## Docker Sandbox

The AI agent runs tools inside a Docker container. Build it:

```bash
docker build -t ziro-sandbox containers/
```

Requires: Docker installed and running.

---

## Improving Subdomain Discovery

By default, subfinder uses only free/public sources. Adding API keys dramatically improves results.

### Step 1: Get free API keys

| Service | Free tier | Sign up |
|---|---|---|
| SecurityTrails | 50 req/month | https://securitytrails.com/app/signup |
| Shodan | 100 req/month | https://account.shodan.io/register |
| VirusTotal | 500 req/day | https://www.virustotal.com/gui/join-us |
| Censys | 250 req/month | https://search.censys.io/register |
| BinaryEdge | 250 req/month | https://app.binaryedge.io/sign-up |
| GitHub | Unlimited | https://github.com/settings/tokens (create PAT with no scopes) |
| Chaos | Free for researchers | https://chaos.projectdiscovery.io/ |
| FullHunt | 100 req/month | https://fullhunt.io/sign-up |

### Step 2: Create config inside the Docker container

```bash
# Enter the running container
docker exec -it <container-name> bash

# Create subfinder config
mkdir -p ~/.config/subfinder
cat > ~/.config/subfinder/provider-config.yaml << 'EOF'
securitytrails:
  - YOUR_SECURITYTRAILS_KEY

shodan:
  - YOUR_SHODAN_KEY

virustotal:
  - YOUR_VIRUSTOTAL_KEY

censys:
  - YOUR_CENSYS_ID:YOUR_CENSYS_SECRET

binaryedge:
  - YOUR_BINARYEDGE_KEY

github:
  - YOUR_GITHUB_TOKEN_1
  - YOUR_GITHUB_TOKEN_2

fullhunt:
  - YOUR_FULLHUNT_KEY

chaos:
  - YOUR_CHAOS_KEY
EOF
```

### Step 3 (Persistent): Bake keys into Docker image

Create `containers/subfinder-config.yaml` with your keys, then add to Dockerfile:

```dockerfile
COPY containers/subfinder-config.yaml /home/pentester/.config/subfinder/provider-config.yaml
```

Rebuild: `docker build -t ziro-sandbox containers/`

---

## Scan Modes

| Mode | Description | Use when |
|---|---|---|
| Quick Scan | Surface-level check, fast | Quick overview |
| Standard | Balanced depth and speed | General testing |
| Deep Scan | Thorough analysis | Comprehensive audit |
| Red Team | Exploit testing, auth bypass, race conditions | Your own apps only |
| 0day Hunter | CVE research, deep fuzzing, logic flaws | Finding unknown vulns |
| Full Arsenal | Red Team + 0day Hunter combined | Maximum coverage |

---

## Panel Features

- **Dashboard** — Stats, vulnerability chart, agent dispatcher, task plan
- **Agent Terminal** — Split view: main agent chat (left) + subagent tabs (right)
- **Target Overview** — Target info, network services, web app info, ROI scores
- **Attack Surface** — ReactFlow graph of discovered attack vectors
- **Vulnerabilities** — Filterable list with PoC code
- **Screenshots** — Real screenshots of discovered web assets
- **MITRE ATT&CK** — Heatmap mapping vulns to MITRE tactics
- **HTTP Log** — All tool executions in Burp-style log
- **Export Report** — Download HTML pentest report

---

## Environment Variables

| Variable | Description | Example |
|---|---|---|
| `ZIRO_LLM` | LLM model to use | `chatgpt/gpt-5.4` |
| `LLM_API_KEY` | API key for the LLM provider | `sk-ant-...` |
| `PERPLEXITY_API_KEY` | For web search tool (optional) | `pplx-...` |

---

## Updating

```bash
cd ~/ziro
git pull
poetry install
cd ziro/panel/frontend && rm -rf dist && npx vite build
cd ~/ziro && poetry run ziro --panel
```

## Stopping

`Ctrl+C` — cleanly stops the panel, kills Docker containers and browser processes.
