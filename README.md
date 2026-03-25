```
     _______ _____ _____   ____
    |___  / |_   _|  __ \ / __ \
       / /  | | | |__) | |  | |
      / /   | | |  _  /| |  | |
     / /__ _| |_| | \ \| |__| |
    /_____|_____|_|  \_\\____/
```

**AI-powered penetration testing agent.** Point it at a target — it finds vulnerabilities.

[![License](https://img.shields.io/badge/License-Apache%202.0-3b82f6?style=flat-square)](LICENSE)

---

## Quick Start

```bash
# Install
curl -sSL https://raw.githubusercontent.com/Xyeino/ziro/master/scripts/install.sh | bash

# Configure
export ZIRO_LLM="openai/gpt-5.4"
export LLM_API_KEY="your-api-key"

# Scan
ziro --target https://your-app.com
```

Or install manually:
```bash
pip install git+https://github.com/Xyeino/ziro.git
```

> Requires Docker running and Python 3.12+. First run pulls the sandbox image automatically.

---

## What It Does

Ziro spins up sandboxed agents that autonomously:
- Crawl and map attack surface
- Identify injection points, auth flaws, misconfigs
- Chain findings into multi-step exploits
- Generate PoC scripts and evidence

Results land in `ziro_runs/<run-name>/` — vulnerability reports, HTTP evidence, reproduction scripts.

---

## Usage

```bash
# Local codebase
ziro --target ./app-directory

# GitHub repo
ziro --target https://github.com/org/repo

# Black-box web app
ziro --target https://your-app.com

# Authenticated testing
ziro --target https://your-app.com --instruction "Use credentials admin:pass123"

# Multiple targets
ziro -t https://github.com/org/app -t https://your-app.com

# Instructions from file
ziro --target api.example.com --instruction-file ./scope.md

# Headless (CI/CD, no TUI)
ziro -n --target https://your-app.com
```

---

## Tools

| Tool | What it does |
|------|-------------|
| HTTP Proxy | Intercept, modify, replay requests |
| Browser | Multi-tab automation for XSS, CSRF, auth flows |
| Terminal | Interactive shells inside sandbox |
| Python Runtime | Write and run custom exploits |
| Metasploit | Search, inspect, execute MSF modules |
| API Spec Parser | OpenAPI/Swagger analysis with risk scoring |
| Attack Graph | Multi-step exploitation planning |
| Evidence Collector | HTTP pairs, screenshots, command output |
| Scope Guard | Enforces target boundaries |
| Finding Dedup | No duplicate vulnerability reports |

---

## Finds

Access control (IDOR, privesc, auth bypass), injections (SQL, NoSQL, command), server-side (SSRF, XXE, deserialization), client-side (XSS, prototype pollution), business logic (race conditions, workflow abuse), JWT/session flaws, infrastructure misconfigs.

---

## Configuration

```bash
export ZIRO_LLM="openai/gpt-5.4"       # required
export LLM_API_KEY="your-api-key"        # required
export LLM_API_BASE="http://localhost:11434"  # for Ollama/local models
export ZIRO_REASONING_EFFORT="high"      # low/medium/high
export ZIRO_DASHBOARD=1                  # enable live web dashboard
```

Config auto-saves to `~/.ziro/cli-config.json`.

**Models that work well:** `openai/gpt-5.4`, `anthropic/claude-sonnet-4-6`, `vertex_ai/gemini-3-pro-preview`

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

> **Warning:** Only test targets you own or have explicit permission to test.
