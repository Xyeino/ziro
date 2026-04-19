# Contributing to Ziro

Thank you for your interest in contributing to Ziro! This guide will help you get started with development and contributions.

## 🚀 Development Setup

### Prerequisites

- Python 3.12+
- Docker (running)
- Poetry (for dependency management)
- Git

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/Xyeino/ziro.git
   cd ziro
   ```

2. **Install development dependencies**
   ```bash
   make setup-dev

   # or manually:
   poetry install --with=dev
   poetry run pre-commit install
   ```

3. **Configure your LLM provider**
   ```bash
   export ZIRO_LLM="openai/gpt-5.4"
   export LLM_API_KEY="your-api-key"
   ```

4. **Run Ziro in development mode**
   ```bash
   poetry run ziro --target https://example.com
   ```

## 📚 Contributing Skills

Skills are specialized knowledge packages that enhance agent capabilities. See [ziro/skills/README.md](ziro/skills/README.md) for detailed guidelines.

### Quick Guide

1. **Choose the right category** (`/vulnerabilities`, `/frameworks`, `/technologies`, etc.)
2. **Create a** `.md` file with your skill content
3. **Include practical examples** - Working payloads, commands, or test cases
4. **Provide validation methods** - How to confirm findings and avoid false positives
5. **Submit via PR** with clear description

## 🔧 Contributing Code

### Pull Request Process

1. **Create an issue first** - Describe the problem or feature
2. **Fork and branch** - Work from the `main` branch
3. **Make your changes** - Follow existing code style
4. **Write/update tests** - Ensure coverage for new features
5. **Run quality checks** - `make check-all` should pass
6. **Submit PR** - Link to issue and provide context

### PR Guidelines

- **Clear description** - Explain what and why
- **Small, focused changes** - One feature/fix per PR
- **Include examples** - Show before/after behavior
- **Update documentation** - If adding features
- **Pass all checks** - Tests, linting, type checking

### Code Style

- Follow PEP 8 with 100-character line limit
- Use type hints for all functions
- Write docstrings for public methods
- Keep functions focused and small
- Use meaningful variable names

## 🐛 Reporting Issues

When reporting bugs, please include:

- Python version and OS
- Ziro version
- LLMs being used
- Full error traceback
- Steps to reproduce
- Expected vs actual behavior

## 💡 Feature Requests

We welcome feature ideas! Please:

- Check existing issues first
- Describe the use case clearly
- Explain why it would benefit users
- Consider implementation approach
- Be open to discussion

## 🤝 Community

- **Discord**: [Join our community](https://discord.gg/ziro-ai)
- **Issues**: [GitHub Issues](https://github.com/Xyeino/ziro/issues)

## ✨ Recognition

We value all contributions! Contributors will be:
- Listed in release notes
- Thanked in our Discord
- Added to contributors list (coming soon)

---

**Questions?** Reach out on [Discord](https://discord.gg/ziro-ai) or create an issue. We're here to help!

---

## 🏗 Architecture Deep-Dive

```
ziro/
├── agents/              # Agent loop + state (ZiroAgent, AgentState, base_agent)
├── engagement/          # Typed engagement state machine (hosts/services/creds/findings)
├── knowledge_graph/     # NetworkX graph + attack path discovery (Dijkstra)
├── vector_memory/       # Semantic memory (sentence-transformers / litellm / sketch)
├── llm/                 # LiteLLM wrapper, prompt composition, dedupe, memory compressor
├── panel/               # FastAPI backend (server.py) + React frontend
│   └── frontend/        # Vite + React + Tailwind UI
├── payloads/            # Curated payload library (600+ entries, 9 categories)
├── personas/            # 8 agent persona profiles (webapp/api/cloud/...)
├── persistence/         # Scan checkpoint / resume
├── playbooks/           # YAML attack playbooks (phase/technique/sub-agent)
├── runtime/             # Docker sandbox spawning + tool server bridge
├── scope/               # RoE middleware (runtime scope enforcement)
├── skills/              # 70+ skill markdown files with MITRE tagging
├── threat_actors/       # 5 threat actor profiles for adversary emulation
└── tools/               # 100+ registered tools (the main place to contribute)
```

### The agent loop

`ziro/agents/base_agent.py::agent_loop()` is the main state machine. On each iteration:

1. Check inter-agent messages (`_check_agent_messages`)
2. Call LLM via `ziro/llm/llm.py::generate()` with the full system prompt
3. Parse tool invocations from the response (XML `<function=name>` syntax)
4. Execute each tool via `ziro/tools/executor.py`
5. Feed results back as conversation history

Root agent = `ZiroAgent`. Sub-agents spawned via `create_agent` tool. Inter-agent messaging via `agents_graph_actions` module.

### Adding a new tool

Every tool has two files under `ziro/tools/<category>/`:

1. `<name>_actions.py`:

```python
from typing import Any
from ziro.tools.registry import register_tool

@register_tool(
    sandbox_execution=True,
    scan_modes=["deep", "standard"],
    agent_roles=["root"],
)
def my_tool(agent_state: Any, some_arg: str) -> dict[str, Any]:
    """Docstring describing what the tool does."""
    return {"success": True, "result": ...}
```

2. `<name>_actions_schema.xml` describing the tool for the LLM:

```xml
<tools>
  <tool name="my_tool">
    <description>What it does, one paragraph, clear.</description>
    <parameters>
      <parameter name="some_arg" type="string" required="true">
        <description>Semantic meaning of the argument.</description>
      </parameter>
    </parameters>
  </tool>
</tools>
```

3. Register in `ziro/tools/__init__.py` as `from .your_module import *  # noqa: F403`.

Decorator options:
- `sandbox_execution=True` — tool runs in the sandbox container (default True)
- `scan_modes=[...]` — restrict to specific scan modes (dropped from quick mode if absent from list)
- `agent_roles=["root"]` — restrict to root agent only (dropped from sub-agent prompts)

### Adding a new skill

Skills are markdown files with frontmatter at `ziro/skills/<category>/<name>.md`:

```markdown
---
name: your_skill
description: One-line summary for the catalog
mitre_techniques: [T1190, T1552.001]
kill_chain_phases: [initial_access, credential_access]
related_skills: [authentication_jwt]
---

# Skill body starts here
...
```

Categories: `vulnerabilities/`, `frameworks/`, `protocols/`, `cloud/`, `technologies/`, `tooling/`, `reconnaissance/`, `analysis/`, `scan_modes/`, `threat_actors/`.

Skills are progressively disclosed — agents see a compact catalog by default, call `load_skill` or `read_skill` to pull the full body when needed.

### Panel API

FastAPI backend at `ziro/panel/server.py`. OpenAPI 3.1 spec auto-exposed at `/api/openapi.json`. Use `openapi-generator` to build typed clients.

Common endpoints:
- `POST /api/scan/start` — kick off a scan
- `GET /api/status` — agent status
- `POST /api/agent-message` — send message to agent
- `GET /api/engagement-state` — structured engagement facts
- `GET /api/cost-breakdown` — per-agent LLM token + cost totals
- `POST /api/scan/pause` / `POST /api/scan/resume` — interactive control
- `GET /api/checkpoints` — list resumable scan checkpoints

### Environment variables

| Var | Default | Effect |
|-----|---------|--------|
| `ZIRO_LLM` | _(required)_ | `openai/gpt-5.4`, `xai/grok-4-1-fast-reasoning`, etc. |
| `LLM_API_KEY` | _(required)_ | API key for the configured provider |
| `ZIRO_PERSONA` | — | `webapp` / `api` / `cloud` / `mobile` / `red_team` etc. |
| `ZIRO_THREAT_ACTOR` | — | `apt29` / `apt28` / `lazarus` / `fin7` / `scattered_spider` |
| `ZIRO_SCOPE_ENFORCE` | `0` | `1` blocks out-of-RoE tool calls |
| `ZIRO_SANDBOX_ISOLATION` | — | `loopback` binds tool_server to 127.0.0.1 only |
| `ZIRO_DRY_RUN` | `0` | Plan-only mode, no side effects |
| `ZIRO_RPM_LIMIT` | — | Rate-limit LLM requests per minute |
| `ZIRO_TOOL_FAILURE_BUDGET` | `15` | Consecutive tool failures before agent termination |
| `ZIRO_CHECKPOINT_INTERVAL` | `300` | Seconds between scan checkpoints |
| `ZIRO_TOOL_CACHE_TTL` | `1800` | Tool result cache TTL |

## Code style

- Python 3.12+, type hints everywhere, Pydantic for data models
- No `print()` — use module-level `logger = logging.getLogger(__name__)`
- Tool return dicts with `success: bool` as the first key
- Prefer dataclasses over dicts for structured internal data
- Run `poetry run ruff check` before submitting a PR
