"""LLM-powered patch generation — given a confirmed finding + vulnerable code, produce unified diff."""

from __future__ import annotations

import os
from typing import Any

from ziro.tools.registry import register_tool


@register_tool(sandbox_execution=False)
def generate_fix_patch(
    agent_state: Any,
    finding_id: str = "",
    title: str = "",
    vuln_type: str = "",
    file_path: str = "",
    vulnerable_snippet: str = "",
    context_before: int = 15,
    context_after: int = 15,
    remediation_hint: str = "",
) -> dict[str, Any]:
    """Ask the LLM to produce a unified-diff patch that remediates a finding.

    Either pass finding_id (we'll pull title/vuln_type from engagement state),
    or pass title + vuln_type + file_path + vulnerable_snippet directly.

    Returns a `patch_diff` field (unified-diff string) suitable to feed into
    create_autofix_pr.

    The LLM is instructed to produce a minimal, reviewable patch — not a
    full refactor. Falls back to a heuristic template when LLM unavailable.
    """
    # Hydrate from engagement state if finding_id given
    if finding_id and not (title and vuln_type and file_path):
        try:
            from ziro.engagement import get_engagement_state

            st = get_engagement_state()
            f = st.findings.get(finding_id)
            if f:
                title = title or f.title
                vuln_type = vuln_type or f.vuln_type
                # Try to infer file path from endpoint if it has file:line format
                if not file_path and f.endpoint and ":" in f.endpoint:
                    parts = f.endpoint.split(":")
                    if parts[0].endswith((".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".tsx", ".jsx")):
                        file_path = parts[0]
        except Exception:
            pass

    if not (title and vuln_type):
        return {"success": False, "error": "Need at least title + vuln_type (or finding_id matching an existing finding)"}

    # Load file contents if available
    full_context = ""
    if file_path and os.path.isfile(file_path):
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                full_context = f.read()[:8000]
        except Exception:
            pass

    # Call LLM via the agent's LLM instance
    prompt = f"""You are a security engineer. Produce a unified-diff patch that remediates the vulnerability described below. The patch MUST be applicable via `git apply` and must:

1. Touch only the lines strictly necessary to fix the vulnerability
2. Include 3-5 lines of context before/after changed hunks
3. Use the canonical file path (`a/{file_path}` and `b/{file_path}`)
4. Preserve existing indentation style
5. Not introduce new imports unless essential
6. Use parameterized queries / proper encoding / safe APIs appropriate to the language

## Finding

- Title: {title}
- Vulnerability class: {vuln_type}
- File: {file_path or "(unknown)"}
{f"- Remediation hint: {remediation_hint}" if remediation_hint else ""}

## Vulnerable snippet

```
{vulnerable_snippet or full_context[:2000]}
```

## Full file context (first 8K chars)

```
{full_context}
```

Return ONLY the unified diff. Start with `--- a/...` and `+++ b/...` lines. No prose, no markdown code fences, no explanation. Just the diff."""

    diff = ""
    used_llm = False
    try:
        # Use the agent's LLM instance if available
        if agent_state is not None and hasattr(agent_state, "_llm_instance"):
            llm = agent_state._llm_instance
            response = llm.generate(prompt, max_tokens=2000, temperature=0.2)
            diff = (response or "").strip()
            used_llm = True
    except Exception:  # noqa: BLE001
        pass

    # Fallback: heuristic template based on vuln type
    if not diff:
        diff = _heuristic_patch(vuln_type, file_path, vulnerable_snippet)
        used_llm = False

    # Clean up common LLM wrapping
    if diff.startswith("```"):
        lines = diff.split("\n")
        diff = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

    return {
        "success": True,
        "finding_id": finding_id,
        "file_path": file_path,
        "vuln_type": vuln_type,
        "patch_diff": diff,
        "used_llm": used_llm,
        "next_step": (
            "Review the patch, then feed it to create_autofix_pr(repo_path, "
            f"findings=[{{finding_id: {finding_id!r}, title: ..., severity: ..., "
            "patch_diff: <this value>}}])"
        ),
    }


def _heuristic_patch(vuln_type: str, file_path: str, snippet: str) -> str:
    """Minimal fallback template when LLM unavailable — just comments pointing at the issue."""
    vt = (vuln_type or "").lower()
    hint = {
        "sqli": "-- Use parameterized queries: cursor.execute('SELECT ... WHERE x = ?', (val,))",
        "xss": "// Encode user input: escape(value) / html.escape() / DOMPurify.sanitize()",
        "ssrf": "# Validate URL host against allowlist before fetching",
        "xxe": "# Disable external entities: parser.setFeature('disallow-doctype-decl', True)",
        "rce": "# Never pass user input to shell; use subprocess with list args",
        "path_trav": "# Resolve real path and ensure it starts with allowed base dir",
        "idor": "# Check that resource.owner_id == current_user.id before returning",
        "weak_crypto": "# Use bcrypt/argon2 for passwords, AES-256-GCM for data",
        "deser": "# Never unpickle untrusted data; use JSON with strict schema validation",
    }
    msg = hint.get(vt, "# TODO: Manual fix needed — LLM unavailable for auto-patching")
    if not file_path:
        return f"{msg}\n"

    return (
        f"--- a/{file_path}\n"
        f"+++ b/{file_path}\n"
        f"@@ -1,3 +1,5 @@\n"
        f"+// FIX ({vt}): {msg}\n"
        f"+// Original problematic snippet: {snippet[:100]}\n"
        f" \n"
    )
