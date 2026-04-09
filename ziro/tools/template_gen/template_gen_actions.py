"""Generate custom nuclei templates based on discovered vulnerabilities.

When the AI agent finds a vulnerability pattern specific to the target,
it can generate a nuclei template to systematically test all similar endpoints.
"""

import json
from typing import Any

from ziro.tools.registry import register_tool


@register_tool(sandbox_execution=False)
def generate_nuclei_template(
    template_id: str,
    name: str,
    severity: str = "high",
    description: str = "",
    method: str = "GET",
    path: str = "/",
    headers: dict[str, str] | None = None,
    body: str = "",
    matchers: list[dict[str, Any]] | None = None,
    extractors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Generate a custom nuclei YAML template for testing specific vulnerability patterns.

    Use this when you discover a vulnerability pattern that should be tested across
    multiple endpoints or targets. The generated template can be saved and executed.

    Args:
        template_id: Unique template ID (e.g. 'custom-idor-users')
        name: Human-readable name (e.g. 'IDOR on User Endpoints')
        severity: critical, high, medium, low, info
        description: What the template detects
        method: HTTP method (GET, POST, PUT, DELETE)
        path: URL path with placeholders (e.g. '/api/users/{{user_id}}')
        headers: Custom headers dict
        body: Request body (for POST/PUT)
        matchers: List of matcher configs [{type: 'status', status: [200]}, {type: 'word', words: ['admin']}]
        extractors: List of extractor configs [{type: 'regex', regex: ['token: (.+)']}]
    """
    if not matchers:
        matchers = [{"type": "status", "status": [200]}]

    template_yaml = f"""id: {template_id}

info:
  name: {name}
  author: ziro-agent
  severity: {severity}
  description: {description}
  tags: custom,ziro

http:
  - method: {method}
    path:
      - "{{{{BaseURL}}}}{path}"
"""

    if headers:
        template_yaml += "    headers:\n"
        for k, v in headers.items():
            template_yaml += f'      {k}: "{v}"\n'

    if body:
        template_yaml += f"    body: |\n      {body}\n"

    # Add matchers
    template_yaml += "    matchers-condition: and\n    matchers:\n"
    for m in matchers:
        mtype = m.get("type", "status")
        if mtype == "status":
            codes = m.get("status", [200])
            template_yaml += f"      - type: status\n        status:\n"
            for code in codes:
                template_yaml += f"          - {code}\n"
        elif mtype == "word":
            words = m.get("words", [])
            template_yaml += f"      - type: word\n        words:\n"
            for w in words:
                template_yaml += f'          - "{w}"\n'
            if m.get("part"):
                template_yaml += f"        part: {m['part']}\n"
        elif mtype == "regex":
            regexes = m.get("regex", [])
            template_yaml += f"      - type: regex\n        regex:\n"
            for r in regexes:
                template_yaml += f'          - "{r}"\n'
        elif mtype == "dsl":
            dsls = m.get("dsl", [])
            template_yaml += f"      - type: dsl\n        dsl:\n"
            for d in dsls:
                template_yaml += f'          - "{d}"\n'

    # Add extractors if provided
    if extractors:
        template_yaml += "    extractors:\n"
        for e in extractors:
            etype = e.get("type", "regex")
            template_yaml += f"      - type: {etype}\n"
            if etype == "regex":
                template_yaml += "        regex:\n"
                for r in e.get("regex", []):
                    template_yaml += f'          - "{r}"\n'
            elif etype == "json":
                template_yaml += "        json:\n"
                for j in e.get("json", []):
                    template_yaml += f'          - "{j}"\n'

    # Save template to file
    template_path = f"/tmp/nuclei-custom/{template_id}.yaml"

    return {
        "success": True,
        "template_id": template_id,
        "template_yaml": template_yaml,
        "template_path": template_path,
        "usage": f"Save this template and run: nuclei -u TARGET -t {template_path}",
        "message": f"Generated custom nuclei template '{name}'. Save to file and execute with nuclei.",
    }
