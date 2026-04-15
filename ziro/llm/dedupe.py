import hashlib
import json
import logging
import re
from typing import Any

import litellm

from ziro.config.config import resolve_llm_config
from ziro.llm.utils import resolve_ziro_model


logger = logging.getLogger(__name__)

DEDUPE_SYSTEM_PROMPT = """You are an expert vulnerability report deduplication judge.
Your task is to determine if a candidate vulnerability report describes the SAME vulnerability
as any existing report.

CRITICAL DEDUPLICATION RULES:

1. SAME VULNERABILITY means:
   - Same root cause (e.g., "missing input validation" not just "SQL injection")
   - Same affected component/endpoint/file (exact match or clear overlap)
   - Same exploitation method or attack vector
   - Would be fixed by the same code change/patch

2. NOT DUPLICATES if:
   - Different endpoints even with same vulnerability type (e.g., SQLi in /login vs /search)
   - Different parameters in same endpoint (e.g., XSS in 'name' vs 'comment' field)
   - Different root causes (e.g., stored XSS vs reflected XSS in same field)
   - Different severity levels due to different impact
   - One is authenticated, other is unauthenticated

3. ARE DUPLICATES even if:
   - Titles are worded differently
   - Descriptions have different level of detail
   - PoC uses different payloads but exploits same issue
   - One report is more thorough than another
   - Minor variations in technical analysis

COMPARISON GUIDELINES:
- Focus on the technical root cause, not surface-level similarities
- Same vulnerability type (SQLi, XSS) doesn't mean duplicate - location matters
- Consider the fix: would fixing one also fix the other?
- When uncertain, lean towards NOT duplicate

FIELDS TO ANALYZE:
- title, description: General vulnerability info
- target, endpoint, method: Exact location of vulnerability
- technical_analysis: Root cause details
- poc_description: How it's exploited
- impact: What damage it can cause

YOU MUST RESPOND WITH EXACTLY THIS XML FORMAT AND NOTHING ELSE:

<dedupe_result>
<is_duplicate>true</is_duplicate>
<duplicate_id>vuln-0001</duplicate_id>
<confidence>0.95</confidence>
<reason>Both reports describe SQL injection in /api/login via the username parameter</reason>
</dedupe_result>

OR if not a duplicate:

<dedupe_result>
<is_duplicate>false</is_duplicate>
<duplicate_id></duplicate_id>
<confidence>0.90</confidence>
<reason>Different endpoints: candidate is /api/search, existing is /api/login</reason>
</dedupe_result>

RULES:
- is_duplicate MUST be exactly "true" or "false" (lowercase)
- duplicate_id MUST be the exact ID from existing reports or empty if not duplicate
- confidence MUST be a decimal (your confidence level in the decision)
- reason MUST be a specific explanation mentioning endpoint/parameter/root cause
- DO NOT include any text outside the <dedupe_result> tags"""


def _prepare_report_for_comparison(report: dict[str, Any]) -> dict[str, Any]:
    relevant_fields = [
        "id",
        "title",
        "description",
        "impact",
        "target",
        "technical_analysis",
        "poc_description",
        "endpoint",
        "method",
    ]

    cleaned = {}
    for field in relevant_fields:
        if report.get(field):
            value = report[field]
            if isinstance(value, str) and len(value) > 8000:
                value = value[:8000] + "...[truncated]"
            cleaned[field] = value

    return cleaned


def _extract_xml_field(content: str, field: str) -> str:
    pattern = rf"<{field}>(.*?)</{field}>"
    match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return ""


def _parse_dedupe_response(content: str) -> dict[str, Any]:
    result_match = re.search(
        r"<dedupe_result>(.*?)</dedupe_result>", content, re.DOTALL | re.IGNORECASE
    )

    if not result_match:
        logger.warning(f"No <dedupe_result> block found in response: {content[:500]}")
        raise ValueError("No <dedupe_result> block found in response")

    result_content = result_match.group(1)

    is_duplicate_str = _extract_xml_field(result_content, "is_duplicate")
    duplicate_id = _extract_xml_field(result_content, "duplicate_id")
    confidence_str = _extract_xml_field(result_content, "confidence")
    reason = _extract_xml_field(result_content, "reason")

    is_duplicate = is_duplicate_str.lower() == "true"

    try:
        confidence = float(confidence_str) if confidence_str else 0.0
    except ValueError:
        confidence = 0.0

    return {
        "is_duplicate": is_duplicate,
        "duplicate_id": duplicate_id[:64] if duplicate_id else "",
        "confidence": confidence,
        "reason": reason[:500] if reason else "",
    }


_VULN_TYPE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "sqli": ("sql injection", "sqli", "sql-injection", "sql_injection"),
    "xss": ("cross-site scripting", "xss", "reflected xss", "stored xss", "dom xss", "dom-xss"),
    "rce": ("remote code execution", "rce", "command injection", "command-injection", "cmd injection"),
    "lfi": ("local file inclusion", "lfi", "path traversal", "directory traversal"),
    "ssrf": ("ssrf", "server-side request forgery", "server side request forgery"),
    "xxe": ("xxe", "xml external entity"),
    "ssti": ("ssti", "server-side template injection", "template injection"),
    "idor": ("idor", "bola", "broken object level authorization", "insecure direct object reference"),
    "open_redirect": ("open redirect", "open-redirect"),
    "auth_bypass": ("auth bypass", "authentication bypass", "broken authentication"),
    "csrf": ("csrf", "cross-site request forgery"),
    "cors": ("cors misconfiguration", "cors"),
    "deser": ("deserialization", "insecure deserialization"),
    "info_disc": ("information disclosure", "info disclosure", "info leak"),
    "secret_exp": ("hardcoded secret", "exposed secret", "leaked credential", "api key exposure"),
    "path_trav": ("path traversal", "directory traversal", "lfi"),
    "mass_assign": ("mass assignment", "mass-assignment"),
    "race": ("race condition", "toctou"),
    "weak_crypto": ("weak crypto", "weak cryptography", "weak encryption", "weak hash"),
    "broken_fla": ("broken function level authorization", "bfla", "privilege escalation"),
}


def _classify_vuln_type(title: str, description: str) -> str:
    """Map a free-form title/description to one of the canonical vuln type keys.

    Used to normalize findings so 'Reflected XSS in search' and 'Cross-Site Scripting
    via q parameter' both map to 'xss' for fingerprinting purposes.
    """
    combined = f"{title} {description}".lower()
    best_match = "other"
    best_len = 0
    for vtype, keywords in _VULN_TYPE_KEYWORDS.items():
        for kw in keywords:
            if kw in combined and len(kw) > best_len:
                best_match = vtype
                best_len = len(kw)
    return best_match


def _normalize_endpoint(endpoint: str | None) -> str:
    """Normalize an endpoint so /api/users/123 and /api/users/456 collapse.

    Replaces numeric IDs and UUIDs with placeholders so different user IDs
    testing the same endpoint don't create false-positive duplicates.
    """
    if not endpoint:
        return ""
    e = endpoint.strip().lower()
    # Strip scheme+host if present
    e = re.sub(r"^https?://[^/]+", "", e)
    # Strip query string
    e = e.split("?")[0].split("#")[0]
    # Collapse numeric IDs
    e = re.sub(r"/\d+(?=/|$)", "/{id}", e)
    # Collapse UUIDs
    e = re.sub(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)", "/{uuid}", e)
    # Collapse hex hashes (8+ hex chars)
    e = re.sub(r"/[0-9a-f]{8,}(?=/|$)", "/{hash}", e)
    # Collapse slugs with trailing digits
    e = re.sub(r"/[a-z_-]+-\d+(?=/|$)", "/{slug}", e)
    # Multiple slashes
    e = re.sub(r"/+", "/", e)
    return e.rstrip("/") or "/"


def _extract_primary_location(report: dict[str, Any]) -> str:
    """Extract a stable location signature from a report dict.

    Prefers the first code_location file:line when present, falls back to
    normalized endpoint+method, falls back to target.
    """
    locations = report.get("code_locations")
    if isinstance(locations, list) and locations:
        first = locations[0]
        if isinstance(first, dict):
            f = (first.get("file") or "").lower()
            line = first.get("line") or ""
            if f:
                return f"code:{f}:{line}"

    endpoint = _normalize_endpoint(report.get("endpoint") or report.get("target") or "")
    method = (report.get("method") or "").upper()
    if endpoint:
        return f"http:{method}:{endpoint}"

    target = (report.get("target") or "").lower()
    return f"target:{target}"


def compute_fingerprint(report: dict[str, Any]) -> str:
    """Short hex fingerprint for fast duplicate detection.

    Fingerprint = blake2s(vuln_type + location). Two findings with the same
    fingerprint are almost certainly the same issue — so we can skip the
    LLM dedupe call entirely for these.
    """
    vuln_type = _classify_vuln_type(
        report.get("title") or "",
        report.get("description") or "",
    )
    location = _extract_primary_location(report)
    composite = f"{vuln_type}|{location}"
    h = hashlib.blake2s(composite.encode(), digest_size=8).hexdigest()
    return h


def check_duplicate(
    candidate: dict[str, Any], existing_reports: list[dict[str, Any]]
) -> dict[str, Any]:
    if not existing_reports:
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 1.0,
            "reason": "No existing reports to compare against",
        }

    # Fast path: fingerprint-based exact match. Catches the obvious duplicates
    # (same vuln type + same normalized endpoint/code location) without an LLM
    # round-trip. LLM fallback handles the fuzzy cases where fingerprints differ
    # but the reports are semantically the same.
    try:
        candidate_fp = compute_fingerprint(candidate)
        for existing in existing_reports:
            existing_fp = existing.get("_fingerprint") or compute_fingerprint(existing)
            if existing_fp == candidate_fp:
                return {
                    "is_duplicate": True,
                    "duplicate_id": existing.get("id") or existing.get("report_id") or "",
                    "confidence": 0.95,
                    "reason": f"Fingerprint match (vuln_type + location) — skipped LLM dedupe",
                    "fingerprint": candidate_fp,
                    "method": "fingerprint",
                }
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Fingerprint dedupe failed, falling back to LLM: {e}")

    try:
        candidate_cleaned = _prepare_report_for_comparison(candidate)
        existing_cleaned = [_prepare_report_for_comparison(r) for r in existing_reports]

        comparison_data = {"candidate": candidate_cleaned, "existing_reports": existing_cleaned}

        model_name, api_key, api_base = resolve_llm_config()
        litellm_model, _ = resolve_ziro_model(model_name)
        litellm_model = litellm_model or model_name

        messages = [
            {"role": "system", "content": DEDUPE_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Compare this candidate vulnerability against existing reports:\n\n"
                    f"{json.dumps(comparison_data, indent=2)}\n\n"
                    f"Respond with ONLY the <dedupe_result> XML block."
                ),
            },
        ]

        completion_kwargs: dict[str, Any] = {
            "model": litellm_model,
            "messages": messages,
            "timeout": 120,
        }
        if api_key:
            completion_kwargs["api_key"] = api_key
        if api_base:
            completion_kwargs["api_base"] = api_base

        response = litellm.completion(**completion_kwargs)

        content = response.choices[0].message.content
        if not content:
            return {
                "is_duplicate": False,
                "duplicate_id": "",
                "confidence": 0.0,
                "reason": "Empty response from LLM",
            }

        result = _parse_dedupe_response(content)

        logger.info(
            f"Deduplication check: is_duplicate={result['is_duplicate']}, "
            f"confidence={result['confidence']}, reason={result['reason'][:100]}"
        )

    except Exception as e:
        logger.exception("Error during vulnerability deduplication check")
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 0.0,
            "reason": f"Deduplication check failed: {e}",
            "error": str(e),
        }
    else:
        return result
