"""Finding Deduplication — prevents reporting the same vulnerability multiple times.

Uses a fingerprint based on vulnerability type + endpoint + parameter to detect
duplicates even when the LLM describes them differently.
"""

import hashlib
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


def _normalize(text: str) -> str:
    """Normalize text for comparison — lowercase, strip whitespace, collapse spaces."""
    return re.sub(r"\s+", " ", text.strip().lower())


def _extract_vuln_type(title: str, description: str = "") -> str:
    """Extract a canonical vulnerability type from title/description."""
    combined = _normalize(f"{title} {description}")

    # Map common vulnerability names to canonical types
    vuln_patterns = {
        "xss": r"\b(xss|cross[- ]?site[- ]?script)",
        "sqli": r"\b(sql[- ]?inject|sqli)\b",
        "csrf": r"\b(csrf|cross[- ]?site[- ]?request[- ]?forg)",
        "ssrf": r"\b(ssrf|server[- ]?side[- ]?request[- ]?forg)",
        "rce": r"\b(rce|remote[- ]?code[- ]?exec|command[- ]?inject)",
        "lfi": r"\b(lfi|local[- ]?file[- ]?inclus|path[- ]?travers|directory[- ]?travers)",
        "rfi": r"\b(rfi|remote[- ]?file[- ]?inclus)",
        "idor": r"\b(idor|insecure[- ]?direct[- ]?object)",
        "auth_bypass": r"\b(auth\w*[- ]?bypass|broken[- ]?auth)",
        "open_redirect": r"\b(open[- ]?redirect)",
        "xxe": r"\b(xxe|xml[- ]?external[- ]?entit)",
        "ssti": r"\b(ssti|server[- ]?side[- ]?template[- ]?inject)",
        "cors": r"\b(cors[- ]?misconfig)",
        "info_disclosure": r"\b(info\w*[- ]?disclos|sensitive[- ]?data[- ]?expos)",
        "missing_headers": r"\b(missing[- ]?security[- ]?header|hsts|x-frame|csp)",
        "weak_crypto": r"\b(weak[- ]?crypt|weak[- ]?cipher|ssl|tls)",
        "default_creds": r"\b(default[- ]?cred|default[- ]?password)",
        "file_upload": r"\b(unrestrict\w*[- ]?file[- ]?upload)",
        "deserialization": r"\b(deseri|insecure[- ]?deseriali)",
    }

    for vuln_type, pattern in vuln_patterns.items():
        if re.search(pattern, combined):
            return vuln_type

    return "unknown"


def _extract_endpoint(target: str = "", endpoint: str = "") -> str:
    """Extract a normalized endpoint identifier."""
    ep = endpoint or target or ""
    ep = _normalize(ep)

    # Remove query strings for comparison
    ep = re.sub(r"\?.*$", "", ep)
    # Remove trailing slash
    ep = ep.rstrip("/")

    return ep


def compute_fingerprint(
    title: str,
    severity: str = "",
    target: str = "",
    endpoint: str = "",
    method: str = "",
    cve: str = "",
    cwe: str = "",
    description: str = "",
    **_kwargs: Any,
) -> str:
    """Compute a dedup fingerprint for a vulnerability finding.

    Two findings with the same fingerprint are considered duplicates.
    """
    vuln_type = _extract_vuln_type(title, description)
    ep = _extract_endpoint(target, endpoint)
    method_norm = _normalize(method) if method else ""

    # If we have a CVE, that's the strongest dedup signal
    if cve:
        key = f"cve:{_normalize(cve)}|ep:{ep}"
    else:
        key = f"type:{vuln_type}|ep:{ep}|method:{method_norm}"

    return hashlib.sha256(key.encode()).hexdigest()[:16]


def is_duplicate(
    existing_reports: list[dict[str, Any]],
    new_title: str,
    new_severity: str = "",
    new_target: str = "",
    new_endpoint: str = "",
    new_method: str = "",
    new_cve: str = "",
    new_cwe: str = "",
    new_description: str = "",
) -> tuple[bool, str | None]:
    """Check if a new finding is a duplicate of an existing one.

    Returns:
        (is_dup, existing_id): True + existing report ID if duplicate, False + None otherwise.
    """
    new_fp = compute_fingerprint(
        title=new_title,
        severity=new_severity,
        target=new_target,
        endpoint=new_endpoint,
        method=new_method,
        cve=new_cve,
        cwe=new_cwe,
        description=new_description,
    )

    for report in existing_reports:
        existing_fp = compute_fingerprint(
            title=report.get("title", ""),
            severity=report.get("severity", ""),
            target=report.get("target", ""),
            endpoint=report.get("endpoint", ""),
            method=report.get("method", ""),
            cve=report.get("cve", ""),
            cwe=report.get("cwe", ""),
            description=report.get("description", ""),
        )

        if new_fp == existing_fp:
            logger.info(
                "Duplicate finding detected: '%s' matches existing '%s' (fp: %s)",
                new_title,
                report.get("title"),
                new_fp,
            )
            return True, report.get("id")

    return False, None
