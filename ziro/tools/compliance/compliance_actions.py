"""Compliance framework mapping — tag findings with OWASP/CWE/MITRE/PCI/SOC2/HIPAA."""

from __future__ import annotations

from typing import Any

from ziro.tools.registry import register_tool


# CWE -> OWASP Top 10 2021 mapping (common cases)
_CWE_TO_OWASP: dict[str, str] = {
    "CWE-22": "A01:2021 — Broken Access Control",
    "CWE-23": "A01:2021 — Broken Access Control",
    "CWE-35": "A01:2021 — Broken Access Control",
    "CWE-59": "A01:2021 — Broken Access Control",
    "CWE-200": "A01:2021 — Broken Access Control",
    "CWE-201": "A01:2021 — Broken Access Control",
    "CWE-219": "A01:2021 — Broken Access Control",
    "CWE-264": "A01:2021 — Broken Access Control",
    "CWE-275": "A01:2021 — Broken Access Control",
    "CWE-284": "A01:2021 — Broken Access Control",
    "CWE-285": "A01:2021 — Broken Access Control",
    "CWE-639": "A01:2021 — Broken Access Control",
    "CWE-829": "A01:2021 — Broken Access Control",
    "CWE-841": "A01:2021 — Broken Access Control",
    "CWE-918": "A10:2021 — SSRF",  # SSRF has its own
    # Cryptography
    "CWE-261": "A02:2021 — Cryptographic Failures",
    "CWE-296": "A02:2021 — Cryptographic Failures",
    "CWE-310": "A02:2021 — Cryptographic Failures",
    "CWE-319": "A02:2021 — Cryptographic Failures",
    "CWE-321": "A02:2021 — Cryptographic Failures",
    "CWE-326": "A02:2021 — Cryptographic Failures",
    "CWE-327": "A02:2021 — Cryptographic Failures",
    "CWE-328": "A02:2021 — Cryptographic Failures",
    "CWE-329": "A02:2021 — Cryptographic Failures",
    "CWE-330": "A02:2021 — Cryptographic Failures",
    "CWE-331": "A02:2021 — Cryptographic Failures",
    "CWE-338": "A02:2021 — Cryptographic Failures",
    "CWE-798": "A02:2021 — Cryptographic Failures",
    # Injection
    "CWE-20": "A03:2021 — Injection",
    "CWE-74": "A03:2021 — Injection",
    "CWE-75": "A03:2021 — Injection",
    "CWE-77": "A03:2021 — Injection",
    "CWE-78": "A03:2021 — Injection",
    "CWE-79": "A03:2021 — Injection",
    "CWE-80": "A03:2021 — Injection",
    "CWE-83": "A03:2021 — Injection",
    "CWE-87": "A03:2021 — Injection",
    "CWE-88": "A03:2021 — Injection",
    "CWE-89": "A03:2021 — Injection",
    "CWE-90": "A03:2021 — Injection",
    "CWE-91": "A03:2021 — Injection",
    "CWE-94": "A03:2021 — Injection",
    "CWE-113": "A03:2021 — Injection",
    "CWE-643": "A03:2021 — Injection",
    "CWE-644": "A03:2021 — Injection",
    "CWE-652": "A03:2021 — Injection",
    # Insecure Design
    "CWE-73": "A04:2021 — Insecure Design",
    "CWE-183": "A04:2021 — Insecure Design",
    "CWE-209": "A04:2021 — Insecure Design",
    "CWE-269": "A04:2021 — Insecure Design",
    "CWE-315": "A04:2021 — Insecure Design",
    "CWE-434": "A04:2021 — Insecure Design",
    "CWE-501": "A04:2021 — Insecure Design",
    "CWE-522": "A04:2021 — Insecure Design",
    "CWE-525": "A04:2021 — Insecure Design",
    "CWE-539": "A04:2021 — Insecure Design",
    "CWE-579": "A04:2021 — Insecure Design",
    "CWE-598": "A04:2021 — Insecure Design",
    # Security Misconfiguration
    "CWE-2": "A05:2021 — Security Misconfiguration",
    "CWE-11": "A05:2021 — Security Misconfiguration",
    "CWE-13": "A05:2021 — Security Misconfiguration",
    "CWE-15": "A05:2021 — Security Misconfiguration",
    "CWE-16": "A05:2021 — Security Misconfiguration",
    "CWE-260": "A05:2021 — Security Misconfiguration",
    "CWE-520": "A05:2021 — Security Misconfiguration",
    "CWE-526": "A05:2021 — Security Misconfiguration",
    "CWE-537": "A05:2021 — Security Misconfiguration",
    "CWE-541": "A05:2021 — Security Misconfiguration",
    "CWE-547": "A05:2021 — Security Misconfiguration",
    "CWE-611": "A05:2021 — Security Misconfiguration",
    "CWE-614": "A05:2021 — Security Misconfiguration",
    "CWE-756": "A05:2021 — Security Misconfiguration",
    # Vulnerable Components
    "CWE-937": "A06:2021 — Vulnerable and Outdated Components",
    "CWE-1035": "A06:2021 — Vulnerable and Outdated Components",
    "CWE-1104": "A06:2021 — Vulnerable and Outdated Components",
    # Authentication
    "CWE-287": "A07:2021 — Identification and Authentication Failures",
    "CWE-288": "A07:2021 — Identification and Authentication Failures",
    "CWE-290": "A07:2021 — Identification and Authentication Failures",
    "CWE-294": "A07:2021 — Identification and Authentication Failures",
    "CWE-295": "A07:2021 — Identification and Authentication Failures",
    "CWE-303": "A07:2021 — Identification and Authentication Failures",
    "CWE-306": "A07:2021 — Identification and Authentication Failures",
    "CWE-307": "A07:2021 — Identification and Authentication Failures",
    "CWE-346": "A07:2021 — Identification and Authentication Failures",
    "CWE-384": "A07:2021 — Identification and Authentication Failures",
    "CWE-521": "A07:2021 — Identification and Authentication Failures",
    "CWE-613": "A07:2021 — Identification and Authentication Failures",
    "CWE-620": "A07:2021 — Identification and Authentication Failures",
    "CWE-640": "A07:2021 — Identification and Authentication Failures",
    # Integrity Failures
    "CWE-345": "A08:2021 — Software and Data Integrity Failures",
    "CWE-353": "A08:2021 — Software and Data Integrity Failures",
    "CWE-502": "A08:2021 — Software and Data Integrity Failures",
    "CWE-829_dup": "A08:2021 — Software and Data Integrity Failures",
    # Logging Failures
    "CWE-117": "A09:2021 — Security Logging and Monitoring Failures",
    "CWE-223": "A09:2021 — Security Logging and Monitoring Failures",
    "CWE-532": "A09:2021 — Security Logging and Monitoring Failures",
    "CWE-778": "A09:2021 — Security Logging and Monitoring Failures",
}


# Vuln type keywords -> most-common CWE
_VULN_TO_CWE: dict[str, str] = {
    "sqli": "CWE-89",
    "sql injection": "CWE-89",
    "xss": "CWE-79",
    "cross-site scripting": "CWE-79",
    "command injection": "CWE-78",
    "rce": "CWE-94",
    "ssrf": "CWE-918",
    "xxe": "CWE-611",
    "ssti": "CWE-1336",
    "path traversal": "CWE-22",
    "lfi": "CWE-22",
    "idor": "CWE-639",
    "bola": "CWE-639",
    "open redirect": "CWE-601",
    "csrf": "CWE-352",
    "cors": "CWE-942",
    "jwt": "CWE-347",
    "auth bypass": "CWE-287",
    "mass assignment": "CWE-915",
    "race condition": "CWE-362",
    "deserialization": "CWE-502",
    "info disclosure": "CWE-200",
    "weak crypto": "CWE-327",
    "hardcoded secret": "CWE-798",
}


# CWE -> MITRE ATT&CK technique mapping (high-level)
_CWE_TO_MITRE: dict[str, list[str]] = {
    "CWE-89": ["T1190"],
    "CWE-79": ["T1059.007", "T1539"],
    "CWE-78": ["T1059"],
    "CWE-94": ["T1190", "T1059"],
    "CWE-918": ["T1190", "T1552.005"],
    "CWE-611": ["T1190", "T1005"],
    "CWE-22": ["T1083", "T1005"],
    "CWE-639": ["T1087", "T1213"],
    "CWE-601": ["T1566.002"],
    "CWE-347": ["T1552.001", "T1606"],
    "CWE-287": ["T1078"],
    "CWE-798": ["T1552.001"],
    "CWE-502": ["T1190", "T1059"],
    "CWE-362": ["T1190"],
}


# CWE -> compliance flags
_CWE_TO_COMPLIANCE: dict[str, list[str]] = {
    # Injection types impact PCI-DSS and SOC 2
    "CWE-89": ["PCI-DSS-6.5.1", "SOC2-CC7.1"],
    "CWE-78": ["PCI-DSS-6.5.1", "SOC2-CC7.1"],
    "CWE-79": ["PCI-DSS-6.5.7", "SOC2-CC7.1"],
    "CWE-94": ["PCI-DSS-6.5.1", "SOC2-CC7.1"],
    # Access control
    "CWE-639": ["PCI-DSS-7.1", "HIPAA-164.308(a)(4)", "SOC2-CC6.1"],
    "CWE-284": ["PCI-DSS-7.1", "HIPAA-164.308(a)(4)", "SOC2-CC6.1"],
    # Auth
    "CWE-287": ["PCI-DSS-8.1", "HIPAA-164.312(d)", "SOC2-CC6.1"],
    "CWE-798": ["PCI-DSS-8.2.1", "HIPAA-164.312(d)", "SOC2-CC6.1"],
    "CWE-347": ["PCI-DSS-8.2.2", "SOC2-CC6.1"],
    # Crypto
    "CWE-327": ["PCI-DSS-4.1", "HIPAA-164.312(e)", "SOC2-CC6.1"],
    "CWE-326": ["PCI-DSS-4.1", "HIPAA-164.312(e)", "SOC2-CC6.1"],
    "CWE-319": ["PCI-DSS-4.1", "HIPAA-164.312(e)"],
    # Data protection
    "CWE-200": ["PCI-DSS-3.2", "HIPAA-164.312(a)", "GDPR-Art.32", "SOC2-CC6.7"],
    "CWE-532": ["PCI-DSS-10.3", "HIPAA-164.312(b)", "SOC2-CC7.2"],
}


@register_tool(sandbox_execution=False)
def map_to_compliance(
    agent_state: Any,
    vuln_type: str = "",
    cwe: str = "",
    cvss_score: float = 0.0,
) -> dict[str, Any]:
    """Map a vulnerability to OWASP Top 10 / CWE / MITRE ATT&CK / PCI/SOC2/HIPAA/GDPR tags.

    Pass either cwe (canonical 'CWE-89') OR vuln_type (free-form keyword),
    or both. Returns complete compliance metadata to attach to the finding
    before create_vulnerability_report.
    """
    cwe_id = (cwe or "").strip().upper()
    if not cwe_id.startswith("CWE-") and vuln_type:
        vt = vuln_type.lower().strip()
        cwe_id = _VULN_TO_CWE.get(vt, "")
        for key, mapped in _VULN_TO_CWE.items():
            if key in vt:
                cwe_id = mapped
                break

    if not cwe_id:
        return {
            "success": False,
            "error": "Could not map to a CWE. Pass explicit cwe= or a recognizable vuln_type.",
            "supported_vuln_types": sorted(_VULN_TO_CWE.keys()),
        }

    owasp = _CWE_TO_OWASP.get(cwe_id, "Unmapped — general security issue")
    mitre = _CWE_TO_MITRE.get(cwe_id, [])
    compliance = _CWE_TO_COMPLIANCE.get(cwe_id, [])

    # Severity tier from CVSS
    if cvss_score >= 9.0:
        sev = "CRITICAL"
    elif cvss_score >= 7.0:
        sev = "HIGH"
    elif cvss_score >= 4.0:
        sev = "MEDIUM"
    elif cvss_score > 0:
        sev = "LOW"
    else:
        sev = ""

    return {
        "success": True,
        "cwe": cwe_id,
        "owasp_top10_2021": owasp,
        "mitre_attack": mitre,
        "compliance_tags": compliance,
        "severity_from_cvss": sev,
        "rationale": (
            f"Finding maps to {cwe_id} → {owasp}. "
            + (f"MITRE: {', '.join(mitre)}. " if mitre else "")
            + (f"Compliance touchpoints: {', '.join(compliance)}." if compliance else "")
        ),
    }
