"""CVE Lookup tool — queries NVD (NIST) API + trickest/cve PoC + CISA KEV.

Allows agents to search for CVEs by keyword, product/vendor, CVE ID,
or CVSS severity. Returns structured vulnerability data including
descriptions, CVSS scores, affected versions, references,
links to public exploit PoCs from trickest/cve GitHub repo,
and CISA Known Exploited Vulnerabilities (KEV) status.
"""

import logging
import time
from typing import Any

import requests

from ziro.tools.registry import register_tool

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TRICKEST_RAW = "https://raw.githubusercontent.com/trickest/cve/main"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
TIMEOUT = 20
MAX_RESULTS = 15

# CISA KEV cache — loaded once, refreshed every 6 hours
_kev_cache: dict[str, dict[str, Any]] = {}  # CVE ID -> KEV entry
_kev_cache_time: float = 0
_KEV_CACHE_TTL = 6 * 3600  # 6 hours


def _load_kev_cache() -> dict[str, dict[str, Any]]:
    """Load CISA Known Exploited Vulnerabilities catalog. Cached for 6h."""
    global _kev_cache, _kev_cache_time
    if _kev_cache and (time.time() - _kev_cache_time) < _KEV_CACHE_TTL:
        return _kev_cache

    try:
        resp = requests.get(CISA_KEV_URL, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        _kev_cache = {}
        for v in vulns:
            cve_id = v.get("cveID", "")
            if cve_id:
                _kev_cache[cve_id] = {
                    "vendor": v.get("vendorProject", ""),
                    "product": v.get("product", ""),
                    "name": v.get("vulnerabilityName", ""),
                    "date_added": v.get("dateAdded", ""),
                    "due_date": v.get("dueDate", ""),
                    "ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
                    "notes": v.get("notes", ""),
                }
        _kev_cache_time = time.time()
        logger.info("Loaded %d CISA KEV entries", len(_kev_cache))
    except Exception as e:
        logger.warning("Failed to load CISA KEV: %s", e)

    return _kev_cache

# Common CWE descriptions for enriching results
CWE_DESCRIPTIONS: dict[str, str] = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-116": "Improper Encoding or Escaping of Output",
    "CWE-119": "Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-264": "Permissions, Privileges, and Access Controls",
    "CWE-269": "Improper Privilege Management",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-284": "Improper Access Control",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-307": "Improper Restriction of Excessive Auth Attempts",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-327": "Use of a Broken Crypto Algorithm",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-362": "Race Condition",
    "CWE-400": "Uncontrolled Resource Consumption (DoS)",
    "CWE-401": "Memory Leak",
    "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted File Upload",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-521": "Weak Password Requirements",
    "CWE-532": "Insertion of Sensitive Info into Log File",
    "CWE-538": "Insertion of Sensitive Info into Externally-Accessible File",
    "CWE-601": "Open Redirect",
    "CWE-611": "XXE (XML External Entity)",
    "CWE-613": "Insufficient Session Expiration",
    "CWE-614": "Sensitive Cookie Without Secure Flag",
    "CWE-639": "Authorization Bypass Through User-Controlled Key (IDOR)",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    "CWE-706": "Use of Incorrectly-Resolved Name or Reference",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-1321": "Improperly Controlled Modification of Object Prototype (Prototype Pollution)",
}


def _fetch_poc_links(cve_id: str) -> list[str]:
    """Fetch PoC exploit links from trickest/cve GitHub repo."""
    if not cve_id or not cve_id.startswith("CVE-"):
        return []

    try:
        year = cve_id.split("-")[1]
        url = f"{TRICKEST_RAW}/{year}/{cve_id}.md"
        resp = requests.get(url, timeout=8)
        if resp.status_code != 200:
            return []

        # Parse GitHub PoC links from markdown
        links: list[str] = []
        for line in resp.text.splitlines():
            line = line.strip()
            # Match markdown links: - [repo](https://github.com/...)
            if "github.com/" in line and "](http" in line:
                start = line.find("(http")
                end = line.find(")", start)
                if start > 0 and end > start:
                    link = line[start + 1:end]
                    if "github.com/" in link and link not in links:
                        links.append(link)
            # Also match bare URLs
            elif line.startswith("http") and "github.com/" in line:
                if line not in links:
                    links.append(line.strip())

        return links[:10]  # Max 10 PoC links
    except Exception:
        return []


def _parse_cve(cve_item: dict[str, Any], fetch_pocs: bool = True) -> dict[str, Any]:
    """Parse a single CVE item from NVD API response."""
    cve = cve_item.get("cve", {})
    cve_id = cve.get("id", "")

    # Description
    descriptions = cve.get("descriptions", [])
    desc = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    if not desc and descriptions:
        desc = descriptions[0].get("value", "")

    # CVSS metrics
    metrics = cve.get("metrics", {})
    cvss_score = None
    cvss_severity = ""
    cvss_vector = ""

    for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(version_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity", "")
            cvss_vector = cvss_data.get("vectorString", "")
            break

    # Affected configurations / CPE
    affected = []
    configurations = cve.get("configurations", [])
    for config in configurations[:3]:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", [])[:5]:
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
                    version = parts[5] if len(parts) > 5 and parts[5] != "*" else "all"
                    affected.append(f"{vendor}/{product}:{version}")

    # References
    refs = []
    for ref in cve.get("references", [])[:5]:
        url = ref.get("url", "")
        tags = ref.get("tags", [])
        refs.append({"url": url, "tags": tags})

    # Weakness (CWE) with descriptions
    weaknesses = cve.get("weaknesses", [])
    cwes = []
    for w in weaknesses:
        for d in w.get("description", []):
            cwe_val = d.get("value", "")
            if cwe_val and cwe_val != "NVD-CWE-noinfo":
                cwe_desc = CWE_DESCRIPTIONS.get(cwe_val, "")
                cwes.append({
                    "id": cwe_val,
                    "name": cwe_desc,
                } if cwe_desc else {"id": cwe_val, "name": ""})

    published = cve.get("published", "")[:10]

    # Fetch PoC exploit links from trickest/cve
    poc_links: list[str] = []
    if fetch_pocs and cve_id:
        poc_links = _fetch_poc_links(cve_id)

    result: dict[str, Any] = {
        "cve_id": cve_id,
        "description": desc[:500] if len(desc) > 500 else desc,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "cwes": cwes,
        "affected": affected[:5],
        "references": refs,
        "published": published,
    }

    if poc_links:
        result["poc_count"] = len(poc_links)
        result["poc_links"] = poc_links
        result["has_public_exploit"] = True
    else:
        result["has_public_exploit"] = False

    # Check CISA KEV — is this CVE actively exploited in the wild?
    kev = _load_kev_cache()
    kev_entry = kev.get(cve_id)
    if kev_entry:
        result["actively_exploited"] = True
        result["kev"] = {
            "vendor": kev_entry["vendor"],
            "product": kev_entry["product"],
            "date_added": kev_entry["date_added"],
            "ransomware_use": kev_entry["ransomware_use"],
        }
    else:
        result["actively_exploited"] = False

    return result


@register_tool(sandbox_execution=False)
def cve_lookup(
    keyword: str = "",
    cve_id: str = "",
    cvss_severity: str = "",
) -> dict[str, Any]:
    """Search NVD (NIST) for CVE vulnerabilities with PoC exploit links.

    Args:
        keyword: Search keyword (e.g. 'nginx 1.24', 'wordpress xmlrpc', 'react prototype pollution')
        cve_id: Specific CVE ID to look up (e.g. 'CVE-2024-1234')
        cvss_severity: Filter by severity: LOW, MEDIUM, HIGH, CRITICAL
    """
    try:
        params: dict[str, Any] = {
            "resultsPerPage": MAX_RESULTS,
        }

        if cve_id:
            params["cveId"] = cve_id.upper()
        elif keyword:
            params["keywordSearch"] = keyword
            params["keywordExactMatch"] = ""
        else:
            return {
                "success": False,
                "message": "Provide either 'keyword' or 'cve_id' parameter",
                "results": [],
            }

        if cvss_severity and cvss_severity.upper() in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            params["cvssV3Severity"] = cvss_severity.upper()

        response = requests.get(
            NVD_API_URL,
            params=params,
            timeout=TIMEOUT,
            headers={"User-Agent": "Ziro-Security-Scanner/1.0"},
        )
        response.raise_for_status()

        data = response.json()
        total = data.get("totalResults", 0)
        vulnerabilities = data.get("vulnerabilities", [])

        # Only fetch PoCs for top results (avoid too many HTTP requests)
        results = []
        for i, v in enumerate(vulnerabilities):
            fetch_pocs = i < 5  # Only first 5 get PoC lookup
            results.append(_parse_cve(v, fetch_pocs=fetch_pocs))

        # Sort by CVSS score descending
        results.sort(key=lambda x: x.get("cvss_score") or 0, reverse=True)

        # Count results with public exploits and active exploitation
        exploitable = sum(1 for r in results if r.get("has_public_exploit"))
        actively_exploited = sum(1 for r in results if r.get("actively_exploited"))

        # Sort: actively exploited first, then by CVSS
        results.sort(key=lambda x: (
            not x.get("actively_exploited", False),
            -(x.get("cvss_score") or 0),
        ))

        return {
            "success": True,
            "total_results": total,
            "returned": len(results),
            "exploitable": exploitable,
            "actively_exploited": actively_exploited,
            "query": cve_id or keyword,
            "results": results,
            "message": (
                f"Found {total} CVEs"
                + (f" (showing top {len(results)})" if total > len(results) else "")
                + (f" — {exploitable} have public PoC exploits" if exploitable else "")
                + (f", {actively_exploited} actively exploited in the wild (CISA KEV)" if actively_exploited else "")
            ),
        }

    except requests.exceptions.Timeout:
        return {"success": False, "message": "NVD API request timed out (try again)", "results": []}
    except requests.exceptions.RequestException as e:
        return {"success": False, "message": f"NVD API error: {e!s}", "results": []}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "message": f"CVE lookup failed: {e!s}", "results": []}
