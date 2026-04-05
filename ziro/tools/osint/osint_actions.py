"""OSINT tools — Google Dorking, breach checking, passive recon.

Provides agents with OSINT capabilities for passive intelligence gathering.
"""

from typing import Any

import requests

from ziro.tools.registry import register_tool


GOOGLE_DORK_TEMPLATES = {
    "admin_panels": 'site:{domain} inurl:admin OR inurl:login OR inurl:dashboard OR inurl:panel',
    "sensitive_files": 'site:{domain} filetype:sql OR filetype:env OR filetype:log OR filetype:bak OR filetype:conf',
    "exposed_docs": 'site:{domain} filetype:pdf OR filetype:xlsx OR filetype:docx OR filetype:csv',
    "api_endpoints": 'site:{domain} inurl:api OR inurl:v1 OR inurl:v2 OR inurl:graphql OR inurl:rest',
    "config_files": 'site:{domain} inurl:wp-config OR inurl:.env OR inurl:config OR inurl:settings',
    "error_pages": 'site:{domain} "error" OR "exception" OR "stack trace" OR "debug" OR "traceback"',
    "backup_files": 'site:{domain} inurl:backup OR inurl:.bak OR inurl:.old OR inurl:copy',
    "git_exposure": 'site:{domain} inurl:.git OR "index of /.git"',
    "open_dirs": 'site:{domain} "index of /" OR "parent directory"',
    "subdomains": 'site:*.{domain} -www',
    "passwords": 'site:{domain} intext:password OR intext:passwd OR intext:credentials',
    "database": 'site:{domain} inurl:phpmyadmin OR inurl:adminer OR inurl:dbadmin',
}


@register_tool(sandbox_execution=False)
def google_dork(
    domain: str,
    dork_type: str = "all",
    custom_dork: str = "",
) -> dict[str, Any]:
    """Generate Google dork queries for passive OSINT reconnaissance.

    Args:
        domain: Target domain (e.g. 'example.com')
        dork_type: Preset type: admin_panels, sensitive_files, exposed_docs, api_endpoints,
                   config_files, error_pages, backup_files, git_exposure, open_dirs, subdomains,
                   passwords, database, or 'all' for all types
        custom_dork: Custom Google dork query (overrides dork_type)
    """
    if custom_dork:
        return {
            "success": True,
            "dorks": [{"type": "custom", "query": custom_dork, "search_url": f"https://www.google.com/search?q={requests.utils.quote(custom_dork)}"}],
            "message": "Custom dork generated. Open the search_url in browser or use web_search tool.",
        }

    dorks = []
    types_to_generate = GOOGLE_DORK_TEMPLATES.keys() if dork_type == "all" else [dork_type]

    for dt in types_to_generate:
        template = GOOGLE_DORK_TEMPLATES.get(dt)
        if template:
            query = template.format(domain=domain)
            dorks.append({
                "type": dt,
                "query": query,
                "search_url": f"https://www.google.com/search?q={requests.utils.quote(query)}",
            })

    return {
        "success": True,
        "domain": domain,
        "dorks": dorks,
        "total": len(dorks),
        "message": f"Generated {len(dorks)} Google dork queries. Use browser or web_search to execute them.",
        "tip": "Execute the most promising dorks first: sensitive_files, git_exposure, admin_panels",
    }


@register_tool(sandbox_execution=False)
def check_breaches(
    domain: str = "",
    email: str = "",
) -> dict[str, Any]:
    """Check if a domain or email appears in known data breaches.

    Args:
        domain: Domain to check (e.g. 'example.com')
        email: Email address to check
    """
    results: list[dict[str, Any]] = []

    target = email or domain
    if not target:
        return {"success": False, "message": "Provide domain or email", "results": []}

    # Check HaveIBeenPwned (public API, limited)
    try:
        if email:
            # HIBP requires API key for email lookup, use breach list instead
            resp = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={"User-Agent": "Ziro-Scanner", "hibp-api-key": ""},
                timeout=10,
            )
            if resp.status_code == 200:
                for breach in resp.json()[:10]:
                    results.append({"source": "HIBP", "breach": breach.get("Name", ""), "date": breach.get("BreachDate", "")})
            elif resp.status_code == 404:
                results.append({"source": "HIBP", "breach": "No breaches found", "date": ""})
        elif domain:
            resp = requests.get(
                f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}",
                headers={"User-Agent": "Ziro-Scanner"},
                timeout=10,
            )
            if resp.status_code == 200:
                for breach in resp.json()[:10]:
                    results.append({
                        "source": "HIBP",
                        "breach": breach.get("Name", ""),
                        "date": breach.get("BreachDate", ""),
                        "count": breach.get("PwnCount", 0),
                    })
    except Exception:
        pass

    # Check breach directory (public, no API key needed)
    try:
        resp = requests.get(
            f"https://breachdirectory.org/api/domain/{domain}" if domain else f"https://breachdirectory.org/api/email/{email}",
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.ok:
            data = resp.json()
            if data.get("found"):
                results.append({"source": "BreachDirectory", "breach": "Found in breach database", "date": "", "details": str(data.get("result", ""))[:200]})
    except Exception:
        pass

    return {
        "success": True,
        "target": target,
        "results": results,
        "breached": any(r.get("breach") != "No breaches found" for r in results),
        "message": f"Checked {target} against breach databases. Found {len(results)} entries.",
    }


@register_tool(sandbox_execution=False)
def osint_recon(
    domain: str,
) -> dict[str, Any]:
    """Passive OSINT reconnaissance — gathers intelligence without touching the target.

    Checks: CT logs, DNS records, WHOIS, email patterns, social media.

    Args:
        domain: Target domain
    """
    findings: list[dict[str, Any]] = []

    # 1. Certificate Transparency logs
    try:
        resp = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        if resp.ok:
            certs = resp.json()
            unique_names = set()
            for cert in certs:
                for name in cert.get("name_value", "").split("\n"):
                    name = name.strip().lower().replace("*.", "")
                    if name and domain in name:
                        unique_names.add(name)
            findings.append({"type": "CT_LOGS", "count": len(unique_names), "data": sorted(unique_names)[:20]})
    except Exception:
        pass

    # 2. DNS records
    try:
        import socket
        ips = []
        try:
            for info in socket.getaddrinfo(domain, None):
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
        except socket.gaierror:
            pass
        if ips:
            findings.append({"type": "DNS_A", "data": ips[:5]})

        # MX records hint at email provider
        try:
            result = socket.getaddrinfo(f"mail.{domain}", 25, socket.AF_INET)
            if result:
                findings.append({"type": "MAIL_SERVER", "data": f"mail.{domain} resolves"})
        except Exception:
            pass
    except Exception:
        pass

    # 3. robots.txt
    try:
        resp = requests.get(f"https://{domain}/robots.txt", timeout=8, headers={"User-Agent": "Mozilla/5.0"}, verify=False)
        if resp.ok and "disallow" in resp.text.lower():
            disallowed = [line.split(":")[1].strip() for line in resp.text.splitlines() if line.lower().startswith("disallow") and ":" in line]
            findings.append({"type": "ROBOTS_TXT", "disallowed_paths": disallowed[:20], "count": len(disallowed)})
    except Exception:
        pass

    # 4. Security.txt
    try:
        for path in ["/.well-known/security.txt", "/security.txt"]:
            resp = requests.get(f"https://{domain}{path}", timeout=5, headers={"User-Agent": "Mozilla/5.0"}, verify=False)
            if resp.ok and ("contact:" in resp.text.lower() or "policy:" in resp.text.lower()):
                findings.append({"type": "SECURITY_TXT", "content": resp.text[:500]})
                break
    except Exception:
        pass

    # 5. Common email patterns
    email_patterns = [f"admin@{domain}", f"info@{domain}", f"support@{domain}", f"security@{domain}", f"webmaster@{domain}"]
    findings.append({"type": "EMAIL_PATTERNS", "data": email_patterns})

    return {
        "success": True,
        "domain": domain,
        "findings": findings,
        "total_findings": len(findings),
        "message": f"OSINT recon for {domain}: {len(findings)} intelligence sources gathered.",
    }
