"""Host header virtual-host fuzzing — find hidden vhosts on shared IPs."""

from __future__ import annotations

import hashlib
from typing import Any

from ziro.tools.registry import register_tool


_DEFAULT_VHOST_WORDLIST = [
    "admin", "administrator", "internal", "intranet", "staging", "stage",
    "dev", "development", "beta", "alpha", "qa", "test", "testing",
    "backup", "old", "new", "api-v2", "api-v3", "api-internal",
    "vpn", "mail", "webmail", "m", "mobile", "app", "panel", "cpanel",
    "portal", "dashboard", "manage", "management", "console", "ops",
    "backoffice", "back-office", "admin-panel", "adminpanel",
    "corp", "internal-api", "private", "secret", "hidden",
    "git", "gitlab", "gitea", "jenkins", "ci", "cd", "build",
    "grafana", "kibana", "prometheus", "metrics", "logs",
    "db", "database", "sql", "mysql", "postgres", "mongo",
    "redis", "memcache", "solr", "elasticsearch",
    "sso", "auth", "oauth", "identity", "login", "sign-in",
    "api-gateway", "kong", "traefik",
    "monitor", "monitoring", "status", "health", "debug",
    "lb", "balancer", "proxy",
    "cms", "wordpress", "drupal", "joomla",
    "crm", "erp", "helpdesk", "support", "zendesk",
    "reports", "reporting", "analytics", "insights",
    "git-admin", "repo", "repos", "source",
    "jenkins-admin", "k8s", "kubernetes", "rancher",
    "aws", "gcp", "azure", "cloud",
    "vpn-admin", "firewall", "fw",
]


@register_tool(sandbox_execution=True)
def fuzz_host_headers(
    agent_state: Any,
    target_ip_or_url: str,
    custom_wordlist: list[str] | None = None,
    base_domain: str = "",
    user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Fuzz the Host: header against a target IP to find hidden virtual hosts.

    Same IP often serves multiple internal sites routed by Host header. This
    tool sends ~75 candidate Host values and flags responses that differ
    from the baseline (different status, different body size, different title).

    target_ip_or_url: IP address or URL (scheme+IP recommended for HTTPS)
    custom_wordlist: override the default 75-name list
    base_domain: suffix to append ("admin" + ".example.com" -> "admin.example.com")

    Returns rows with host tried, status, size, body hash, and an interest flag
    marking responses that differ from the baseline.
    """
    try:
        import requests

        wordlist = list(custom_wordlist) if custom_wordlist else list(_DEFAULT_VHOST_WORDLIST)

        # Normalize to URL
        url = target_ip_or_url
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        # Baseline request (no Host override, just default)
        try:
            base_resp = requests.get(
                url,
                timeout=timeout,
                verify=False,
                headers={"User-Agent": user_agent},
                allow_redirects=False,
            )
            base_status = base_resp.status_code
            base_size = len(base_resp.content)
            base_hash = hashlib.md5(base_resp.content).hexdigest()[:10]
        except Exception as e:
            return {"success": False, "error": f"Baseline request failed: {e!s}"}

        results: list[dict[str, Any]] = []
        interesting: list[dict[str, Any]] = []

        for word in wordlist:
            host_value = f"{word}.{base_domain}" if base_domain else word
            try:
                r = requests.get(
                    url,
                    timeout=timeout,
                    verify=False,
                    headers={"User-Agent": user_agent, "Host": host_value},
                    allow_redirects=False,
                )
                status = r.status_code
                size = len(r.content)
                body_hash = hashlib.md5(r.content).hexdigest()[:10]
                differs = (
                    status != base_status
                    or abs(size - base_size) > 100
                    or body_hash != base_hash
                )
                row = {
                    "host": host_value,
                    "status": status,
                    "size": size,
                    "hash": body_hash,
                    "differs_from_baseline": differs,
                    "location": r.headers.get("location", ""),
                }
                results.append(row)
                if differs:
                    interesting.append(row)
            except Exception:  # noqa: BLE001
                continue

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"fuzz_host_headers failed: {e!s}"}
    else:
        return {
            "success": True,
            "target": url,
            "baseline": {"status": base_status, "size": base_size, "hash": base_hash},
            "total_probed": len(results),
            "interesting_count": len(interesting),
            "interesting": interesting,
        }
