---
name: passive_osint_apis
description: Direct HTTP queries to public OSINT APIs for subdomain enumeration, certificate transparency, and passive DNS when dedicated tools are unavailable
---

# Passive OSINT API Reconnaissance

When tools like subfinder, amass, or theHarvester are unavailable or you need quick passive reconnaissance, query public OSINT APIs directly via curl.

## Certificate Transparency (crt.sh)

Most reliable source for subdomain discovery via CT logs:
```bash
curl -s "https://crt.sh/?q=%25.TARGET_DOMAIN&output=json" | jq -r '.[].name_value' | sort -u | grep -v '\*'
```

Parse response: each entry has `name_value` (may contain newlines with multiple names). Filter wildcards and deduplicate.

## HackerTarget API

Free tier (50 queries/day), returns CSV of subdomain,IP pairs:
```bash
curl -s "https://api.hackertarget.com/hostsearch/?q=TARGET_DOMAIN"
```

Output format: `subdomain.example.com,1.2.3.4` — split on comma for subdomain and IP.

## AlienVault OTX Passive DNS

No auth required for basic queries:
```bash
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/TARGET_DOMAIN/passive_dns" | jq -r '.passive_dns[].hostname' | sort -u
```

Returns passive DNS records. Filter results to those ending with `.TARGET_DOMAIN`.

## URLScan.io

Search scans for domain appearances:
```bash
curl -s "https://urlscan.io/api/v1/search/?q=domain:TARGET_DOMAIN" | jq -r '.results[].page.domain' | sort -u
```

Rate limited. May reveal subdomains seen in web scans.

## Shodan InternetDB

Quick port/service lookup for discovered IPs (no API key needed):
```bash
curl -s "https://internetdb.shodan.io/IP_ADDRESS"
```

Returns JSON with open ports, hostnames, CPEs, and vulns.

## SecurityTrails (requires API key)

If `SECURITYTRAILS_API_KEY` env var is set:
```bash
curl -s -H "APIKEY: $SECURITYTRAILS_API_KEY" "https://api.securitytrails.com/v1/domain/TARGET_DOMAIN/subdomains" | jq -r '.subdomains[]' | sed "s/$/.TARGET_DOMAIN/"
```

## Aggregation Workflow

1. Query all free APIs in parallel (crt.sh, HackerTarget, OTX, URLScan.io)
2. Merge and deduplicate results
3. Resolve each subdomain to check if alive: `httpx -l subdomains.txt -silent -status-code`
4. For each resolved IP, query Shodan InternetDB for quick port/service info
5. Feed live subdomains into active scanning (nmap, nuclei, etc.)

## Rate Limiting Notes

- **crt.sh**: No hard rate limit but can be slow; timeout at 30s
- **HackerTarget**: 50 queries/day free tier
- **OTX**: No documented limit for passive queries
- **URLScan.io**: 60 requests/minute, 1000/day for free tier
- **Shodan InternetDB**: 1 request/second

## When to Use This Skill

- Tools like subfinder/amass not installed or broken
- Quick initial recon before heavy tooling
- Validating tool output with independent sources
- Environments where tool installation is restricted
