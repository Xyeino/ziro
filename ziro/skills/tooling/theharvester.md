---
name: theHarvester
description: OSINT tool for gathering emails, subdomains, hosts, employee names, open ports and banners from public sources.
---

# theHarvester CLI Playbook

Official docs:
- https://github.com/laramies/theHarvester

Canonical syntax:
`theHarvester -d <domain> -b <source> [options]`

Key flags:
- `-d <domain>` target domain
- `-b <source>` data source (or `all` for everything)
- `-l <limit>` limit results (default 500)
- `-S <start>` start result number
- `-f <file>` output to HTML/XML file
- `-n` enable DNS brute-force
- `-c` perform DNS brute-force with TLD expansion
- `-t` perform DNS TLD expansion
- `-r <file>` use custom DNS resolver
- `-s` use Shodan for host discovery

Available sources:
anubis, baidu, bevigil, binaryedge, bing, bingapi, bufferoverun, brave, censys, certspotter, criminalip, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, hackertarget, hunter, hunterhow, intelx, netlas, onyphe, otx, pentesttools, projectdiscovery, rapiddns, rocketreach, securityTrails, sitedossier, subdomaincenter, subdomainfinderc99, threatminer, urlscan, virustotal, yahoo, zoomeye

Agent-safe baseline:
`theHarvester -d <domain> -b all -l 200 -f theharvester_results`

Common patterns:
- Full OSINT scan:
  `theHarvester -d example.com -b all -l 500 -f osint_results`
- Email harvesting:
  `theHarvester -d example.com -b hunter,bing,yahoo,baidu -l 500 -f emails`
- Subdomain focused:
  `theHarvester -d example.com -b crtsh,dnsdumpster,hackertarget,virustotal -l 500 -f subdomains`
- With DNS brute-force:
  `theHarvester -d example.com -b all -l 200 -n -f full_osint`
- Quick passive:
  `theHarvester -d example.com -b crtsh,hackertarget,urlscan -l 100 -f quick_osint`

What theHarvester finds:
- Email addresses (for phishing/social engineering)
- Subdomains (expands attack surface)
- IP addresses and hostnames
- Employee names (from LinkedIn, etc.)
- Virtual hosts
- Open ports and banners (with Shodan)

Workflow:
1. theHarvester for initial OSINT
2. Feed emails into credential stuffing checks
3. Feed subdomains into httpx for alive check
4. Feed IPs into masscan/nmap for port scanning
