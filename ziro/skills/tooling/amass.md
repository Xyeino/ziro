---
name: amass
description: Advanced subdomain enumeration using passive DNS, certificate transparency, web archives, and active brute-force.
---

# Amass CLI Playbook

Official docs:
- https://github.com/owasp-amass/amass

Canonical syntax:
`amass enum [options] -d <domain>`

Key subcommands:
- `amass enum` — subdomain enumeration
- `amass intel` — discover root domains from ASN/CIDR/org name
- `amass db` — query local amass database

Key flags for `enum`:
- `-d <domain>` target domain
- `-passive` passive only (no DNS brute-force, stealthier)
- `-active` include active techniques (zone transfer, certificate grabbing)
- `-brute` enable brute-force subdomain guessing
- `-w <wordlist>` wordlist for brute-force
- `-o <file>` output file
- `-json <file>` JSON output
- `-timeout <min>` timeout in minutes
- `-max-dns-queries <n>` limit DNS queries per second
- `-rf <file>` resolver file (list of DNS resolvers)

Agent-safe baseline:
`amass enum -passive -d <domain> -timeout 10 -o amass_passive.txt`

Common patterns:
- Passive enumeration (stealthy):
  `amass enum -passive -d example.com -o subdomains_passive.txt`
- Active + brute-force (thorough):
  `amass enum -active -brute -d example.com -w /usr/share/wordlists/amass/subdomains-top1mil-5000.txt -o subdomains_full.txt -timeout 20`
- Intel from ASN:
  `amass intel -asn <ASN_NUMBER> -o domains_from_asn.txt`
- Intel from org name:
  `amass intel -org "Company Name" -o discovered_domains.txt`
- JSON output for parsing:
  `amass enum -passive -d example.com -json amass_results.json`

Workflow with other tools:
1. Amass for comprehensive subdomain discovery
2. Subfinder for additional passive sources
3. Merge and deduplicate: `cat amass.txt subfinder.txt | sort -u > all_subs.txt`
4. Resolve with httpx: `httpx -l all_subs.txt -o alive.txt`
5. Scan alive hosts with nuclei/nmap

Amass vs subfinder:
- Amass: more sources, active probing, brute-force, slower
- Subfinder: fast passive-only, good for quick results
- Best practice: use both and merge results
