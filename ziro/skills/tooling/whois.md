---
name: whois
description: Domain and IP registration lookup for identifying ownership, registrars, nameservers, and expiration dates.
---

# Whois CLI Playbook

Canonical syntax:
`whois <domain_or_ip>`

Common patterns:
- Domain lookup:
  `whois example.com`
- IP lookup:
  `whois 93.184.216.34`
- Specific whois server:
  `whois -h whois.verisign-grs.com example.com`
- Brief output (grep key fields):
  `whois example.com | grep -iE "registrar|creation|expir|nameserver|registrant|admin|tech|status"`

Key fields to extract:
- **Registrar** — who registered the domain
- **Creation/Expiry dates** — age and renewal status
- **Nameservers** — DNS infrastructure
- **Registrant/Admin/Tech contact** — ownership info (often redacted)
- **Domain status** — clientTransferProhibited, etc.
- **ASN/CIDR** — for IP lookups, network ownership

Security relevance:
- Recently registered domains may be phishing/malicious
- About to expire domains — potential takeover
- Registrant email — pivot to find other domains
- Nameserver changes — detect hijacking
- ASN info — identify hosting provider and other assets

Workflow:
1. `whois <domain>` — basic registration info
2. `whois <ip>` — identify hosting/ISP
3. Cross-reference registrant email to find related domains
4. Check nameservers against known providers
5. Feed ASN into amass: `amass intel -asn <ASN>`
