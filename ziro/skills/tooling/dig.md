---
name: dig
description: DNS query tool for enumerating records, zone transfers, reverse lookups, and identifying DNS misconfigurations.
---

# Dig CLI Playbook

Canonical syntax:
`dig [@server] <domain> [type] [options]`

Key record types:
- `A` — IPv4 address
- `AAAA` — IPv6 address
- `MX` — mail servers
- `NS` — nameservers
- `TXT` — text records (SPF, DKIM, DMARC, verification)
- `CNAME` — aliases
- `SOA` — start of authority
- `SRV` — service records
- `PTR` — reverse DNS
- `ANY` — all records (often blocked)
- `AXFR` — zone transfer

Key flags:
- `+short` compact output
- `+noall +answer` only answer section
- `+trace` trace delegation path
- `+dnssec` request DNSSEC records
- `-x <ip>` reverse lookup
- `@<server>` query specific DNS server

Common patterns:
- All important records:
  `for type in A AAAA MX NS TXT SOA CNAME SRV; do echo "=== $type ==="; dig +noall +answer example.com $type; done`
- Zone transfer attempt:
  `dig @ns1.example.com example.com AXFR`
- Reverse lookup:
  `dig -x 93.184.216.34 +short`
- Trace delegation:
  `dig example.com +trace`
- Check SPF/DMARC:
  `dig +short example.com TXT`
  `dig +short _dmarc.example.com TXT`
- Check specific nameserver:
  `dig @8.8.8.8 example.com A +short`
- Subdomain check:
  `dig +noall +answer sub.example.com A`

Security checks:
- Zone transfer (AXFR) — if works, full domain map exposed
- Missing SPF/DMARC — email spoofing possible
- Wildcard DNS — `dig +short *.example.com` or `dig +short random123456.example.com`
- DNSSEC validation — `dig +dnssec example.com`
- DNS rebinding — check TTL values with `dig +noall +answer +ttlid example.com`
