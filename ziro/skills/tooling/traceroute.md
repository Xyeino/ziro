---
name: traceroute
description: Network route tracing for mapping infrastructure, identifying firewalls, CDNs, and load balancers between attacker and target.
---

# Traceroute CLI Playbook

Canonical syntax:
`traceroute [options] <host>`

Key flags:
- `-n` no DNS resolution (faster)
- `-m <max_hops>` max TTL (default 30)
- `-w <sec>` wait time per probe
- `-q <n>` probes per hop (default 3)
- `-T` TCP mode (bypass ICMP filtering)
- `-p <port>` destination port for TCP mode
- `-I` ICMP echo mode
- `-U` UDP mode (default)

Common patterns:
- Basic trace:
  `traceroute -n example.com`
- TCP trace (bypasses ICMP blocks):
  `traceroute -T -p 443 -n example.com`
- Quick trace:
  `traceroute -n -w 2 -q 1 -m 20 example.com`
- Compare routes to different ports:
  `traceroute -T -p 80 -n example.com`
  `traceroute -T -p 443 -n example.com`

Security relevance:
- Identify CDN/WAF in front of target (Cloudflare, Akamai hops)
- Find real IP behind CDN (compare routes)
- Map internal network topology
- Identify firewall boundaries (where * * * starts)
- Detect load balancers (different IPs for same hop)
- Find adjacent network infrastructure

Workflow:
1. `traceroute -n <target>` — basic path mapping
2. If ICMP blocked: `traceroute -T -p 443 -n <target>`
3. Note CDN/WAF hops → try to bypass
4. Note firewall boundaries → understand network segmentation
5. Feed intermediate IPs into whois for infrastructure mapping
