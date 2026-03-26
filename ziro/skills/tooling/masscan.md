---
name: masscan
description: Ultra-fast port scanner for large IP ranges. Use for initial wide port discovery before targeted nmap scans.
---

# Masscan CLI Playbook

Official docs:
- https://github.com/robertdavidgraham/masscan

Canonical syntax:
`masscan <target> -p <ports> --rate <pps> [options]`

Key flags:
- `-p <ports>` ports to scan (`-p0-65535` for all, `-p80,443,8080`)
- `--rate <pps>` packets per second (default 100, max depends on network)
- `--banners` grab service banners
- `-oJ <file>` JSON output
- `-oL <file>` list output (simple)
- `-oG <file>` grepable output
- `--open` only show open ports
- `-e <iface>` specify network interface
- `--exclude <ip>` exclude targets
- `--excludefile <file>` exclude from file

Agent-safe baseline:
`masscan <target> --top-ports 1000 --rate 1000 --open -oJ masscan_results.json`

Common patterns:
- Quick top ports on a /24:
  `masscan 10.0.0.0/24 --top-ports 100 --rate 500 --open -oJ quick_scan.json`
- Full port scan single host:
  `masscan <host> -p0-65535 --rate 1000 --open -oJ full_ports.json`
- Targeted common web ports on large range:
  `masscan <range> -p80,443,8080,8443,8000,3000,5000 --rate 2000 --open -oJ web_ports.json`
- Banner grab on discovered ports:
  `masscan <host> -p<ports> --banners --rate 500 -oJ banners.json`

Workflow:
1. Use masscan for fast wide discovery across large ranges
2. Pipe results into nmap for detailed service/version detection
3. `masscan <range> -p0-65535 --rate 1000 -oL - | awk '/^open/{print $4}' | sort -u > targets.txt`
4. `nmap -n -Pn -sV -sC -iL targets.txt -p <discovered_ports>`

Rate limiting:
- Internal network: `--rate 5000-10000`
- External/cloud: `--rate 500-2000`
- Sensitive targets: `--rate 100-500`
- Never exceed what the network can handle

Masscan vs nmap:
- Masscan: fast discovery, millions of IPs, no service detection
- Nmap: slow but thorough, service/version/script detection
- Best practice: masscan first → nmap on results
