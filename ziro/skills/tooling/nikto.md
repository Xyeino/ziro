---
name: nikto
description: Classic web server scanner for misconfigurations, dangerous files, outdated software, and known vulnerabilities.
---

# Nikto CLI Playbook

Official docs:
- https://github.com/sullo/nikto

Canonical syntax:
`nikto -h <target> [options]`

Key flags:
- `-h <host>` target host/URL
- `-p <port>` target port (default 80)
- `-ssl` force SSL
- `-Tuning <x>` scan tuning (what to test)
- `-o <file>` output file
- `-Format <fmt>` output format (csv, htm, json, xml, txt)
- `-timeout <sec>` per-request timeout
- `-Pause <sec>` delay between requests
- `-maxtime <sec>` maximum scan time
- `-nointeractive` non-interactive mode
- `-no404` skip 404 guessing
- `-C all` force check all CGI dirs
- `-useragent <ua>` custom user-agent

Tuning options (-Tuning):
- `0` File upload
- `1` Interesting file / Seen in logs
- `2` Misconfiguration / Default file
- `3` Information disclosure
- `4` Injection (XSS/Script/HTML)
- `5` Remote file retrieval (inside web root)
- `6` Denial of service
- `7` Remote file retrieval (server-wide)
- `8` Command execution / Remote shell
- `9` SQL injection
- `a` Authentication bypass
- `b` Software identification
- `c` Remote source inclusion
- `x` Reverse tuning (exclude these)

Agent-safe baseline:
`nikto -h <target> -maxtime 300 -nointeractive -Format json -o nikto_results.json`

Common patterns:
- Quick scan:
  `nikto -h https://example.com -maxtime 180 -nointeractive -o nikto_quick.json -Format json`
- Full scan with all CGI checks:
  `nikto -h https://example.com -C all -maxtime 600 -nointeractive -o nikto_full.json -Format json`
- Target specific vulnerability types:
  `nikto -h https://example.com -Tuning 249 -maxtime 300 -o nikto_vulns.json -Format json`
- Scan specific port:
  `nikto -h example.com -p 8443 -ssl -maxtime 300 -o nikto_8443.json -Format json`
- Slow/stealthy scan:
  `nikto -h https://example.com -Pause 3 -maxtime 900 -nointeractive -o nikto_stealth.json -Format json`

What nikto finds that others miss:
- Default files and directories (phpinfo.php, server-status, etc.)
- Outdated server software versions
- HTTP methods (PUT, DELETE enabled)
- Missing security headers
- Known vulnerable CGI scripts
- Dangerous file types accessible
