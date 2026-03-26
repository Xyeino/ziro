---
name: wafw00f
description: Wafw00f WAF detection — fingerprint web application firewalls before running scans to adapt attack strategies.
---

# Wafw00f CLI Playbook

Official docs:
- https://github.com/EnableSecurity/wafw00f
- https://github.com/EnableSecurity/wafw00f/wiki

Canonical syntax:
`wafw00f <url> [options]`

High-signal flags:
- `-a` test against all known WAF signatures (not just first match)
- `-l` list all WAF signatures that wafw00f can detect
- `-o <file>` output results to file
- `-f json|csv|text` output format
- `-v` verbose output (show request/response details)
- `-r` do not follow redirects
- `-t <seconds>` HTTP request timeout
- `-p <proxy>` use an HTTP proxy (e.g., `http://127.0.0.1:8080`)
- `-H <headers>` custom headers as a dictionary string
- `-i <file>` file containing list of target URLs (batch mode)

Agent-safe baseline for automation:
`wafw00f https://target.com -a -f json -o /tmp/wafw00f_results.json`

Common patterns:
- Detect WAF on a single target:
  `wafw00f https://target.com`
- Test all known WAF signatures:
  `wafw00f https://target.com -a`
- JSON output for automation:
  `wafw00f https://target.com -a -f json -o /tmp/waf_detect.json`
- Batch scan multiple targets:
  `wafw00f -i /tmp/urls.txt -a -f json -o /tmp/batch_waf.json`
- Verbose mode for debugging:
  `wafw00f https://target.com -a -v`
- List all detectable WAFs:
  `wafw00f -l`
- Scan through a proxy:
  `wafw00f https://target.com -a -p http://127.0.0.1:8080`
- Skip redirects:
  `wafw00f https://target.com -a -r`

Workflow integration:
- Run wafw00f BEFORE other scanning tools (nuclei, sqlmap, dirsearch) to know what defenses exist.
- If a WAF is detected, adjust scan strategies:
  - Increase delays between requests.
  - Use WAF bypass techniques or evasion flags in downstream tools.
  - Switch to passive reconnaissance methods first.
- Feed JSON output into automation pipelines to conditionally branch scan logic.
- Pair with `httpx` for bulk target filtering before WAF detection.

Sandbox safety:
- Wafw00f sends minimal requests (typically 3-10 per target), so it is inherently lightweight.
- Set `-t` timeout to 10-15s for slow or distant targets.
- Use `-r` to prevent redirect chains if the target redirects aggressively.
- When scanning lists with `-i`, keep the list reasonable (hundreds, not thousands).
- Use `-f json` for structured output that can be parsed by downstream tools.

Failure recovery:
- If wafw00f returns "No WAF detected", the target may still have a WAF (not all WAFs are fingerprinted); use `-a` for broader detection.
- If connection fails, check if the URL is reachable with curl first.
- If redirected to a login page, try the direct application URL or use `-r` to skip redirects.
- If behind a CDN, the CDN itself may be identified as the WAF (e.g., Cloudflare, Akamai).
