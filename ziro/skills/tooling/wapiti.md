---
name: wapiti
description: Wapiti web vulnerability scanner — module-based scanning with scope control, authentication, and multiple report formats.
---

# Wapiti CLI Playbook

Official docs:
- https://wapiti-scanner.github.io/
- https://github.com/wapiti-scanner/wapiti

Canonical syntax:
`wapiti -u <url> [options]`

High-signal flags:
- `-u <url>` target base URL to scan
- `-m <modules>` comma-separated module list (e.g., `sql,xss,exec`)
- `--scope page|folder|domain|url|punk` control crawl boundary
- `-f html|json|xml|txt` output report format
- `-o <path>` output report file path
- `--max-links <n>` limit number of URLs to crawl
- `--max-files-per-dir <n>` limit files explored per directory
- `--max-scan-time <seconds>` global scan timeout
- `--timeout <seconds>` HTTP request timeout
- `-t <seconds>` alias for `--timeout`
- `-a <creds>` HTTP basic auth (`user%password`)
- `--auth-method <method>` authentication method (basic, digest, ntlm)
- `-H <header>` custom header (repeatable)
- `-d <depth>` max crawl depth
- `-S <url>` force start URL (skip crawling, scan this page only)
- `--color` colorize terminal output
- `-v <level>` verbosity (0=quiet, 1=normal, 2=verbose)
- `--flush-session` discard previous scan session data

Agent-safe baseline for automation:
`wapiti -u https://target.com --scope folder --max-links 100 --max-scan-time 300 --timeout 10 -f json -o /tmp/wapiti_report.json -v 1`

Common patterns:
- Quick scan with limited scope:
  `wapiti -u https://target.com --scope folder --max-links 50 -f html -o /tmp/report.html`
- SQL injection and XSS only:
  `wapiti -u https://target.com -m sql,xss --scope domain --max-links 200 -f json -o /tmp/sqli_xss.json`
- Full module scan with auth:
  `wapiti -u https://target.com -a admin%password123 --auth-method basic --scope domain --max-links 300 -f html -o /tmp/full_scan.html`
- Scan single page (no crawl):
  `wapiti -u https://target.com/login -S https://target.com/login -m xss,sql -f json -o /tmp/login_scan.json`
- List available modules:
  `wapiti --list-modules`
- Resume a previous scan session:
  `wapiti -u https://target.com --scope folder -f html -o /tmp/resume_report.html`
- Fresh scan discarding old data:
  `wapiti -u https://target.com --flush-session --scope folder --max-links 100 -f json -o /tmp/fresh.json`

Sandbox safety:
- Always set `--max-links` to prevent unbounded crawling (100-500 is reasonable).
- Always set `--max-scan-time` to enforce a hard timeout.
- Use `--scope folder` or `--scope page` to avoid scanning out-of-scope domains.
- Set `--timeout` to 10-15s to avoid hanging on slow endpoints.
- Prefer targeted module lists (`-m sql,xss`) over full module runs for scoped assessments.
- Use `--max-files-per-dir` to avoid excessive enumeration of directory listings.

Failure recovery:
- If scan hangs, reduce `--max-links` and `--timeout`.
- If auth fails, verify credentials with curl first, then pass via `-a` or cookie header with `-H`.
- If modules error out, run `--list-modules` to verify module names.
