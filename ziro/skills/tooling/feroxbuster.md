---
name: feroxbuster
description: Fast content discovery tool written in Rust. 10x faster than dirsearch/gobuster for directory and file brute-forcing.
---

# Feroxbuster CLI Playbook

Official docs:
- https://github.com/epi052/feroxbuster

Canonical syntax:
`feroxbuster -u <url> [options]`

Key flags:
- `-u <url>` target URL
- `-w <wordlist>` wordlist path
- `-t <threads>` concurrent threads (default 50)
- `-d <depth>` recursion depth (default 4)
- `-x <ext>` file extensions to check (e.g., php,html,js,txt)
- `-o <file>` output file
- `--json` JSON output
- `-s <codes>` status codes to include (e.g., 200,301,302)
- `-C <codes>` status codes to exclude (e.g., 404,403)
- `-n` no recursion
- `-k` disable TLS certificate validation
- `--rate-limit <n>` requests per second limit
- `--timeout <sec>` request timeout
- `-H <header>` custom header
- `-b <cookie>` cookies
- `--burp` proxy through Burp (127.0.0.1:8080)
- `--silent` suppress banner and status updates
- `-q` quiet mode (only URLs)
- `--auto-tune` auto-adjust scan rate based on errors

Agent-safe baseline:
`feroxbuster -u <target> -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 20 --rate-limit 100 -d 2 --json -o ferox_results.json --auto-tune`

Common patterns:
- Quick directory scan:
  `feroxbuster -u https://example.com -w /usr/share/wordlists/dirb/common.txt -t 20 -d 1 -o ferox_quick.txt`
- With file extensions:
  `feroxbuster -u https://example.com -w /usr/share/wordlists/dirb/common.txt -x php,html,js,txt,bak,old,conf -t 20 -o ferox_files.txt`
- Authenticated scan:
  `feroxbuster -u https://example.com -w wordlist.txt -b "session=abc123" -H "Authorization: Bearer token" -t 20 -o ferox_auth.txt`
- API endpoint discovery:
  `feroxbuster -u https://example.com/api -w /usr/share/wordlists/dirb/common.txt -x json -t 20 -s 200,201,301 -o ferox_api.txt`
- Recursive deep scan:
  `feroxbuster -u https://example.com -w wordlist.txt -d 4 -t 30 --rate-limit 50 --json -o ferox_deep.json`
- Exclude noise:
  `feroxbuster -u https://example.com -w wordlist.txt -C 404,403,500 -t 20 -o ferox_clean.txt`

Feroxbuster vs dirsearch vs ffuf:
- Feroxbuster: fastest, recursive by default, auto-filtering
- Dirsearch: good defaults, Python, slower
- ffuf: most flexible fuzzer, not just directories
- Best practice: feroxbuster for dir discovery, ffuf for parameter fuzzing
