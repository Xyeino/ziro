---
name: dirsearch
description: Dirsearch directory/file brute-forcer — enumerate hidden paths, extensions, and directories on web servers.
---

# Dirsearch CLI Playbook

Official docs:
- https://github.com/maurosoria/dirsearch
- https://github.com/maurosoria/dirsearch/wiki

Canonical syntax:
`dirsearch -u <url> [options]`

High-signal flags:
- `-u <url>` target URL (can be specified multiple times)
- `-l <file>` file containing list of target URLs
- `-e <extensions>` comma-separated extensions to append (e.g., `php,asp,html`)
- `-w <wordlist>` custom wordlist path
- `-t <threads>` number of threads (default 25)
- `--timeout <seconds>` HTTP request timeout
- `-x <codes>` exclude HTTP status codes (e.g., `403,404,500`)
- `-i <codes>` include only these HTTP status codes
- `-o <file>` output file path
- `--format plain|json|xml|csv|md` output format
- `-r` recursive scanning (follow found directories)
- `-R <depth>` max recursion depth
- `--random-agent` use random User-Agent per request
- `-H <header>` custom header (repeatable)
- `--delay <seconds>` delay between requests
- `-F` follow redirects
- `--min-response-size <n>` filter by minimum response size
- `--max-response-size <n>` filter by maximum response size
- `-q` quiet mode (less output)
- `--full-url` print full URL in output
- `-s <seconds>` delay between requests (alias for --delay)

Agent-safe baseline for automation:
`dirsearch -u https://target.com -e php,html,js,txt -t 10 --timeout 10 -x 404,403 --format json -o /tmp/dirsearch_results.json --random-agent`

Common patterns:
- Basic directory enumeration:
  `dirsearch -u https://target.com -e php,html,txt -t 10 --timeout 10 -x 404`
- Enumerate with custom wordlist:
  `dirsearch -u https://target.com -w /usr/share/wordlists/dirb/common.txt -t 10 --timeout 10 -x 404,403`
- Recursive scan with depth limit:
  `dirsearch -u https://target.com -e php,html -r -R 3 -t 10 --timeout 10 -x 404`
- Scan multiple targets:
  `dirsearch -l /tmp/urls.txt -e php,html -t 10 --timeout 10 -x 404 --format json -o /tmp/multi_scan.json`
- API endpoint discovery:
  `dirsearch -u https://target.com/api -w /usr/share/wordlists/api-endpoints.txt -t 10 --timeout 10 -x 404,405`
- Filter by response size to eliminate false positives:
  `dirsearch -u https://target.com -e php,html -t 10 --timeout 10 -x 404 --min-response-size 100`
- Scan with authentication header:
  `dirsearch -u https://target.com -e php -t 10 --timeout 10 -H "Authorization: Bearer <token>" -x 404`
- Throttled scan to avoid rate limiting:
  `dirsearch -u https://target.com -e php,html -t 5 --delay 0.5 --timeout 10 -x 404`

Sandbox safety:
- Limit threads to 5-15 with `-t` to avoid overwhelming the target or triggering WAF blocks.
- Always set `--timeout` to prevent hanging requests (10-15s recommended).
- Use `-x 404,403` to filter noise from output.
- Set `--delay` when scanning production systems to reduce load.
- Limit recursion depth with `-R` when using `-r` to prevent unbounded crawling.
- Use `--random-agent` to reduce fingerprinting.
- Prefer JSON output (`--format json`) for automated parsing.

Failure recovery:
- If getting blocked (all 403s), add `--random-agent` and increase `--delay`.
- If too much noise, tighten `-x` exclusions or use `-i 200,301,302` to include only interesting codes.
- If scan is slow, reduce `-t` threads and check network connectivity.
- If wordlist not found, check path or use built-in default wordlist.
