---
name: arjun
description: Arjun HTTP parameter discovery — fuzz GET/POST/JSON endpoints to find hidden or undocumented parameters.
---

# Arjun CLI Playbook

Official docs:
- https://github.com/s0md3v/Arjun
- https://github.com/s0md3v/Arjun/wiki

Canonical syntax:
`arjun -u <url> [options]`

High-signal flags:
- `-u <url>` target URL to scan
- `-m GET|POST|JSON|XML` HTTP method to use (default GET)
- `-w <wordlist>` custom parameter wordlist
- `--headers <file>` file containing custom headers (JSON format)
- `-t <threads>` number of concurrent threads (default 5)
- `-d <delay>` delay between requests in seconds
- `-o <file>` output file (supports JSON)
- `--stable` use only one thread for stability
- `-c <chunk_size>` number of parameters per request (default 500)
- `--include <params>` always include these parameters
- `-oJ <file>` output as JSON
- `-oT <file>` output as plain text
- `--disable-redirects` do not follow redirects
- `-q` quiet mode
- `--passive` collect parameters from web archives (no active fuzzing)
- `-i <urls_file>` file containing target URLs (batch mode)

Agent-safe baseline for automation:
`arjun -u https://target.com/endpoint -m GET -t 5 -d 0.5 -oJ /tmp/arjun_results.json`

Common patterns:
- Discover GET parameters:
  `arjun -u https://target.com/page -m GET -t 5 -oJ /tmp/get_params.json`
- Discover POST parameters:
  `arjun -u https://target.com/api/login -m POST -t 5 -oJ /tmp/post_params.json`
- Discover JSON body parameters:
  `arjun -u https://target.com/api/endpoint -m JSON -t 5 -oJ /tmp/json_params.json`
- Use custom wordlist:
  `arjun -u https://target.com/page -w /path/to/params.txt -t 5 -oJ /tmp/custom_params.json`
- Scan with custom headers (e.g., auth token):
  `arjun -u https://target.com/api/data -m GET --headers /tmp/headers.json -t 5 -oJ /tmp/auth_params.json`
  (headers.json: `{"Authorization": "Bearer <token>", "Content-Type": "application/json"}`)
- Batch scan multiple URLs:
  `arjun -i /tmp/urls.txt -m GET -t 5 -oJ /tmp/batch_results.json`
- Passive parameter discovery (no active requests):
  `arjun -u https://target.com -m GET --passive -oJ /tmp/passive_params.json`
- Stable mode for fragile targets:
  `arjun -u https://target.com/page -m GET --stable -oJ /tmp/stable_results.json`
- Smaller chunks to avoid WAF:
  `arjun -u https://target.com/page -m GET -c 100 -d 1 -t 3 -oJ /tmp/stealth_params.json`

Sandbox safety:
- Limit threads to 3-5 with `-t` to avoid aggressive traffic.
- Use `-d` to add delay between requests (0.5-1s for production targets).
- Use `-c` to reduce chunk size (100-250) if the target has request size limits or WAF.
- Prefer `--stable` for targets that behave inconsistently under load.
- Use `--passive` first to gather parameters without sending any probes.
- Always use `-oJ` for JSON output that can be parsed by downstream tools.

Failure recovery:
- If detection rate is low, try a larger custom wordlist with `-w`.
- If target returns inconsistent responses, use `--stable` mode.
- If WAF blocks requests, reduce `-c` to 50-100 and increase `-d`.
- If JSON method fails, verify the endpoint actually accepts JSON payloads.
