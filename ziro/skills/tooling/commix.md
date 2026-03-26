---
name: commix
description: Automated OS command injection detection and exploitation tool. The sqlmap equivalent for command injection.
---

# Commix CLI Playbook

Official docs:
- https://github.com/commixproject/commix

Canonical syntax:
`commix [options]`

Key flags:
- `-u <url>` target URL with injectable parameter
- `--data <data>` POST data
- `--cookie <cookie>` HTTP cookie
- `--headers <headers>` extra HTTP headers
- `--technique <tech>` injection techniques (C=classic, E=eval-based, T=time-based, F=file-based)
- `--os-cmd <cmd>` execute single OS command
- `--batch` non-interactive (auto-answer prompts)
- `--output-dir <dir>` output directory
- `--level <1-3>` test level (higher=more tests)
- `--tamper <script>` use tamper scripts
- `--proxy <proxy>` use proxy
- `--timeout <sec>` request timeout
- `--retries <n>` retry count

Agent-safe baseline:
`commix -u "<url>?param=INJECT_HERE" --batch --technique=CT --timeout=10 --output-dir=/home/pentester/output/commix`

Common patterns:
- Test GET parameter:
  `commix -u "https://example.com/ping?ip=INJECT_HERE" --batch --output-dir=commix_out`
- Test POST parameter:
  `commix -u "https://example.com/api" --data="cmd=INJECT_HERE" --batch --output-dir=commix_out`
- Test with cookie auth:
  `commix -u "https://example.com/exec?input=INJECT_HERE" --cookie="session=abc123" --batch`
- Classic + time-based only:
  `commix -u "<url>?param=INJECT_HERE" --technique=CT --batch`
- Execute specific command:
  `commix -u "<url>?param=INJECT_HERE" --os-cmd="id" --batch`
- Through proxy:
  `commix -u "<url>?param=INJECT_HERE" --proxy="http://127.0.0.1:8080" --batch`

Injection techniques:
- Classic (C): `; id`, `| id`, `&& id`, `|| id`
- Eval-based (E): code evaluation in interpreted languages
- Time-based (T): blind detection via sleep/delay
- File-based (F): write results to web-accessible file

Where to test:
- Any parameter that interacts with OS (ping, traceroute, DNS lookup, file operations)
- Form fields that execute system commands
- API endpoints that process user input server-side
- File upload names, header values (Host, User-Agent, Referer)
