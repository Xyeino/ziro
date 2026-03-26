---
name: zap
description: OWASP ZAP web app scanner — spider, active/passive scan, AJAX spider, and report generation via CLI and API.
---

# OWASP ZAP CLI Playbook

Official docs:
- https://www.zaproxy.org/docs/
- https://www.zaproxy.org/docs/desktop/cmdline/
- https://www.zaproxy.org/docs/api/

Canonical syntax:
`zap.sh -cmd [options]` (headless CLI)
`zap-cli [command] [options]` (Python wrapper)

High-signal flags:
- `-cmd` run in command-line/headless mode (no GUI)
- `-quickurl <url>` quick scan a single URL
- `-quickprogress` show progress during quick scan
- `-quickout <file>` output quick scan report to file
- `-port <port>` set ZAP proxy listener port (default 8080)
- `-config api.disablekey=true` disable API key for local automation
- `-daemon` start ZAP as a background daemon
- `-addoninstall <addon>` install an add-on before scanning
- `-newsession <path>` start with a fresh session file

Agent-safe baseline for automation:
`zap.sh -daemon -port 8090 -config api.disablekey=true -config spider.maxDuration=5 -config scanner.maxScanDurationInMins=10`

Common patterns:
- Quick scan (single URL, headless):
  `zap.sh -cmd -quickurl https://target.com -quickprogress -quickout /tmp/zap_report.html`
- Start daemon and scan via API:
  `zap.sh -daemon -port 8090 -config api.disablekey=true`
  Then use the REST API at `http://localhost:8090/JSON/`
- Spider a target via zap-cli:
  `zap-cli -p 8090 spider http://target.com`
- Run active scan via zap-cli:
  `zap-cli -p 8090 active-scan http://target.com`
- AJAX spider for JS-heavy apps:
  `zap-cli -p 8090 ajax-spider http://target.com`
- Export HTML report:
  `zap-cli -p 8090 report -o /tmp/zap_report.html -f html`
- Passive scan only (no active attacks):
  `zap-cli -p 8090 spider http://target.com`
  `zap-cli -p 8090 alerts --alert-level Low`
- Docker-based headless scan:
  `docker run --rm -v /tmp:/zap/wrk owasp/zap2docker-stable zap-baseline.py -t https://target.com -r report.html`

Sandbox safety:
- Always run in `-cmd` or `-daemon` mode; never launch the GUI in automation.
- Set `spider.maxDuration` to cap spider runtime (minutes).
- Set `scanner.maxScanDurationInMins` to cap active scan time.
- Limit spider depth with `spider.maxDepth` (default 5, keep at 3-5 for scoped scans).
- Use `spider.maxChildren` to limit links per node.
- Disable API key only when running locally behind a firewall.
- Prefer `zap-baseline.py` for safe, passive-only scans.
- Kill the daemon after scans: `zap-cli -p 8090 shutdown`.

Failure recovery:
- If ZAP port conflicts, change with `-port <alt>`.
- If spider stalls, reduce `spider.maxDuration` and `spider.maxDepth`.
- If active scan takes too long, lower `scanner.threadPerHost` via API config.
