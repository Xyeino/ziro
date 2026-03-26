---
name: gospider
description: Gospider fast web spider — crawl sites, parse JavaScript, extract subdomains, and discover endpoints at scale.
---

# Gospider CLI Playbook

Official docs:
- https://github.com/jaeles-project/gospider

Canonical syntax:
`gospider -s <site> [options]`

High-signal flags:
- `-s <url>` target site URL
- `-S <file>` file containing list of target URLs
- `-d <depth>` max crawl depth (default 1)
- `-c <n>` concurrent requests (default 5)
- `-t <seconds>` request timeout in seconds (default 10)
- `--js` enable JavaScript file link parsing
- `--sitemap` include sitemap.xml parsing
- `--robots` include robots.txt parsing
- `-o <dir>` output directory (one file per target)
- `-w` write output to files in output directory
- `-a` include all subdomains of the target
- `--subs` include subdomains discovered during crawling
- `-H <header>` custom header (repeatable)
- `-p <proxy>` HTTP proxy URL
- `--cookie <cookie>` cookies for requests
- `--user-agent <ua>` custom User-Agent string
- `--delay <ms>` delay between requests in milliseconds
- `-q` quiet mode (only output found URLs)
- `-l <n>` max URLs per site (limit total output)
- `--blacklist <extensions>` file extensions to skip (e.g., `png,jpg,gif`)
- `-r` include other sources (Wayback, CommonCrawl, VirusTotal)
- `--no-redirect` do not follow redirects

Agent-safe baseline for automation:
`gospider -s https://target.com -d 3 -c 5 -t 10 --js --sitemap --robots -w -o /tmp/gospider_output -q`

Common patterns:
- Basic crawl with JS parsing:
  `gospider -s https://target.com -d 2 -c 5 --js -q`
- Deep crawl with all discovery features:
  `gospider -s https://target.com -d 3 -c 5 --js --sitemap --robots --subs -w -o /tmp/crawl_output`
- Crawl with external sources (Wayback, CommonCrawl):
  `gospider -s https://target.com -d 2 -c 5 --js -r -w -o /tmp/full_crawl`
- Batch crawl multiple targets:
  `gospider -S /tmp/urls.txt -d 2 -c 3 -t 10 --js -w -o /tmp/batch_crawl -q`
- Crawl with authentication:
  `gospider -s https://target.com -d 2 -c 5 --js --cookie "session=abc123" -H "Authorization: Bearer <token>" -q`
- Throttled crawl for sensitive targets:
  `gospider -s https://target.com -d 2 -c 2 --delay 500 --js -q`
- Extract only JavaScript file URLs:
  `gospider -s https://target.com -d 1 -c 5 --js -q | grep -i "\.js"`
- Crawl skipping static assets:
  `gospider -s https://target.com -d 3 -c 5 --js --blacklist png,jpg,gif,css,svg,woff,woff2 -q`

Sandbox safety:
- Limit `-d` depth to 2-3 to prevent excessive crawling.
- Set `-c` concurrency to 3-10 to avoid overwhelming targets.
- Always set `-t` timeout (10-15s) to prevent hanging requests.
- Use `--delay` (200-500ms) on production targets to reduce load.
- Use `--blacklist` to skip binary/static file extensions and save bandwidth.
- Use `-l` to cap the maximum number of URLs collected per site.
- Use `-q` for cleaner output in automated pipelines.
- Avoid `-r` (external sources) on first pass; add it only when broader coverage is needed.

Failure recovery:
- If crawl hangs, reduce `-c` concurrency and increase `-t` timeout.
- If blocked by WAF, add `--delay`, reduce `-c`, and use `--user-agent` with a realistic browser string.
- If too many results, add `--blacklist` for static assets and reduce `-d` depth.
- If subdomains are needed, add `--subs` and `-a` flags.
