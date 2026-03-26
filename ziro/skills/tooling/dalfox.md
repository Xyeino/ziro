---
name: dalfox
description: Fast XSS scanner with parameter analysis, DOM-based detection, and blind XSS support via callback servers.
---

# DalFox CLI Playbook

Official docs:
- https://github.com/hahwul/dalfox

Canonical syntax:
`dalfox [mode] [options]`

Modes:
- `url` — scan single URL
- `file` — scan URLs from file
- `pipe` — scan URLs from stdin
- `sxss` — stored XSS mode

Key flags:
- `-b <url>` blind XSS callback (use with interactsh)
- `--data <data>` POST body
- `--cookie <cookie>` HTTP cookie
- `--header <header>` custom header
- `-p <param>` specific parameter to test
- `--mining-dict` use dictionary mining for param discovery
- `--deep-domxss` deep DOM XSS analysis
- `--waf-evasion` enable WAF bypass payloads
- `-w <workers>` concurrent workers (default 100)
- `--timeout <sec>` request timeout
- `-o <file>` output file
- `--format <fmt>` output format (plain, json)
- `--skip-bav` skip BAV (Basic Another Vulnerability) analysis
- `--only-poc <type>` PoC type: plain, curl, httpie

Agent-safe baseline:
`dalfox url "<target_url>" --timeout 10 -w 10 --format json -o dalfox_results.json`

Common patterns:
- Scan single URL:
  `dalfox url "https://example.com/search?q=test" --format json -o dalfox_single.json`
- Scan with blind XSS:
  `dalfox url "https://example.com/contact?msg=test" -b "https://your-interactsh-server" --format json -o dalfox_blind.json`
- Scan URL list from file:
  `dalfox file urls.txt -w 20 --format json -o dalfox_batch.json`
- Pipeline from other tools:
  `cat parameterized_urls.txt | dalfox pipe -w 10 --format json -o dalfox_pipe.json`
- Stored XSS mode:
  `dalfox sxss "https://example.com/post" --data "comment=FUZZ" --format json -o dalfox_stored.json`
- Deep DOM analysis:
  `dalfox url "https://example.com/app?input=test" --deep-domxss --format json -o dalfox_dom.json`
- WAF bypass:
  `dalfox url "https://example.com/search?q=test" --waf-evasion --format json -o dalfox_waf.json`

Workflow with other tools:
1. Crawl with katana: `katana -u https://example.com -o urls.txt`
2. Filter parameterized URLs: `grep '?' urls.txt > param_urls.txt`
3. Scan with dalfox: `dalfox file param_urls.txt -w 10 --format json -o xss_results.json`

DalFox vs manual XSS testing:
- Automatically discovers reflection points
- Tests DOM-based, reflected, and stored XSS
- Built-in WAF fingerprinting and bypass payloads
- Supports blind XSS with OOB callbacks
