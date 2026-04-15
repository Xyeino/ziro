---
name: js_bundle_analysis
description: Download and deeply analyze JavaScript bundles — secret extraction, API endpoint discovery, DOM XSS sinks, source map reconstruction
mitre_techniques: [T1592.002, T1593.003, T1213, T1552.001, T1083]
kill_chain_phases: [reconnaissance, credential_access, discovery]
related_skills: [graphql_introspection, passive_osint_apis, information_disclosure, telegram_mini_app]
---

# JavaScript Bundle Analysis

The frontend JS of any modern web app is a goldmine of attack-relevant intel: hardcoded secrets, the entire API surface, framework hints, internal hostnames, role definitions, business logic, and (when source maps are exposed) the full original source tree. This skill teaches you how to extract all of it efficiently using the `download_js_bundles`, `analyze_js_file`, and `fetch_source_map` tools.

## When to Run This

**Always**, on any web target with a frontend. The cost is low (few seconds), the signal is high. Run it in the early recon phase, BEFORE any active testing — knowing the API surface and finding leaked secrets fundamentally changes which exploits you should try.

Especially valuable for:
- **SPAs (React/Vue/Angular/Svelte/Next.js/Nuxt)** — entire API contract is in the bundle
- **Telegram Mini Apps** — bot tokens, initData handling, custom auth flows
- **Crypto/Web3 frontends** — wallet integration, contract addresses, RPC URLs, sometimes private keys
- **Mobile-first web apps** — often share JS with iOS/Android wrappers, doubled exposure
- **Enterprise SaaS** — admin endpoints, role checks, feature flags, internal services

## The Three-Step Workflow

### Step 1 — Download

```
download_js_bundles(url="https://target.example.com", max_files=100, follow_chunks=true)
```

Returns inventory of every JS file saved to `/workspace/js/<host>/`. Look at `files_with_sourcemap` in the response — if non-zero, you've already won a major prize, jump to Step 3.

### Step 2 — Analyze

```
analyze_js_file(host="target.example.com")
```

Runs deep static analysis on every downloaded file. Returns:
- **`secrets`** — what to triage first. Each entry has `type`, `value`, `file`, `line`. Always validate before reporting (test the credential against its actual API).
- **`api_endpoints`** — full API surface from string literals. Use these as a starting list for endpoint testing (auth, IDOR, mass assignment).
- **`spa_routes`** — every route the frontend knows. Some routes only exist for admins or after certain state — try them all.
- **`dom_xss_sinks`** — `innerHTML`, `document.write`, `eval`, etc. Each comes with the surrounding context and the variable feeding the sink. Trace back to find user-controlled inputs.
- **`source_map_refs`** — files with `sourceMappingURL` trailers. Move to Step 3 for these.
- **`third_party_urls`** — external services the app talks to. Some (Stripe, Auth0, AWS Cognito) imply specific auth/payment vulnerabilities.

To narrow analysis to a single suspicious file:
```
analyze_js_file(file_path="/workspace/js/target.example.com/main.bb7c7604.js")
```

### Step 3 — Reconstruct sources from .map files (when present)

```
fetch_source_map(js_url="https://target.example.com/static/js/main.bb7c7604.js")
```

If the target accidentally ships .map files, this reconstructs the **original source tree** under `/workspace/sources/<host>/` — including variable names, comments, file structure, framework code. Then use:

```
read_skill("information_disclosure")
load_skill("sql_injection")
```

...and treat the reconstructed tree as a white-box code review target. You now have everything a real developer has.

The tool returns 4xx if .map files are locked down — that's the secure default. Note it as a positive finding in the report.

## Secret Triage Priority

Not all secrets are created equal. Reading the `analyze_js_file` output, prioritize like this:

**Critical — exploit immediately:**
- `AWS_ACCESS_KEY` + matching secret in same file → full cloud takeover potential
- `STRIPE_SECRET_LIVE`, `STRIPE_RESTRICTED_LIVE` → real money
- `GITHUB_PAT_*` → source code access, CI/CD takeover
- `PRIVATE_KEY_PEM` → MitM, SSL takeover, code signing
- `SUPABASE_SERVICE_KEY` (`sbp_...`) → bypasses Row Level Security, full DB
- `TELEGRAM_BOT_TOKEN` → forge any user's initData, full TMA bypass
- `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` → financial loss, possible PII via prompts
- `DB_CONNECTION_URL` → direct database access
- `SLACK_TOKEN` (xoxb-/xoxp-) → message read/write, lateral movement to internal data

**High — verify scope and exploit:**
- `JWT_TOKEN` if not expired and has interesting claims
- `STRIPE_SECRET_TEST` (data still real for testing)
- `SHOPIFY_ACCESS_TOKEN`, `TWILIO_ACCOUNT_SID` + auth token
- `FIREBASE_CONFIG_BLOCK` — pivot to Firestore/Realtime DB rule audit
- `MAPBOX_SECRET_TOKEN`, `SENDGRID_API_KEY`
- `DISCORD_BOT_TOKEN` / `DISCORD_WEBHOOK`

**Medium — investigate context:**
- `GENERIC_API_KEY`, `BEARER_TOKEN_GENERIC` — verify what API they unlock
- Hardcoded `password` / `secret` values — often dev defaults, sometimes real
- `STRIPE_PUBLIC_LIVE` (`pk_live_`) — public by design, but combined with logic flaws can enable card scraping

**Always validate before reporting** — credentials get rotated, generic patterns false-positive on UUIDs and hashes. Use the relevant API's identity/health endpoint to confirm.

## Validating Secrets Without Causing Damage

Use **read-only identity endpoints** to prove a credential is live, never modify state:

| Service | Validation endpoint | Notes |
|---|---|---|
| AWS | `aws sts get-caller-identity` | safe, returns account ID |
| GitHub PAT | `curl -H "Authorization: Bearer <token>" https://api.github.com/user` | safe |
| Stripe | `curl -u <key>: https://api.stripe.com/v1/balance` | read-only |
| Telegram bot | `curl https://api.telegram.org/bot<token>/getMe` | safe |
| OpenAI | `curl -H "Authorization: Bearer <key>" https://api.openai.com/v1/models` | safe |
| Slack | `curl -H "Authorization: Bearer <token>" https://slack.com/api/auth.test` | safe |
| Twilio | `curl -u <sid>:<token> https://api.twilio.com/2010-04-01/Accounts.json` | safe |
| Sendgrid | `curl -H "Authorization: Bearer <key>" https://api.sendgrid.com/v3/scopes` | safe |
| GCP | `curl -H "Authorization: Bearer <token>" https://www.googleapis.com/oauth2/v3/tokeninfo` | safe |

**Never** call `sendMessage`, `createCharge`, `setWebhook`, `transfer`, `delete`, etc. against credentials you're testing. Just prove liveness.

## DOM XSS Sink Triage

`analyze_js_file` returns sinks with the surrounding context. To confirm an actual XSS:

1. Trace the sink's input variable backwards through the bundle (use `terminal_execute` with `grep -n "<varname>" /workspace/js/<host>/*.js`)
2. Find where it's assigned — is it from `location.search`, `location.hash`, `URLSearchParams`, postMessage event data, fetch response?
3. If user-controlled, craft a test payload and verify in browser via `browser_action`
4. Document with: file/line of sink, file/line of source, full taint path, working PoC URL

## API Endpoint Use

The `api_endpoints` list is your **starting set for active testing**. For each:

1. Issue an unauthenticated GET — see if it works (broken auth)
2. Try with a low-privilege session — broken object-level authz (IDOR)
3. Substitute path parameters with admin/other-user IDs — horizontal privilege escalation
4. Try POST/PUT/DELETE on read-only-looking endpoints — mass assignment, parameter pollution
5. Send malformed input (JSON garbage, oversized strings, unicode, type confusion) — error handling leaks

## SPA Route Use

Spy on `spa_routes` to find pages the public navigation never links to:

- `/admin/*` — almost always interesting
- `/internal/*`, `/staff/*`, `/staff-only/*`
- `/debug/*`, `/dev/*`
- `/_health`, `/_metrics`, `/_status`, `/.well-known/*`
- Routes with `:id` placeholders — often IDOR
- Routes that look incomplete (`/upload-test`, `/migration`) — leftover dev artifacts

## Common Pitfalls

- **Don't trust file size as a measure of importance**. The smallest chunk file is sometimes a config blob with all the secrets.
- **Don't deduplicate secrets across files prematurely** — sometimes a secret appears in one file by accident and in another intentionally; both are findings.
- **Source maps may be partial** — only the files the bundler chose to include have content; vendored libraries usually don't. Check `skipped_no_content` in fetch_source_map's return.
- **chunk_pattern matching is heuristic** — if `download_js_bundles` says `chunks_discovered=0` but you see fewer files than expected, manually inspect the page in the browser DevTools Network tab and use `download_js_bundles` again with explicit URLs (or just terminal curl them).
- **Some apps hash chunk filenames per build** — re-running download after a deployment will pull different files. That's normal; analyze the new set.

## Reporting

For every finding, the report should include:

- **Type** (matches one of the SECRET_PATTERNS labels)
- **Source location** (file + line as returned by analyze_js_file)
- **Validation status** (live / revoked / unknown — if you tested it)
- **Impact** (what does this credential unlock if abused)
- **Remediation** (rotate the credential, move to env vars, set up secret scanning in CI to prevent recurrence)

For DOM XSS sinks, include the full taint path and a working PoC URL.

For exposed source maps, include the `_INDEX.txt` file path so the client can see the full reconstructed tree.

## References

- OWASP ASVS V14.3 Web frontend security
- MITRE ATT&CK T1592.002 — Software (Reconnaissance)
- MITRE ATT&CK T1552.001 — Credentials in Files
- "JS Recon Master Class" — Detectify Labs / various pentest blogs
- truffleHog / gitleaks pattern lists (this tool uses extended versions)
