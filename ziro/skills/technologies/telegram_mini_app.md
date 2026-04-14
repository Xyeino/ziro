---
name: telegram_mini_app
description: Telegram Mini App (TMA) security testing — initData HMAC validation, forgery, replay, bot token exposure, postMessage XSS, deep link abuse
mitre_techniques: [T1190, T1528, T1552.001, T1078, T1539]
kill_chain_phases: [initial_access, credential_access, reconnaissance]
related_skills: [authentication_jwt, idor, business_logic, information_disclosure]
---

# Telegram Mini App (TMA)

Security testing for Telegram Mini Apps (Web Apps opened inside Telegram clients via bots). The single most important fact: **the entire trust model hinges on the server-side HMAC-SHA256 validation of `initData`**. Skip it, implement it wrong, or trust any user-controlled field outside of the validated `initData.user.id`, and every authorization decision becomes forgeable.

## Architecture

**Components**
- **Bot** — owns the `BOT_TOKEN` (format `<bot_id>:<secret>`), registered via BotFather
- **Mini App (Web App)** — HTML/JS served from a URL associated with the bot, rendered inside Telegram's WebView (iOS/Android/Desktop/Web-K/Web-A/macOS)
- **Backend** — the Mini App's API server, must validate `initData` on every authenticated request
- **Telegram JS SDK** — `window.Telegram.WebApp` providing `initData`, `initDataUnsafe`, theme, viewport, events, `postMessage` bridge

**Trust boundaries**
- Telegram client signs `initData` with HMAC-SHA256 derived from `BOT_TOKEN`
- Backend re-validates the signature using the same `BOT_TOKEN`
- The Mini App's frontend JS is **fully untrusted** — anything it sends must be re-verified server-side
- `initDataUnsafe` is the parsed JS object **without signature check** — never use for auth decisions
- `initData` (raw query string) is what you hash/validate

## initData Format

Query-string passed as `window.Telegram.WebApp.initData`:

```
user=%7B%22id%22%3A12345...%7D&chat_instance=-123&chat_type=sender&auth_date=1728123456&hash=abc123...&signature=...
```

**Standard fields**
- `user` — URL-encoded JSON: `{id, first_name, last_name?, username?, language_code?, is_premium?, photo_url?, allows_write_to_pm?}`
- `receiver` — peer user (for attachment menu apps)
- `chat` — if launched in chat context
- `chat_type` — `sender` / `private` / `group` / `supergroup` / `channel`
- `chat_instance` — opaque per-chat identifier
- `start_param` — arg from deep link `t.me/<bot>/<app>?startapp=<value>` or inline `?start=...`
- `can_send_after` — rate-limit hint
- `auth_date` — **Unix timestamp, freshness anchor**
- `query_id` — for `answerWebAppQuery` flow
- `hash` — HMAC to verify against
- `signature` — Ed25519 over the data (newer clients, optional second factor)

### Validation Algorithm (HMAC-SHA256)

```
1. Parse query string into key/value pairs
2. Extract and remove "hash" (and "signature" for newer validation)
3. Sort remaining pairs alphabetically by key
4. data_check_string = "\n".join(f"{k}={v}" for k,v in sorted_pairs)
5. secret_key = HMAC_SHA256(key="WebAppData", msg=BOT_TOKEN)
6. calculated = HMAC_SHA256(key=secret_key, msg=data_check_string).hexdigest()
7. Compare calculated == hash (constant-time)
8. Check auth_date freshness (<=5 minutes recommended, <=24h max)
```

**Reference implementation (Python)**
```python
import hmac, hashlib, time
from urllib.parse import parse_qsl, unquote

def validate(init_data: str, bot_token: str, max_age: int = 300) -> dict:
    pairs = dict(parse_qsl(init_data, strict_parsing=True))
    recv_hash = pairs.pop("hash", None)
    pairs.pop("signature", None)  # not part of HMAC check
    if not recv_hash:
        raise ValueError("missing hash")

    data_check = "\n".join(f"{k}={pairs[k]}" for k in sorted(pairs))
    secret = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    calc = hmac.new(secret, data_check.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(calc, recv_hash):
        raise ValueError("bad hash")
    if int(pairs.get("auth_date", 0)) + max_age < time.time():
        raise ValueError("stale auth_date")
    return pairs
```

## Attack Surface

**Backend API endpoints**
- `/api/auth/telegram` — exchange `initData` for session/JWT
- `/api/me`, `/api/profile`, `/api/balance` — reads user state
- `/api/tap`, `/api/claim`, `/api/upgrade` — game/economy writes (Hamster Kombat–style apps)
- `/api/withdraw`, `/api/convert`, `/api/referral` — money/reward flows
- `/api/admin/*` — admin panels often reuse the same backend

**Client-side**
- `window.Telegram.WebApp` API
- `postMessage` bridge to Telegram native client
- Deep link parameters: `tgWebAppStartParam` from `start_param`
- `tgWebAppData` hash-fragment on the Mini App URL (contains initData)

**Transport**
- HTTPS required, but initData visible to MiTM on proxy-terminating networks
- Bot messages via HTTPS (not E2E) — see CVEs on bot token exposure

## Key Vulnerabilities

### 1. Missing or bypassed initData validation (CRITICAL)

The #1 TMA bug. Many apps:
- Parse `initDataUnsafe` client-side and forward `user.id` to backend as a **query or body parameter**
- Accept `X-User-Id`/`X-Telegram-Id` headers without verifying
- Validate `initData` **once** on login and then trust a session cookie without re-binding to Telegram user
- Disable validation in dev and ship to prod

**Tests**
```bash
# (A) Drop initData entirely, see if backend still serves the user
curl https://api.target.tg/api/me \
  -H "Authorization: tma " \
  -H "Content-Type: application/json"

# (B) Trust-header injection
curl https://api.target.tg/api/me \
  -H "X-User-Id: 123456789" \
  -H "X-Telegram-User-Id: 123456789"

# (C) Pass your own Telegram ID in the body
curl https://api.target.tg/api/balance \
  -X POST -d '{"user_id": 999999999}' \
  -H "Content-Type: application/json"

# (D) Send malformed hash — if accepted, validation is off
curl "https://api.target.tg/api/auth" \
  -d 'init_data=user=%7B%22id%22%3A1%7D&auth_date=1&hash=deadbeef'
```

Any HTTP 200 with real data = broken auth.

### 2. Hash forgery / missing signature check

Some servers parse `initData` and check only that `hash` is present (non-empty string), not that it matches. Or they use the wrong secret derivation (use `BOT_TOKEN` directly as HMAC key instead of `HMAC("WebAppData", BOT_TOKEN)`).

**Tests**
- Replace `hash` with random hex of correct length — expect 401
- Omit `hash` — expect 401
- Provide empty `hash=` — expect 401
- Truncate hash to 1 char — some string-compare implementations accept prefix
- Change one byte of `user` JSON but keep original `hash` — expect 401
- Swap fields (e.g., change `user.id`) while leaving `hash` — expect 401

If any of the above returns 200, the check is broken.

### 3. auth_date replay (no freshness window)

Without a time bound, a valid `initData` is forever-usable. Captured once via MiTM, shared link, browser history, or CI logs.

**Tests**
- Capture a valid `initData` from a real user open
- Replay it 30 minutes later — should fail
- Replay it 24 hours later — should fail
- Replay it 7 days later — should fail
- Set `auth_date` to a far-future value with recomputed hash (requires bot token) — should fail; if accepted, the server probably compares with `int(auth_date) > now - X` without `< now + Y`

### 4. Bot token leakage

If the bot token is exposed, an attacker can **forge arbitrary `initData` for any `user.id`**, fully bypassing validation.

**Sources**
- Hardcoded in Mini App JS bundle (`main.js`, chunked webpack files) — grep for `BOT_TOKEN`, `:AAE`, `:AAF`, `\d{9,10}:[A-Za-z0-9_-]{35}`
- Leaked in error responses / stack traces
- `.env` files in public directory
- Old commits in `.git` if deployed from git clone
- Response body of `/api/config`, `/api/init`, `/debug/*` endpoints
- Mobile app decompilation if a companion native app exists
- CI logs, Docker image layers, S3 buckets tied to the project

**Tests**
```bash
# Regex to scan JS bundles and responses
grep -rE '[0-9]{9,10}:[A-Za-z0-9_-]{35}' ./downloaded-bundle/

# Test a found token
curl "https://api.telegram.org/bot<TOKEN>/getMe"
# {"ok":true,"result":{"id":...,"username":"..."}}
```

**If you confirm a live token:** stop, report immediately, do not use it to call `sendMessage`/`setWebhook` etc. Only `getMe` to prove liveness.

### 5. User ID trust violation

Server validates `initData.hash` correctly, but then uses a DIFFERENT `user_id` from the request body or query, or takes `first_name` from client.

```
POST /api/profile/update
{
  "init_data": "<valid>",
  "user_id": "999",    ← attacker-supplied, server uses this instead of initData.user.id
  "display_name": "victim"
}
```

**Tests**
- Valid `initData` of user A + `user_id` of user B in body → expect 403; 200 with B's data = horizontal IDOR
- Valid `initData` + negative/admin `user_id` → privilege escalation
- Check all write endpoints (`/update`, `/claim`, `/transfer`, `/convert`)

### 6. start_param / deep link injection

`tgWebAppStartParam` (from `?startapp=<value>`) is **user-controlled**. Apps often use it as:
- Referral code → log injection, SQLi, self-referral abuse
- Invite token → unauth access if not bound to user
- Affiliate redirect → open redirect / SSRF
- Action trigger (`startapp=claim_bonus`) → state machine bypass

**Tests**
```
t.me/<bot>/<app>?startapp=<payload>
```
- `'-- `, `"><svg onload=alert(1)>`, `{{7*7}}`, `../../etc/passwd`
- Self-refer: create own ref code, open own link, see if bonus granted
- Replay another user's referral `start_param` after they already used it
- `startapp=admin`, `startapp=null`, `startapp=` (empty)
- Unicode/homograph collisions with real codes

### 7. postMessage XSS / web_app_open_link abuse (CVE-2024-33905)

Historic one-click XSS in Telegram WebK before 2.0.0 (488): a malicious Mini App could `postMessage({eventType: 'web_app_open_link', eventData: {url: 'javascript:...'}})` to the parent and get JS execution on `web.telegram.org`.

**Still relevant because:**
- Legacy clients (Telegram WebK < 2.0.0/488, old Desktop builds, unpatched custom forks) may still be in use
- The *pattern* (client trusting eventData URL/HTML from the iframe) recurs in custom wrappers and third-party "TMA launchers"
- Application's own `postMessage` handling often mimics Telegram's — check for unvalidated URL sinks

**Tests**
```javascript
// Inside the Mini App context:
window.parent.postMessage(JSON.stringify({
  eventType: 'web_app_open_link',
  eventData: {url: 'javascript:alert(document.domain)'}
}), '*');

// Same for custom events the app handles
window.parent.postMessage({type: 'navigate', href: 'javascript:...'}, '*');
```
- Check if links with `javascript:`, `data:text/html`, `blob:`, `intent://` schemes are normalized/blocked
- Verify `target="_blank" rel="noopener noreferrer"` on all outbound links
- Check `openLink`, `openTelegramLink`, `openInvoice` wrappers

### 8. No CSRF binding / session not bound to TG user

Some apps exchange `initData` for a session cookie and then stop checking Telegram context. If the session cookie is stolen (XSS, shared device, log exposure), the attacker has the user forever, even outside Telegram.

**Tests**
- Validate with user A, get session, use it from a plain browser — should still work? If yes, consider stealing vectors
- Does session cookie have `SameSite=Lax/Strict`, `Secure`, `HttpOnly`?
- Does the backend re-verify the initData periodically or bind the session to `auth_date`?

### 9. Webhook endpoint without authentication

The bot's Telegram webhook (`/bot-webhook` or similar) is often unauth because Telegram doesn't authenticate to you — you're supposed to use an obscure URL as the secret. Frequently leaked.

**Tests**
- Find the webhook URL (check `setWebhook` in leaked tokens, `robots.txt`, docs, `/api/*` enumeration)
- POST a crafted `Update` payload simulating a user message:
```bash
curl https://api.target.tg/bot-webhook -d '{
  "update_id": 1,
  "message": {
    "message_id": 1,
    "from": {"id": 999, "is_bot": false, "first_name": "x"},
    "chat": {"id": 999, "type": "private"},
    "date": 1728000000,
    "text": "/admin grant_premium"
  }
}' -H "Content-Type: application/json"
```
- If the bot processes it as if from Telegram, any user command is injectable
- Check `X-Telegram-Bot-Api-Secret-Token` header verification (introduced in Bot API 6.0 — many bots ignore it)

### 10. Rate limiting on auth + tap endpoints

TMA games (clicker/tap-to-earn) almost always have broken rate limiting because the entire UX assumes high-frequency writes from the client.

**Tests**
- Replay `/api/tap` 1000 times in parallel — expect per-second cap
- Send `count=1000000` in single request — expect cap on amount per call
- Race condition: parallel requests to `/api/claim` with same timestamp → double claim
- Negative amount in `/api/upgrade`, `/api/convert`, `/api/bet`

### 11. initData field tampering via JSON encoding

`user` field is URL-encoded JSON. Parsers differ:
- Some servers URL-decode but then `json.loads(user)` and trust every field
- If server reads `user.is_premium` from JSON instead of Telegram's trusted `user` object, client can set `is_premium: true` — forge hash by either finding token or hoping validation is off

**Tests**
- Modify `user` JSON to add `is_premium: true`, `is_admin: true`, `role: "admin"` — requires fresh hash, so this is a COMBO with Bug #1 (no validation)
- Check which fields from `initData.user` are actually used server-side via response diffing

### 12. answerWebAppQuery flow abuse

If the app uses `query_id` flow (inline result via `answerWebAppQuery`), the backend calls Telegram's API with the `query_id`. Risks:
- Forged `query_id` → attacker coerces backend to send messages as bot
- Missing validation of who the `query_id` belongs to → inject into another user's conversation

## Reconnaissance

**Find the Mini App**
- Telegram BotFather lists `/newapp` registered apps
- Check `https://t.me/<bot>?startapp=` or `https://t.me/<bot>/<short_name>` — Telegram shows a preview
- Inspect `initData` from Telegram Desktop DevTools (Settings → Advanced → Experimental → Enable WebView Inspecting) or via `window.Telegram.WebApp.initData` in the mini-app console
- Grab the backend API origin from `fetch`/`XMLHttpRequest` in DevTools Network tab

**Map the API**
- Enumerate endpoints under the origin discovered above
- Look for Swagger/OpenAPI: `/docs`, `/openapi.json`, `/api-docs`, `/graphql`, `/swagger-ui`
- Grep JS bundles for URL literals and route tables
- Check `start_param` propagation: set it, observe which backend endpoints receive it

**Collect a valid initData**
- Open the app in Telegram Desktop or Web
- DevTools console: `copy(Telegram.WebApp.initData)`
- This is your baseline for all replay/tampering tests

## Test Scenarios

**Scenario A — Validation smoke test**
1. POST `/api/auth` with empty body → expect 4xx
2. POST with initData but no `hash` → expect 4xx
3. POST with initData and junk `hash` → expect 4xx
4. POST with tampered `user.id` keeping original `hash` → expect 4xx
5. POST with expired `auth_date` (>24h old) → expect 4xx
6. If any of 1–5 returns 2xx + real data → Bug #1 (full auth bypass)

**Scenario B — Horizontal IDOR via user_id params**
1. Authenticate as user A, intercept `/api/me` response → record `user_id_A`
2. Replay all `/api/*` endpoints with `user_id=<another_id>` in query/body/header
3. If data from other users returned → broken object-level auth

**Scenario C — Economy manipulation**
1. Hit `/api/tap` 1000× in parallel over 1 second → check if count accepted in full
2. POST `/api/claim` with negative/huge amount
3. Claim daily bonus twice via race condition
4. Referral self-refer via `startapp=ref_<own_id>`

**Scenario D — Bot token hunt**
1. Download all JS chunks from Mini App origin
2. `grep -rE '[0-9]{9,10}:[A-Za-z0-9_-]{35}'`
3. Check `/api/config`, `/api/init`, `/health`, `/debug/*` for token fields
4. `curl https://api.telegram.org/bot<TOKEN>/getMe` → if ok, critical

**Scenario E — Deep link abuse**
1. Enumerate `start_param` handlers: `ref`, `invite`, `promo`, `claim`, `gift`, `bonus`, `admin`
2. Try each with injection payloads and replay across users
3. Test `tg://resolve?domain=<bot>&appname=<name>&startapp=<payload>`

## Tooling

- **curl / httpie / Caido** — replay and mutate API requests
- **Burp / Caido Repeater** — batch intruder attacks on `/api/tap`, `/api/claim`
- **jwt-cli, jose** — decode session JWTs returned by TMA auth exchange
- **pytma-validator / tma-js-init-data-node** — generate/validate initData locally
- **gfstringscan / trufflehog / gitleaks** — scan bundles for bot tokens
- **Telegram Desktop + DevTools** — live `initData` capture, DOM inspection, postMessage monitoring
- **Python one-liner** for fake initData (use only if you have token — own target):
  ```python
  import hmac, hashlib, time, urllib.parse, json
  t = "<BOT_TOKEN>"; u = {"id": 1, "first_name": "t"}
  p = {"user": json.dumps(u), "auth_date": str(int(time.time())), "query_id": "x"}
  dcs = "\n".join(f"{k}={p[k]}" for k in sorted(p))
  sk = hmac.new(b"WebAppData", t.encode(), hashlib.sha256).digest()
  p["hash"] = hmac.new(sk, dcs.encode(), hashlib.sha256).hexdigest()
  print(urllib.parse.urlencode(p))
  ```

## Validation Requirements

- Proof of **horizontal privilege escalation**: requesting another user's resource with your valid `initData` returns their data
- Proof of **full auth bypass**: meaningful API response without any `initData` or with invalid `hash`
- Proof of **replay**: a captured `initData` still works after the documented freshness window
- Proof of **forged user_id**: response contains another user's data when `user_id` is swapped in request body/query/header
- Proof of **bot token exposure**: `getMe` call succeeds with a token recovered from non-authorized location (report privately, do not use beyond liveness check)
- Screenshot or request/response pair for each PoC, clearly showing the principal and the unauthorized access

## Out of Scope for Defensive Testing

- Spamming real Telegram users via a leaked bot token
- `sendMessage`, `editMessage`, `setWebhook`, `deleteWebhook` calls on production bots
- Social engineering of real users into opening malicious Mini Apps
- Phishing impersonation of legitimate bots

Only test against bots you own or have explicit written permission to test.
