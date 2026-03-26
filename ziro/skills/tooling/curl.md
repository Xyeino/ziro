---
name: curl
description: HTTP client for manual request crafting, header inspection, auth testing, cookie manipulation, and API probing.
---

# Curl CLI Playbook

Canonical syntax:
`curl [options] <url>`

Key flags:
- `-v` verbose (show headers)
- `-s` silent (no progress bar)
- `-o <file>` output to file
- `-O` save with remote filename
- `-L` follow redirects
- `-k` ignore TLS errors
- `-I` HEAD request only (headers)
- `-X <method>` HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS)
- `-H <header>` custom header
- `-d <data>` POST data (application/x-www-form-urlencoded)
- `-d @file` POST data from file
- `-F <field=value>` multipart form upload
- `-b <cookie>` send cookie
- `-c <file>` save cookies to file
- `-u user:pass` basic auth
- `-A <ua>` user agent
- `-x <proxy>` use proxy
- `-w <format>` output format string
- `--connect-timeout <sec>` connection timeout
- `-m <sec>` max time

Common patterns:
- Check response headers:
  `curl -sI https://example.com`
- Check security headers:
  `curl -sI https://example.com | grep -iE "strict-transport|content-security|x-frame|x-content-type|x-xss|referrer-policy|permissions-policy"`
- POST JSON:
  `curl -s -X POST https://example.com/api -H "Content-Type: application/json" -d '{"key":"value"}'`
- POST form:
  `curl -s -X POST https://example.com/login -d "username=admin&password=test"`
- With auth token:
  `curl -s https://example.com/api -H "Authorization: Bearer <token>"`
- Cookie auth:
  `curl -s https://example.com/dashboard -b "session=abc123"`
- File upload:
  `curl -s -X POST https://example.com/upload -F "file=@shell.php"`
- Follow redirects and show chain:
  `curl -sIL https://example.com 2>&1 | grep -E "^(HTTP/|Location:)"`
- Check HTTP methods:
  `curl -s -X OPTIONS https://example.com -I | grep Allow`
- Timing info:
  `curl -s -o /dev/null -w "DNS: %{time_namelookup}s\nConnect: %{time_connect}s\nTLS: %{time_appconnect}s\nTotal: %{time_total}s\nCode: %{http_code}\n" https://example.com`
- Through proxy (Caido/Burp):
  `curl -s -x http://127.0.0.1:8080 -k https://example.com`

Security testing:
- CORS check: `curl -sI -H "Origin: https://evil.com" https://example.com | grep -i access-control`
- Host header injection: `curl -sI -H "Host: evil.com" https://example.com`
- Path traversal: `curl -s "https://example.com/file?path=../../etc/passwd"`
- CRLF injection: `curl -s "https://example.com/%0d%0aSet-Cookie:hacked=1"`
- HTTP verb tampering: `curl -s -X PUT https://example.com/admin`
- Open redirect: `curl -sIL "https://example.com/redirect?url=https://evil.com" | grep Location`
