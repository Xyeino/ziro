---
name: security_test_cases
description: Generate and execute structured security test cases with pass/fail assertions for CI/CD integration
---

# Security Unit Tests

Structure every security assessment as discrete, reproducible test cases. Each test has a clear target, action, expected behavior, and pass/fail result.

## Test Case Format

For every vulnerability class tested, produce structured test cases:

```
TEST: [ID] [Category] — [Short description]
TARGET: [URL/endpoint]
PRECONDITION: [Auth state, setup required]
STEPS:
  1. [Action]
  2. [Action]
EXPECTED: [What should happen if secure]
ACTUAL: [What actually happened]
RESULT: PASS | FAIL | SKIP
EVIDENCE: [HTTP request/response, screenshot, command output]
SEVERITY: [If FAIL — CVSS + Business Impact]
```

## Standard Test Categories

### AUTH — Authentication Tests
```
AUTH-001: Brute force protection on login
AUTH-002: Account lockout after N failed attempts
AUTH-003: Password complexity enforcement
AUTH-004: Session invalidation on logout
AUTH-005: Session timeout after inactivity
AUTH-006: Concurrent session handling
AUTH-007: Password reset token expiry
AUTH-008: MFA bypass attempts
AUTH-009: Default credentials check
AUTH-010: Authentication over HTTPS only
```

### AUTHZ — Authorization Tests
```
AUTHZ-001: Vertical privilege escalation (user → admin)
AUTHZ-002: Horizontal privilege escalation (user A → user B data)
AUTHZ-003: IDOR on all resource endpoints
AUTHZ-004: Direct object reference via API
AUTHZ-005: Function-level access control
AUTHZ-006: Admin panel access without admin role
AUTHZ-007: API endpoint authorization consistency
AUTHZ-008: GraphQL authorization per field/mutation
```

### INPUT — Input Validation Tests
```
INPUT-001: Reflected XSS in search/input fields
INPUT-002: Stored XSS in user-generated content
INPUT-003: SQL injection in query parameters
INPUT-004: SQL injection in form fields
INPUT-005: Command injection in file processing
INPUT-006: Path traversal in file access
INPUT-007: XXE in XML upload/processing
INPUT-008: SSTI in template rendering
INPUT-009: SSRF in URL input fields
INPUT-010: NoSQL injection in API queries
INPUT-011: CRLF injection in headers
INPUT-012: Prototype pollution in JSON parsing
```

### CONFIG — Configuration Tests
```
CONFIG-001: Security headers present (CSP, HSTS, X-Frame-Options)
CONFIG-002: CORS policy not overly permissive
CONFIG-003: TLS configuration (no SSLv3, TLS 1.0/1.1)
CONFIG-004: Cookie flags (Secure, HttpOnly, SameSite)
CONFIG-005: Directory listing disabled
CONFIG-006: Debug mode disabled in production
CONFIG-007: Error messages don't leak internals
CONFIG-008: Rate limiting on sensitive endpoints
CONFIG-009: HTTPS redirect enforced
CONFIG-010: Unnecessary HTTP methods disabled
```

### DATA — Data Protection Tests
```
DATA-001: Sensitive data not in URL parameters
DATA-002: Passwords not stored in plaintext
DATA-003: API keys not exposed in client-side code
DATA-004: PII not logged in application logs
DATA-005: Sensitive data not cached
DATA-006: Proper data sanitization on output
DATA-007: File upload type validation (not just extension)
DATA-008: Uploaded files not executable
```

### LOGIC — Business Logic Tests
```
LOGIC-001: Price manipulation in checkout flow
LOGIC-002: Quantity manipulation (negative, zero, overflow)
LOGIC-003: Coupon/discount code abuse
LOGIC-004: Race condition in balance/inventory operations
LOGIC-005: Workflow step bypass (skip payment, skip verification)
LOGIC-006: Rate limit bypass on expensive operations
LOGIC-007: Account enumeration via different error messages
LOGIC-008: Email/phone verification bypass
```

### API — API-Specific Tests
```
API-001: Mass assignment via extra fields
API-002: Excessive data exposure in responses
API-003: Broken pagination (access all records)
API-004: API versioning security (old versions still accessible)
API-005: GraphQL introspection enabled in production
API-006: GraphQL depth/complexity limits
API-007: Webhook endpoint validation
API-008: API key scope enforcement
```

## Execution Strategy

### Phase 1: Automated (Tool-based)
Run these first — fast, deterministic:
- CONFIG tests → security headers check, TLS scan
- AUTH-009 → default credential scan
- INPUT tests → automated scanner + manual payload verification
- DATA-003 → JS source code analysis

### Phase 2: Semi-Automated (Tool + Logic)
Requires understanding the application:
- AUTHZ tests → authenticated scanning with role switching
- API tests → API spec analysis + fuzzing
- AUTH tests → session manipulation

### Phase 3: Manual Reasoning
Requires business context:
- LOGIC tests → understand workflows then test abuse cases
- Complex AUTHZ → multi-step privilege escalation chains

## Reporting Test Results

At the end of a scan, produce a test summary:

```
SECURITY TEST RESULTS
=====================
Total: [N] tests
Passed: [N] ✓
Failed: [N] ✗
Skipped: [N] -
Coverage: [%]

FAILED TESTS:
  [FAIL] AUTH-001 — No brute force protection on /api/login
  [FAIL] AUTHZ-003 — IDOR on /api/users/{id}/profile
  [FAIL] INPUT-001 — Reflected XSS in /search?q=

CRITICAL FINDINGS:
  AUTHZ-003 → CVSS 7.5 / BIS 4.2 (CRITICAL BUSINESS RISK)
  INPUT-001 → CVSS 6.1 / BIS 3.1 (HIGH BUSINESS RISK)
```

## Mapping to Vulnerability Reports

Every FAIL test case that reveals a real vulnerability should become a `create_vulnerability_report` call. Include:
- Test ID in the title: "AUTH-001: Missing Brute Force Protection"
- Test steps as PoC
- Expected vs actual behavior in description
- Business impact score in impact field
