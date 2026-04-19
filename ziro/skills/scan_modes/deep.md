---
name: deep
description: Exhaustive security assessment with maximum coverage, depth, and vulnerability chaining
---

# Deep Testing Mode

Exhaustive security assessment. Maximum coverage, maximum depth. Finding what others miss is the goal.

## Approach

Thorough understanding before exploitation. Test every parameter, every endpoint, every edge case. Chain findings for maximum impact.

## Phase 1: Exhaustive Reconnaissance

**Whitebox (source available)**
- Map every file, module, and code path in the repository
- Trace all entry points from HTTP handlers to database queries
- Document all authentication mechanisms and implementations
- Map authorization checks and access control model
- Identify all external service integrations and API calls
- Analyze configuration for secrets and misconfigurations
- Review database schemas and data relationships
- Map background jobs, cron tasks, async processing
- Identify all serialization/deserialization points
- Review file handling: upload, download, processing
- Understand the deployment model and infrastructure assumptions
- Check all dependency versions against CVE databases

**Blackbox (no source)**
- Exhaustive subdomain enumeration with multiple sources and tools
- Full port scanning across all services
- Complete content discovery with multiple wordlists
- Technology fingerprinting on all assets
- API discovery via docs, JavaScript analysis, fuzzing
- Identify all parameters including hidden and rarely-used ones
- Map all user roles with different account types
- Document rate limiting, WAF rules, security controls
- Document complete application architecture as understood from outside

## Phase 2: Business Logic Deep Dive

Create a complete storyboard of the application:

- **User flows** - document every step of every workflow
- **State machines** - map all transitions (Created → Paid → Shipped → Delivered)
- **Trust boundaries** - identify where privilege changes hands
- **Invariants** - what rules should the application always enforce
- **Implicit assumptions** - what does the code assume that might be violated
- **Multi-step attack surfaces** - where can normal functionality be abused
- **Third-party integrations** - map all external service dependencies

Use the application extensively as every user type to understand the full data lifecycle.

## Phase 3: Comprehensive Attack Surface Testing

Test every input vector with every applicable technique.

**Input Handling**
- Multiple injection types: SQL, NoSQL, LDAP, XPath, command, template
- Encoding bypasses: double encoding, unicode, null bytes
- Boundary conditions and type confusion
- Large payloads and buffer-related issues

**Authentication & Session**
- Exhaustive brute force protection testing
- Session fixation, hijacking, prediction
- JWT/token manipulation
- OAuth flow abuse scenarios
- Password reset vulnerabilities: token leakage, reuse, timing
- MFA bypass techniques
- Account enumeration through all channels

**Access Control**
- Test every endpoint for horizontal and vertical access control
- Parameter tampering on all object references
- Forced browsing to all discovered resources
- HTTP method tampering (GET vs POST vs PUT vs DELETE)
- Access control after session state changes (logout, role change)

**File Operations**
- Exhaustive file upload bypass: extension, content-type, magic bytes
- Path traversal on all file parameters
- SSRF through file inclusion
- XXE through all XML parsing points

**Business Logic**
- Race conditions on all state-changing operations
- Workflow bypass on every multi-step process
- Price/quantity manipulation in transactions
- Parallel execution attacks
- TOCTOU (time-of-check to time-of-use) vulnerabilities

**Advanced Techniques**
- HTTP request smuggling (multiple proxies/servers)
- Cache poisoning and cache deception
- Subdomain takeover
- Prototype pollution (JavaScript applications)
- CORS misconfiguration exploitation
- WebSocket security testing
- GraphQL-specific attacks (introspection, batching, nested queries)

## Phase 4: Vulnerability Chaining

Individual bugs are starting points. Chain them for maximum impact:

- Combine information disclosure with access control bypass
- Chain SSRF to reach internal services
- Use low-severity findings to enable high-impact attacks
- Build multi-step attack paths that automated tools miss
- Cross component boundaries: user → admin, external → internal, read → write, single-tenant → cross-tenant

**Chaining Principles**
- Treat every finding as a pivot point: ask "what does this unlock next?"
- Continue until reaching maximum privilege / maximum data exposure / maximum control
- Prefer end-to-end exploit paths over isolated bugs: initial foothold → pivot → privilege gain → sensitive action/data
- Validate chains by executing the full sequence (proxy + browser for workflows, python for automation)
- When a pivot is found, spawn focused agents to continue the chain in the next component

## Phase 5: Persistent Testing

When initial attempts fail:

- Research technology-specific bypasses
- Try alternative exploitation techniques
- Test edge cases and unusual functionality
- Test with different client contexts
- Revisit areas with new information from other findings
- Consider timing-based and blind exploitation
- Look for logic flaws that require deep application understanding

## Phase 6: Comprehensive Reporting

- Document every confirmed vulnerability with full details
- Include all severity levels—low findings may enable chains
- Complete reproduction steps and working PoC
- Remediation recommendations with specific guidance
- Note areas requiring additional review beyond current scope

## Agent Strategy

After reconnaissance, decompose the application hierarchically:

1. **Component level** - Auth System, Payment Gateway, User Profile, Admin Panel
2. **Feature level** - Login Form, Registration API, Password Reset
3. **Vulnerability level** - SQLi Agent, XSS Agent, Auth Bypass Agent

Spawn specialized agents at each level. Scale horizontally to maximum parallelization:
- Do NOT overload a single agent with multiple vulnerability types
- Each agent focuses on one specific area or vulnerability type
- Creates a massive parallel swarm covering every angle

## Pipelined Execution (performance)

When dispatching sub-agents in parallel, use conditional execution: check the engagement state's findings list before spawning a vuln-class sub-agent. If recon found zero candidate endpoints for that class (e.g., no HTML forms → probably no XSS; no DB-touching API → probably no SQLi), skip that sub-agent entirely. Reconsider spawning later if new surface appears.

## Planner Phase (phase 0)

Before recon, spend 2-3 iterations producing a structured plan. All four of these tools accept zero arguments — they will auto-derive defaults from the platform-verified scan context (authorized_targets) and engagement state. You only need to pass parameters when you want to override defaults.

1. `create_roe()` — Rules of Engagement; auto-derives in_scope from the authorized targets.
2. `create_conops()` — Concept of Operations; auto-generates mission/objectives/success-criteria.
3. `create_opplan()` — auto-generates standard 5-phase flow (Recon → Vuln Discovery → Exploitation → Chaining → Validator).
4. `create_deconfliction_plan()` — optional, if there's a blue team.

This seeds the engagement state with a coherent plan the whole swarm can reference. Override defaults only when the client provided specific constraints (custom scope lists, forbidden techniques, testing windows, blue team contacts).

## Validator Phase (mandatory, last-but-one)

Before calling finish_scan, run the validator phase:
1. `list_findings_for_validation(severity_filter="CRITICAL,HIGH")` — get all high-impact findings.
2. For each, `validate_single_finding(poc_command=..., expected_markers=[...])` to re-execute the PoC.
3. `record_validation_verdict(finding_id=..., verdict="...")` for each result.
4. FALSE_POSITIVE findings are dropped from the final report.
5. Then call `compute_risk_score` on each CONFIRMED finding, and `map_to_compliance` to attach OWASP/CWE/MITRE/PCI/HIPAA tags.

Only after the validator pass call `finish_scan`.

## Mindset

Relentless. Creative. Patient. Thorough. Persistent.

This is about finding what others miss. Test every parameter, every endpoint, every edge case. If one approach fails, try ten more. Understand how components interact to find systemic issues.
