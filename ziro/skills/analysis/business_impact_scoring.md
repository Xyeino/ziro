---
name: business_impact_scoring
description: Assess business impact of vulnerabilities beyond CVSS — data sensitivity, blast radius, compliance, revenue risk
---

# Business Impact Scoring

CVSS measures technical severity. Business impact scoring measures real-world consequences. Always provide both when reporting vulnerabilities.

## Impact Dimensions

### Data Sensitivity (weight: 30%)
Score 1-5 based on what data is at risk:

| Score | Data Type | Examples |
|-------|-----------|---------|
| 5 | PII / Financial / Health | Credit cards, SSNs, medical records, passwords |
| 4 | Authentication / Secrets | API keys, tokens, session data, private keys |
| 3 | Business Confidential | Internal docs, pricing, customer lists, contracts |
| 2 | Internal Operational | Logs, configs, non-sensitive user data |
| 1 | Public / Non-sensitive | Marketing content, public profiles |

### Blast Radius (weight: 25%)
How many users/systems are affected:

| Score | Scope |
|-------|-------|
| 5 | All users / entire platform |
| 4 | Major segment (>25% users, critical service) |
| 3 | Moderate segment (specific feature, department) |
| 2 | Limited (single user class, non-critical service) |
| 1 | Isolated (single account, test environment) |

### Exploitability in Context (weight: 20%)
How easy to exploit in THIS specific deployment:

| Score | Context |
|-------|---------|
| 5 | Unauthenticated, internet-facing, no WAF, trivial exploit |
| 4 | Authenticated but low-privilege, public endpoint |
| 3 | Requires specific conditions or chained exploit |
| 2 | Internal network only, or requires high-privilege |
| 1 | Requires physical access or extremely unlikely conditions |

### Compliance & Regulatory (weight: 15%)
Regulatory exposure if exploited:

| Score | Impact |
|-------|--------|
| 5 | PCI-DSS / HIPAA / GDPR breach — mandatory disclosure, fines |
| 4 | SOC2 / ISO27001 audit failure |
| 3 | Industry-specific regulation risk |
| 2 | Internal policy violation |
| 1 | No regulatory impact |

### Revenue & Reputation (weight: 10%)
Direct business damage:

| Score | Impact |
|-------|--------|
| 5 | Service outage, direct revenue loss, public breach disclosure |
| 4 | Customer churn risk, partner trust damage |
| 3 | Feature degradation, support cost increase |
| 2 | Minor UX impact, internal productivity loss |
| 1 | Negligible business impact |

## Calculating Business Impact Score

```
BIS = (data × 0.30) + (blast × 0.25) + (exploit × 0.20) + (compliance × 0.15) + (revenue × 0.10)
```

Map to business risk level:
- **4.0 - 5.0** → CRITICAL BUSINESS RISK — immediate executive escalation
- **3.0 - 3.9** → HIGH BUSINESS RISK — fix within current sprint
- **2.0 - 2.9** → MEDIUM BUSINESS RISK — schedule for next release
- **1.0 - 1.9** → LOW BUSINESS RISK — backlog

## How to Apply

When creating a vulnerability report, ALWAYS include business impact assessment in the `impact` field:

```
Technical Impact: [from CVSS]
Business Impact Score: [X.X] — [CRITICAL/HIGH/MEDIUM/LOW] BUSINESS RISK
  - Data Sensitivity: [score] — [reasoning]
  - Blast Radius: [score] — [reasoning]
  - Exploitability: [score] — [reasoning]
  - Compliance: [score] — [reasoning]
  - Revenue: [score] — [reasoning]
Priority: [based on combined CVSS + BIS]
```

## Context Inference

When target context is unknown, infer from observable signals:
- Login/signup forms → user PII likely present
- Payment endpoints → financial data (PCI-DSS scope)
- `/api/admin` → high-privilege operations
- Health/medical terms in endpoints → HIPAA scope
- EU-targeted site (GDPR cookie banners) → GDPR scope
- `.gov` domains → government compliance requirements

## Priority Matrix

| CVSS | BIS | Action |
|------|-----|--------|
| Critical + Critical | P0 — Drop everything |
| Critical + Low | P1 — Urgent but contained |
| Low + Critical | P1 — Technical minor, business major |
| Low + Low | P3 — Backlog |

The key insight: a LOW-CVSS IDOR on a payment endpoint (BIS: Critical) is MORE urgent than a HIGH-CVSS XSS on a marketing page (BIS: Low).
