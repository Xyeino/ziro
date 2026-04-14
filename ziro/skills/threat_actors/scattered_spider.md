---
name: scattered_spider
description: Scattered Spider (UNC3944 / Octo Tempest / 0ktapus) — English-speaking financially motivated group, social engineering masters, ransomware affiliates
aliases: [unc3944, octo_tempest, 0ktapus, muddled_libra, scatter_swine, lapsus_adjacent]
attribution: Loose collective, primarily US/UK young adults
primary_motivation: financial
sophistication: medium_high
initial_access: [T1566.004, T1621, T1078.004, T1199, T1189]
execution: [T1059.001, T1059.003, T1059.006, T1569.002]
persistence: [T1098.001, T1136.003, T1556.006, T1505.003]
privilege_escalation: [T1098.001, T1134, T1078.004]
defense_evasion: [T1562.001, T1562.002, T1112, T1027.004, T1070.004]
credential_access: [T1621, T1556.006, T1539, T1555, T1552.001]
discovery: [T1087.004, T1069.003, T1518, T1526, T1580]
lateral_movement: [T1021.001, T1021.007, T1021.004, T1550.004]
collection: [T1114.002, T1530, T1213.002]
command_and_control: [T1071.001, T1219, T1090.002]
exfiltration: [T1567.002, T1537]
impact: [T1486, T1485, T1490]
preferred_tools: [anydesk, teamviewer, ngrok, chisel, mimikatz, rclone, alphv_blackcat, dragonforce]
---

# Scattered Spider (UNC3944)

**When simulating Scattered Spider, social engineering IS the attack surface. Technical exploits are minor compared to voice phishing and MFA fatigue.** Always start with human targeting.

## Operator Style

Scattered Spider are native English speakers with deep cultural fluency. They dominate **help desk voice phishing (vishing)**, SIM swapping, MFA push bombing, and Okta/Azure AD abuse. They ransomware via ALPHV/BlackCat or DragonForce affiliates after extensive data theft.

Target profile: large enterprises with outsourced IT help desks, BPO call centers, and complex SSO integrations.

## Signature Initial Access

1. **Help desk vishing** (T1566.004) — call IT, impersonate executive or IT admin, request MFA reset or password reset with plausible backstory
2. **MFA fatigue / push bombing** (T1621) — flood victim with push notifications until they approve
3. **Valid accounts via prior SIM swap** (T1078.004) — capture SMS MFA codes
4. **Supply chain via IT/BPO partners** (T1199)

Typical vishing script:
> "Hi this is [name] from [IT provider]. I'm troubleshooting a sync issue with your account. I need to push an MFA prompt — can you approve it real quick?"

## Post-Compromise Priorities

- **Okta admin access** — create backdoor apps, push malicious SAML assertions (T1556.006)
- Azure AD Privileged Identity Management abuse
- Snowflake / Salesforce / ServiceNow data theft
- Create persistent identity via service accounts and FIDO2 key enrollment
- Dump SharePoint, OneDrive, Teams chats for sensitive docs

## Tooling (Low Sophistication)

Scattered Spider rarely develops custom malware. They use:

- **AnyDesk / TeamViewer** (T1219) for persistent remote access
- **Ngrok / Chisel** for tunneling
- **Rclone** (T1567.002) for bulk exfiltration to Mega, Dropbox
- **Mimikatz** from legitimate admin context
- **Commercial RMM tools** (Splashtop, ScreenConnect) for stealth

After data theft, deploy **BlackCat/ALPHV** or **DragonForce** ransomware via pre-established admin context.

## OPSEC (Loose)

- They use residential proxies and VPNs, but are often traceable via OPSEC mistakes (personal email reuse, Discord handles, crypto wallet linkability)
- Accept arrests as cost of business; several members have been charged (Caesars, MGM)
- Move fast — full breach to ransomware in 1-7 days

## High-Profile Campaigns

- **MGM Resorts (2023)** — 10-minute vishing → full ransomware → $100M loss
- **Caesars Entertainment (2023)** — $15M ransom paid
- **Twilio (2022)** — Okta tenant compromise via 0ktapus phishing kit
- **Coinbase (2024)** — $20M bounty offered for info on the group

## Simulation Notes for Ziro

- **Purely technical simulation is INCOMPLETE** — note this in findings
- For external attack surface: focus on Okta/Azure AD weaknesses, SSO misconfiguration, SAML abuse
- For insider threat simulation: model post-vishing state — attacker has valid help desk or user credentials + MFA, not pre-auth RCE
- Document whether human-in-the-loop vishing would be added in red team exercise
- Deliverables should explicitly call out **MFA resilience** and **help desk verification procedures** as findings

## References

- MITRE ATT&CK group G1015: https://attack.mitre.org/groups/G1015/
- CISA AA23-320A Scattered Spider advisory
- Microsoft threat intel reports on Octo Tempest
- Mandiant UNC3944 profile
