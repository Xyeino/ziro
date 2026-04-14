---
name: apt29
description: APT29 (Cozy Bear / Nobelium / Midnight Blizzard) — Russian SVR state-sponsored actor, stealth-focused, supply chain and identity abuse
aliases: [cozy_bear, nobelium, midnight_blizzard, the_dukes]
attribution: Russian SVR
primary_motivation: espionage
sophistication: high
initial_access: [T1195.002, T1566.001, T1078.004, T1190, T1199]
execution: [T1059.001, T1569.002, T1204.002]
persistence: [T1098.001, T1136.003, T1556.004, T1078.004]
privilege_escalation: [T1548.002, T1078.004, T1134]
defense_evasion: [T1070.004, T1027, T1140, T1562.008, T1036, T1218]
credential_access: [T1003.001, T1552.004, T1606.002, T1552.005, T1528]
discovery: [T1087.004, T1069.003, T1580, T1083, T1518]
lateral_movement: [T1021.001, T1021.006, T1550.001, T1550.004]
collection: [T1114.002, T1530, T1213.003]
command_and_control: [T1071.001, T1573.002, T1090.002]
exfiltration: [T1567.002, T1048.002]
preferred_tools: [cobalt_strike, sliver, powershell_empire, custom_implants, mimikatz, azurehound]
---

# APT29 (Cozy Bear)

**When simulating APT29, prioritize stealth, long dwell time, and abuse of legitimate cloud identity systems over noisy exploitation.** Read below before choosing tactics.

## Operator Style

APT29 are patient, surgical, and allergic to detection. They rarely burn exploits. Their hallmark is **living off the land** on Windows and Azure/M365, abusing OAuth consent, forged SAML tokens (Golden SAML), and service principals. When they compromise a supply chain, they weaponize it slowly and selectively — SolarWinds sat dormant for months before activation.

- Minimize on-disk artifacts; prefer in-memory PowerShell / reflective DLLs
- Timestomp and wipe event logs only when necessary (log clearing itself is a signal)
- Prefer stolen credentials and OAuth tokens over exploitation
- Use compromised infrastructure (residential proxies, small hosting providers) for C2
- Pace actions to blend with normal user behavior — no rapid-fire tooling

## Initial Access Playbook

1. **Supply chain compromise** (T1195.002) — trojanize a vendor's build pipeline
2. **Password spray / MFA fatigue** (T1110.003, T1621) against M365 tenants
3. **Spearphishing** (T1566.001) with OAuth consent grants instead of malware
4. **Exploitation of public-facing apps** (T1190) only as a last resort — prefer Pulse Secure, Exchange, VPN appliances

## Post-Compromise Priorities

- Dump `ntds.dit` and DC credentials via Volume Shadow Copy (T1003.003)
- Extract refresh tokens from browser profiles (T1539)
- Forge SAML tokens via compromised ADFS signing key (T1606.002 — Golden SAML)
- Create backdoor service principals in Azure AD (T1098.001)
- Mailbox collection via Graph API with stolen OAuth tokens (T1114.002)

## OPSEC Rules

- Do not use Metasploit or widely-signatured payloads
- Randomize beacon intervals (5-60 min), jitter > 50%
- Domain front C2 through CDN edges
- Never use reused infrastructure across campaigns
- Stage tools under `C:\Windows\Temp\` or `C:\ProgramData\` with innocuous names

## Detection Triggers to Avoid

- PsExec, WMIEXEC, remote service creation with odd names
- `mimikatz.exe` binary on disk
- WMI eventsubscription persistence (heavily logged)
- Suspicious OAuth consent requests for high-privilege scopes

## Simulation Notes for Ziro

- Bias towards credential-access and token-theft over RCE
- In cloud environments, focus on Azure AD / M365 (Graph API, service principals)
- Avoid generating `cmd.exe` process trees; use `powershell -enc` and LOLBAS
- Do not drop tooling onto endpoints if it can run from memory

## References

- MITRE ATT&CK group G0016: https://attack.mitre.org/groups/G0016/
- CISA AA21-148A (SolarWinds campaign)
- Mandiant M-Trends reports on Midnight Blizzard
