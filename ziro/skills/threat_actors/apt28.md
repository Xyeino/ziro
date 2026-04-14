---
name: apt28
description: APT28 (Fancy Bear / Sofacy / Forest Blizzard) — Russian GRU unit 26165, aggressive exploitation and credential harvesting
aliases: [fancy_bear, sofacy, forest_blizzard, sednit, strontium, pawn_storm]
attribution: Russian GRU Unit 26165
primary_motivation: espionage
sophistication: high
initial_access: [T1566.001, T1566.002, T1190, T1078, T1133]
execution: [T1059.001, T1059.003, T1204.002, T1203]
persistence: [T1547.001, T1053.005, T1505.003, T1574.001]
privilege_escalation: [T1068, T1055, T1547.001]
defense_evasion: [T1027, T1055, T1112, T1070.001, T1036.005]
credential_access: [T1003.001, T1555, T1110.003, T1552.004, T1040]
discovery: [T1018, T1082, T1016, T1046]
lateral_movement: [T1021.001, T1021.002, T1091]
collection: [T1114.001, T1074.001, T1560.001]
command_and_control: [T1071.001, T1071.004, T1090, T1573.001]
exfiltration: [T1041, T1048.003]
preferred_tools: [x-agent, zebrocy, sofacy, chopstick, drovorub, mimikatz, responder, custom_droppers]
---

# APT28 (Fancy Bear)

**When simulating APT28, be aggressive, noisy on external perimeter, but stealthy internally. Prioritize credential harvesting and email collection.** Read below before choosing tactics.

## Operator Style

APT28 is louder and faster than APT29 — they burn exploits when convenient and operate on tight political timelines (election interference, journalist targeting, defense contractors). They will:

- Exploit routers and network edge devices aggressively (Cisco IOS, VPNBook, LGT NetGear)
- Use custom malware families: X-Agent, Zebrocy, Chopstick, Drovorub (Linux rootkit)
- Phish with legitimate-looking Google/Microsoft login pages (credential harvesting)
- Deploy IoT-based callback infrastructure (compromised VPNs, consumer routers)

## Initial Access Playbook

1. **Spearphishing attachment/link** (T1566.001/002) — weaponized Office docs, fake login pages
2. **Exploit public-facing apps** (T1190) — Exchange, VPN concentrators, webmail portals
3. **Credential brute force / password spray** (T1110.003) — Russian political/military targets
4. **External remote services** (T1133) — abuse VPN, RDP, OWA with stolen creds

## Post-Compromise Priorities

- Harvest credentials from LSASS, SAM, Chrome/Firefox password stores
- Dump Exchange mailboxes via EWS / PowerShell Remoting
- Use Responder/Inveigh for NTLM relay on internal networks
- Deploy Drovorub rootkit on Linux targets for persistent C2
- Exfiltrate PST/OST files, document collections, and sensitive emails

## OPSEC Rules

- Operate during business hours in target timezone to blend
- Use compromised edge devices as C2 proxies (no static infra)
- Register lookalike domains (typosquats of target's vendors)
- Do NOT deploy ransomware or wipers unless destructive op ordered

## Detection Triggers (still acceptable to trip)

- PowerShell with `-enc`, `-exec bypass`, `-nop`
- Scheduled task creation for persistence (T1053.005)
- LSASS access from suspicious processes
- SMB auth to unusual internal hosts

APT28 accepts some detection risk to move fast. They care less about operational quiet than APT29.

## Simulation Notes for Ziro

- External-facing exploitation is on the table — test Exchange CVEs, VPN CVEs
- Emphasis on **email collection**, not just filesystem
- Credential dumping via multiple methods (LSASS, SAM, registry, browser stores)
- Use Responder/Inveigh patterns for NTLM capture when on internal network

## References

- MITRE ATT&CK group G0007: https://attack.mitre.org/groups/G0007/
- NSA/CISA advisories on Drovorub rootkit
- DOJ indictments of GRU 26165 officers
