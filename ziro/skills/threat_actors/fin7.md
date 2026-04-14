---
name: fin7
description: FIN7 (Carbanak-adjacent) — financially motivated cybercrime syndicate, point-of-sale and hospitality sector specialists, also ransomware affiliates
aliases: [carbon_spider, carbanak_group, sangria_tempest, goldbeeetle]
attribution: Russian-speaking cybercrime, corporate-structured
primary_motivation: financial
sophistication: high
initial_access: [T1566.001, T1566.003, T1195.002, T1199, T1189]
execution: [T1059.001, T1059.003, T1059.005, T1204.002, T1059.007]
persistence: [T1547.001, T1053.005, T1543.003, T1574.002, T1505.003]
privilege_escalation: [T1055, T1548.002, T1068]
defense_evasion: [T1027, T1036.005, T1070.004, T1562.001, T1218.005, T1140]
credential_access: [T1003.001, T1555, T1552, T1056.001]
discovery: [T1087, T1018, T1082, T1016, T1057]
lateral_movement: [T1021.001, T1021.002, T1570]
collection: [T1005, T1074.001, T1560.001, T1056.002]
command_and_control: [T1071.001, T1105, T1573.002, T1090]
exfiltration: [T1041, T1567.002]
impact: [T1486, T1489]
preferred_tools: [carbanak, bateleur, halfbaked, powerplant, tirion, griffon, cobalt_strike, loki_bot, boostwrite]
---

# FIN7 (Carbanak-adjacent)

**When simulating FIN7, think organized cybercrime: professional spearphishing operation, custom malware families, and patient monetization through PoS/payment card theft or ransomware affiliation.**

## Operator Style

FIN7 operates with corporate rigor — they ran a fake front company ("Combi Security") to recruit pentesters. They deliver weaponized documents via targeted phishing at specific industries (hospitality, restaurants, casinos, gaming), then install custom backdoors (Carbanak, Bateleur, Griffon) and pivot to PoS systems or high-value data.

Post-2018 arrests, FIN7 split into overlapping subgroups and some members joined ALPHV/BlackCat and Darkside ransomware operations.

## Initial Access Playbook

1. **Phishing with weaponized Office documents** (T1566.001) — INI file tricks, DDE exploitation, embedded VBA/macros
2. **USB drops** (T1566.003) — USB Ninja and BadUSB devices mailed to executives posing as Best Buy gift cards
3. **Compromise of MSPs and hospitality software vendors** (T1195.002)
4. **Hospitality chain SaaS** — credential stuffing against property management systems
5. **Watering hole** on industry-specific sites

## Post-Compromise Priorities

**PoS theft track:**
- Memory scraping of PoS terminals (T1056.002)
- Deploy Griffon JS backdoor on retail networks
- Harvest Track 1/2 credit card data via HalfBaked
- Exfiltrate to controlled infrastructure for carding marketplaces

**Ransomware track (post-split):**
- Full AD enumeration and Cobalt Strike deployment
- Dump credentials, map Tier-0 infrastructure
- Deploy ALPHV/BlackCat or Darkside with double extortion
- Exfiltrate critical business data before encryption

## Custom Malware

- **Carbanak** — backdoor for reconnaissance and C2
- **Bateleur** — JavaScript backdoor delivered via macro documents
- **HalfBaked** — PowerShell-based RAT
- **Griffon** — small JS backdoor for Magecart-style web skimming
- **Tirion / POWERPLANT** — PowerShell post-exploitation frameworks
- **BoostWrite** — DLL loader abusing Invoke-Obfuscation
- **Loki Bot** — commodity stealer for second-stage credential theft

## Operational Characteristics

- Targeted phishing templates highly customized per victim industry
- Heavy use of LOLBAS: `mshta.exe`, `rundll32.exe`, `wscript.exe`, `cscript.exe`
- Persistence via Office templates and Outlook home page (T1137)
- Timestomping on all dropped files
- Pivots via RDP, SMB, PsExec once inside

## Simulation Notes for Ziro

- For **retail/hospitality targets**: focus on PoS network segmentation, PCI scope, payment processor communication, memory protection on terminals
- For **enterprise simulation**: Office macro security, mail gateway sandboxing, JS/HTA download controls
- Credential access via LSASS and browser stores (not just AD)
- Include **email collection + IP theft** in findings — FIN7 always exfiltrates business intelligence alongside payment data
- Test detection of USB HID injection (BadUSB family)

## References

- MITRE ATT&CK group G0046: https://attack.mitre.org/groups/G0046/
- DOJ indictments (2018) of FIN7 leadership in Combi Security front company
- Mandiant FIN7 evolution reports
- CrowdStrike Carbon Spider profile
