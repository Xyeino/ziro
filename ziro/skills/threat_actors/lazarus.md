---
name: lazarus
description: Lazarus Group (Hidden Cobra / APT38 / Diamond Sleet) — North Korean RGB, financially motivated with espionage capability, cryptocurrency theft specialists
aliases: [hidden_cobra, apt38, diamond_sleet, labyrinth_chollima, zinc, bluenoroff, andariel]
attribution: North Korean Reconnaissance General Bureau (RGB)
primary_motivation: [financial, espionage]
sophistication: high
initial_access: [T1566.001, T1566.002, T1195.002, T1190, T1199]
execution: [T1059.001, T1059.003, T1059.007, T1203, T1204]
persistence: [T1547.001, T1053.005, T1574.011, T1546.008, T1543.003]
privilege_escalation: [T1068, T1134.001, T1055.012]
defense_evasion: [T1027.002, T1055, T1070.004, T1140, T1562.001, T1497]
credential_access: [T1003.001, T1539, T1056.001, T1552.001]
discovery: [T1057, T1012, T1518.001, T1082]
lateral_movement: [T1021.002, T1570]
collection: [T1560.001, T1113, T1005]
command_and_control: [T1071.001, T1573.002, T1095, T1105]
impact: [T1565.001, T1486, T1489, T1529]
preferred_tools: [applejeus, bankshot, fallchill, badcall, ratankba, hopligbht, manuscrypt, dtrack]
---

# Lazarus Group (Hidden Cobra / APT38)

**When simulating Lazarus, split personality: espionage side is patient and quiet, financial side (APT38/BlueNoroff) is aggressive and willing to cause destructive impact.** Specify sub-mode in task.

## Operator Style

Lazarus runs multiple parallel sub-units with distinct TTPs:

- **APT38 / BlueNoroff** — financial theft (SWIFT attacks, DeFi/DEX hacks, crypto exchanges)
- **Andariel** — South Korean targets, destructive ops
- **Labyrinth Chollima** — defense/aerospace espionage
- **AppleJeus subcluster** — trojanized crypto trading apps

Known for ingenious supply chain attacks (npm package takeovers, fake job offer lures to crypto devs), destructive wipers when caught, and the longest dwell times in banking sector breaches.

## Initial Access Playbook

1. **Fake job offer phishing** (T1566.001) — LinkedIn recruiter persona sends "coding challenge" ZIP with malicious LNK
2. **Trojanized software** (T1195.002) — cryptocurrency trading apps (AppleJeus, CryptoNeuron), npm packages
3. **Watering hole** on crypto news sites
4. **Exploitation of exchange web portals** (T1190)
5. **Supply chain on CI/CD tools** — CodeCov, PyPI package squatting

## Post-Compromise Priorities

**Financial mode (APT38):**
- SWIFT message tampering to redirect wire transfers
- Hot wallet private key extraction
- DEX/bridge smart contract exploitation with prior code audit access
- Post-theft destructive wipers to hinder forensic recovery

**Espionage mode (G0032):**
- Engineering documents, intellectual property
- Defense contractor project files
- Credential harvesting for lateral movement to air-gapped networks

## OPSEC Rules

- Use stolen code signing certificates (favorites: stolen from Taiwanese/Korean software vendors)
- Custom malware recompiled per campaign to evade signatures
- C2 via hacked WordPress sites and compromised commercial servers
- Time operations to NPRK workday (UTC+09)

## Destructive Capability

When compromise is discovered or mission complete, Lazarus deploys:

- **MBR/VBR wipers** (DestOver, WannaCry-family without worm capability)
- **Ransomware as destructive cover** (masked extortion)
- **Database destruction** on exit

## Simulation Notes for Ziro

- For **crypto exchange / DeFi audits**: focus on smart contract vulnerabilities (reentrancy, oracle manipulation, flash loan), hot wallet key management, admin multisig abuse
- For **defense/aerospace**: traditional Windows AD compromise, engineering workstation focus, blueprint/CAD file collection
- For **supply chain assessment**: CI/CD pipeline, code signing cert protection, dependency integrity
- DO NOT simulate actual destructive payloads in production — replace with neutral indicator file

## References

- MITRE ATT&CK group G0032: https://attack.mitre.org/groups/G0032/
- US Treasury OFAC Lazarus Group designations
- CISA AA20-239A (Hidden Cobra overview)
- Chainalysis reports on Lazarus crypto theft (~$3B+ stolen)
