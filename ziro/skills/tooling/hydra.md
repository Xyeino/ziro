---
name: hydra
description: Fast network brute-force tool supporting 50+ protocols including SSH, FTP, HTTP, SMB, RDP, databases.
---

# Hydra CLI Playbook

Official docs:
- https://github.com/vanhauser-thc/thc-hydra

Canonical syntax:
`hydra [options] <target> <protocol>`

Key flags:
- `-l <login>` single username
- `-L <file>` username list
- `-p <pass>` single password
- `-P <file>` password list
- `-C <file>` colon-separated user:pass file
- `-t <tasks>` parallel connections (default 16)
- `-w <secs>` max wait for response
- `-f` stop after first valid pair found
- `-F` stop after first valid pair on any host
- `-v` verbose output
- `-o <file>` output file
- `-s <port>` custom port
- `-S` use SSL
- `-e nsr` try null password (n), login as pass (s), reversed login (r)

Supported protocols:
ssh, ftp, http-get, http-post-form, https-get, https-post-form, smb, rdp, vnc, mysql, postgres, mssql, oracle, mongodb, redis, telnet, smtp, pop3, imap, ldap, snmp

Agent-safe baseline:
`hydra -l admin -P /home/pentester/wordlists/common_passwords.txt -t 4 -w 10 -f -o hydra_results.txt <target> <protocol>`

Common patterns:
- SSH brute-force:
  `hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 -f -o ssh_brute.txt <target> ssh`
- HTTP POST form login:
  `hydra -l admin -P passwords.txt <target> http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials" -f -o http_brute.txt`
- HTTP Basic Auth:
  `hydra -l admin -P passwords.txt <target> http-get /admin -f`
- FTP:
  `hydra -L users.txt -P passwords.txt -t 4 -f <target> ftp`
- MySQL:
  `hydra -l root -P passwords.txt -t 4 -f <target> mysql`
- Multiple targets:
  `hydra -L users.txt -P passwords.txt -M targets.txt ssh -t 4 -f`

HTTP form syntax:
`http-post-form "/path:USER_FIELD=^USER^&PASS_FIELD=^PASS^:FAILURE_STRING"`
- `^USER^` replaced with username
- `^PASS^` replaced with password
- `FAILURE_STRING` text that appears on failed login
- Use `S=SUCCESS_STRING` to match successful login instead

Rate limiting:
- Use `-t 1-4` for sensitive targets
- Add `-w 15` for slow servers
- Use `-e nsr` before brute-force (checks common weak creds first)

Important:
- Always use `-f` to stop on first success
- Keep `-t` low (1-4) to avoid lockouts
- Check for account lockout policies first
- Use targeted wordlists, not massive ones
