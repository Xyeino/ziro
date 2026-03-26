---
name: netcat
description: Network toolkit for port checking, banner grabbing, file transfer, and raw TCP/UDP connections.
---

# Netcat CLI Playbook

Available as `nc` or `ncat` in the sandbox.

Canonical syntax:
`nc [options] <host> <port>`

Key flags:
- `-v` verbose
- `-z` scan mode (no data, just check if port open)
- `-w <sec>` timeout
- `-u` UDP mode
- `-l` listen mode
- `-p <port>` local port
- `-n` no DNS resolution
- `-e <cmd>` execute command on connect (ncat only)
- `--ssl` TLS/SSL connection (ncat)

Common patterns:
- Check if port is open:
  `nc -zv <host> <port> -w 3`
- Quick port range check:
  `nc -zv <host> 1-1000 -w 1 2>&1 | grep open`
- Banner grabbing:
  `echo "" | nc -v -w 3 <host> <port>`
- HTTP banner grab:
  `echo -e "HEAD / HTTP/1.1\r\nHost: <host>\r\n\r\n" | nc <host> 80 -w 5`
- HTTPS banner (ncat):
  `echo -e "HEAD / HTTP/1.1\r\nHost: <host>\r\n\r\n" | ncat --ssl <host> 443`
- SMTP check:
  `nc -v <host> 25 -w 5`
- Raw TCP connection:
  `nc <host> <port>`
- UDP connection:
  `nc -u <host> <port>`
- File transfer (receiver):
  `nc -l -p 9999 > received_file`
- File transfer (sender):
  `nc <host> 9999 < file_to_send`
- Listen for incoming connection:
  `nc -lvp 4444`

Security uses:
- Quick port verification without full nmap scan
- Banner grabbing to identify services
- Testing firewall rules
- Verifying reverse shell connectivity
- Raw protocol interaction (SMTP, FTP, HTTP, Redis, etc.)

Protocol interaction examples:
- Redis: `echo "INFO" | nc <host> 6379 -w 3`
- Memcached: `echo "stats" | nc <host> 11211 -w 3`
- FTP: `nc <host> 21 -w 5` then type `USER anonymous`
- MySQL banner: `nc <host> 3306 -w 3`
