---
name: security_misconfiguration
description: Security misconfiguration testing for default credentials, missing headers, exposed services, cloud storage, TLS, and debug endpoints (OWASP A02:2025)
---

# Security Misconfiguration

OWASP A02:2025 (up from #5). The most commonly found issue in real assessments. Covers default credentials, unnecessary features, verbose errors, missing hardening, exposed admin interfaces, cloud storage permissions, and TLS weaknesses.

## Attack Surface

**Server Configuration**
- Default credentials on admin panels, databases, message brokers, management interfaces
- Directory listing enabled, backup files accessible, debug endpoints in production
- Unnecessary HTTP methods (TRACE, OPTIONS revealing internal routing)
- Missing rate limiting on authentication and sensitive endpoints

**HTTP Security Headers**
- Missing or misconfigured Content-Security-Policy, X-Frame-Options, HSTS, X-Content-Type-Options
- Permissive CORS (Access-Control-Allow-Origin: *, credentials: true)
- Missing Referrer-Policy, Permissions-Policy

**Cloud & Infrastructure**
- Public S3 buckets, Azure Blob containers, GCS buckets
- Exposed management ports (databases, caches, admin panels)
- Debug/monitoring endpoints accessible without authentication

**TLS/SSL**
- Outdated protocols (TLS 1.0/1.1), weak cipher suites
- Missing certificate validation, expired certificates
- HSTS not configured or with short max-age

## Key Vulnerabilities

### Default Credentials

```bash
# Common admin panels with default creds
# Jenkins: admin/admin or no auth
curl -s https://target.com:8080/api/json
# Tomcat: tomcat/tomcat, admin/admin
curl -u tomcat:tomcat https://target.com:8080/manager/html
# Grafana: admin/admin
curl -X POST https://target.com:3000/api/login -H "Content-Type: application/json" -d '{"user":"admin","password":"admin"}'
# Kibana/Elasticsearch: no auth by default
curl -s https://target.com:9200/_cat/indices
curl -s https://target.com:5601/api/status
# RabbitMQ: guest/guest
curl -u guest:guest https://target.com:15672/api/overview
# MongoDB: no auth by default
mongosh --host target.com --eval "db.adminCommand('listDatabases')"
# Redis: no auth by default
redis-cli -h target.com INFO
```

### Missing Security Headers

```bash
# Comprehensive header check
curl -sI https://target.com | grep -iE '^(strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy|access-control|x-xss|set-cookie)'

# Check specific headers
# HSTS
curl -sI https://target.com | grep -i 'strict-transport-security'
# CSP
curl -sI https://target.com | grep -i 'content-security-policy'
# CORS - test with Origin header
curl -sI -H "Origin: https://evil.com" https://target.com/api/ | grep -i 'access-control'
# Wildcard CORS with credentials (critical misconfiguration)
curl -sI -H "Origin: https://evil.com" https://target.com/api/ | grep -iE 'access-control-allow-(origin|credentials)'

# Cookie flags
curl -sI https://target.com/login | grep -i 'set-cookie' | grep -ivE 'secure|httponly|samesite'
```

### Directory Listing & Exposed Files

```bash
# Directory listing
curl -s https://target.com/ | grep -i "index of"
curl -s https://target.com/images/
curl -s https://target.com/uploads/
curl -s https://target.com/static/

# Backup and config files
for ext in bak old orig save swp swo tmp sql gz tar.gz zip conf cfg env log; do
  curl -so /dev/null -w "%{http_code} %{url_effective}\n" "https://target.com/config.$ext"
  curl -so /dev/null -w "%{http_code} %{url_effective}\n" "https://target.com/backup.$ext"
done

# Common exposed files
for path in .env .git/config .git/HEAD robots.txt sitemap.xml .htaccess web.config wp-config.php.bak server-status server-info phpinfo.php info.php .DS_Store .svn/entries; do
  curl -so /dev/null -w "%{http_code} $path\n" "https://target.com/$path"
done
```

### Cloud Storage Misconfiguration

```bash
# S3 bucket enumeration and permission check
aws s3 ls s3://target-bucket --no-sign-request
aws s3 cp s3://target-bucket/test.txt /tmp/ --no-sign-request
# Check bucket policy
aws s3api get-bucket-policy --bucket target-bucket --no-sign-request
# Check ACL
aws s3api get-bucket-acl --bucket target-bucket --no-sign-request

# GCS bucket check
curl -s "https://storage.googleapis.com/BUCKET_NAME/"
curl -s "https://storage.googleapis.com/storage/v1/b/BUCKET_NAME/iam"

# Azure Blob
curl -s "https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list"
```

### Debug Endpoints in Production

```bash
# Common debug/admin paths
for path in debug trace console actuator actuator/env actuator/health actuator/configprops \
  _debug _profiler __debug__ elmah.axd telescope api-docs swagger-ui swagger.json \
  graphiql graphql/playground adminer phpmyadmin server-status metrics prometheus \
  healthz health ready status/debug pprof/heap debug/vars; do
  code=$(curl -so /dev/null -w "%{http_code}" "https://target.com/$path" 2>/dev/null)
  [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$code https://target.com/$path"
done

# Spring Boot Actuator
curl -s https://target.com/actuator/env | python3 -m json.tool 2>/dev/null | head -50
```

### TLS Misconfiguration

```bash
# testssl.sh comprehensive scan
testssl.sh --vulnerable --headers --protocols --ciphers https://target.com

# Quick protocol check with openssl
for proto in ssl3 tls1 tls1_1; do
  echo | openssl s_client -connect target.com:443 -$proto 2>&1 | grep -q "CONNECTED" && echo "WEAK: $proto supported"
done

# Check cipher suites
nmap --script ssl-enum-ciphers -p 443 target.com

# Certificate details
echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -dates -subject -issuer
```

### Unnecessary HTTP Methods

```bash
# Test for dangerous methods
for method in TRACE TRACK DEBUG CONNECT OPTIONS PUT DELETE PATCH; do
  code=$(curl -so /dev/null -w "%{http_code}" -X "$method" https://target.com/ 2>/dev/null)
  echo "$method: $code"
done

# TRACE method XST (Cross-Site Tracing)
curl -X TRACE https://target.com/ -H "X-Custom: test" 2>/dev/null
```

### Exposed Admin Panels

```bash
# Common admin paths
for path in admin administrator admin.php wp-admin wp-login.php cpanel \
  manager/html admin/login dashboard control panel manage administration; do
  code=$(curl -so /dev/null -w "%{http_code}" "https://target.com/$path" 2>/dev/null)
  [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$code https://target.com/$path"
done
```

## Tools

```bash
# Nuclei misconfiguration templates
nuclei -u https://target.com -t misconfiguration/ -t exposures/ -t default-logins/
# Nikto web server scanner
nikto -h https://target.com
# testssl.sh for TLS analysis
testssl.sh https://target.com
# Mozilla Observatory
curl -s "https://http-observatory.security.mozilla.org/api/v1/analyze?host=target.com" | python3 -m json.tool
```

## Testing Methodology

1. **Service enumeration** - Identify all exposed services, ports, admin interfaces
2. **Default credentials** - Test all management interfaces with common default credentials
3. **Header analysis** - Check security headers on all response types (HTML, API, redirects, errors)
4. **Directory/file exposure** - Scan for listings, backups, configs, version control artifacts
5. **Cloud storage** - Enumerate and test permissions on all cloud storage resources
6. **TLS audit** - Test protocol versions, cipher suites, certificate validity and chain
7. **Debug endpoints** - Probe for actuator, profiler, debug, and monitoring endpoints
8. **CORS validation** - Test with attacker origins, null origin, and credential combinations
9. **HTTP methods** - Verify only necessary methods are enabled per endpoint
10. **Rate limiting** - Confirm rate limits on login, password reset, API endpoints

## Validation

- Demonstrate access using default credentials on any management interface
- Show security headers missing from responses with specific exploitation path (e.g., missing CSP enables XSS)
- Prove cloud storage is publicly readable/writable with evidence of sensitive data
- Document debug endpoints exposing environment variables, configuration, or internal state
- Show TLS weaknesses with specific protocol/cipher downgrade proof

## Impact

- Full application compromise via default credentials on admin panels or databases
- Data exfiltration from publicly accessible cloud storage buckets
- Credential and secret exposure through debug endpoints and environment dumps
- Client-side attacks enabled by missing security headers (XSS, clickjacking, CSRF)
- Man-in-the-middle attacks via weak TLS configuration
