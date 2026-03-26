---
name: flask
description: Security testing playbook for Flask applications covering Werkzeug debugger, Jinja2 SSTI, client-side sessions, and extension misconfigurations
---

# Flask

Security testing for Flask applications. Focus on debug mode RCE, server-side template injection, client-side session tampering, missing security defaults, and extension-specific vulnerabilities.

## Attack Surface

**Core Components**
- Routing: `@app.route`, `Blueprint`, `MethodView`, URL converters, `url_for` generation
- Middleware: WSGI middleware stack, `before_request`/`after_request` hooks, `teardown_request`
- Extensions: Flask-Login, Flask-WTF, Flask-RESTful, Flask-SQLAlchemy, Flask-CORS, Flask-Admin
- Error handlers: `@app.errorhandler`, custom 404/500 pages

**Data Handling**
- Request parsing: `request.args`, `request.form`, `request.json`, `request.files`, `request.data`
- Templates: Jinja2 with autoescape, custom filters/globals, `render_template_string()`
- Sessions: client-side signed cookies (itsdangerous), server-side via Flask-Session
- Database: Flask-SQLAlchemy, raw `db.engine.execute()`, `text()` constructs

**Channels**
- HTTP (sync via WSGI), Flask-SocketIO (WebSocket), Celery background tasks
- CLI commands via `flask` CLI / `@app.cli.command()`

**Deployment**
- Gunicorn/uWSGI behind Nginx, development server (Werkzeug), Docker, serverless (Zappa)

## High-Value Targets

- Werkzeug debugger (`/console`) in production — interactive Python shell (RCE)
- Debug mode error pages revealing source code, local variables, stack traces
- `SECRET_KEY` exposure enabling session forgery and signed data tampering
- Flask-Admin panel (`/admin/`) with default or weak authentication
- Configuration endpoints, health checks leaking `app.config`
- File upload/download endpoints, `send_from_directory` / `send_file` usage
- API endpoints without authentication (Flask-RESTful resources, Blueprint routes)
- `/static/` path with directory traversal potential

## Reconnaissance

**Debug Detection**
```
GET /nonexistent  (check for Werkzeug debugger traceback page)
GET /console      (Werkzeug interactive debugger console)
```

Werkzeug debugger shows interactive traceback with Python eval. If PIN-protected, the PIN can be derived from: `username`, `app.py` absolute path, MAC address, `/etc/machine-id` or `/proc/sys/kernel/random/boot_id`, and `cgroup` data.

**Endpoint Discovery**
```python
# If debug page is accessible, enumerate routes:
app.url_map.iter_rules()
```
- Check for `sitemap.xml`, common API prefixes (`/api/v1/`, `/api/v2/`)
- Flask-Admin: `/admin/`, `/admin/modelview/`
- Flask-RESTful Swagger: `/swagger.json`, `/api/spec`, `/apidocs`

**Configuration Leakage**
- Error pages in debug mode expose `app.config` in local variables
- Environment variables in process dumps: `SECRET_KEY`, `DATABASE_URL`, `SQLALCHEMY_DATABASE_URI`
- `.env` files accessible via path traversal or static file misconfiguration

## Key Vulnerabilities

### Debug Mode RCE

**Werkzeug Debugger**
- Debug mode enables interactive traceback pages with in-browser Python execution
- `/console` endpoint provides direct Python REPL (no auth or PIN-only)
- PIN bypass: deterministic PIN derived from system attributes (machine-id, MAC, username, module path)
- PIN brute-force: no rate limiting, 9-digit numeric PIN

**PIN Derivation Attack**
Required values (obtainable via SSRF, LFI, or info disclosure):
- `getattr(mod, '__file__', None)` — path to `app.py`
- `uuid.getnode()` — MAC address from `/sys/class/net/eth0/address`
- Machine ID from `/etc/machine-id` + `/proc/sys/kernel/random/boot_id`
- `get_machine_id()` cgroup value from `/proc/self/cgroup`

### Jinja2 SSTI

**Template Injection via render_template_string**
```python
# Vulnerable pattern
render_template_string(user_input)
render_template_string("Hello " + name)
```

**Exploitation Chain**
```
{{7*7}}                                          # Detection: outputs 49
{{config}}                                       # Leak Flask config including SECRET_KEY
{{request.environ}}                              # Leak WSGI environment
{{''.__class__.__mro__[1].__subclasses__()}}     # Enumerate available classes
{{cycler.__init__.__globals__['os'].popen('id').read()}}  # RCE
{{url_for.__globals__['__builtins__']['__import__']('os').popen('id').read()}}
```

**Sandbox Escape Vectors**
- `|attr()` filter to bypass dot notation restrictions
- `request|attr('application')|attr('__globals__')` chain
- Hex/unicode encoding to bypass WAF: `\x5f\x5f` for `__`
- `{% for c in ''.__class__.__mro__[1].__subclasses__() %}` iteration to find `subprocess.Popen`

### Session Tampering

**Client-Side Sessions**
- Flask sessions are signed (HMAC) but not encrypted — contents are base64-visible
- Decode without key: `flask-unsign --decode --cookie <cookie_value>`
- With known `SECRET_KEY`: forge arbitrary session data
- `flask-unsign --sign --cookie "{'admin': True}" --secret <key>`

**Weak SECRET_KEY**
- Default/example keys: `'dev'`, `'secret'`, `'changeme'`, `'super-secret-key'`
- Brute-force with `flask-unsign --unsign --wordlist rockyou.txt --cookie <cookie>`
- Key in source control, environment variable leaks, config file exposure

**Pickle Deserialization**
- `SESSION_SERIALIZER` or Flask-Session with pickle backend
- Server-side sessions (Redis/Memcached) using pickle: if session store is writable, RCE via crafted pickle payload
- `itsdangerous` with pickle serializer in custom signed data

### Missing Security Defaults

**No CSRF Protection by Default**
- Flask has no built-in CSRF; requires Flask-WTF `CSRFProtect`
- API endpoints often skip CSRF even when Flask-WTF is installed
- AJAX requests missing `X-CSRFToken` header configuration
- `@csrf.exempt` on sensitive views

**Missing Security Headers**
- No `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options` by default
- Requires Flask-Talisman or manual `after_request` hooks
- `X-XSS-Protection` deprecated but absence may indicate no security hardening at all

**CORS Misconfiguration**
- Flask-CORS with `resources={r"/*": {"origins": "*"}}` — overly permissive
- `supports_credentials=True` with wildcard origins (browser blocks but misconfigured)
- Missing `Access-Control-Allow-Origin` validation per route

### SQL Injection

**Raw Query Patterns**
```python
# Vulnerable
db.engine.execute("SELECT * FROM users WHERE id = %s" % user_id)
db.session.execute(text("SELECT * FROM t WHERE name = '" + name + "'"))

# Safe
db.session.execute(text("SELECT * FROM t WHERE name = :name"), {"name": name})
```

- Flask-SQLAlchemy `text()` with string concatenation
- `.filter()` with string expressions instead of column objects
- `db.engine.execute()` with format strings

### File Handling

**Path Traversal via send_from_directory**
```python
# Vulnerable if filename not sanitized
send_from_directory(upload_dir, request.args['file'])
```
- `werkzeug.utils.secure_filename()` may not be applied
- Null byte injection (older Python): `file.txt%00.jpg`
- `send_file()` with user-controlled absolute paths

**Upload Vulnerabilities**
- No file type validation on `request.files`
- Executable uploads to web-accessible directories
- Filename collision/overwrite attacks
- Missing `MAX_CONTENT_LENGTH` enabling DoS via large uploads

### Blueprint Misconfiguration

**Auth Bypass via Blueprint Isolation**
- `before_request` hooks on app don't apply to separately registered blueprints (depending on registration order)
- Blueprint-level `before_request` missing on some blueprints
- URL prefix collisions between blueprints creating routing ambiguity
- Static file routes per blueprint (`/blueprint/static/`) potentially serving sensitive files

### Flask-Login Issues

**Remember Me Token**
- Weak `REMEMBER_COOKIE_DURATION` or perpetual tokens
- Remember cookie not invalidated on password change
- `user_loader` callback trusting cookie-provided user ID without validation

**Session Protection**
- `LOGIN_DISABLED` config accidentally set in production
- `session_protection` set to `None` instead of `'strong'`

### Configuration Exposure

**app.config Leakage**
- `app.config` accessible via SSTI: `{{config}}`
- Debug error pages showing local variables including config references
- Health/status endpoints returning `app.config.items()`
- `.env` files in webroot served as static files

## Bypass Techniques

- Trailing slash: `/admin` vs `/admin/` (Flask strict_slashes behavior)
- Method override via `?_method=PUT` if `flask-method-override` is installed
- Blueprint URL prefix manipulation to access routes under different auth contexts
- Content-type switching between `application/json` and `application/x-www-form-urlencoded`
- Werkzeug routing edge cases: converter types (`<int:id>` vs `<id>`) accepting unexpected formats

## Testing Methodology

1. **Debug detection** — Check for Werkzeug debugger, console endpoint, verbose error pages
2. **Config extraction** — Attempt SSTI `{{config}}`, check error pages, `.env` file exposure
3. **Session analysis** — Decode session cookie, attempt brute-force of SECRET_KEY, check serializer
4. **SSTI probing** — Test all user-reflected inputs for `{{7*7}}`, `${7*7}`, `#{7*7}` variants
5. **Auth audit** — Map `before_request` hooks per blueprint, check for gaps across route groups
6. **SQL analysis** — Grep for `text()`, `.execute()`, string formatting in query construction
7. **File handling** — Test upload endpoints for traversal, download endpoints for LFI

## Validation Requirements

- Debug RCE: Werkzeug console access or PIN derivation with code execution proof
- SSTI: template injection with output confirmation (`49` for `{{7*7}}`), escalate to config leak or RCE
- Session forgery: crafted session cookie accepted by application with elevated privileges
- SQL injection: crafted input producing error-based or data-exfiltration evidence
- Path traversal: file read outside intended directory via `send_from_directory` or upload path
- Missing CSRF: cross-origin state-changing request succeeding without token
- Config leak: SECRET_KEY or database credentials obtained via any vector
