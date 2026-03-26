---
name: django
description: Security testing playbook for Django applications covering ORM injection, admin panel, middleware bypass, and session security
---

# Django

Security testing for Django applications. Focus on ORM bypass via raw/extra queries, admin panel exposure, middleware ordering flaws, session serialization, and DRF permission gaps.

## Attack Surface

**Core Components**
- URL routing: `urlpatterns`, `path()`, `re_path()`, namespace resolution, versioned APIs
- Middleware stack: `SecurityMiddleware`, `CsrfViewMiddleware`, `SessionMiddleware`, `ClickjackingMiddleware`, `AuthenticationMiddleware`
- Views: function-based with decorators, class-based views (CBVs) with mixins, `ViewSet` (DRF)
- Admin site: `django.contrib.admin`, custom admin views, admin actions

**Data Handling**
- ORM: QuerySet API, `.extra()`, `.raw()`, `RawSQL()`, `connection.cursor()`
- Forms: `ModelForm`, `Form`, validators, `cleaned_data`, file upload handlers
- Serializers (DRF): `ModelSerializer`, `Serializer`, nested serializers, field-level validation
- Templates: Django template engine, Jinja2 backend

**Channels**
- HTTP (sync), ASGI with Django Channels (WebSocket, background workers)
- Management commands, Celery tasks

**Deployment**
- WSGI (Gunicorn/uWSGI), ASGI (Daphne/Uvicorn), Nginx/Apache reverse proxy, static file serving

## High-Value Targets

- `/admin/` panel and all sub-paths, custom admin views, admin actions (bulk delete, export)
- `DEBUG=True` in production: full tracebacks, SQL queries, settings exposure via error pages
- `SECRET_KEY` exposure: session forgery, signed cookie tampering, password reset token crafting
- DRF browsable API (`/api/?format=api`), schema endpoints (`/api/schema/`, `/api/docs/`)
- File upload endpoints, media file serving, `MEDIA_ROOT` directory listing
- Password reset flow (`/accounts/password_reset/`), email-based token endpoints
- Django Channels WebSocket consumers
- Management command endpoints exposed via admin or custom views

## Reconnaissance

**Debug Page Mining**
```
GET /nonexistent-path/  (triggers 404 with full URL map when DEBUG=True)
GET /trigger-error/     (500 page reveals settings, installed apps, middleware)
```

When `DEBUG=True`, the 404 page lists every registered URL pattern. The 500 page shows `settings`, SQL queries, local variables, and full stack traces.

**Admin Discovery**
```
GET /admin/
GET /admin/login/
GET /django-admin/
GET /management/
GET /admin/doc/         (admindocs app)
```

**DRF Endpoints**
```
GET /api/
GET /api/?format=json
GET /api/schema/
GET /api/docs/
GET /api/swagger/
```

**Version Detection**
- `X-Frame-Options` header presence (default since 1.10)
- Admin page HTML source contains Django version in comments/meta
- Error pages explicitly show Django version when `DEBUG=True`

## Key Vulnerabilities

### Configuration Exposure

**DEBUG=True in Production**
- Full tracebacks with source code, local variables, SQL queries
- 404 page reveals all URL patterns (complete route map)
- Settings module partially visible in error context
- Technical 500 emails may be sent to `ADMINS` with sensitive data

**SECRET_KEY Leakage**
- Hardcoded in `settings.py` committed to version control
- Exposed via `DEBUG=True` error pages, environment variable dumps
- Impact: forge session cookies, CSRF tokens, password reset tokens, signed cookies
- Reconstruct: `django.core.signing.dumps()` / `loads()` for arbitrary signed data

**ALLOWED_HOSTS Bypass**
- Empty or wildcard `ALLOWED_HOSTS` enables Host header poisoning
- Password reset emails use `Host` header for link generation
- Cache poisoning via crafted `Host` values

### ORM Injection

**Raw Query Injection**
- `Model.objects.raw("SELECT * FROM t WHERE id = %s" % user_input)` — direct interpolation
- `connection.cursor().execute()` with string formatting instead of parameterized queries
- `RawSQL()` expressions passed to `.annotate()` or `.filter()`

**Extra/Annotate Injection**
- `.extra(where=["field = '%s'" % input])` — deprecated but still widely used
- `.extra(select={"val": "..."})` with user-controlled SQL fragments
- `Func()`, `Value()`, `RawSQL()` in complex annotations without parameterization

**Filter Injection**
- Dynamic filter kwargs from user input: `Model.objects.filter(**request.GET.dict())` allows `field__startswith`, `field__regex`, relation traversal
- JSON field lookups with crafted keys

### Admin Panel

**Brute Force**
- No rate limiting on `/admin/login/` by default
- Username enumeration via timing differences or error messages

**Permission Escalation**
- `is_staff` grants admin access; fine-grained `ModelAdmin` permissions often misconfigured
- Custom admin actions without proper `has_permission()` checks
- Inline models exposing related data beyond intended scope
- Admin log (`/admin/log/`) revealing sensitive operation history

### CSRF Bypass

**Middleware Gaps**
- `@csrf_exempt` decorator on views handling sensitive operations
- Missing `CsrfViewMiddleware` in `MIDDLEWARE` list
- CSRF not enforced on AJAX with missing `X-CSRFToken` header config
- Subdomain cookie injection when `CSRF_COOKIE_DOMAIN` is too broad

**Token Handling**
- CSRF token rotation issues with caching proxies
- `CSRF_TRUSTED_ORIGINS` overly permissive patterns

### Session Security

**Cookie-Based Sessions**
- `django.contrib.sessions.backends.signed_cookies`: client-side sessions signed with `SECRET_KEY`
- If `SECRET_KEY` is compromised, arbitrary session data can be forged
- `SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'` enables RCE via deserialization

**Session Fixation**
- Missing `session.cycle_key()` after authentication
- `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE` misconfigs

### Template Injection

**Django Templates**
- Autoescaping bypass via `|safe`, `{% autoescape off %}`, `mark_safe()`
- User-controlled template strings passed to `Template()` constructor (rare but critical)
- Custom template tags with unsafe rendering

**Jinja2 Backend**
- If Jinja2 is configured as template backend, SSTI applies: `{{config}}`, `{{''.__class__.__mro__}}`
- Autoescape may not be enabled by default depending on configuration

### File Upload

**Path Traversal**
- `FileField`/`ImageField` with user-controlled `upload_to` path components
- Directory traversal in filename: `../../etc/passwd`
- Symlink attacks in `MEDIA_ROOT`

**Content Validation**
- Missing file type validation beyond extension checking
- `ImageField` validates image headers but content can still be malicious
- Oversized uploads without `FILE_UPLOAD_MAX_MEMORY_SIZE` limits

### Django REST Framework

**Authentication Issues**
- `DEFAULT_AUTHENTICATION_CLASSES` not set globally (views default to session + basic)
- `TokenAuthentication` tokens never expire unless custom rotation implemented
- `SessionAuthentication` in DRF without CSRF enforcement on unsafe methods
- JWT libraries (`djangorestframework-simplejwt`): algorithm confusion, weak secrets

**Permission Gaps**
- `DEFAULT_PERMISSION_CLASSES` set to `AllowAny` globally
- `IsAuthenticated` without object-level permissions (`has_object_permission`)
- Custom permissions with logic errors in `has_permission` vs `has_object_permission`
- ViewSet actions (`@action`) missing explicit `permission_classes`

**Serializer Exploits**
- `ModelSerializer` exposing unintended fields (check `fields = '__all__'`)
- Nested writable serializers enabling mass assignment on related models
- `read_only_fields` bypassed via explicit field declaration
- `.validated_data` containing extra fields when `extra_kwargs` not strict

### Clickjacking

- Missing `X_FRAME_OPTIONS` setting or set to `SAMEORIGIN` when `DENY` is needed
- `@xframe_options_exempt` on sensitive views
- CSP `frame-ancestors` not deployed alongside X-Frame-Options

## Bypass Techniques

- Trailing slash differences: `/api/users` vs `/api/users/` (Django's `APPEND_SLASH` may create redirect loops or bypass middleware)
- Method override: some middleware only checks specific HTTP methods
- Content-type switching between `application/json` and `multipart/form-data` for DRF
- Unicode normalization in URL paths affecting URL routing vs middleware matching
- `@csrf_exempt` combined with session auth for CSRF-free state-changing operations

## Testing Methodology

1. **Enumerate** — Trigger DEBUG 404 for URL map, discover admin/DRF/schema endpoints
2. **Config audit** — Check DEBUG, SECRET_KEY, ALLOWED_HOSTS, CSRF settings, session backend
3. **ORM analysis** — Grep for `.raw()`, `.extra()`, `RawSQL`, `cursor.execute()`, string formatting in queries
4. **Admin probe** — Test admin access, permissions, custom actions, inline exposure
5. **DRF matrix** — Test each ViewSet action across unauth/user/admin, check permission_classes per action
6. **Session testing** — Verify serializer (JSON vs Pickle), cookie flags, session cycling on auth

## Validation Requirements

- DEBUG exposure: screenshot or response body showing tracebacks, URL patterns, settings
- ORM injection: crafted input producing SQL error or unauthorized data via `.raw()`/`.extra()`
- Admin bypass: non-admin user accessing admin views or performing admin actions
- CSRF bypass: cross-origin request succeeding against `@csrf_exempt` or misconfigured endpoint
- Session forgery: crafted signed cookie accepted by the application (requires SECRET_KEY)
- DRF permission gap: request to ViewSet action succeeding without required authorization
- Mass assignment: writable serializer accepting fields that should be read-only
