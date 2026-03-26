---
name: laravel
description: Security testing playbook for Laravel applications covering debug exposure, Eloquent injection, mass assignment, session deserialization, and middleware bypass
---

# Laravel

Security testing for Laravel applications. Focus on debug mode information disclosure, APP_KEY abuse for RCE via deserialization, Eloquent ORM injection, mass assignment, and middleware/route authorization gaps.

## Attack Surface

**Core Components**
- Routing: `routes/web.php`, `routes/api.php`, `Route::resource`, route model binding, named routes
- Middleware: `web` group (session, CSRF), `api` group (throttle), custom middleware, route groups
- Controllers: resource controllers, invokable controllers, form requests, API resources
- Artisan commands: `php artisan`, scheduled tasks, queue workers

**Data Handling**
- Eloquent ORM: query builder, `whereRaw()`, `DB::raw()`, `DB::select()`, model events
- Blade templates: `{{ }}` (escaped), `{!! !!}` (raw), `@php` directive, components
- Validation: form requests, `Validator::make()`, custom rules, conditional validation
- File storage: `Storage` facade, public/private disks, `storage:link` symlink

**Channels**
- HTTP (web + API routes), WebSocket (Laravel Echo / Pusher / Reverb), queued jobs (Redis/SQS/database)
- Broadcasting: channels, presence channels, private channels

**Deployment**
- Apache/Nginx with PHP-FPM, Laravel Forge, Vapor (serverless), Docker, shared hosting

## High-Value Targets

- Debug mode (`APP_DEBUG=true`): Ignition error page with full stack traces, environment variables, SQL queries
- `.env` file exposure via web server misconfiguration or path traversal
- `APP_KEY` extraction: enables session/cookie forgery and deserialization RCE
- Telescope dashboard (`/telescope`): request/response logs, queries, jobs, exceptions
- Horizon dashboard (`/horizon`): Redis queue monitoring, job payloads
- Laravel Nova / Filament admin panels
- `storage/logs/laravel.log`: leaked stack traces, user data, tokens
- Password reset, email verification, and OAuth endpoints

## Reconnaissance

**Debug Page Detection**
```
GET /nonexistent                 (triggers Ignition error page if APP_DEBUG=true)
GET /_ignition/health-check      (Ignition health check endpoint)
GET /_ignition/execute-solution   (Ignition RCE in older versions — CVE-2021-3129)
```

Ignition error pages expose: full stack trace, request data, environment variables (including `APP_KEY`, `DB_PASSWORD`, mail credentials), SQL queries, session data, and application source code.

**File/Config Discovery**
```
GET /.env                    (direct .env exposure)
GET /.env.backup
GET /storage/logs/laravel.log
GET /public/.env
GET /config/app.php          (if misconfigured document root)
GET /vendor/autoload.php     (path traversal indicator)
```

**Route Enumeration**
```bash
# If Artisan access is possible
php artisan route:list --json
```
- Check for `api/` prefix routes without auth middleware
- Test `/telescope`, `/horizon`, `/nova`, `/filament` admin dashboards
- Fuzz common resource routes: `/api/users`, `/api/admin/users`, `/api/settings`

## Key Vulnerabilities

### Debug Mode Exposure (APP_DEBUG=true)

**Ignition Error Page**
- Full stack traces with source code context (file paths, line numbers)
- Environment variables displayed: `APP_KEY`, `DB_PASSWORD`, `MAIL_PASSWORD`, `AWS_SECRET_ACCESS_KEY`
- Request/response details: headers, cookies, session data
- SQL queries executed during the request
- Application root path revealed

**Ignition RCE (CVE-2021-3129)**
- `/_ignition/execute-solution` endpoint allows arbitrary file write
- Chain: log file clearing → phar deserialization → RCE
- Affects `facade/ignition < 2.5.2`

### APP_KEY Extraction and Abuse

**APP_KEY as Master Key**
- Used to sign/encrypt sessions, cookies, CSRF tokens, and any `Crypt::encrypt()` data
- Exposed via: debug pages, `.env` file disclosure, version control, backup files

**Deserialization RCE via APP_KEY**
```php
// Laravel encrypts session cookies with APP_KEY
// Attacker crafts serialized PHP payload, encrypts with known APP_KEY
// Server deserializes the cookie → RCE
```

- Craft gadget chain (e.g., via `phpggc`): `Laravel/RCE1` through `Laravel/RCE16`
- Encrypt payload with APP_KEY using Laravel's encrypter
- Send as session cookie → triggers `unserialize()` → RCE

**Cookie Forgery**
- With APP_KEY: decrypt any encrypted cookie, forge session with arbitrary user ID
- Impersonate any user by crafting session cookie with target user's session data

### Blade Template Injection

**Raw Output**
```php
{!! $userInput !!}     // Unescaped output — XSS if user-controlled
{!! Str::markdown($bio) !!}  // Markdown rendering may allow HTML injection
```

- `{!! !!}` used for "trusted" HTML — verify all sources are actually trusted
- `@php` directive in user-controlled template content (rare but critical)
- Component attributes with raw rendering

**Dynamic Template Rendering**
```php
// Vulnerable: user input rendered as Blade template
Blade::render($userControlledString);
view()->make($userControlledView);
```

### Eloquent ORM Injection

**Raw Query Methods**
```php
// Vulnerable patterns
User::whereRaw("name = '" . $request->name . "'")->get();
DB::raw("CASE WHEN " . $input . " THEN 1 ELSE 0 END");
DB::select("SELECT * FROM users WHERE id = " . $id);
DB::statement("DROP TABLE " . $table);
User::where('name', 'LIKE', $request->search)->get();  // safe, but...
User::whereRaw('name LIKE ' . $request->search)->get(); // injectable
```

**Query Builder Injection**
- `orderByRaw()`, `groupByRaw()`, `havingRaw()`, `selectRaw()` with user input
- `DB::raw()` inside `where()`, `select()`, `join()` clauses
- Column name injection: `User::where($request->field, $value)` — attacker controls column name

**JSON Column Injection**
```php
// PostgreSQL: User input in JSON path
User::where("metadata->" . $request->key, $value)->get();
```

### Mass Assignment

**Unprotected Models**
```php
// Vulnerable: $fillable not defined, or $guarded = []
User::create($request->all());
$user->update($request->all());
$user->forceFill($request->all());  // bypasses $fillable/$guarded entirely
```

**Bypass Techniques**
- `$guarded = []` (empty guarded) allows all fields
- `$fillable` missing sensitive fields: `role`, `is_admin`, `email_verified_at`, `password`
- Nested relation assignment via `push()` or relationship methods
- `forceFill()` and `forceCreate()` bypass mass assignment protection

**Hidden Fields Still Writable**
- `$hidden` only affects serialization (JSON output), not mass assignment
- Fields hidden from API responses may still be writable via `create()`/`update()`

### File Upload and Storage

**Storage Symlink Exposure**
```
GET /storage/               (directory listing if index disabled)
GET /storage/framework/sessions/    (session files)
GET /storage/logs/laravel.log       (log files with sensitive data)
GET /storage/app/            (uploaded files)
```

- `storage:link` creates `public/storage → storage/app/public` symlink
- Misconfigured: symlink pointing to `storage/` root instead of `storage/app/public`
- Private files accessible if stored under `storage/app/public` instead of `storage/app/private`

**Upload Vulnerabilities**
- Extension-only validation bypassed with double extensions: `shell.php.jpg`
- MIME type mismatch: validate both extension and MIME
- Path traversal in uploaded filename: `../../shell.php`
- Missing disk configuration: default `local` disk may serve files publicly

### Session Deserialization

**PHP Serialization**
- Session driver `file`: serialized PHP stored in `storage/framework/sessions/`
- Session driver `cookie`: encrypted + serialized, vulnerable if APP_KEY known
- Queue payloads use `serialize()`: if queue backend is accessible (Redis without auth), inject payloads

**Queue Serialization RCE**
- Redis/database queue workers deserialize job payloads
- If attacker can write to queue (unsecured Redis), craft serialized gadget chain
- `phpggc` chains for Laravel: `Laravel/RCE1-16`, `Monolog/RCE1-5`

### Route and Middleware Bypass

**Middleware Gaps**
- Routes in `routes/api.php` missing `auth:sanctum` or `auth:api` middleware
- Route groups with auth middleware but individual routes using `->withoutMiddleware('auth')`
- `Route::resource` generating routes not all intended to be public (e.g., `destroy`, `update`)

**Route Model Binding**
- Implicit binding without scoping: `/users/{user}/posts/{post}` — `post` may belong to different user
- Custom resolution logic in `resolveRouteBinding()` not checking ownership

**Parameter Injection**
- Route parameters used directly in queries without validation
- `Route::any()` accepting all HTTP methods on sensitive endpoints

### CSRF Token Issues

**Bypass Vectors**
- API routes (under `api` middleware group) don't have CSRF protection
- `VerifyCsrfToken::$except` with overly broad exclusions (`'api/*'`, `'webhooks/*'`)
- `X-CSRF-TOKEN` and `X-XSRF-TOKEN` header handling differences
- Token not rotated on login (session fixation vector)

### Log File Exposure

**Laravel Log Information Leakage**
```
GET /storage/logs/laravel.log
GET /storage/logs/laravel-2024-01-15.log    (daily log driver)
```

- Stack traces with file paths, SQL queries, request data
- Logged exceptions containing user passwords, tokens, API keys
- Log file injection: craft input that appears in logs, then exploit via LFI → phar deserialization

### Telescope and Horizon Dashboards

**Telescope (`/telescope`)**
- Records all requests, exceptions, queries, jobs, mail, notifications
- Contains: full request/response bodies, SQL queries with bindings, queue job payloads
- Default gate: only accessible in `local` environment, but misconfigured in production

**Horizon (`/horizon`)**
- Redis queue dashboard with job payloads, failed job data
- `HorizonServiceProvider::gate()` must restrict access — often left permissive

## Bypass Techniques

- Trailing slash: `/admin` vs `/admin/` — route matching differences
- Verb spoofing: `_method=DELETE` in POST form to trigger route method constraints
- Content-type switching for API endpoints between JSON and form-encoded
- Route caching (`route:cache`) may serve stale auth middleware configuration
- Middleware `priority` array ordering affecting security filter execution
- `X-Forwarded-For` spoofing when `TrustProxies` middleware configured with `*` (trust all)

## Testing Methodology

1. **Debug/config audit** — Check for debug mode, `.env` exposure, log file access, Ignition endpoints
2. **APP_KEY assessment** — Attempt to extract APP_KEY, test cookie decryption/forgery if obtained
3. **Route mapping** — Enumerate all routes, identify auth middleware gaps, test resource controller actions
4. **ORM injection** — Grep for `whereRaw`, `DB::raw`, `selectRaw`, `orderByRaw` with user input
5. **Mass assignment** — Send extra fields to create/update endpoints, check `$fillable`/`$guarded`
6. **Dashboard access** — Test `/telescope`, `/horizon`, `/nova` access without authentication
7. **File/storage audit** — Test storage symlink exposure, upload handling, log file access

## Validation Requirements

- Debug exposure: Ignition page showing environment variables, APP_KEY, or source code
- APP_KEY RCE: crafted encrypted cookie triggering deserialization with evidence of execution
- ORM injection: SQL error or unauthorized data via `whereRaw`/`DB::raw` with crafted input
- Mass assignment: unauthorized field (role, is_admin) persisted via create/update request
- Middleware bypass: unauthenticated request reaching protected controller action
- Dashboard access: Telescope/Horizon data accessible without proper authorization
- File exposure: `.env` contents, log file data, or storage directory listing obtained
- CSRF bypass: state-changing request succeeding without valid CSRF token
