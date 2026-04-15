"""Context-aware path fuzzing — generate wordlists from already-discovered paths.

Static wordlists (seclists) are dumb: they bang the same N paths at every
target. This tool observes what the scanner has already found, spots the
naming conventions (singular/plural, versioning, admin variants, file
extensions), and generates a target-specific wordlist that's 10x denser in
actually-reachable paths.

Core idea: if you've seen /api/users, try /api/user, /api/users/me,
/api/users/admin, /api/users/export, /api/v2/users, /api/users.json, etc.
If you've seen /admin/dashboard, try /admin/users, /admin/logs,
/admin/settings, /admin/api/users.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

from ziro.tools.registry import register_tool


# Common variant transforms
ADMIN_SUFFIXES = [
    "/admin",
    "/admin/users",
    "/admin/login",
    "/admin/dashboard",
    "/admin/settings",
    "/admin/logs",
    "/admin/api",
    "/admin/config",
]

USER_SUBRESOURCES = [
    "/me",
    "/self",
    "/profile",
    "/account",
    "/current",
    "/{id}",
    "/export",
    "/import",
    "/search",
    "/bulk",
    "/count",
    "/all",
]

DEBUG_SUFFIXES = [
    "/debug",
    "/debug/vars",
    "/_debug",
    "/_internal",
    "/dev",
    "/test",
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/heapdump",
    "/actuator/httptrace",
    "/metrics",
    "/prometheus",
    "/healthz",
    "/readyz",
    "/livez",
    "/status",
    "/phpinfo.php",
    "/server-status",
    "/server-info",
]

WELL_KNOWN = [
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/jwks.json",
    "/.well-known/apple-app-site-association",
    "/.well-known/assetlinks.json",
    "/.well-known/change-password",
    "/robots.txt",
    "/sitemap.xml",
    "/security.txt",
]

FILE_EXTENSIONS = [".json", ".xml", ".bak", ".old", ".orig", ".backup", ".swp", "~"]

VERSION_PREFIXES = ["/v1", "/v2", "/v3", "/v4", "/api/v1", "/api/v2", "/api/v3"]


def _singular(word: str) -> str:
    if word.endswith("ies") and len(word) > 3:
        return word[:-3] + "y"
    if word.endswith("es") and len(word) > 3:
        return word[:-2]
    if word.endswith("s") and len(word) > 2:
        return word[:-1]
    return word


def _plural(word: str) -> str:
    if word.endswith("y") and len(word) > 1 and word[-2] not in "aeiou":
        return word[:-1] + "ies"
    if word.endswith(("s", "x", "z", "ch", "sh")):
        return word + "es"
    return word + "s"


@register_tool(sandbox_execution=False)
def generate_smart_wordlist(
    agent_state: Any,
    discovered_paths: list[str] | None = None,
    base_url: str = "",
    include_admin: bool = True,
    include_debug: bool = True,
    include_well_known: bool = True,
    include_versions: bool = True,
    include_extensions: bool = True,
    max_entries: int = 500,
) -> dict[str, Any]:
    """Generate a target-specific wordlist from already-discovered paths.

    Pass the paths the scanner has seen so far (from recon, crawling, or the
    API spec discovery tool). The tool derives variants:

    - Singular/plural forms (/users → /user)
    - User subresources (/users/me, /users/{id}, /users/export)
    - Admin variants (/admin/users from /users)
    - Version variants (/v1/users, /v2/users, /api/v3/users)
    - File extension variants (/users.json, /users.xml, /users.bak)
    - Well-known endpoints (always)
    - Debug / actuator / metrics endpoints (if include_debug)

    The output is deduplicated, ordered by likelihood, and capped at
    max_entries. Feed it to ffuf / feroxbuster / dirsearch, or iterate
    with terminal_execute + curl for surgical testing.
    """
    try:
        discovered_paths = discovered_paths or []
        generated: set[str] = set()

        # Always-useful endpoints
        if include_well_known:
            for p in WELL_KNOWN:
                generated.add(p)

        if include_debug:
            for p in DEBUG_SUFFIXES:
                generated.add(p)

        # Derive from each discovered path
        for raw in discovered_paths:
            if not raw:
                continue
            # Normalize: ensure leading slash, strip query/fragment
            parsed = urlparse(raw)
            path = parsed.path if parsed.path else raw
            if not path.startswith("/"):
                path = "/" + path
            path = re.sub(r"/+", "/", path).rstrip("/")
            if not path or path == "/":
                continue

            generated.add(path)

            # Segment-based transforms
            segments = path.split("/")
            # Last segment transforms
            last = segments[-1]
            parent = "/".join(segments[:-1]) or ""

            # Singular / plural swap
            if last:
                alt = _singular(last) if last.endswith("s") else _plural(last)
                if alt != last:
                    generated.add(f"{parent}/{alt}")

            # User subresources (only if last segment looks like a collection)
            if last and last.lower() in (
                "users", "user", "accounts", "account", "orders", "order",
                "products", "product", "items", "item", "posts", "post",
                "comments", "files", "documents", "messages", "customers",
                "payments", "transactions", "subscriptions", "invoices",
            ):
                for sub in USER_SUBRESOURCES:
                    generated.add(path + sub)

            # Version variants
            if include_versions:
                # Strip existing version prefix if any
                stripped = re.sub(r"^/(api/)?v\d+/", "/", path)
                if stripped.startswith("/"):
                    for vp in VERSION_PREFIXES:
                        candidate = (vp + stripped).replace("//", "/")
                        generated.add(candidate)

            # Admin variants — if path looks API, try admin path too
            if include_admin and path.startswith(("/api/", "/rest/")):
                admin_path = "/admin" + path
                generated.add(admin_path)
                # Also try /api/admin/...
                internal_admin = re.sub(r"^(/api)", r"\1/admin", path)
                generated.add(internal_admin)

            # File extension variants (only if path has no extension)
            if include_extensions and "." not in last:
                for ext in FILE_EXTENSIONS:
                    generated.add(path + ext)

            # Parent-directory exploration — if /api/v1/users/me, try /api/v1/users, /api/v1
            for i in range(len(segments) - 1, 0, -1):
                parent_path = "/".join(segments[:i])
                if parent_path and parent_path != "/":
                    generated.add(parent_path)

            # Sibling guess based on common patterns — if /users seen, also try
            # companion resources
            if last.lower() == "users":
                for sibling in ("roles", "permissions", "groups", "teams", "sessions", "tokens"):
                    generated.add(f"{parent}/{sibling}")
            elif last.lower() == "orders":
                for sibling in ("payments", "invoices", "refunds", "shipments"):
                    generated.add(f"{parent}/{sibling}")
            elif last.lower() in ("login", "signin"):
                for sibling in ("logout", "signout", "register", "signup", "reset-password", "forgot-password"):
                    generated.add(f"{parent}/{sibling}")

        # Normalize and cap
        final = sorted(p for p in generated if p and p.startswith("/"))
        final = final[:max_entries]

        absolute_urls: list[str] = []
        if base_url:
            base = base_url.rstrip("/")
            absolute_urls = [base + p for p in final]

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"generate_smart_wordlist failed: {e!s}"}
    else:
        return {
            "success": True,
            "input_paths": len(discovered_paths or []),
            "generated_count": len(final),
            "wordlist": final,
            "absolute_urls": absolute_urls,
            "note": (
                "Feed this wordlist to ffuf/feroxbuster via terminal_execute for "
                "bulk probing, or iterate with curl for surgical checks. Re-run "
                "after each wave of discoveries to compound the intelligence."
            ),
        }
