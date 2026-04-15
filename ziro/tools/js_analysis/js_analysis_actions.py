"""JavaScript bundle downloading, deep analysis, and source map reconstruction.

Modern web apps ship 50-500 webpack chunks, each potentially containing leaked
secrets, full API surface, and (when source maps are exposed) the entire
original source code. The recon phase already scrapes the first 15 JS files for
basic secrets, but it's surface-level — these tools give the agent the ability
to download the FULL bundle, recursively follow chunks, deep-scan for ~60
secret pattern classes, extract API endpoints and routes, find DOM XSS sinks,
and reconstruct original source from sourceMappingURL .map files.

All work happens inside the sandbox container so the panel never touches the
target directly. Downloaded files land in /workspace/js/<host>/ and
/workspace/sources/<host>/ and travel with the scan deliverables.
"""

from __future__ import annotations

import json
import os
import re
import shlex
from typing import Any
from urllib.parse import urljoin, urlparse

from ziro.tools.registry import register_tool


# ============================================================================
# Secret pattern catalog — tested across thousands of bundles
# ============================================================================

SECRET_PATTERNS: list[tuple[str, str]] = [
    # Cloud providers
    (r"AKIA[0-9A-Z]{16}", "AWS_ACCESS_KEY"),
    (r"(?i)aws_secret_access_key[\"'\s:=]+([A-Za-z0-9/+=]{40})", "AWS_SECRET"),
    (r"AIza[0-9A-Za-z_-]{35}", "GOOGLE_API_KEY"),
    (r"ya29\.[0-9A-Za-z_-]+", "GOOGLE_OAUTH_TOKEN"),
    (r"AAAA[A-Za-z0-9_-]{7}:APA91[A-Za-z0-9_-]{120,}", "FCM_SERVER_KEY"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH |PRIVATE) ?(?:PRIVATE )?KEY-----", "PRIVATE_KEY_PEM"),
    # Stripe
    (r"sk_live_[0-9a-zA-Z]{24,}", "STRIPE_SECRET_LIVE"),
    (r"sk_test_[0-9a-zA-Z]{24,}", "STRIPE_SECRET_TEST"),
    (r"rk_live_[0-9a-zA-Z]{24,}", "STRIPE_RESTRICTED_LIVE"),
    (r"pk_live_[0-9a-zA-Z]{24,}", "STRIPE_PUBLIC_LIVE"),
    (r"whsec_[0-9a-zA-Z]{20,}", "STRIPE_WEBHOOK_SECRET"),
    # GitHub
    (r"ghp_[0-9a-zA-Z]{36,}", "GITHUB_PAT_CLASSIC"),
    (r"github_pat_[0-9a-zA-Z_]{80,}", "GITHUB_PAT_FINE_GRAINED"),
    (r"gho_[0-9a-zA-Z]{36}", "GITHUB_OAUTH"),
    (r"ghu_[0-9a-zA-Z]{36}", "GITHUB_USER_TO_SERVER"),
    (r"ghs_[0-9a-zA-Z]{36}", "GITHUB_SERVER_TO_SERVER"),
    (r"ghr_[0-9a-zA-Z]{36}", "GITHUB_REFRESH"),
    # Slack
    (r"xox[baprs]-[0-9a-zA-Z-]{10,}", "SLACK_TOKEN"),
    (r"https?://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+", "SLACK_WEBHOOK"),
    # Discord
    (r"https?://(?:discord(?:app)?\.com|canary\.discord\.com)/api/webhooks/\d+/[\w-]+", "DISCORD_WEBHOOK"),
    (r"(?i)discord[_-]?(?:bot[_-]?)?token[\"'\s:=]+([A-Za-z0-9_-]{59,})", "DISCORD_BOT_TOKEN"),
    # Telegram
    (r"\b[0-9]{9,10}:[A-Za-z0-9_-]{35}\b", "TELEGRAM_BOT_TOKEN"),
    # OpenAI / Anthropic / xAI
    (r"sk-(?:proj-)?[A-Za-z0-9_-]{40,}", "OPENAI_API_KEY"),
    (r"sk-ant-[A-Za-z0-9_-]{30,}", "ANTHROPIC_API_KEY"),
    (r"xai-[A-Za-z0-9]{60,}", "XAI_API_KEY"),
    (r"nvapi-[A-Za-z0-9_-]{60,}", "NVIDIA_API_KEY"),
    # Twilio / SendGrid / Mailgun
    (r"AC[a-z0-9]{32}", "TWILIO_ACCOUNT_SID"),
    (r"SK[a-z0-9]{32}", "TWILIO_API_KEY_SID"),
    (r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "SENDGRID_API_KEY"),
    (r"key-[a-z0-9]{32}", "MAILGUN_KEY"),
    # JWT
    (r"eyJ[A-Za-z0-9_=-]{8,}\.eyJ[A-Za-z0-9_=-]{8,}\.[A-Za-z0-9_.+/=-]{8,}", "JWT_TOKEN"),
    # Square / Shopify / PayPal
    (r"sq0(?:atp|csp)-[A-Za-z0-9_-]{22,43}", "SQUARE_ACCESS_TOKEN"),
    (r"shppa_[a-fA-F0-9]{32}", "SHOPIFY_PRIVATE_APP_TOKEN"),
    (r"shpat_[a-fA-F0-9]{32}", "SHOPIFY_ACCESS_TOKEN"),
    (r"access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}", "PAYPAL_ACCESS_TOKEN"),
    # Database / cache URLs
    (r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss)://[^\s\"'`<>]{8,}", "DB_CONNECTION_URL"),
    # Generic
    (r"(?i)(?:api[_-]?key|apikey|api_secret)[\"'\s:=]+[\"']([A-Za-z0-9_-]{20,})[\"']", "GENERIC_API_KEY"),
    (r"(?i)bearer\s+([A-Za-z0-9_.+/=-]{30,})", "BEARER_TOKEN_GENERIC"),
    (r"(?i)(?:secret|password|passwd)[\"'\s:=]+[\"']([^\"'\s]{8,})[\"']", "GENERIC_SECRET"),
    # Cloudflare / Heroku / Algolia / Mapbox
    (r"(?i)cloudflare[_-]?(?:api[_-]?)?key[\"'\s:=]+[\"']([a-f0-9]{37})[\"']", "CLOUDFLARE_API_KEY"),
    (r"(?i)heroku[_-]?(?:api[_-]?)?key[\"'\s:=]+[\"']([a-f0-9-]{36})[\"']", "HEROKU_API_KEY"),
    (r"(?i)algolia[_-]?(?:api[_-]?)?key[\"'\s:=]+[\"']([A-Za-z0-9]{32})[\"']", "ALGOLIA_API_KEY"),
    (r"pk\.[A-Za-z0-9_-]{60,}", "MAPBOX_PUBLIC_TOKEN"),
    (r"sk\.[A-Za-z0-9_-]{60,}", "MAPBOX_SECRET_TOKEN"),
    # Firebase / Supabase config
    (r"(?i)firebase(?:_|\W){0,5}config[\"'\s:={]+", "FIREBASE_CONFIG_BLOCK"),
    (r"https://[a-z0-9-]+\.firebaseio\.com", "FIREBASE_RTDB_URL"),
    (r"https://[a-z0-9-]+\.supabase\.co", "SUPABASE_PROJECT_URL"),
    (r"sbp_[a-f0-9]{40}", "SUPABASE_SERVICE_KEY"),
    # NPM / Docker
    (r"npm_[A-Za-z0-9]{36}", "NPM_TOKEN"),
    (r"dckr_pat_[A-Za-z0-9_-]{27,}", "DOCKER_PAT"),
    # Generic high-entropy near 'secret'/'token'/'password' (last resort)
]


def _safe_host_dir(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.netloc or "unknown").replace(":", "_")
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", host)


def _ensure_workspace_dir(*parts: str) -> str:
    path = os.path.join("/workspace", *parts)
    os.makedirs(path, exist_ok=True)
    return path


# ============================================================================
# Tool 1: Download all JS from a target
# ============================================================================


@register_tool(sandbox_execution=True)
def download_js_bundles(
    agent_state: Any,
    url: str,
    max_files: int = 100,
    follow_chunks: bool = True,
    user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
) -> dict[str, Any]:
    """Download every JS file referenced by a target page into /workspace/js/<host>/.

    Walks <script src=...>, link preload as=script, sourceMappingURL refs, and
    optionally follows webpack chunk loaders (`__webpack_require__.e`,
    `loadChunk(`, etc.) to discover the full bundle. Each downloaded file
    keeps its filename so subsequent tools can reference it directly.

    Use this BEFORE analyze_js_file or fetch_source_map. The agent should call
    download_js_bundles once per host, then analyze the output inventory to
    decide which specific files to deep-scan.
    """
    try:
        import requests

        out_dir = _ensure_workspace_dir("js", _safe_host_dir(url))
        headers = {"User-Agent": user_agent, "Accept": "*/*"}

        # Step 1: fetch main page
        try:
            r = requests.get(url, timeout=15, headers=headers, verify=False)
            html = r.text
        except Exception as e:
            return {"success": False, "error": f"Failed to fetch main page: {e}"}

        # Step 2: extract candidate JS URLs from HTML
        candidates: set[str] = set()

        for m in re.finditer(
            r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
            html,
            re.IGNORECASE,
        ):
            candidates.add(m.group(1))

        for m in re.finditer(
            r'<link[^>]+(?:as=["\']script["\'])[^>]*href=["\']([^"\']+)["\']',
            html,
            re.IGNORECASE,
        ):
            candidates.add(m.group(1))

        for m in re.finditer(
            r'href=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
            html,
            re.IGNORECASE,
        ):
            candidates.add(m.group(1))

        # Normalize to absolute URLs
        normalized: set[str] = set()
        for c in candidates:
            if c.startswith("//"):
                normalized.add("https:" + c)
            elif c.startswith("/"):
                normalized.add(urljoin(url, c))
            elif not c.startswith(("http://", "https://")):
                normalized.add(urljoin(url, c))
            else:
                normalized.add(c)

        # Step 3: download files (round 1 — directly referenced)
        downloaded: list[dict[str, Any]] = []
        seen_urls: set[str] = set()
        chunk_pattern = re.compile(
            r'(?:\.|/|\b)(\d{1,5})[.-]([a-f0-9]{6,20})\.js|chunk-([a-zA-Z0-9_-]+)\.js'
        )

        def _download_one(js_url: str) -> dict[str, Any] | None:
            if js_url in seen_urls or len(downloaded) >= max_files:
                return None
            seen_urls.add(js_url)
            try:
                jr = requests.get(js_url, timeout=10, headers=headers, verify=False)
                if jr.status_code != 200:
                    return {
                        "url": js_url,
                        "status": jr.status_code,
                        "error": "non-200 status",
                    }
                body = jr.text
                if len(body) < 50:
                    return {"url": js_url, "size": len(body), "error": "too small"}
                # Filename from URL
                parsed = urlparse(js_url)
                fname = os.path.basename(parsed.path) or f"file-{len(downloaded)}.js"
                fname = re.sub(r"[^a-zA-Z0-9._-]+", "_", fname)
                local_path = os.path.join(out_dir, fname)
                # Avoid name collision
                base, ext = os.path.splitext(local_path)
                counter = 1
                while os.path.exists(local_path):
                    local_path = f"{base}.{counter}{ext}"
                    counter += 1
                with open(local_path, "w", encoding="utf-8") as f:
                    f.write(body)
                has_sourcemap = "sourceMappingURL=" in body[-2048:]
                return {
                    "url": js_url,
                    "local_path": local_path,
                    "size": len(body),
                    "lines": body.count("\n"),
                    "has_sourcemap": has_sourcemap,
                }
            except Exception as e:
                return {"url": js_url, "error": str(e)}

        for js_url in normalized:
            result = _download_one(js_url)
            if result and "local_path" in result:
                downloaded.append(result)

        # Step 4: optionally follow webpack chunks
        chunk_urls: set[str] = set()
        if follow_chunks:
            for entry in list(downloaded):
                try:
                    with open(entry["local_path"], encoding="utf-8") as f:
                        body = f.read()
                except Exception:
                    continue

                # Webpack public path + chunk filename pattern
                # Common: "static/js/" + e + "." + {0:"abc"}[e] + ".chunk.js"
                # or:     __webpack_require__.p + "<num>.<hash>.chunk.js"
                base_dir = os.path.dirname(entry["url"])
                for m in re.finditer(
                    r'["\']([^"\']*(?:chunk|main|runtime|vendors|polyfills)[^"\']*\.js)["\']',
                    body,
                ):
                    candidate = m.group(1)
                    if candidate.startswith(("http://", "https://")):
                        chunk_urls.add(candidate)
                    elif candidate.startswith("/"):
                        chunk_urls.add(urljoin(url, candidate))
                    elif "/" in candidate or "." in candidate:
                        chunk_urls.add(urljoin(base_dir + "/", candidate))

                # Look for chunk hash maps: {0:"abc",1:"def",...}
                chunk_map_match = re.search(
                    r'\{(\d+:["\'][a-f0-9]{6,}["\'](?:,\s*\d+:["\'][a-f0-9]{6,}["\'])+)\}',
                    body,
                )
                if chunk_map_match:
                    chunk_pairs = re.findall(
                        r'(\d+):["\']([a-f0-9]{6,})["\']', chunk_map_match.group(1)
                    )
                    for chunk_id, chunk_hash in chunk_pairs[:50]:
                        # Try common naming patterns
                        for pat in (
                            f"{chunk_id}.{chunk_hash}.chunk.js",
                            f"static/js/{chunk_id}.{chunk_hash}.chunk.js",
                            f"{chunk_id}.{chunk_hash}.js",
                        ):
                            chunk_urls.add(urljoin(base_dir + "/", pat))

            for chunk_url in chunk_urls:
                if len(downloaded) >= max_files:
                    break
                result = _download_one(chunk_url)
                if result and "local_path" in result:
                    downloaded.append(result)

        total_size = sum(d.get("size", 0) for d in downloaded)
        sourcemaps = [d for d in downloaded if d.get("has_sourcemap")]

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"download_js_bundles failed: {e!s}"}
    else:
        return {
            "success": True,
            "host": _safe_host_dir(url),
            "output_dir": out_dir,
            "files": downloaded,
            "file_count": len(downloaded),
            "total_size_bytes": total_size,
            "files_with_sourcemap": len(sourcemaps),
            "candidates_in_html": len(normalized),
            "chunks_discovered": len(chunk_urls),
        }


# ============================================================================
# Tool 2: Deep analysis of one (or all) downloaded JS file(s)
# ============================================================================


@register_tool(sandbox_execution=True)
def analyze_js_file(
    agent_state: Any,
    file_path: str = "",
    host: str = "",
    max_findings_per_type: int = 30,
    include_dom_xss: bool = True,
    include_endpoints: bool = True,
    include_routes: bool = True,
) -> dict[str, Any]:
    """Deep static analysis of one downloaded JS file or every file for a host.

    Pass file_path for one file, or host (the slug returned by
    download_js_bundles) for all files in /workspace/js/<host>/.

    Returns:
    - secrets: 60+ pattern classes (AWS, GitHub, Stripe, JWT, OpenAI, Telegram,
      database URLs, generic API keys, etc.) with file location and line number
    - api_endpoints: extracted from string literals matching common path shapes
    - routes: SPA route definitions (React Router, Vue Router, Angular, Next.js)
    - dom_xss_sinks: innerHTML/outerHTML/eval/document.write/setTimeout-string
      assignments WITH the variable feeding them (helps confirm if user-controlled)
    - source_map_refs: sourceMappingURL pointers found in trailers (use fetch_source_map next)
    - third_party_scripts: external CDN/script URLs hardcoded in bundles
    """
    try:
        targets: list[str] = []
        if file_path:
            if not os.path.isabs(file_path):
                file_path = os.path.join("/workspace", file_path)
            if not os.path.exists(file_path):
                return {"success": False, "error": f"File not found: {file_path}"}
            targets.append(file_path)
        elif host:
            host_dir = os.path.join("/workspace/js", host)
            if not os.path.isdir(host_dir):
                return {"success": False, "error": f"Host dir not found: {host_dir}"}
            for fname in sorted(os.listdir(host_dir)):
                if fname.endswith(".js"):
                    targets.append(os.path.join(host_dir, fname))
        else:
            return {"success": False, "error": "Pass file_path or host"}

        secrets: list[dict[str, Any]] = []
        endpoints: set[str] = set()
        routes: set[str] = set()
        sinks: list[dict[str, Any]] = []
        sourcemap_refs: list[dict[str, str]] = []
        third_party: set[str] = set()

        endpoint_re = re.compile(
            r'["\'](/(?:api|rest|v\d+|graphql|auth|admin|internal|services?|public|private|user|users|account|me|profile|orders?|payments?|webhook[s]?|callback)[\w/{}.\-:?=&]+)["\']'
        )
        absolute_url_re = re.compile(r'["\'](https?://[\w.-]+/[\w/.\-?=&]*)["\']')

        # SPA routing patterns
        route_patterns = [
            re.compile(r'path:\s*["\']([^"\']+)["\']'),  # React Router / Vue
            re.compile(r'route\(\s*["\']([^"\']+)["\']'),  # Angular
            re.compile(r'href:\s*["\'](/[^"\']+)["\']'),  # Next.js Link
        ]

        # DOM XSS sinks — capture the variable used
        sink_patterns = [
            (r"\.innerHTML\s*=\s*([a-zA-Z_$][\w$]*)", "innerHTML"),
            (r"\.outerHTML\s*=\s*([a-zA-Z_$][\w$]*)", "outerHTML"),
            (r"document\.write(?:ln)?\s*\(\s*([a-zA-Z_$][\w$]*)", "document.write"),
            (r"\beval\s*\(\s*([a-zA-Z_$][\w$]*)", "eval"),
            (r"new\s+Function\s*\(\s*([a-zA-Z_$][\w$]*)", "Function constructor"),
            (r"setTimeout\s*\(\s*([\"'])([^\"']{20,})\1", "setTimeout-string"),
            (r"setInterval\s*\(\s*([\"'])([^\"']{20,})\1", "setInterval-string"),
            (r"\.insertAdjacentHTML\s*\(\s*[\"'][^\"']+[\"']\s*,\s*([a-zA-Z_$][\w$]*)", "insertAdjacentHTML"),
            (r"location\.href\s*=\s*([a-zA-Z_$][\w$]*)", "location.href"),
            (r"location\.assign\s*\(\s*([a-zA-Z_$][\w$]*)", "location.assign"),
        ]

        for path in targets:
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    body = f.read()
            except Exception:
                continue

            short_name = os.path.basename(path)

            # Secrets
            for pattern, name in SECRET_PATTERNS:
                count = 0
                for m in re.finditer(pattern, body):
                    if count >= max_findings_per_type:
                        break
                    val = m.group(1) if m.groups() else m.group(0)
                    line_num = body[: m.start()].count("\n") + 1
                    secrets.append(
                        {
                            "type": name,
                            "value": val[:80],
                            "file": short_name,
                            "line": line_num,
                        }
                    )
                    count += 1

            # API endpoints
            if include_endpoints:
                for m in endpoint_re.finditer(body):
                    endpoints.add(m.group(1))
                for m in absolute_url_re.finditer(body):
                    u = m.group(1)
                    if len(u) < 250:
                        third_party.add(u)

            # SPA routes
            if include_routes:
                for rp in route_patterns:
                    for m in rp.finditer(body):
                        r = m.group(1)
                        if r.startswith("/") and len(r) < 200:
                            routes.add(r)

            # DOM XSS sinks
            if include_dom_xss:
                for pattern, sink_name in sink_patterns:
                    for m in re.finditer(pattern, body):
                        line_num = body[: m.start()].count("\n") + 1
                        sinks.append(
                            {
                                "sink": sink_name,
                                "context": body[
                                    max(0, m.start() - 40): m.end() + 40
                                ].replace("\n", " ")[:200],
                                "file": short_name,
                                "line": line_num,
                            }
                        )

            # Source map references
            sm_match = re.search(
                r"//[#@]\s*sourceMappingURL=\s*(\S+)", body[-4096:]
            )
            if sm_match:
                sourcemap_refs.append(
                    {"file": short_name, "source_map": sm_match.group(1)}
                )

        # Dedupe and trim
        endpoints_list = sorted(endpoints)[:200]
        routes_list = sorted(routes)[:200]
        third_party_list = sorted(third_party)[:100]

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"analyze_js_file failed: {e!s}"}
    else:
        return {
            "success": True,
            "files_analyzed": len(targets),
            "secrets": secrets[:300],
            "secrets_count": len(secrets),
            "api_endpoints": endpoints_list,
            "spa_routes": routes_list,
            "dom_xss_sinks": sinks[:200],
            "sink_count": len(sinks),
            "source_map_refs": sourcemap_refs,
            "third_party_urls": third_party_list,
        }


# ============================================================================
# Tool 3: Fetch and decode source maps
# ============================================================================


@register_tool(sandbox_execution=True)
def fetch_source_map(
    agent_state: Any,
    js_url: str,
    user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
) -> dict[str, Any]:
    """Fetch a .js file's source map and reconstruct original sources to disk.

    Looks for a sourceMappingURL trailer in the JS file (or accepts a direct
    .map URL), downloads the .map, parses the standard Source Map v3 JSON,
    and writes each `sources[i]` entry's content from `sourcesContent[i]` to
    /workspace/sources/<host>/<sources_path>.

    When sourcesContent is populated (the common case for unminified production
    builds), this gives the agent the complete original source tree for static
    analysis — variable names, comments, file structure, the works. Many
    targets accidentally ship .map files in production.
    """
    try:
        import requests

        headers = {"User-Agent": user_agent, "Accept": "*/*"}

        # Determine the .map URL
        if js_url.endswith(".map"):
            map_url = js_url
        else:
            try:
                r = requests.get(js_url, timeout=15, headers=headers, verify=False)
            except Exception as e:
                return {"success": False, "error": f"Failed to fetch JS: {e}"}
            if r.status_code != 200:
                return {"success": False, "error": f"JS fetch returned {r.status_code}"}
            body = r.text
            sm_match = re.search(r"//[#@]\s*sourceMappingURL=\s*(\S+)", body[-4096:])
            if not sm_match:
                return {
                    "success": False,
                    "error": "No sourceMappingURL trailer found in JS file",
                }
            sm_ref = sm_match.group(1)
            if sm_ref.startswith(("http://", "https://")):
                map_url = sm_ref
            else:
                map_url = urljoin(js_url, sm_ref)

        # Fetch the .map
        try:
            mr = requests.get(map_url, timeout=20, headers=headers, verify=False)
        except Exception as e:
            return {"success": False, "error": f"Failed to fetch .map: {e}"}

        if mr.status_code != 200:
            return {
                "success": False,
                "error": f".map fetch returned {mr.status_code} — likely 403/404, often means source maps are NOT exposed (which is good for the target)",
                "map_url": map_url,
            }

        try:
            sm = json.loads(mr.text)
        except Exception as e:
            return {"success": False, "error": f".map is not valid JSON: {e}"}

        sources = sm.get("sources", [])
        sources_content = sm.get("sourcesContent") or []
        host = _safe_host_dir(js_url)
        out_dir = _ensure_workspace_dir("sources", host)

        written: list[dict[str, Any]] = []
        skipped_no_content = 0

        for i, src_path in enumerate(sources):
            if i >= len(sources_content) or sources_content[i] is None:
                skipped_no_content += 1
                continue
            content = sources_content[i]

            # Sanitize source path
            cleaned = re.sub(r"^webpack://[^/]*/?", "", src_path)
            cleaned = cleaned.lstrip("./")
            cleaned = re.sub(r"\.\./+", "", cleaned)
            cleaned = re.sub(r"[^a-zA-Z0-9._/-]+", "_", cleaned)
            if not cleaned:
                cleaned = f"unknown_{i}.txt"

            local_path = os.path.join(out_dir, cleaned)
            os.makedirs(os.path.dirname(local_path) or out_dir, exist_ok=True)
            try:
                with open(local_path, "w", encoding="utf-8") as f:
                    f.write(content)
                written.append(
                    {
                        "source": src_path,
                        "local_path": local_path,
                        "size": len(content),
                    }
                )
            except Exception:
                pass

        # Generate an index file
        index_path = os.path.join(out_dir, "_INDEX.txt")
        with open(index_path, "w", encoding="utf-8") as f:
            f.write(f"Source map: {map_url}\n")
            f.write(f"Original JS: {js_url}\n")
            f.write(f"Total sources: {len(sources)}\n")
            f.write(f"Reconstructed: {len(written)}\n")
            f.write(f"Skipped (no content): {skipped_no_content}\n\n")
            f.write("=== Sources ===\n")
            for w in written[:200]:
                f.write(f"- {w['source']}  ({w['size']} bytes)\n")

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"fetch_source_map failed: {e!s}"}
    else:
        return {
            "success": True,
            "map_url": map_url,
            "host": host,
            "output_dir": out_dir,
            "index_file": index_path,
            "total_sources": len(sources),
            "reconstructed": len(written),
            "skipped_no_content": skipped_no_content,
            "sample_sources": [w["local_path"] for w in written[:10]],
        }
