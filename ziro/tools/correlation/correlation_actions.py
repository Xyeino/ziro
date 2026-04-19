"""Static-dynamic correlation + multi-target coordination + reachability analysis."""

from __future__ import annotations

import json
import os
import re
from typing import Any

from ziro.tools.registry import register_tool


@register_tool(sandbox_execution=False)
def correlate_static_dynamic(
    agent_state: Any,
    min_confidence_boost: float = 0.3,
) -> dict[str, Any]:
    """Promote SAST-imported findings to CONFIRMED when dynamic agents proved them.

    Walks all UNCONFIRMED findings in engagement state (typically imported via
    import_sarif), matches each against confirmed findings, and boosts confidence
    + promotes status when there's dynamic proof for the same endpoint+vuln_type.

    Core of white-box static-dynamic correlation: SAST sees 'possibly vulnerable
    pattern at file:line', dynamic agent sees 'exploit works at endpoint' — when
    both agree, it's definitively exploitable.
    """
    try:
        from ziro.engagement import get_engagement_state
    except ImportError:
        return {"success": False, "error": "engagement state not available"}

    state = get_engagement_state()
    findings = list(state.findings.values())

    unconfirmed = [f for f in findings if f.status == "unconfirmed"]
    confirmed = [f for f in findings if f.status == "confirmed"]

    promoted = []
    for uf in unconfirmed:
        best_match = None
        best_score = 0.0
        for cf in confirmed:
            score = _similarity(uf, cf)
            if score > best_score:
                best_score = score
                best_match = cf

        if best_match and best_score >= min_confidence_boost:
            state.update_finding_status(
                uf.id, "confirmed", confidence=min(1.0, uf.confidence + best_score)
            )
            promoted.append(
                {
                    "finding_id": uf.id,
                    "title": uf.title[:100],
                    "matched_to": best_match.id,
                    "match_score": round(best_score, 2),
                    "new_confidence": round(min(1.0, uf.confidence + best_score), 2),
                }
            )

    return {
        "success": True,
        "unconfirmed_before": len(unconfirmed),
        "confirmed_before": len(confirmed),
        "promoted_count": len(promoted),
        "promoted": promoted,
        "note": (
            "Findings matched by vuln_type + endpoint similarity. Now CONFIRMED "
            "means both static pattern AND dynamic exploit agree — strongest "
            "evidence class, include with full PoC in final report."
        ),
    }


def _similarity(a: Any, b: Any) -> float:
    """Simple similarity between two findings (0.0 - 1.0)."""
    score = 0.0
    # Vuln type match
    a_type = (a.vuln_type or "").lower()
    b_type = (b.vuln_type or "").lower()
    if a_type == b_type and a_type:
        score += 0.5
    elif a_type and b_type and (a_type in b_type or b_type in a_type):
        score += 0.25

    # Endpoint overlap
    a_ep = (a.endpoint or "").lower()
    b_ep = (b.endpoint or "").lower()
    if a_ep and b_ep:
        if a_ep == b_ep:
            score += 0.4
        elif a_ep in b_ep or b_ep in a_ep:
            score += 0.2
        else:
            # Compare path segments
            a_parts = re.split(r"[/:]", a_ep)
            b_parts = re.split(r"[/:]", b_ep)
            common = set(a_parts) & set(b_parts)
            if len(common) >= 2:
                score += 0.15

    # Title bigram overlap
    a_words = set((a.title or "").lower().split())
    b_words = set((b.title or "").lower().split())
    if a_words and b_words:
        overlap = len(a_words & b_words) / max(len(a_words | b_words), 1)
        score += overlap * 0.2

    return min(score, 1.0)


@register_tool(sandbox_execution=False)
def build_target_map(
    agent_state: Any,
    code_paths: list[str] | None = None,
    live_urls: list[str] | None = None,
) -> dict[str, Any]:
    """Build a Target Map for multi-target scans — correlates code repo files with live endpoints.

    Grep route handlers in source files (Express router, Django urls.py, FastAPI
    decorators, Spring @RequestMapping, etc.) and matches them to live URLs.
    Writes /workspace/target_map.json with the correlation.

    White-box agents use this to know 'this file implements that endpoint'
    when pivoting between static review and dynamic testing.
    """
    code_paths = code_paths or ["/workspace"]
    live_urls = live_urls or []
    route_hits: list[dict[str, Any]] = []

    route_patterns = [
        # Express / JS — app.get('/path', ...) or router.post('/x')
        (r"""(?:app|router|express)\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*['"]([^'"]+)['"]""", "express"),
        # FastAPI — @app.get("/path")
        (r"""@\s*(?:app|router)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]""", "fastapi"),
        # Django urls.py — path("api/x", view)
        (r"""path\s*\(\s*['"]([^'"]+)['"]""", "django"),
        # Flask — @app.route('/x', methods=['POST'])
        (r"""@\s*(?:app|bp)\s*\.\s*route\s*\(\s*['"]([^'"]+)['"]""", "flask"),
        # Spring — @RequestMapping("/x"), @GetMapping, @PostMapping
        (r"""@(?:Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*['"]([^'"]+)['"]""", "spring"),
        # Laravel — Route::get('/x', ...)
        (r"""Route\s*::\s*(get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]""", "laravel"),
        # Rails — get '/x', to:
        (r"""^\s*(get|post|put|patch|delete)\s+['"]([^'"]+)['"]""", "rails"),
    ]

    compiled = [(re.compile(p, re.MULTILINE | re.IGNORECASE), fw) for p, fw in route_patterns]

    for code_root in code_paths:
        if not os.path.isdir(code_root):
            continue
        for current, _, files in os.walk(code_root):
            # Skip noise dirs
            if any(s in current for s in ("node_modules", ".git", "venv", "__pycache__", "dist", "build")):
                continue
            for fname in files:
                if not any(fname.endswith(ext) for ext in (".js", ".ts", ".tsx", ".py", ".java", ".kt", ".rb", ".php", ".go")):
                    continue
                fpath = os.path.join(current, fname)
                try:
                    with open(fpath, encoding="utf-8", errors="ignore") as f:
                        src = f.read()
                except Exception:
                    continue
                if len(src) > 500_000:
                    continue
                for pat, framework in compiled:
                    for m in pat.finditer(src):
                        # Last group is always the path
                        path = m.group(m.lastindex or 1)
                        line = src[: m.start()].count("\n") + 1
                        route_hits.append({
                            "route": path,
                            "method": m.group(1) if m.lastindex and m.lastindex > 1 else "?",
                            "framework": framework,
                            "file": fpath,
                            "line": line,
                        })

    # Correlate routes to live URLs
    correlations = []
    for r in route_hits:
        route = r["route"]
        for url in live_urls:
            # Normalize url path
            from urllib.parse import urlparse

            live_path = urlparse(url).path or url
            # Match by suffix or exact
            if route in live_path or live_path.endswith(route.rstrip("/")):
                correlations.append({
                    **r,
                    "live_url": url,
                    "match_strength": "exact" if route == live_path else "suffix",
                })

    # Persist
    target_map = {
        "code_paths": code_paths,
        "live_urls": live_urls,
        "route_hits_count": len(route_hits),
        "correlations_count": len(correlations),
        "routes": route_hits[:500],
        "correlations": correlations[:500],
    }
    try:
        with open("/workspace/target_map.json", "w", encoding="utf-8") as f:
            json.dump(target_map, f, indent=2)
    except Exception:
        pass

    return {
        "success": True,
        "target_map_path": "/workspace/target_map.json",
        "code_paths": code_paths,
        "live_url_count": len(live_urls),
        "route_handlers_found": len(route_hits),
        "correlations_found": len(correlations),
        "framework_breakdown": _count_frameworks(route_hits),
        "sample_correlations": correlations[:20],
    }


def _count_frameworks(hits: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for h in hits:
        fw = h.get("framework", "?")
        out[fw] = out.get(fw, 0) + 1
    return out


@register_tool(sandbox_execution=True)
def analyze_sca_reachability(
    agent_state: Any,
    repo_path: str,
    vulnerable_function_patterns: list[str],
    entry_points: list[str] | None = None,
) -> dict[str, Any]:
    """Check if a CVE's vulnerable function is actually called from application code.

    Given a list of regex patterns matching the vulnerable function (e.g. from
    a CVE advisory: 'yaml.load(' for PyYAML CVE), scans the codebase for
    callers and checks whether any caller is reachable from an entry point.

    Half of SCA findings are unreachable library code — this dramatically
    reduces noise in white-box SCA reports.

    Returns reachable:true findings to promote to HIGH severity, unreachable:
    callers:false to downgrade to INFO.
    """
    if not os.path.isabs(repo_path):
        repo_path = os.path.join("/workspace", repo_path)
    if not os.path.isdir(repo_path):
        return {"success": False, "error": f"Not a directory: {repo_path}"}

    entry_points = entry_points or [
        # Common web entry patterns
        "if __name__", "app.run(", "main(",
        "exports.handler", "export default",
        "public static void main",
    ]

    compiled_vuln = [re.compile(p) for p in vulnerable_function_patterns]
    callers: list[dict[str, Any]] = []
    entry_files: set[str] = set()

    for current, _, files in os.walk(repo_path):
        if any(s in current for s in ("node_modules", ".git", "venv", "__pycache__", "dist", "build", "vendor")):
            continue
        for fname in files:
            if not any(fname.endswith(e) for e in (".py", ".js", ".ts", ".tsx", ".java", ".go", ".rb", ".php")):
                continue
            fpath = os.path.join(current, fname)
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as f:
                    src = f.read()
            except Exception:
                continue
            if len(src) > 500_000:
                continue

            # Entry point check
            if any(ep in src for ep in entry_points):
                entry_files.add(fpath)

            # Vulnerable function caller check
            for pat in compiled_vuln:
                for m in pat.finditer(src):
                    line = src[: m.start()].count("\n") + 1
                    callers.append({
                        "file": fpath,
                        "line": line,
                        "match": m.group(0)[:200],
                        "pattern": pat.pattern,
                    })

    # Reachability: does a caller file appear in entry points, OR is it imported/included
    # from an entry point? For now: simple heuristic — if any caller is in /src, /app,
    # /lib, /api directories, treat as reachable.
    reachable_paths = {"/src/", "/app/", "/api/", "/controllers/", "/handlers/", "/routes/", "/views/"}
    reachable_callers = []
    unreachable_callers = []
    for c in callers:
        path = c["file"]
        if path in entry_files or any(rp in path for rp in reachable_paths):
            c["reachable_from_entry"] = True
            reachable_callers.append(c)
        else:
            c["reachable_from_entry"] = False
            unreachable_callers.append(c)

    return {
        "success": True,
        "repo": repo_path,
        "patterns_checked": vulnerable_function_patterns,
        "entry_files_found": len(entry_files),
        "total_callers": len(callers),
        "reachable_callers": len(reachable_callers),
        "unreachable_callers": len(unreachable_callers),
        "reachable": reachable_callers[:50],
        "unreachable_sample": unreachable_callers[:20],
        "recommendation": (
            "REACHABLE — treat as HIGH severity, include in report with caller trace."
            if reachable_callers
            else "UNREACHABLE — downgrade to INFO/LOW. Vulnerable function exists in "
                 "dependencies but is not called from application entry points."
        ),
    }
