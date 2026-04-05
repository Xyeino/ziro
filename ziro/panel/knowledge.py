"""Knowledge Graph — persistent learning from past scans.

Stores patterns, findings, and technology correlations across scans.
The AI agent can query this to make smarter decisions:
"React+GraphQL apps often have IDOR via introspection"
"""

import json
import sqlite3
from pathlib import Path
from typing import Any

_kb_path = Path.home() / ".ziro" / "knowledge.db"


def _get_conn() -> sqlite3.Connection:
    _kb_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_kb_path))
    conn.execute("""CREATE TABLE IF NOT EXISTS patterns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tech_stack TEXT,
        vuln_type TEXT,
        description TEXT,
        confidence REAL DEFAULT 0.5,
        occurrences INTEGER DEFAULT 1,
        last_seen TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS tech_vulns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        technology TEXT,
        version TEXT DEFAULT '',
        cve_id TEXT DEFAULT '',
        vuln_title TEXT,
        severity TEXT,
        target TEXT,
        scan_date TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS attack_chains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        chain_json TEXT,
        steps INTEGER DEFAULT 0,
        final_impact TEXT DEFAULT '',
        scan_date TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.commit()
    return conn


def learn_from_scan(target: str, technologies: list[str], vulns: list[dict[str, Any]]) -> None:
    """Extract patterns from a completed scan and store them."""
    conn = _get_conn()
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()

    tech_key = ",".join(sorted(set(t.lower() for t in technologies)))

    for v in vulns:
        vuln_type = v.get("cwe", "") or _classify_vuln(v.get("title", ""))
        if not vuln_type:
            continue

        # Check if pattern exists
        existing = conn.execute(
            "SELECT id, occurrences, confidence FROM patterns WHERE tech_stack = ? AND vuln_type = ?",
            (tech_key, vuln_type),
        ).fetchone()

        if existing:
            conn.execute(
                "UPDATE patterns SET occurrences = occurrences + 1, confidence = MIN(0.99, confidence + 0.1), last_seen = ? WHERE id = ?",
                (now, existing[0]),
            )
        else:
            conn.execute(
                "INSERT INTO patterns (tech_stack, vuln_type, description, last_seen) VALUES (?, ?, ?, ?)",
                (tech_key, vuln_type, f"Found {v.get('title', '')} on {tech_key} stack", now),
            )

        # Store tech-vuln correlation
        for tech in technologies:
            conn.execute(
                "INSERT INTO tech_vulns (technology, vuln_title, severity, target, scan_date) VALUES (?, ?, ?, ?, ?)",
                (tech.lower(), v.get("title", ""), v.get("severity", ""), target, now),
            )

    conn.commit()
    conn.close()


def get_patterns_for_tech(technologies: list[str]) -> list[dict[str, Any]]:
    """Get known vulnerability patterns for a technology stack."""
    conn = _get_conn()
    patterns = []

    for tech in technologies:
        tech_lower = tech.lower()
        # Find patterns where this tech appears
        rows = conn.execute(
            "SELECT vuln_type, description, confidence, occurrences FROM patterns WHERE tech_stack LIKE ? ORDER BY confidence DESC LIMIT 10",
            (f"%{tech_lower}%",),
        ).fetchall()
        for row in rows:
            patterns.append({
                "vuln_type": row[0],
                "description": row[1],
                "confidence": row[2],
                "occurrences": row[3],
                "matching_tech": tech,
            })

    # Also get historical vulns for these technologies
    for tech in technologies:
        rows = conn.execute(
            "SELECT DISTINCT vuln_title, severity FROM tech_vulns WHERE technology = ? ORDER BY severity LIMIT 5",
            (tech.lower(),),
        ).fetchall()
        for row in rows:
            patterns.append({
                "vuln_type": "historical",
                "description": f"Previously found: {row[0]} ({row[1]})",
                "confidence": 0.7,
                "occurrences": 1,
                "matching_tech": tech,
            })

    conn.close()
    return patterns


def get_knowledge_summary() -> dict[str, Any]:
    """Get overall knowledge base stats."""
    conn = _get_conn()
    pattern_count = conn.execute("SELECT COUNT(*) FROM patterns").fetchone()[0]
    tech_vuln_count = conn.execute("SELECT COUNT(*) FROM tech_vulns").fetchone()[0]
    chain_count = conn.execute("SELECT COUNT(*) FROM attack_chains").fetchone()[0]
    top_patterns = conn.execute(
        "SELECT tech_stack, vuln_type, confidence, occurrences FROM patterns ORDER BY occurrences DESC LIMIT 10"
    ).fetchall()
    conn.close()
    return {
        "total_patterns": pattern_count,
        "total_tech_vulns": tech_vuln_count,
        "total_chains": chain_count,
        "top_patterns": [
            {"tech": r[0], "vuln": r[1], "confidence": r[2], "occurrences": r[3]}
            for r in top_patterns
        ],
    }


def save_attack_chain(target: str, chain: list[dict[str, str]], final_impact: str) -> None:
    """Save a successful attack chain for learning."""
    conn = _get_conn()
    from datetime import datetime, timezone
    conn.execute(
        "INSERT INTO attack_chains (target, chain_json, steps, final_impact, scan_date) VALUES (?, ?, ?, ?, ?)",
        (target, json.dumps(chain), len(chain), final_impact, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()


def _classify_vuln(title: str) -> str:
    """Classify vulnerability type from title."""
    title_lower = title.lower()
    mappings = [
        ("sql", "SQLi"), ("xss", "XSS"), ("ssrf", "SSRF"), ("idor", "IDOR"),
        ("auth", "Auth"), ("csrf", "CSRF"), ("rce", "RCE"), ("lfi", "LFI"),
        ("open redirect", "OpenRedirect"), ("cors", "CORS"), ("jwt", "JWT"),
        ("deserialization", "Deserialization"), ("xxe", "XXE"),
        ("injection", "Injection"), ("traversal", "PathTraversal"),
    ]
    for keyword, vuln_type in mappings:
        if keyword in title_lower:
            return vuln_type
    return ""
