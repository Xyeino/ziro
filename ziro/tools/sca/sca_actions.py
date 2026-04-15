"""Software Composition Analysis — Trivy wrapper for dependency vulnerability scanning.

Trivy is already installed in the sandbox container. This tool provides typed
wrappers so agents can run SCA on a codebase without memorizing the CLI syntax,
and parses the JSON output into a structured, severity-sorted finding list that
slots directly into the reporting pipeline.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from typing import Any, Literal

from ziro.tools.registry import register_tool


# File → lockfile type hints for detection
LOCKFILE_SIGNATURES: list[tuple[str, str]] = [
    ("package-lock.json", "npm"),
    ("yarn.lock", "yarn"),
    ("pnpm-lock.yaml", "pnpm"),
    ("requirements.txt", "pip"),
    ("poetry.lock", "poetry"),
    ("Pipfile.lock", "pipenv"),
    ("uv.lock", "uv"),
    ("go.sum", "go"),
    ("go.mod", "go"),
    ("Cargo.lock", "cargo"),
    ("Cargo.toml", "cargo"),
    ("pom.xml", "maven"),
    ("build.gradle", "gradle"),
    ("build.gradle.kts", "gradle"),
    ("Gemfile.lock", "bundler"),
    ("composer.lock", "composer"),
    ("composer.json", "composer"),
    ("mix.lock", "hex"),
    ("pubspec.lock", "dart"),
    ("pubspec.yaml", "dart"),
]


def _run(cmd: str, timeout: int = 300) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"Command timed out after {timeout}s"
    except FileNotFoundError as e:
        return 127, "", f"Command not found: {e}"
    except Exception as e:  # noqa: BLE001
        return 1, "", f"Execution error: {e}"


@register_tool(sandbox_execution=True)
def sca_scan_dependencies(
    agent_state: Any,
    target_path: str,
    scan_type: Literal["fs", "image"] = "fs",
    severity_filter: str = "CRITICAL,HIGH,MEDIUM",
    include_dev_deps: bool = True,
    timeout: int = 300,
    max_findings_per_severity: int = 50,
) -> dict[str, Any]:
    """Scan a codebase (or container image) for known-CVE dependency vulnerabilities via Trivy.

    scan_type:
    - "fs" (default): filesystem scan of a project directory. Trivy auto-detects
      package-lock.json, poetry.lock, go.sum, pom.xml, Gemfile.lock, composer.lock,
      Cargo.lock, etc.
    - "image": container image scan. Pass the image name/tag as target_path.

    Returns a structured list of vulnerabilities sorted by severity, with
    CVE ID, affected package, fixed version, CVSS score, references, and the
    lockfile where each was detected. Feeds directly into
    create_vulnerability_report for each finding.
    """
    try:
        # Validate path for fs scans
        if scan_type == "fs":
            if not os.path.isabs(target_path):
                target_path = os.path.join("/workspace", target_path)
            if not os.path.exists(target_path):
                return {"success": False, "error": f"Target path not found: {target_path}"}

        # Build trivy command
        cmd_parts = [
            "trivy",
            scan_type,
            "--format",
            "json",
            "--severity",
            severity_filter,
            "--quiet",
            "--timeout",
            f"{timeout}s",
            "--scanners",
            "vuln",
        ]
        if scan_type == "fs":
            # Without --include-dev-deps, Trivy excludes devDependencies from scan
            # With it, it includes them
            if not include_dev_deps:
                cmd_parts.append("--skip-dirs")
                cmd_parts.append("node_modules")

        cmd_parts.append(shlex.quote(target_path))
        cmd = " ".join(cmd_parts)

        rc, stdout, stderr = _run(cmd, timeout=timeout + 30)

        if rc == 127:
            return {
                "success": False,
                "error": "trivy binary not found in sandbox PATH",
                "command": cmd,
            }
        if rc == 124:
            return {
                "success": False,
                "error": f"trivy timed out after {timeout}s",
                "command": cmd,
            }
        if rc != 0 and not stdout.strip():
            return {
                "success": False,
                "error": f"trivy exited with code {rc}",
                "stderr": stderr[:2000],
                "command": cmd,
            }

        # Parse JSON output
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            return {
                "success": False,
                "error": f"trivy output is not valid JSON: {e}",
                "stdout_preview": stdout[:2000],
                "command": cmd,
            }

        # Flatten findings across all detected targets
        all_findings: list[dict[str, Any]] = []
        by_severity: dict[str, list[dict[str, Any]]] = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "UNKNOWN": [],
        }
        packages_with_vulns: set[str] = set()

        for tgt in data.get("Results", []):
            target_name = tgt.get("Target", "")
            tgt_class = tgt.get("Class", "")
            tgt_type = tgt.get("Type", "")
            for vuln in tgt.get("Vulnerabilities", []) or []:
                severity = (vuln.get("Severity") or "UNKNOWN").upper()
                finding = {
                    "cve": vuln.get("VulnerabilityID", ""),
                    "severity": severity,
                    "package": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", ""),
                    "title": vuln.get("Title", ""),
                    "description": (vuln.get("Description") or "")[:500],
                    "cvss_score": _extract_cvss(vuln),
                    "references": (vuln.get("References") or [])[:5],
                    "published_date": vuln.get("PublishedDate", ""),
                    "primary_url": vuln.get("PrimaryURL", ""),
                    "detected_in": target_name,
                    "target_class": tgt_class,
                    "target_type": tgt_type,
                }
                all_findings.append(finding)
                by_severity.setdefault(severity, []).append(finding)
                packages_with_vulns.add(f"{vuln.get('PkgName')}@{vuln.get('InstalledVersion')}")

        # Trim per severity
        for sev, findings in by_severity.items():
            findings.sort(
                key=lambda f: (f.get("cvss_score") or 0, f.get("cve", "")),
                reverse=True,
            )
            by_severity[sev] = findings[:max_findings_per_severity]

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"sca_scan_dependencies failed: {e!s}"}
    else:
        return {
            "success": True,
            "scan_type": scan_type,
            "target": target_path,
            "total_findings": len(all_findings),
            "by_severity": {
                "CRITICAL": len(by_severity["CRITICAL"]),
                "HIGH": len(by_severity["HIGH"]),
                "MEDIUM": len(by_severity["MEDIUM"]),
                "LOW": len(by_severity["LOW"]),
                "UNKNOWN": len(by_severity["UNKNOWN"]),
            },
            "vulnerable_packages_count": len(packages_with_vulns),
            "findings": by_severity,
        }


def _extract_cvss(vuln: dict[str, Any]) -> float | None:
    """Pull highest CVSS v3 score from the multiple sources Trivy includes."""
    cvss = vuln.get("CVSS") or {}
    scores: list[float] = []
    for source_data in cvss.values():
        if isinstance(source_data, dict):
            v3 = source_data.get("V3Score")
            if isinstance(v3, (int, float)):
                scores.append(float(v3))
            v2 = source_data.get("V2Score")
            if isinstance(v2, (int, float)) and not v3:
                scores.append(float(v2))
    return max(scores) if scores else None


@register_tool(sandbox_execution=True)
def detect_lockfiles(
    agent_state: Any,
    root_path: str = "/workspace",
    max_depth: int = 5,
) -> dict[str, Any]:
    """Find all dependency lockfiles and manifests under a path.

    Useful as a first step before sca_scan_dependencies — lets the agent see
    what's actually there before deciding how to scan. Recurses up to max_depth
    directories (default 5) and skips the usual noise dirs.
    """
    try:
        if not os.path.isabs(root_path):
            root_path = os.path.join("/workspace", root_path)
        if not os.path.isdir(root_path):
            return {"success": False, "error": f"Not a directory: {root_path}"}

        skip_dirs = {
            "node_modules",
            ".git",
            "vendor",
            ".venv",
            "venv",
            "env",
            "__pycache__",
            "dist",
            "build",
            "target",
            ".gradle",
            ".idea",
            ".vscode",
        }
        found: dict[str, list[str]] = {}

        root_depth = root_path.rstrip("/").count("/")
        for current, dirs, files in os.walk(root_path):
            depth = current.rstrip("/").count("/") - root_depth
            if depth > max_depth:
                dirs[:] = []
                continue
            dirs[:] = [d for d in dirs if d not in skip_dirs]

            for fname, ecosystem in LOCKFILE_SIGNATURES:
                if fname in files:
                    full_path = os.path.join(current, fname)
                    found.setdefault(ecosystem, []).append(full_path)

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"detect_lockfiles failed: {e!s}"}
    else:
        return {
            "success": True,
            "root": root_path,
            "ecosystems_detected": sorted(found.keys()),
            "lockfiles_by_ecosystem": found,
            "total_lockfiles": sum(len(v) for v in found.values()),
        }
