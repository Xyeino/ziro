"""Evidence Collector — captures and organizes proof artifacts for findings.

Automatically collects HTTP request/response pairs, command output, and
screenshots, linking them to specific vulnerability reports.
"""

import base64
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_global_collector: "EvidenceCollector | None" = None


def get_evidence_collector() -> "EvidenceCollector | None":
    return _global_collector


def set_evidence_collector(collector: "EvidenceCollector | None") -> None:
    global _global_collector  # noqa: PLW0603
    _global_collector = collector


class EvidenceCollector:
    """Collects and organizes evidence artifacts for vulnerability findings."""

    def __init__(self, run_dir: Path):
        self._run_dir = run_dir
        self._evidence_dir = run_dir / "evidence"
        self._evidence_dir.mkdir(parents=True, exist_ok=True)
        self._artifacts: list[dict[str, Any]] = []
        self._next_id = 1

    @property
    def evidence_dir(self) -> Path:
        return self._evidence_dir

    def capture_http(
        self,
        url: str,
        method: str,
        request_headers: dict[str, str] | None = None,
        request_body: str | None = None,
        status_code: int | None = None,
        response_headers: dict[str, str] | None = None,
        response_body: str | None = None,
        vuln_id: str | None = None,
        description: str = "",
    ) -> str:
        """Capture an HTTP request/response pair as evidence."""
        artifact_id = f"http-{self._next_id:04d}"
        self._next_id += 1

        artifact: dict[str, Any] = {
            "id": artifact_id,
            "type": "http",
            "timestamp": datetime.now(UTC).isoformat(),
            "vuln_id": vuln_id,
            "description": description,
            "request": {
                "url": url,
                "method": method.upper(),
                "headers": request_headers or {},
                "body": request_body,
            },
            "response": {
                "status_code": status_code,
                "headers": response_headers or {},
                "body": self._truncate(response_body, 10000) if response_body else None,
            },
        }

        self._artifacts.append(artifact)
        self._save_artifact(artifact_id, artifact)

        logger.debug("Captured HTTP evidence: %s %s -> %s", method, url, artifact_id)
        return artifact_id

    def capture_command(
        self,
        command: str,
        output: str,
        exit_code: int | None = None,
        vuln_id: str | None = None,
        description: str = "",
    ) -> str:
        """Capture a command execution and its output as evidence."""
        artifact_id = f"cmd-{self._next_id:04d}"
        self._next_id += 1

        artifact: dict[str, Any] = {
            "id": artifact_id,
            "type": "command",
            "timestamp": datetime.now(UTC).isoformat(),
            "vuln_id": vuln_id,
            "description": description,
            "command": command,
            "output": self._truncate(output, 20000),
            "exit_code": exit_code,
        }

        self._artifacts.append(artifact)
        self._save_artifact(artifact_id, artifact)

        logger.debug("Captured command evidence: %s -> %s", command[:50], artifact_id)
        return artifact_id

    def capture_screenshot(
        self,
        screenshot_b64: str,
        url: str = "",
        vuln_id: str | None = None,
        description: str = "",
    ) -> str:
        """Capture a screenshot as evidence."""
        artifact_id = f"screenshot-{self._next_id:04d}"
        self._next_id += 1

        # Save the image file
        img_path = self._evidence_dir / f"{artifact_id}.png"
        try:
            img_data = base64.b64decode(screenshot_b64)
            img_path.write_bytes(img_data)
        except (ValueError, OSError) as e:
            logger.warning("Failed to save screenshot %s: %s", artifact_id, e)

        artifact: dict[str, Any] = {
            "id": artifact_id,
            "type": "screenshot",
            "timestamp": datetime.now(UTC).isoformat(),
            "vuln_id": vuln_id,
            "description": description,
            "url": url,
            "file": str(img_path.name),
        }

        self._artifacts.append(artifact)
        self._save_artifact(artifact_id, artifact)

        logger.debug("Captured screenshot evidence: %s -> %s", url, artifact_id)
        return artifact_id

    def link_to_finding(self, artifact_id: str, vuln_id: str) -> bool:
        """Link an existing evidence artifact to a vulnerability finding."""
        for artifact in self._artifacts:
            if artifact["id"] == artifact_id:
                artifact["vuln_id"] = vuln_id
                self._save_artifact(artifact_id, artifact)
                return True
        return False

    def get_evidence_for_finding(self, vuln_id: str) -> list[dict[str, Any]]:
        """Get all evidence artifacts linked to a specific finding."""
        return [a for a in self._artifacts if a.get("vuln_id") == vuln_id]

    def get_all_artifacts(self) -> list[dict[str, Any]]:
        return list(self._artifacts)

    def generate_evidence_index(self) -> Path:
        """Generate a markdown index of all evidence artifacts."""
        index_path = self._evidence_dir / "INDEX.md"

        lines = ["# Evidence Index\n"]
        lines.append(f"**Total artifacts:** {len(self._artifacts)}\n")

        # Group by vulnerability
        by_vuln: dict[str, list[dict[str, Any]]] = {}
        unlinked: list[dict[str, Any]] = []

        for artifact in self._artifacts:
            vid = artifact.get("vuln_id")
            if vid:
                by_vuln.setdefault(vid, []).append(artifact)
            else:
                unlinked.append(artifact)

        for vuln_id, artifacts in sorted(by_vuln.items()):
            lines.append(f"\n## {vuln_id}\n")
            for a in artifacts:
                lines.append(f"- **{a['id']}** ({a['type']}) — {a.get('description', '')}")
                if a["type"] == "http":
                    req = a.get("request", {})
                    resp = a.get("response", {})
                    lines.append(f"  - `{req.get('method', '?')} {req.get('url', '?')}` → {resp.get('status_code', '?')}")
                elif a["type"] == "command":
                    lines.append(f"  - `{a.get('command', '?')[:80]}`")
                elif a["type"] == "screenshot":
                    lines.append(f"  - ![{a['id']}]({a.get('file', '')})")

        if unlinked:
            lines.append("\n## Unlinked Evidence\n")
            for a in unlinked:
                lines.append(f"- **{a['id']}** ({a['type']}) — {a.get('description', '')}")

        index_path.write_text("\n".join(lines), encoding="utf-8")
        return index_path

    def _save_artifact(self, artifact_id: str, artifact: dict[str, Any]) -> None:
        """Save artifact metadata as JSON."""
        path = self._evidence_dir / f"{artifact_id}.json"
        try:
            # Don't save large binary data in JSON
            save_data = {k: v for k, v in artifact.items() if k != "screenshot_b64"}
            path.write_text(json.dumps(save_data, indent=2, default=str), encoding="utf-8")
        except OSError as e:
            logger.warning("Failed to save artifact %s: %s", artifact_id, e)

    @staticmethod
    def _truncate(text: str | None, max_len: int) -> str:
        if not text:
            return ""
        if len(text) <= max_len:
            return text
        half = max_len // 2
        return text[:half] + "\n\n... [truncated] ...\n\n" + text[-half:]
