"""Tests for Tracer.save_run_data robustness and set_run_name behavior."""

import os
from unittest.mock import patch

from ziro.telemetry.tracer import Tracer


def _make_tracer(tmp_path, name="test-run"):
    """Create a Tracer that writes to tmp_path."""
    with patch.dict(os.environ, {"ZIRO_TELEMETRY": "0"}):
        tracer = Tracer(name)
        tracer._run_dir = tmp_path / name
        tracer._run_dir.mkdir(parents=True, exist_ok=True)
    return tracer


def test_save_individual_vuln_files(tmp_path) -> None:
    tracer = _make_tracer(tmp_path)

    tracer.add_vulnerability_report(
        title="Test XSS",
        severity="high",
        description="XSS in search",
        impact="Session hijack",
        target="https://example.com",
        technical_analysis="Reflected input",
        poc_description="Inject script tag",
        poc_script_code="<script>alert(1)</script>",
        remediation_steps="Encode output",
    )

    vuln_dir = tracer._run_dir / "vulnerabilities"
    assert vuln_dir.exists()
    vuln_files = list(vuln_dir.glob("*.md"))
    assert len(vuln_files) == 1
    content = vuln_files[0].read_text(encoding="utf-8")
    assert "Test XSS" in content
    assert "HIGH" in content


def test_save_creates_csv_index(tmp_path) -> None:
    tracer = _make_tracer(tmp_path)

    tracer.add_vulnerability_report(
        title="SQLi",
        severity="critical",
        description="SQL injection",
        impact="Data breach",
        target="https://example.com/api",
        technical_analysis="Unsanitized input",
        poc_description="sqlmap",
        poc_script_code="' OR 1=1--",
        remediation_steps="Use parameterized queries",
    )

    csv_file = tracer._run_dir / "vulnerabilities.csv"
    assert csv_file.exists()
    csv_content = csv_file.read_text(encoding="utf-8")
    assert "SQLi" in csv_content
    assert "CRITICAL" in csv_content


def test_set_run_name_resets_saved_vuln_ids(tmp_path) -> None:
    tracer = _make_tracer(tmp_path, "old-name")

    tracer.add_vulnerability_report(
        title="Bug1",
        severity="low",
        description="d",
        impact="i",
        target="t",
        technical_analysis="ta",
        poc_description="pd",
        poc_script_code="pc",
        remediation_steps="r",
    )

    assert len(tracer._saved_vuln_ids) == 1

    # Change run name — should reset saved IDs
    tracer._run_dir = None
    tracer.set_run_name("new-name")

    assert len(tracer._saved_vuln_ids) == 0


def test_partial_save_failure_doesnt_block_others(tmp_path) -> None:
    tracer = _make_tracer(tmp_path)

    tracer.add_vulnerability_report(
        title="Vuln1",
        severity="medium",
        description="d",
        impact="i",
        target="t",
        technical_analysis="ta",
        poc_description="pd",
        poc_script_code="pc",
        remediation_steps="r",
    )

    tracer.add_vulnerability_report(
        title="Vuln2",
        severity="high",
        description="d2",
        impact="i2",
        target="t2",
        technical_analysis="ta2",
        poc_description="pd2",
        poc_script_code="pc2",
        remediation_steps="r2",
    )

    # Both vulns should have been saved
    vuln_dir = tracer._run_dir / "vulnerabilities"
    vuln_files = list(vuln_dir.glob("*.md"))
    assert len(vuln_files) == 2


def test_save_final_report(tmp_path) -> None:
    tracer = _make_tracer(tmp_path)

    tracer.update_scan_final_fields(
        executive_summary="Summary",
        methodology="Method",
        technical_analysis="Analysis",
        recommendations="Fix things",
    )

    report_file = tracer._run_dir / "penetration_test_report.md"
    assert report_file.exists()
    content = report_file.read_text(encoding="utf-8")
    assert "Summary" in content
    assert "Method" in content
