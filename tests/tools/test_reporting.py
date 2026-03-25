"""Tests for reporting anti-hallucination and validation logic."""

from unittest.mock import MagicMock, patch

from ziro.tools.reporting.reporting_actions import (
    _is_blackbox_scan,
    _validate_code_locations,
    _validate_file_path,
    parse_code_locations_xml,
    parse_cvss_xml,
)


class TestIsBlackboxScan:
    def test_blackbox_when_only_urls(self) -> None:
        mock_tracer = MagicMock()
        mock_tracer.scan_config = {
            "targets": [
                {"type": "web_application", "details": {"target_url": "https://example.com"}},
            ]
        }
        with patch(
            "ziro.tools.reporting.reporting_actions.get_global_tracer",
            return_value=mock_tracer,
        ):
            assert _is_blackbox_scan() is True

    def test_not_blackbox_when_repo_present(self) -> None:
        mock_tracer = MagicMock()
        mock_tracer.scan_config = {
            "targets": [
                {"type": "web_application", "details": {}},
                {"type": "repository", "details": {"target_repo": "https://github.com/x/y"}},
            ]
        }
        with patch(
            "ziro.tools.reporting.reporting_actions.get_global_tracer",
            return_value=mock_tracer,
        ):
            assert _is_blackbox_scan() is False

    def test_not_blackbox_when_local_code(self) -> None:
        mock_tracer = MagicMock()
        mock_tracer.scan_config = {
            "targets": [{"type": "local_code", "details": {"target_path": "/code"}}]
        }
        with patch(
            "ziro.tools.reporting.reporting_actions.get_global_tracer",
            return_value=mock_tracer,
        ):
            assert _is_blackbox_scan() is False

    def test_blackbox_when_no_tracer(self) -> None:
        with patch(
            "ziro.tools.reporting.reporting_actions.get_global_tracer",
            return_value=None,
        ):
            assert _is_blackbox_scan() is False

    def test_blackbox_ip_only(self) -> None:
        mock_tracer = MagicMock()
        mock_tracer.scan_config = {
            "targets": [{"type": "ip_address", "details": {"target_ip": "10.0.0.1"}}]
        }
        with patch(
            "ziro.tools.reporting.reporting_actions.get_global_tracer",
            return_value=mock_tracer,
        ):
            assert _is_blackbox_scan() is True


class TestValidateFilePath:
    def test_rejects_absolute_path(self) -> None:
        assert _validate_file_path("/etc/passwd") is not None

    def test_rejects_traversal(self) -> None:
        assert _validate_file_path("../../secret") is not None

    def test_accepts_relative_path(self) -> None:
        assert _validate_file_path("src/main.py") is None

    def test_rejects_empty(self) -> None:
        assert _validate_file_path("") is not None


class TestParseCvssXml:
    def test_parses_valid_cvss(self) -> None:
        xml = (
            "<attack_vector>N</attack_vector>"
            "<attack_complexity>L</attack_complexity>"
            "<privileges_required>N</privileges_required>"
            "<user_interaction>N</user_interaction>"
            "<scope>U</scope>"
            "<confidentiality>H</confidentiality>"
            "<integrity>H</integrity>"
            "<availability>H</availability>"
        )
        result = parse_cvss_xml(xml)
        assert result is not None
        assert result["attack_vector"] == "N"
        assert result["availability"] == "H"

    def test_returns_none_for_empty(self) -> None:
        assert parse_cvss_xml("") is None
        assert parse_cvss_xml("   ") is None


class TestParseCodeLocationsXml:
    def test_parses_valid_location(self) -> None:
        xml = "<location><file>src/app.py</file><start_line>10</start_line><end_line>15</end_line></location>"
        result = parse_code_locations_xml(xml)
        assert result is not None
        assert len(result) == 1
        assert result[0]["file"] == "src/app.py"
        assert result[0]["start_line"] == 10

    def test_returns_none_for_empty(self) -> None:
        assert parse_code_locations_xml("") is None


class TestValidateCodeLocations:
    def test_rejects_absolute_file_path(self) -> None:
        locations = [{"file": "/etc/passwd", "start_line": 1, "end_line": 1}]
        errors = _validate_code_locations(locations)
        assert any("absolute" in e for e in errors)

    def test_accepts_valid_location(self) -> None:
        locations = [{"file": "src/app.py", "start_line": 10, "end_line": 20}]
        errors = _validate_code_locations(locations)
        assert errors == []

    def test_rejects_end_before_start(self) -> None:
        locations = [{"file": "app.py", "start_line": 20, "end_line": 10}]
        errors = _validate_code_locations(locations)
        assert any("end_line" in e for e in errors)
