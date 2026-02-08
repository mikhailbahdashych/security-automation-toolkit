"""Tests for log analyzer tool."""

import pytest

from security_toolkit.tools.log_analyzer import LogAnalyzerTool


class TestLogAnalyzerTool:
    """Tests for LogAnalyzerTool."""

    def test_parse_auth_log(self, sample_auth_log):
        """Test parsing auth.log file."""
        tool = LogAnalyzerTool()
        result = tool.run(input_file=str(sample_auth_log), log_type="auth")

        assert result.success
        assert result.summary["total_events"] > 0

    def test_auto_detect_auth_log(self, sample_auth_log):
        """Test auto-detection of auth.log format."""
        tool = LogAnalyzerTool()
        result = tool.run(input_file=str(sample_auth_log), log_type="auto")

        assert result.success
        assert result.data["log_type"] == "auth"

    def test_failed_logins_pattern(self, sample_auth_log):
        """Test filtering failed login attempts."""
        tool = LogAnalyzerTool()
        result = tool.run(
            input_file=str(sample_auth_log),
            log_type="auth",
            pattern="failed-logins",
        )

        assert result.success
        # Should only have failed login events
        for event in result.data.get("events", []):
            assert event["event_type"] in ["failed_password", "invalid_user"]

    def test_parse_cloudtrail(self, sample_cloudtrail_json):
        """Test parsing CloudTrail JSON file."""
        tool = LogAnalyzerTool()
        result = tool.run(input_file=str(sample_cloudtrail_json), log_type="cloudtrail")

        assert result.success
        assert result.summary["total_events"] > 0

    def test_top_sources(self, sample_auth_log):
        """Test top sources analysis."""
        tool = LogAnalyzerTool()
        result = tool.run(input_file=str(sample_auth_log))

        assert "top_sources" in result.summary
        assert len(result.summary["top_sources"]) > 0

    def test_top_users(self, sample_auth_log):
        """Test top users analysis."""
        tool = LogAnalyzerTool()
        result = tool.run(input_file=str(sample_auth_log))

        assert "top_users" in result.summary

    def test_file_not_found(self, temp_dir):
        """Test handling of missing file."""
        tool = LogAnalyzerTool()
        result = tool.run(input_file=str(temp_dir / "nonexistent.log"))

        assert not result.success
        assert len(result.errors) > 0

    def test_events_by_type(self, sample_auth_log):
        """Test event type counting."""
        tool = LogAnalyzerTool()
        result = tool.run(input_file=str(sample_auth_log))

        assert "events_by_type" in result.summary
        events_by_type = result.summary["events_by_type"]
        assert isinstance(events_by_type, dict)
