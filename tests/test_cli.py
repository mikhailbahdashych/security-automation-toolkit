"""Tests for CLI commands."""

from typer.testing import CliRunner

import pytest

from security_toolkit.cli.main import app


runner = CliRunner()


class TestCLI:
    """Tests for CLI commands."""

    def test_help(self):
        """Test help command."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "Security Automation Toolkit" in result.output

    def test_version(self):
        """Test version command."""
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "Security Automation Toolkit" in result.output

    def test_info(self):
        """Test info command."""
        result = runner.invoke(app, ["info"])
        assert result.exit_code == 0
        assert "Available Tools" in result.output

    def test_stats(self):
        """Test stats command."""
        result = runner.invoke(app, ["stats"])
        assert result.exit_code == 0
        assert "Execution Statistics" in result.output or "Scripts" in result.output


class TestAccessReviewCLI:
    """Tests for access-review CLI commands."""

    def test_help(self):
        """Test access-review help."""
        result = runner.invoke(app, ["access-review", "--help"])
        assert result.exit_code == 0
        assert "IAM" in result.output or "access" in result.output


class TestVulnScanCLI:
    """Tests for vuln-scan CLI commands."""

    def test_help(self):
        """Test vuln-scan help."""
        result = runner.invoke(app, ["vuln-scan", "--help"])
        assert result.exit_code == 0
        assert "vulnerability" in result.output.lower() or "scan" in result.output.lower()

    def test_parse_missing_file(self):
        """Test parsing with missing file."""
        result = runner.invoke(app, ["vuln-scan", "parse", "--input", "/nonexistent.nessus"])
        assert result.exit_code != 0
        assert "not found" in result.output.lower() or "error" in result.output.lower()

    def test_parse_with_file(self, sample_nessus_xml):
        """Test parsing a valid file."""
        result = runner.invoke(
            app,
            ["vuln-scan", "parse", "--input", str(sample_nessus_xml)],
        )
        assert result.exit_code == 0
        assert "Vulnerability" in result.output or "vulnerabilities" in result.output.lower()


class TestComplianceCLI:
    """Tests for compliance CLI commands."""

    def test_help(self):
        """Test compliance help."""
        result = runner.invoke(app, ["compliance", "--help"])
        assert result.exit_code == 0
        assert "compliance" in result.output.lower()

    def test_frameworks(self):
        """Test frameworks list."""
        result = runner.invoke(app, ["compliance", "frameworks"])
        assert result.exit_code == 0
        assert "SOC" in result.output or "soc2" in result.output.lower()
        assert "ISO" in result.output or "iso27001" in result.output.lower()


class TestLogAnalyzerCLI:
    """Tests for log-analyzer CLI commands."""

    def test_help(self):
        """Test log-analyzer help."""
        result = runner.invoke(app, ["log-analyzer", "--help"])
        assert result.exit_code == 0
        assert "log" in result.output.lower()

    def test_analyze_missing_file(self):
        """Test analyze with missing file."""
        result = runner.invoke(app, ["log-analyzer", "analyze", "--input", "/nonexistent.log"])
        assert result.exit_code != 0

    def test_analyze_auth_log(self, sample_auth_log):
        """Test analyzing auth.log."""
        result = runner.invoke(
            app,
            ["log-analyzer", "analyze", "--input", str(sample_auth_log)],
        )
        assert result.exit_code == 0
        assert "Analysis" in result.output or "events" in result.output.lower()


class TestScriptsCLI:
    """Tests for scripts CLI commands."""

    def test_help(self):
        """Test scripts help."""
        result = runner.invoke(app, ["scripts", "--help"])
        assert result.exit_code == 0
        assert "script" in result.output.lower()

    def test_list_empty(self):
        """Test listing scripts when empty."""
        result = runner.invoke(app, ["scripts", "list"])
        # Should succeed even with no scripts
        assert result.exit_code == 0

    def test_register_missing_file(self):
        """Test registering with missing file."""
        result = runner.invoke(
            app,
            ["scripts", "register", "test", "--path", "/nonexistent.py"],
        )
        assert result.exit_code != 0

    def test_categories(self):
        """Test categories command."""
        result = runner.invoke(app, ["scripts", "categories"])
        assert result.exit_code == 0
