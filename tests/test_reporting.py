"""Tests for reporting module."""

import json
from datetime import datetime

import pytest

from security_toolkit.reporting import (
    CSVReporter,
    HTMLReporter,
    JSONReporter,
    MarkdownReporter,
    get_reporter,
)
from security_toolkit.tools.base import ToolResult


@pytest.fixture
def sample_result():
    """Create a sample tool result for testing."""
    return ToolResult(
        tool_name="test-tool",
        success=True,
        started_at=datetime(2024, 1, 15, 10, 0, 0),
        completed_at=datetime(2024, 1, 15, 10, 5, 0),
        summary={
            "total_findings": 3,
            "by_severity": {"high": 1, "medium": 2},
        },
        findings=[
            {
                "severity": "high",
                "title": "Critical Issue",
                "description": "This is critical",
                "resource_name": "resource1",
            },
            {
                "severity": "medium",
                "title": "Medium Issue 1",
                "description": "Medium priority",
                "resource_name": "resource2",
            },
            {
                "severity": "medium",
                "title": "Medium Issue 2",
                "description": "Another medium",
                "resource_name": "resource3",
            },
        ],
    )


class TestGetReporter:
    """Tests for get_reporter function."""

    def test_get_json_reporter(self):
        """Test getting JSON reporter."""
        reporter = get_reporter("json")
        assert isinstance(reporter, JSONReporter)

    def test_get_csv_reporter(self):
        """Test getting CSV reporter."""
        reporter = get_reporter("csv")
        assert isinstance(reporter, CSVReporter)

    def test_get_html_reporter(self):
        """Test getting HTML reporter."""
        reporter = get_reporter("html")
        assert isinstance(reporter, HTMLReporter)

    def test_get_markdown_reporter(self):
        """Test getting Markdown reporter."""
        reporter = get_reporter("md")
        assert isinstance(reporter, MarkdownReporter)

    def test_invalid_format(self):
        """Test invalid format raises error."""
        with pytest.raises(ValueError):
            get_reporter("invalid")


class TestJSONReporter:
    """Tests for JSONReporter."""

    def test_generate_json(self, sample_result):
        """Test JSON report generation."""
        reporter = JSONReporter()
        content = reporter.generate(sample_result)

        data = json.loads(content)
        assert data["tool_name"] == "test-tool"
        assert data["success"] is True
        assert len(data["findings"]) == 3

    def test_save_json(self, sample_result, temp_dir):
        """Test saving JSON report to file."""
        reporter = JSONReporter()
        output_path = temp_dir / "report.json"
        reporter.generate(sample_result, output_path)

        assert output_path.exists()
        with open(output_path) as f:
            data = json.load(f)
        assert data["tool_name"] == "test-tool"


class TestCSVReporter:
    """Tests for CSVReporter."""

    def test_generate_csv(self, sample_result):
        """Test CSV report generation."""
        reporter = CSVReporter()
        content = reporter.generate(sample_result)

        lines = content.strip().split("\n")
        assert len(lines) == 4  # Header + 3 findings
        assert "severity" in lines[0]
        assert "high" in lines[1]

    def test_csv_empty_findings(self):
        """Test CSV with no findings."""
        result = ToolResult(tool_name="empty", findings=[])
        reporter = CSVReporter()
        content = reporter.generate(result)

        assert content == ""


class TestHTMLReporter:
    """Tests for HTMLReporter."""

    def test_generate_html(self, sample_result):
        """Test HTML report generation."""
        reporter = HTMLReporter()
        content = reporter.generate(sample_result)

        assert "<!DOCTYPE html>" in content
        assert "test-tool" in content.lower() or "Test Tool" in content
        assert "Critical Issue" in content

    def test_html_severity_stats(self, sample_result):
        """Test severity statistics in HTML."""
        reporter = HTMLReporter()
        content = reporter.generate(sample_result)

        assert "Critical" in content or "critical" in content
        assert "High" in content or "high" in content


class TestMarkdownReporter:
    """Tests for MarkdownReporter."""

    def test_generate_markdown(self, sample_result):
        """Test Markdown report generation."""
        reporter = MarkdownReporter()
        content = reporter.generate(sample_result)

        assert "# " in content  # H1 header
        assert "## " in content  # H2 headers
        assert "**" in content  # Bold text

    def test_markdown_findings_grouped(self, sample_result):
        """Test findings are grouped by severity."""
        reporter = MarkdownReporter()
        content = reporter.generate(sample_result)

        # Check severity headers exist
        assert "High" in content or "high" in content
        assert "Medium" in content or "medium" in content

    def test_markdown_summary(self, sample_result):
        """Test summary section in Markdown."""
        reporter = MarkdownReporter()
        content = reporter.generate(sample_result)

        assert "Summary" in content
        assert "Total Findings" in content or "total_findings" in content
