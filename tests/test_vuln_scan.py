"""Tests for vulnerability scan tool."""

import pytest

from security_toolkit.tools.vuln_scan import VulnScanTool


class TestVulnScanTool:
    """Tests for VulnScanTool."""

    def test_parse_nessus(self, sample_nessus_xml):
        """Test parsing Nessus XML file."""
        tool = VulnScanTool()
        result = tool.run(input_file=str(sample_nessus_xml), scanner_type="nessus")

        assert result.success
        assert len(result.findings) == 2
        assert result.summary["total_vulnerabilities"] == 2

    def test_auto_detect_nessus(self, sample_nessus_xml):
        """Test auto-detection of Nessus format."""
        tool = VulnScanTool()
        result = tool.run(input_file=str(sample_nessus_xml), scanner_type="auto")

        assert result.success
        assert result.data["scanner_type"] == "nessus"

    def test_min_severity_filter(self, sample_nessus_xml):
        """Test filtering by minimum severity."""
        tool = VulnScanTool()
        result = tool.run(
            input_file=str(sample_nessus_xml),
            scanner_type="nessus",
            min_severity="high",
        )

        assert result.success
        # Only high severity should be included
        assert all(f["severity"] == "high" for f in result.findings)

    def test_file_not_found(self, temp_dir):
        """Test handling of missing file."""
        tool = VulnScanTool()
        result = tool.run(input_file=str(temp_dir / "nonexistent.nessus"))

        assert not result.success
        assert len(result.errors) > 0

    def test_summary_generation(self, sample_nessus_xml):
        """Test summary statistics generation."""
        tool = VulnScanTool()
        result = tool.run(input_file=str(sample_nessus_xml))

        summary = result.summary
        assert "total_vulnerabilities" in summary
        assert "unique_hosts" in summary
        assert "by_severity" in summary

    def test_cve_extraction(self, sample_nessus_xml):
        """Test CVE ID extraction."""
        tool = VulnScanTool()
        result = tool.run(input_file=str(sample_nessus_xml))

        # Find the finding with CVE
        vulns_with_cve = [f for f in result.findings if f.get("cve_ids")]
        assert len(vulns_with_cve) >= 1
        assert "CVE-2021-1234" in vulns_with_cve[0]["cve_ids"]
