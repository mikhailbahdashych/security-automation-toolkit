"""Markdown reporter for generating Markdown output."""

from datetime import datetime
from pathlib import Path
from typing import Any

from security_toolkit.reporting.base import BaseReporter
from security_toolkit.tools.base import ToolResult


class MarkdownReporter(BaseReporter):
    """Reporter for Markdown format output."""

    format = "markdown"
    extension = ".md"

    def generate(self, result: ToolResult, output_path: Path | None = None) -> str:
        """Generate a Markdown report."""
        lines: list[str] = []

        # Header
        lines.append(f"# {result.tool_name.replace('-', ' ').title()} Report")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Status:** {'Success' if result.success else 'Failed'}")
        if result.started_at and result.completed_at:
            duration = result.completed_at - result.started_at
            lines.append(f"**Duration:** {duration}")
        lines.append("")

        # Summary section
        if result.summary:
            lines.append("## Summary")
            lines.append("")
            lines.append(self._format_summary(result.summary))
            lines.append("")

        # Errors section
        if result.errors:
            lines.append("## Errors")
            lines.append("")
            for error in result.errors:
                lines.append(f"- {error}")
            lines.append("")

        # Warnings section
        if result.warnings:
            lines.append("## Warnings")
            lines.append("")
            for warning in result.warnings:
                lines.append(f"- {warning}")
            lines.append("")

        # Findings section
        if result.findings:
            lines.append("## Findings")
            lines.append("")
            lines.append(self._format_findings(result.findings))

        content = "\n".join(lines)

        if output_path:
            self.save(content, output_path)

        return content

    def _format_summary(self, summary: dict[str, Any]) -> str:
        """Format summary section as Markdown."""
        lines: list[str] = []

        for key, value in summary.items():
            formatted_key = key.replace("_", " ").title()

            if isinstance(value, dict):
                lines.append(f"### {formatted_key}")
                lines.append("")
                for k, v in value.items():
                    lines.append(f"- **{k}:** {v}")
                lines.append("")
            elif isinstance(value, list):
                lines.append(f"### {formatted_key}")
                lines.append("")
                for item in value[:10]:  # Limit list items
                    if isinstance(item, dict):
                        item_str = ", ".join(f"{k}: {v}" for k, v in item.items())
                        lines.append(f"- {item_str}")
                    else:
                        lines.append(f"- {item}")
                if len(value) > 10:
                    lines.append(f"- ... and {len(value) - 10} more")
                lines.append("")
            else:
                lines.append(f"- **{formatted_key}:** {value}")

        return "\n".join(lines)

    def _format_findings(self, findings: list[Any]) -> str:
        """Format findings section as Markdown."""
        lines: list[str] = []

        # Group findings by severity if available
        severity_order = ["critical", "high", "medium", "low", "info"]
        grouped: dict[str, list[Any]] = {s: [] for s in severity_order}
        ungrouped: list[Any] = []

        for finding in findings:
            if isinstance(finding, dict) and "severity" in finding:
                severity = finding["severity"].lower()
                if severity in grouped:
                    grouped[severity].append(finding)
                else:
                    ungrouped.append(finding)
            else:
                ungrouped.append(finding)

        # Output grouped findings
        for severity in severity_order:
            items = grouped[severity]
            if items:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}.get(severity, "⚪")
                lines.append(f"### {emoji} {severity.title()} ({len(items)})")
                lines.append("")

                for finding in items:
                    lines.append(self._format_finding(finding))
                    lines.append("")

        # Output ungrouped findings
        if ungrouped:
            lines.append("### Other Findings")
            lines.append("")
            for finding in ungrouped:
                lines.append(self._format_finding(finding))
                lines.append("")

        return "\n".join(lines)

    def _format_finding(self, finding: Any) -> str:
        """Format a single finding."""
        if not isinstance(finding, dict):
            return f"- {finding}"

        lines: list[str] = []

        # Title or main identifier
        title = finding.get("title") or finding.get("finding_type") or finding.get("control_id") or "Finding"
        lines.append(f"#### {title}")
        lines.append("")

        # Resource info
        resource_type = finding.get("resource_type")
        resource_name = finding.get("resource_name")
        if resource_type or resource_name:
            lines.append(f"**Resource:** {resource_type or ''} - {resource_name or ''}")

        # Host/port for vulnerabilities
        host = finding.get("host")
        port = finding.get("port")
        if host:
            lines.append(f"**Host:** {host}" + (f":{port}" if port else ""))

        # Description
        description = finding.get("description")
        if description:
            lines.append("")
            lines.append(description[:500] + ("..." if len(description) > 500 else ""))

        # Recommendation
        recommendation = finding.get("recommendation")
        if recommendation:
            lines.append("")
            lines.append(f"**Recommendation:** {recommendation}")

        # CVEs
        cve_ids = finding.get("cve_ids")
        if cve_ids:
            lines.append(f"**CVEs:** {', '.join(cve_ids[:5])}")

        return "\n".join(lines)
