"""HTML reporter for generating professional HTML reports."""

from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from security_toolkit.reporting.base import BaseReporter
from security_toolkit.tools.base import ToolResult


class HTMLReporter(BaseReporter):
    """Reporter for HTML format output with professional templates."""

    format = "html"
    extension = ".html"

    def __init__(self) -> None:
        """Initialize the HTML reporter."""
        self._env: Environment | None = None

    @property
    def env(self) -> Environment:
        """Get Jinja2 environment."""
        if self._env is None:
            try:
                self._env = Environment(
                    loader=PackageLoader("security_toolkit", "reporting/templates"),
                    autoescape=select_autoescape(["html", "xml"]),
                )
            except Exception:
                # Fallback to inline template if package loader fails
                from jinja2 import BaseLoader

                self._env = Environment(
                    loader=BaseLoader(),
                    autoescape=select_autoescape(["html", "xml"]),
                )
        return self._env

    def generate(self, result: ToolResult, output_path: Path | None = None) -> str:
        """Generate an HTML report."""
        data = self.prepare_data(result)
        data["generated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data["severity_stats"] = self._calculate_severity_stats(result.findings)

        try:
            template = self.env.get_template("report.html")
            content = template.render(**data)
        except Exception:
            # Fallback to inline template
            content = self._generate_inline_html(data)

        if output_path:
            self.save(content, output_path)

        return content

    def _calculate_severity_stats(self, findings: list[Any]) -> dict[str, int]:
        """Calculate severity statistics from findings."""
        stats: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in findings:
            if isinstance(finding, dict) and "severity" in finding:
                severity = finding["severity"].lower()
                if severity in stats:
                    stats[severity] += 1

        return stats

    def _generate_inline_html(self, data: dict[str, Any]) -> str:
        """Generate HTML using inline template."""
        severity_stats = data.get("severity_stats", {})
        findings = data.get("findings", [])
        summary = data.get("summary", {})

        findings_html = ""
        for finding in findings:
            if isinstance(finding, dict):
                severity = finding.get("severity", "info").lower()
                severity_class = f"severity-{severity}"
                title = finding.get("title") or finding.get("finding_type") or "Finding"
                description = finding.get("description", "")[:300]
                resource = finding.get("resource_name") or finding.get("host") or ""

                findings_html += f"""
                <div class="finding {severity_class}">
                    <div class="finding-header">
                        <span class="severity-badge {severity}">{severity.upper()}</span>
                        <span class="finding-title">{self._escape_html(title)}</span>
                    </div>
                    <div class="finding-resource">{self._escape_html(resource)}</div>
                    <div class="finding-description">{self._escape_html(description)}</div>
                </div>
                """

        summary_html = ""
        for key, value in summary.items():
            formatted_key = key.replace("_", " ").title()
            if isinstance(value, dict):
                value_str = ", ".join(f"{k}: {v}" for k, v in value.items())
            elif isinstance(value, list):
                value_str = str(len(value)) + " items"
            else:
                value_str = str(value)
            summary_html += f"<tr><td>{formatted_key}</td><td>{self._escape_html(value_str)}</td></tr>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self._escape_html(data.get('tool_name', 'Security'))} Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        .header h1 {{ font-size: 24px; margin-bottom: 10px; }}
        .header .meta {{ opacity: 0.8; font-size: 14px; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .stat-card .value {{ font-size: 32px; font-weight: bold; }}
        .stat-card .label {{ color: #666; font-size: 14px; }}
        .stat-card.critical .value {{ color: #dc3545; }}
        .stat-card.high .value {{ color: #fd7e14; }}
        .stat-card.medium .value {{ color: #ffc107; }}
        .stat-card.low .value {{ color: #28a745; }}
        .stat-card.info .value {{ color: #17a2b8; }}
        .section {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            font-size: 18px;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        table td {{ padding: 10px; border-bottom: 1px solid #eee; }}
        table td:first-child {{ font-weight: 500; width: 200px; color: #666; }}
        .finding {{
            border-left: 4px solid #ddd;
            padding: 15px;
            margin-bottom: 15px;
            background: #fafafa;
            border-radius: 0 8px 8px 0;
        }}
        .finding.severity-critical {{ border-left-color: #dc3545; }}
        .finding.severity-high {{ border-left-color: #fd7e14; }}
        .finding.severity-medium {{ border-left-color: #ffc107; }}
        .finding.severity-low {{ border-left-color: #28a745; }}
        .finding.severity-info {{ border-left-color: #17a2b8; }}
        .finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
        .severity-badge {{
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            color: white;
        }}
        .severity-badge.critical {{ background: #dc3545; }}
        .severity-badge.high {{ background: #fd7e14; }}
        .severity-badge.medium {{ background: #ffc107; color: #333; }}
        .severity-badge.low {{ background: #28a745; }}
        .severity-badge.info {{ background: #17a2b8; }}
        .finding-title {{ font-weight: 600; }}
        .finding-resource {{ color: #666; font-size: 13px; margin-bottom: 5px; }}
        .finding-description {{ font-size: 14px; color: #555; }}
        .errors {{ background: #fff5f5; border-left: 4px solid #dc3545; padding: 15px; margin-bottom: 20px; border-radius: 0 8px 8px 0; }}
        .errors h3 {{ color: #dc3545; margin-bottom: 10px; }}
        .errors ul {{ margin-left: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{self._escape_html(data.get('tool_name', 'Security').replace('-', ' ').title())} Report</h1>
            <div class="meta">
                Generated: {data.get('generated_at', '')} |
                Status: {'Success' if data.get('success') else 'Failed'} |
                Duration: {data.get('duration', 'N/A')}
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card critical">
                <div class="value">{severity_stats.get('critical', 0)}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="value">{severity_stats.get('high', 0)}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="value">{severity_stats.get('medium', 0)}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="value">{severity_stats.get('low', 0)}</div>
                <div class="label">Low</div>
            </div>
            <div class="stat-card info">
                <div class="value">{severity_stats.get('info', 0)}</div>
                <div class="label">Info</div>
            </div>
        </div>

        {"<div class='errors'><h3>Errors</h3><ul>" + "".join(f"<li>{self._escape_html(e)}</li>" for e in data.get('errors', [])) + "</ul></div>" if data.get('errors') else ""}

        <div class="section">
            <h2>Summary</h2>
            <table>{summary_html}</table>
        </div>

        <div class="section">
            <h2>Findings ({len(findings)})</h2>
            {findings_html if findings_html else "<p>No findings to report.</p>"}
        </div>
    </div>
</body>
</html>"""

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )
