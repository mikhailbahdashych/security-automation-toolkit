"""CSV reporter for generating CSV output."""

import csv
import io
from pathlib import Path
from typing import Any

from security_toolkit.reporting.base import BaseReporter
from security_toolkit.tools.base import ToolResult


class CSVReporter(BaseReporter):
    """Reporter for CSV format output."""

    format = "csv"
    extension = ".csv"

    def generate(self, result: ToolResult, output_path: Path | None = None) -> str:
        """Generate a CSV report from findings."""
        if not result.findings:
            return ""

        # Get all unique keys from findings
        all_keys: set[str] = set()
        for finding in result.findings:
            if isinstance(finding, dict):
                all_keys.update(finding.keys())

        if not all_keys:
            return ""

        # Order columns sensibly
        priority_cols = [
            "severity", "finding_type", "title", "resource_type", "resource_name",
            "host", "port", "description", "recommendation", "control_id", "status",
        ]
        ordered_cols = [c for c in priority_cols if c in all_keys]
        remaining_cols = sorted(all_keys - set(ordered_cols))
        columns = ordered_cols + remaining_cols

        # Generate CSV
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()

        for finding in result.findings:
            if isinstance(finding, dict):
                # Flatten nested dicts
                flat_finding = self._flatten_dict(finding)
                writer.writerow(flat_finding)

        content = output.getvalue()

        if output_path:
            self.save(content, output_path)

        return content

    def _flatten_dict(self, d: dict[str, Any], prefix: str = "") -> dict[str, Any]:
        """Flatten nested dictionaries."""
        items: dict[str, Any] = {}
        for key, value in d.items():
            new_key = f"{prefix}{key}" if prefix else key
            if isinstance(value, dict):
                items.update(self._flatten_dict(value, f"{new_key}_"))
            elif isinstance(value, list):
                items[new_key] = "; ".join(str(v) for v in value)
            else:
                items[new_key] = value
        return items
