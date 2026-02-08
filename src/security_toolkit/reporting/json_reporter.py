"""JSON reporter for generating JSON output."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from security_toolkit.reporting.base import BaseReporter
from security_toolkit.tools.base import ToolResult


class JSONReporter(BaseReporter):
    """Reporter for JSON format output."""

    format = "json"
    extension = ".json"

    def generate(self, result: ToolResult, output_path: Path | None = None) -> str:
        """Generate a JSON report."""
        data = self.prepare_data(result)

        # Use custom encoder for datetime objects
        content = json.dumps(data, indent=2, default=self._json_serializer)

        if output_path:
            self.save(content, output_path)

        return content

    def _json_serializer(self, obj: Any) -> Any:
        """Custom JSON serializer for objects not serializable by default."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Type {type(obj)} not serializable")
