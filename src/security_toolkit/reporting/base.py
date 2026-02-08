"""Base class for reporters."""

from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any

from security_toolkit.tools.base import ToolResult


class BaseReporter(ABC):
    """Abstract base class for report generators."""

    format: str = "base"
    extension: str = ".txt"

    @abstractmethod
    def generate(self, result: ToolResult, output_path: Path | None = None) -> str:
        """
        Generate a report from tool results.

        Args:
            result: The tool result to report on
            output_path: Optional path to save the report

        Returns:
            The generated report content as a string
        """
        pass

    def save(self, content: str, output_path: Path) -> Path:
        """Save report content to file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        return output_path

    def get_default_filename(self, result: ToolResult) -> str:
        """Generate a default filename for the report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{result.tool_name}_{timestamp}{self.extension}"

    def prepare_data(self, result: ToolResult) -> dict[str, Any]:
        """Prepare data for report generation."""
        return {
            "tool_name": result.tool_name,
            "success": result.success,
            "started_at": result.started_at.isoformat() if result.started_at else None,
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
            "duration": self._calculate_duration(result),
            "summary": result.summary,
            "findings": result.findings,
            "errors": result.errors,
            "warnings": result.warnings,
            "data": result.data,
        }

    def _calculate_duration(self, result: ToolResult) -> str | None:
        """Calculate execution duration."""
        if result.started_at and result.completed_at:
            delta = result.completed_at - result.started_at
            return str(delta)
        return None
