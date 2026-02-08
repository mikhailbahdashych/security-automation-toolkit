"""Reporting module for generating output in various formats."""

from security_toolkit.reporting.base import BaseReporter
from security_toolkit.reporting.csv_reporter import CSVReporter
from security_toolkit.reporting.html_reporter import HTMLReporter
from security_toolkit.reporting.json_reporter import JSONReporter
from security_toolkit.reporting.markdown_reporter import MarkdownReporter

__all__ = [
    "BaseReporter",
    "CSVReporter",
    "HTMLReporter",
    "JSONReporter",
    "MarkdownReporter",
]


def get_reporter(format: str) -> BaseReporter:
    """Get a reporter instance by format name."""
    reporters = {
        "json": JSONReporter,
        "csv": CSVReporter,
        "html": HTMLReporter,
        "md": MarkdownReporter,
        "markdown": MarkdownReporter,
    }

    reporter_class = reporters.get(format.lower())
    if not reporter_class:
        raise ValueError(f"Unsupported format: {format}. Supported: {', '.join(reporters.keys())}")

    return reporter_class()
