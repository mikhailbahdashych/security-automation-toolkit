"""Log Analyzer CLI commands."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from security_toolkit.reporting import get_reporter
from security_toolkit.tools.log_analyzer import LogAnalyzerTool

console = Console()
app = typer.Typer(help="Security log analysis")


@app.command()
def analyze(
    input_file: Annotated[
        Path,
        typer.Option("--input", "-i", help="Path to log file"),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file path"),
    ] = None,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format (json, csv, html, md)"),
    ] = "json",
    log_type: Annotated[
        str,
        typer.Option("--type", "-t", help="Log type (auto, auth, syslog, cloudtrail)"),
    ] = "auto",
    pattern: Annotated[
        str | None,
        typer.Option("--pattern", "-p", help="Filter pattern (failed-logins, successful-logins, sudo)"),
    ] = None,
    time_range: Annotated[
        str | None,
        typer.Option("--time-range", help="Time range filter (e.g., 1h, 24h, 7d)"),
    ] = None,
) -> None:
    """Analyze security log file."""
    if not input_file.exists():
        console.print(f"[red]Error:[/red] Input file not found: {input_file}")
        raise typer.Exit(1)

    console.print(f"[bold blue]Analyzing log file:[/bold blue] {input_file}")

    tool = LogAnalyzerTool()
    result = tool.execute(
        input_file=str(input_file),
        log_type=log_type,
        pattern=pattern,
        time_range=time_range,
    )

    if result.errors:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        raise typer.Exit(1)

    # Display summary
    _display_summary(result.summary)

    # Display anomalies
    anomalies = result.summary.get("anomalies", [])
    if anomalies:
        _display_anomalies(anomalies)

    # Display failed attempts
    if result.findings:
        _display_failed_attempts(result.findings)

    # Generate report
    if output:
        reporter = get_reporter(format)
        reporter.generate(result, output)
        console.print(f"\n[green]Report saved to:[/green] {output}")


@app.command()
def failed_logins(
    input_file: Annotated[
        Path,
        typer.Option("--input", "-i", help="Path to auth.log file"),
    ],
    time_range: Annotated[
        str | None,
        typer.Option("--time-range", help="Time range filter (e.g., 1h, 24h, 7d)"),
    ] = None,
) -> None:
    """Show failed login attempts from auth.log."""
    if not input_file.exists():
        console.print(f"[red]Error:[/red] Input file not found: {input_file}")
        raise typer.Exit(1)

    tool = LogAnalyzerTool()
    result = tool.execute(
        input_file=str(input_file),
        log_type="auth",
        pattern="failed-logins",
        time_range=time_range,
    )

    if result.errors:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        raise typer.Exit(1)

    console.print(f"\n[bold]Failed Login Attempts[/bold] ({len(result.findings)} total)")

    if result.findings:
        _display_failed_attempts(result.findings)
    else:
        console.print("[green]No failed login attempts found.[/green]")


@app.command()
def top_sources(
    input_file: Annotated[
        Path,
        typer.Option("--input", "-i", help="Path to log file"),
    ],
    limit: Annotated[
        int,
        typer.Option("--limit", "-n", help="Number of top sources to show"),
    ] = 10,
) -> None:
    """Show top source IPs from log file."""
    if not input_file.exists():
        console.print(f"[red]Error:[/red] Input file not found: {input_file}")
        raise typer.Exit(1)

    tool = LogAnalyzerTool()
    result = tool.execute(input_file=str(input_file))

    if result.errors:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        raise typer.Exit(1)

    top_sources = result.summary.get("top_sources", [])[:limit]

    console.print(f"\n[bold]Top {limit} Source IPs[/bold]")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Rank", justify="right", width=6)
    table.add_column("Source IP", width=20)
    table.add_column("Count", justify="right", width=10)

    for i, source in enumerate(top_sources, 1):
        table.add_row(
            str(i),
            source.get("source", ""),
            str(source.get("count", 0)),
        )

    console.print(table)


@app.command()
def top_users(
    input_file: Annotated[
        Path,
        typer.Option("--input", "-i", help="Path to log file"),
    ],
    limit: Annotated[
        int,
        typer.Option("--limit", "-n", help="Number of top users to show"),
    ] = 10,
) -> None:
    """Show top users from log file."""
    if not input_file.exists():
        console.print(f"[red]Error:[/red] Input file not found: {input_file}")
        raise typer.Exit(1)

    tool = LogAnalyzerTool()
    result = tool.execute(input_file=str(input_file))

    if result.errors:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        raise typer.Exit(1)

    top_users = result.summary.get("top_users", [])[:limit]

    console.print(f"\n[bold]Top {limit} Users[/bold]")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Rank", justify="right", width=6)
    table.add_column("User", width=25)
    table.add_column("Events", justify="right", width=10)

    for i, user in enumerate(top_users, 1):
        table.add_row(
            str(i),
            user.get("user", ""),
            str(user.get("count", 0)),
        )

    console.print(table)


def _display_summary(summary: dict) -> None:
    """Display analysis summary."""
    console.print("\n[bold]Analysis Summary[/bold]")

    table = Table(show_header=False, box=None)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")

    table.add_row("Total Events", str(summary.get("total_events", 0)))

    time_range = summary.get("time_range", {})
    if time_range.get("start"):
        table.add_row("Time Range Start", time_range["start"])
    if time_range.get("end"):
        table.add_row("Time Range End", time_range["end"])

    table.add_row("Failed Attempts", str(summary.get("failed_attempts_count", 0)))

    console.print(table)
    console.print()

    # Events by type
    by_type = summary.get("events_by_type", {})
    if by_type:
        type_table = Table(title="Events by Type", show_header=True, header_style="bold")
        type_table.add_column("Type", width=25)
        type_table.add_column("Count", justify="right")

        for event_type, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:10]:
            type_table.add_row(event_type, str(count))

        console.print(type_table)


def _display_anomalies(anomalies: list) -> None:
    """Display detected anomalies."""
    console.print("\n[bold red]Anomalies Detected[/bold red]")

    for anomaly in anomalies:
        anomaly_type = anomaly.get("type", "unknown")
        severity = anomaly.get("severity", "medium")

        severity_style = {
            "high": "bold red",
            "medium": "yellow",
            "low": "blue",
        }.get(severity, "white")

        console.print(f"\n[{severity_style}][{severity.upper()}][/{severity_style}] {anomaly_type}")

        # Display anomaly details
        for key, value in anomaly.items():
            if key not in ["type", "severity"]:
                console.print(f"  {key}: {value}")


def _display_failed_attempts(findings: list) -> None:
    """Display failed login attempts."""
    console.print("\n[bold]Recent Failed Attempts[/bold]")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Timestamp", width=20)
    table.add_column("User", width=15)
    table.add_column("Source IP", width=18)
    table.add_column("Type", width=20)

    from datetime import datetime as dt

    for finding in findings[:20]:
        timestamp = finding.get("timestamp", "")
        if isinstance(timestamp, dt):
            timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        elif isinstance(timestamp, str) and "T" in timestamp:
            timestamp_str = timestamp.split("T")[0] + " " + timestamp.split("T")[1][:8]
        else:
            timestamp_str = str(timestamp)[:19] if timestamp else ""

        user = finding.get("user") or ""
        source_ip = finding.get("source_ip") or ""

        table.add_row(
            timestamp_str,
            user[:13],
            source_ip[:16],
            finding.get("event_type", ""),
        )

    console.print(table)

    if len(findings) > 20:
        console.print(f"[dim]... and {len(findings) - 20} more attempts[/dim]")
