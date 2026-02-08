"""Vulnerability Scan CLI commands."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from security_toolkit.reporting import get_reporter
from security_toolkit.tools.vuln_scan import VulnScanTool

console = Console()
app = typer.Typer(help="Vulnerability scan parsing and analysis")


@app.command()
def parse(
    input_file: Annotated[
        Path,
        typer.Option("--input", "-i", help="Path to vulnerability scan output file"),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file path"),
    ] = None,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format (json, csv, html, md)"),
    ] = "json",
    scanner_type: Annotated[
        str,
        typer.Option("--scanner", "-s", help="Scanner type (auto, nessus, qualys, openvas)"),
    ] = "auto",
    min_severity: Annotated[
        str,
        typer.Option("--min-severity", help="Minimum severity to include"),
    ] = "info",
) -> None:
    """Parse vulnerability scan output file."""
    if not input_file.exists():
        console.print(f"[red]Error:[/red] Input file not found: {input_file}")
        raise typer.Exit(1)

    console.print(f"[bold blue]Parsing vulnerability scan:[/bold blue] {input_file}")

    tool = VulnScanTool()
    result = tool.execute(
        input_file=str(input_file),
        scanner_type=scanner_type,
        min_severity=min_severity,
    )

    if result.errors:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        raise typer.Exit(1)

    # Display summary
    _display_summary(result.summary)

    # Display findings
    if result.findings:
        _display_findings(result.findings)

    # Generate report
    if output:
        reporter = get_reporter(format)
        reporter.generate(result, output)
        console.print(f"\n[green]Report saved to:[/green] {output}")
    elif format != "json":
        reporter = get_reporter(format)
        output = Path(reporter.get_default_filename(result))
        reporter.generate(result, output)
        console.print(f"\n[green]Report saved to:[/green] {output}")


@app.command()
def summary(
    input_file: Annotated[
        Path,
        typer.Option("--input", "-i", help="Path to vulnerability scan output file"),
    ],
    scanner_type: Annotated[
        str,
        typer.Option("--scanner", "-s", help="Scanner type (auto, nessus, qualys, openvas)"),
    ] = "auto",
) -> None:
    """Show summary of vulnerability scan without full parsing."""
    if not input_file.exists():
        console.print(f"[red]Error:[/red] Input file not found: {input_file}")
        raise typer.Exit(1)

    tool = VulnScanTool()
    result = tool.execute(
        input_file=str(input_file),
        scanner_type=scanner_type,
    )

    if result.errors:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        raise typer.Exit(1)

    _display_summary(result.summary)


def _display_summary(summary: dict) -> None:
    """Display summary statistics."""
    console.print("\n[bold]Vulnerability Summary[/bold]")

    # Main stats
    table = Table(show_header=False, box=None)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")

    table.add_row("Total Vulnerabilities", str(summary.get("total_vulnerabilities", 0)))
    table.add_row("Unique Hosts", str(summary.get("unique_hosts", 0)))
    table.add_row("Unique CVEs", str(summary.get("unique_cves", 0)))

    console.print(table)
    console.print()

    # Severity breakdown
    by_severity = summary.get("by_severity", {})
    if by_severity:
        sev_table = Table(title="By Severity", show_header=True, header_style="bold")
        sev_table.add_column("Severity", width=15)
        sev_table.add_column("Count", justify="right", width=10)
        sev_table.add_column("Bar", width=30)

        total = sum(by_severity.values()) or 1
        severity_styles = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "green",
            "info": "blue",
        }

        for severity in ["critical", "high", "medium", "low", "info"]:
            count = by_severity.get(severity, 0)
            style = severity_styles.get(severity, "white")
            bar_width = int(count / total * 25)
            bar = "[" + style + "]" + "█" * bar_width + "[/" + style + "]"

            sev_table.add_row(
                f"[{style}]{severity.upper()}[/{style}]",
                str(count),
                bar,
            )

        console.print(sev_table)


def _display_findings(findings: list) -> None:
    """Display top findings in a table."""
    console.print("\n[bold]Top Vulnerabilities[/bold]")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity", width=10)
    table.add_column("Host", width=20)
    table.add_column("Title", width=50)
    table.add_column("CVEs", width=20)

    severity_styles = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
        "info": "blue",
    }

    # Sort by severity and take top 15
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings,
        key=lambda x: severity_order.get(x.get("severity", "info"), 5),
    )

    for finding in sorted_findings[:15]:
        severity = finding.get("severity", "info")
        style = severity_styles.get(severity, "white")
        cves = finding.get("cve_ids", [])
        cve_str = ", ".join(cves[:2]) + ("..." if len(cves) > 2 else "")

        table.add_row(
            f"[{style}]{severity.upper()}[/{style}]",
            finding.get("host", ""),
            finding.get("title", "")[:48] + ("..." if len(finding.get("title", "")) > 48 else ""),
            cve_str,
        )

    console.print(table)

    if len(findings) > 15:
        console.print(f"[dim]... and {len(findings) - 15} more vulnerabilities[/dim]")
