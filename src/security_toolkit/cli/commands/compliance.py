"""Compliance CLI commands."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from security_toolkit.reporting import get_reporter
from security_toolkit.tools.compliance import ComplianceTool

console = Console()
app = typer.Typer(help="Compliance evidence collection")


@app.command()
def collect(
    framework: Annotated[
        str,
        typer.Option("--framework", "-f", help="Compliance framework (soc2, iso27001, pci-dss)"),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output directory for evidence files"),
    ] = None,
    controls: Annotated[
        str | None,
        typer.Option("--controls", "-c", help="Comma-separated list of control IDs"),
    ] = None,
    format: Annotated[
        str,
        typer.Option("--format", help="Output format for report (json, csv, html, md)"),
    ] = "json",
    include_aws: Annotated[
        bool,
        typer.Option("--include-aws/--no-aws", help="Include AWS evidence collection"),
    ] = True,
) -> None:
    """Collect compliance evidence for specified framework."""
    console.print(f"[bold blue]Collecting {framework.upper()} compliance evidence...[/bold blue]")

    tool = ComplianceTool()

    # Parse controls if provided
    control_list = None
    if controls:
        control_list = [c.strip() for c in controls.split(",")]

    result = tool.execute(
        framework=framework,
        controls=control_list,
        output_dir=str(output) if output else None,
        include_aws=include_aws,
    )

    if result.errors:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        raise typer.Exit(1)

    if result.warnings:
        for warning in result.warnings:
            console.print(f"[yellow]Warning:[/yellow] {warning}")

    # Display summary
    _display_summary(result.summary)

    # Display evidence
    if result.findings:
        _display_evidence(result.findings)

    # Generate report if output specified
    if output:
        console.print(f"\n[green]Evidence files saved to:[/green] {output}")

        # Also generate a formatted report
        reporter = get_reporter(format)
        report_path = output / f"{framework}_report{reporter.extension}"
        reporter.generate(result, report_path)
        console.print(f"[green]Report saved to:[/green] {report_path}")


@app.command()
def frameworks() -> None:
    """List available compliance frameworks and controls."""
    from security_toolkit.tools.compliance.tool import ComplianceTool

    frameworks = ComplianceTool.FRAMEWORKS

    for framework_id, info in frameworks.items():
        console.print(f"\n[bold blue]{info['name']}[/bold blue] ({framework_id})")
        console.print("-" * 50)

        table = Table(show_header=True, header_style="bold")
        table.add_column("Control ID", style="cyan", width=15)
        table.add_column("Description")

        for control_id, description in info["controls"].items():
            table.add_row(control_id, description)

        console.print(table)


@app.command()
def status(
    framework: Annotated[
        str,
        typer.Option("--framework", "-f", help="Compliance framework"),
    ],
) -> None:
    """Show compliance status summary."""
    console.print(f"[bold blue]Checking {framework.upper()} compliance status...[/bold blue]")

    tool = ComplianceTool()
    result = tool.execute(framework=framework, include_aws=True)

    if result.errors:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")

    _display_status(result.findings)


def _display_summary(summary: dict) -> None:
    """Display summary statistics."""
    console.print(f"\n[bold]{summary.get('framework', 'Compliance')} Summary[/bold]")

    table = Table(show_header=False, box=None)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")

    table.add_row("Total Evidence Items", str(summary.get("total_evidence", 0)))
    table.add_row("Pass Rate", summary.get("pass_rate", "N/A"))

    console.print(table)
    console.print()

    # Status breakdown
    by_status = summary.get("by_status", {})
    if by_status:
        status_table = Table(title="By Status", show_header=True, header_style="bold")
        status_table.add_column("Status", width=15)
        status_table.add_column("Count", justify="right")

        status_styles = {
            "pass": "green",
            "fail": "red",
            "partial": "yellow",
            "not_applicable": "dim",
        }

        for status, count in by_status.items():
            style = status_styles.get(status, "white")
            status_table.add_row(f"[{style}]{status.upper()}[/{style}]", str(count))

        console.print(status_table)


def _display_evidence(evidence: list) -> None:
    """Display evidence items in a table."""
    console.print("\n[bold]Evidence Items[/bold]")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Control", width=12)
    table.add_column("Status", width=12)
    table.add_column("Source", width=20)
    table.add_column("Description", width=40)

    status_styles = {
        "pass": "green",
        "fail": "red",
        "partial": "yellow",
        "not_applicable": "dim",
    }

    for item in evidence:
        status = item.get("status", "unknown")
        style = status_styles.get(status, "white")

        table.add_row(
            item.get("control_id", ""),
            f"[{style}]{status.upper()}[/{style}]",
            item.get("source", ""),
            item.get("control_name", "")[:38] + "...",
        )

    console.print(table)


def _display_status(evidence: list) -> None:
    """Display compliance status dashboard."""
    console.print("\n[bold]Compliance Status Dashboard[/bold]")

    # Group by control
    by_control: dict[str, list] = {}
    for item in evidence:
        control_id = item.get("control_id", "Unknown")
        if control_id not in by_control:
            by_control[control_id] = []
        by_control[control_id].append(item)

    table = Table(show_header=True, header_style="bold")
    table.add_column("Control", width=12)
    table.add_column("Name", width=35)
    table.add_column("Status", width=12)
    table.add_column("Evidence", justify="right", width=10)

    status_styles = {
        "pass": "green",
        "fail": "red",
        "partial": "yellow",
        "not_applicable": "dim",
    }

    for control_id, items in sorted(by_control.items()):
        # Determine overall status
        statuses = [i.get("status", "unknown") for i in items]
        if "fail" in statuses:
            overall_status = "fail"
        elif "partial" in statuses:
            overall_status = "partial"
        elif all(s == "pass" for s in statuses):
            overall_status = "pass"
        else:
            overall_status = "not_applicable"

        style = status_styles.get(overall_status, "white")
        control_name = items[0].get("control_name", "") if items else ""

        table.add_row(
            control_id,
            control_name[:33] + ("..." if len(control_name) > 33 else ""),
            f"[{style}]{overall_status.upper()}[/{style}]",
            str(len(items)),
        )

    console.print(table)
