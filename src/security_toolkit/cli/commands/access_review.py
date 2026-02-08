"""Access Review CLI commands."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from security_toolkit.reporting import get_reporter
from security_toolkit.tools.access_review import AccessReviewTool

console = Console()
app = typer.Typer(help="AWS IAM access review and analysis")


@app.command()
def run(
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format (json, csv, html, md)"),
    ] = "json",
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file path"),
    ] = None,
    check_unused_users: Annotated[
        bool,
        typer.Option("--check-unused-users/--no-check-unused-users", help="Check for unused users"),
    ] = True,
    check_unused_roles: Annotated[
        bool,
        typer.Option("--check-unused-roles/--no-check-unused-roles", help="Check for unused roles"),
    ] = True,
    check_mfa: Annotated[
        bool,
        typer.Option("--check-mfa/--no-check-mfa", help="Check MFA status"),
    ] = True,
    check_access_keys: Annotated[
        bool,
        typer.Option("--check-access-keys/--no-check-access-keys", help="Check access key security"),
    ] = True,
    check_policies: Annotated[
        bool,
        typer.Option("--check-policies/--no-check-policies", help="Check admin policies"),
    ] = True,
    inactive_days: Annotated[
        int,
        typer.Option("--inactive-days", "-d", help="Days threshold for inactivity"),
    ] = 90,
) -> None:
    """Run AWS IAM access review analysis."""
    console.print("[bold blue]Running Access Review...[/bold blue]")

    tool = AccessReviewTool()
    result = tool.execute(
        check_unused_users=check_unused_users,
        check_unused_roles=check_unused_roles,
        check_mfa=check_mfa,
        check_access_keys=check_access_keys,
        check_policies=check_policies,
        inactive_days=inactive_days,
    )

    if result.errors:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        raise typer.Exit(1)

    # Display summary
    _display_summary(result.summary)

    # Display findings table
    if result.findings:
        _display_findings(result.findings)

    # Generate report
    if output or format != "json":
        reporter = get_reporter(format)
        if output is None:
            output = Path(reporter.get_default_filename(result))
        content = reporter.generate(result, output)
        console.print(f"\n[green]Report saved to:[/green] {output}")
    else:
        # Print JSON to console
        import json
        console.print_json(json.dumps(result.summary, indent=2))


def _display_summary(summary: dict) -> None:
    """Display summary statistics."""
    console.print("\n[bold]Summary[/bold]")

    table = Table(show_header=False, box=None)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")

    table.add_row("Total Users", str(summary.get("total_users", 0)))
    table.add_row("Total Roles", str(summary.get("total_roles", 0)))
    table.add_row("Total Findings", str(summary.get("total_findings", 0)))
    table.add_row("Users without MFA", str(summary.get("users_without_mfa", 0)))
    table.add_row("Users with Admin", str(summary.get("users_with_admin", 0)))

    console.print(table)


def _display_findings(findings: list) -> None:
    """Display findings in a table."""
    console.print("\n[bold]Findings[/bold]")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity", width=10)
    table.add_column("Type", width=20)
    table.add_column("Resource", width=30)
    table.add_column("Description")

    severity_styles = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
        "info": "blue",
    }

    for finding in findings[:20]:  # Limit display
        severity = finding.get("severity", "info")
        style = severity_styles.get(severity, "white")

        table.add_row(
            f"[{style}]{severity.upper()}[/{style}]",
            finding.get("finding_type", ""),
            finding.get("resource_name", ""),
            finding.get("description", "")[:60] + "...",
        )

    console.print(table)

    if len(findings) > 20:
        console.print(f"[dim]... and {len(findings) - 20} more findings[/dim]")
