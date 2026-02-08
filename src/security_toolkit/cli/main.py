"""Main CLI entry point using Typer."""

import typer
from rich.console import Console

from security_toolkit.cli.commands import (
    access_review,
    compliance,
    log_analyzer,
    scripts,
    vuln_scan,
)

console = Console()

app = typer.Typer(
    name="seckit",
    help="Security Automation Toolkit - Professional CLI for SecOps automation",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

# Register command groups
app.add_typer(access_review.app, name="access-review", help="AWS IAM access review and analysis")
app.add_typer(vuln_scan.app, name="vuln-scan", help="Vulnerability scan parsing and analysis")
app.add_typer(compliance.app, name="compliance", help="Compliance evidence collection")
app.add_typer(log_analyzer.app, name="log-analyzer", help="Security log analysis")
app.add_typer(scripts.app, name="scripts", help="Custom script management")


@app.command()
def tui() -> None:
    """Launch interactive TUI mode."""
    try:
        from security_toolkit.tui.app import SecurityToolkitApp

        app_instance = SecurityToolkitApp()
        app_instance.run()
    except ImportError as e:
        console.print(f"[red]Error:[/red] TUI dependencies not available: {e}")
        console.print("Install with: pip install textual")
        raise typer.Exit(1)


@app.command()
def version() -> None:
    """Show version information."""
    from security_toolkit import __version__

    console.print(f"[bold]Security Automation Toolkit[/bold] v{__version__}")


@app.command()
def info() -> None:
    """Show toolkit information and available tools."""
    from rich.panel import Panel
    from rich.table import Table

    from security_toolkit import __version__
    from security_toolkit.core.config import get_settings

    settings = get_settings()

    # Header
    console.print(
        Panel.fit(
            f"[bold blue]Security Automation Toolkit[/bold blue] v{__version__}\n"
            "[dim]Professional CLI for SecOps automation[/dim]",
            border_style="blue",
        )
    )

    # Tools table
    tools_table = Table(title="Available Tools", show_header=True, header_style="bold cyan")
    tools_table.add_column("Tool", style="green")
    tools_table.add_column("Description")
    tools_table.add_column("Command")

    tools_table.add_row(
        "Access Review",
        "AWS IAM analysis and permission review",
        "seckit access-review run",
    )
    tools_table.add_row(
        "Vuln Scan Parser",
        "Parse Nessus, Qualys, OpenVAS outputs",
        "seckit vuln-scan parse",
    )
    tools_table.add_row(
        "Compliance",
        "SOC2, ISO27001, PCI-DSS evidence collection",
        "seckit compliance collect",
    )
    tools_table.add_row(
        "Log Analyzer",
        "Analyze auth.log, syslog, CloudTrail",
        "seckit log-analyzer analyze",
    )

    console.print(tools_table)
    console.print()

    # Configuration
    config_table = Table(title="Configuration", show_header=True, header_style="bold cyan")
    config_table.add_column("Setting", style="yellow")
    config_table.add_column("Value")

    config_table.add_row("Database", str(settings.db_path))
    config_table.add_row("Scripts Directory", str(settings.scripts_dir))
    config_table.add_row("Output Directory", str(settings.output_dir))
    config_table.add_row("AWS Region", settings.aws_region)
    config_table.add_row("AWS Profile", settings.aws_profile or "(default)")

    console.print(config_table)


@app.command()
def stats() -> None:
    """Show execution statistics."""
    from rich.table import Table

    from security_toolkit.core.database import get_database

    db = get_database()
    stats = db.get_stats()

    console.print("[bold]Execution Statistics[/bold]\n")

    # Scripts stats
    scripts_table = Table(title="Scripts", show_header=True)
    scripts_table.add_column("Metric", style="cyan")
    scripts_table.add_column("Value", justify="right")

    scripts_table.add_row("Active Scripts", str(stats.get("active_scripts", 0)))
    for category, count in stats.get("scripts_by_category", {}).items():
        scripts_table.add_row(f"  {category}", str(count))

    console.print(scripts_table)
    console.print()

    # Execution stats
    exec_table = Table(title="Executions", show_header=True)
    exec_table.add_column("Metric", style="cyan")
    exec_table.add_column("Value", justify="right")

    exec_table.add_row("Total Executions", str(stats.get("total_executions", 0)))
    exec_table.add_row("Last 24 Hours", str(stats.get("executions_last_24h", 0)))

    for status, count in stats.get("executions_by_status", {}).items():
        style = "green" if status == "success" else "red" if status == "failed" else "yellow"
        exec_table.add_row(f"  {status.title()}", f"[{style}]{count}[/{style}]")

    console.print(exec_table)


if __name__ == "__main__":
    app()
