"""Scripts management CLI commands."""

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from security_toolkit.scripts.executor import ScriptExecutor
from security_toolkit.scripts.manager import ScriptManager

console = Console()
app = typer.Typer(help="Custom script management")


@app.command("list")
def list_scripts(
    category: Annotated[
        str | None,
        typer.Option("--category", "-c", help="Filter by category"),
    ] = None,
    include_inactive: Annotated[
        bool,
        typer.Option("--all", "-a", help="Include inactive scripts"),
    ] = False,
) -> None:
    """List all registered scripts."""
    manager = ScriptManager()
    scripts = manager.list(category=category, include_inactive=include_inactive)

    if not scripts:
        console.print("[yellow]No scripts found.[/yellow]")
        if not include_inactive:
            console.print("[dim]Use --all to include inactive scripts.[/dim]")
        return

    table = Table(title="Registered Scripts", show_header=True, header_style="bold")
    table.add_column("Name", style="cyan")
    table.add_column("Type", width=8)
    table.add_column("Category", width=15)
    table.add_column("Parameters", width=10, justify="right")
    table.add_column("Description")

    for script in scripts:
        status = "" if script.is_active else "[dim](inactive)[/dim] "
        table.add_row(
            f"{status}{script.name}",
            script.script_type.value,
            script.category,
            str(len(script.parameters)),
            script.description[:40] + ("..." if len(script.description) > 40 else ""),
        )

    console.print(table)


@app.command()
def register(
    name: Annotated[
        str,
        typer.Argument(help="Unique name for the script"),
    ],
    path: Annotated[
        Path,
        typer.Option("--path", "-p", help="Path to script file"),
    ],
    description: Annotated[
        str,
        typer.Option("--description", "-d", help="Script description"),
    ] = "",
    category: Annotated[
        str,
        typer.Option("--category", "-c", help="Script category"),
    ] = "uncategorized",
    parameters: Annotated[
        str | None,
        typer.Option("--params", help="JSON string of parameters"),
    ] = None,
) -> None:
    """Register a new script."""
    manager = ScriptManager()

    params_list = None
    if parameters:
        try:
            params_list = json.loads(parameters)
        except json.JSONDecodeError as e:
            console.print(f"[red]Error:[/red] Invalid JSON for parameters: {e}")
            raise typer.Exit(1)

    try:
        script = manager.register(
            name=name,
            path=str(path),
            description=description,
            category=category,
            parameters=params_list,
        )
        console.print(f"[green]Script registered:[/green] {script.name}")
        console.print(f"  Path: {script.path}")
        console.print(f"  Type: {script.script_type.value}")
        console.print(f"  Category: {script.category}")
        if script.parameters:
            console.print(f"  Parameters: {len(script.parameters)}")
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def run(
    name: Annotated[
        str,
        typer.Argument(help="Name of the script to run"),
    ],
    params: Annotated[
        list[str] | None,
        typer.Option("--param", "-p", help="Parameter in key=value format"),
    ] = None,
    timeout: Annotated[
        int | None,
        typer.Option("--timeout", "-t", help="Timeout in seconds"),
    ] = None,
) -> None:
    """Run a registered script."""
    executor = ScriptExecutor()

    # Parse parameters
    parameters: dict[str, str] = {}
    if params:
        for param in params:
            if "=" not in param:
                console.print(f"[red]Error:[/red] Invalid parameter format: {param}")
                console.print("[dim]Use --param key=value[/dim]")
                raise typer.Exit(1)
            key, value = param.split("=", 1)
            parameters[key] = value

    console.print(f"[bold blue]Running script:[/bold blue] {name}")

    try:
        execution, stdout, stderr = executor.run(
            script_name=name,
            parameters=parameters,
            timeout=timeout,
        )

        if execution.status.value == "success":
            console.print(f"[green]Script completed successfully[/green]")
        else:
            console.print(f"[red]Script failed[/red]")

        if stdout:
            console.print("\n[bold]Output:[/bold]")
            console.print(stdout)

        if stderr and execution.status.value != "success":
            console.print("\n[bold red]Errors:[/bold red]")
            console.print(stderr)

        if execution.output_path:
            console.print(f"\n[dim]Output saved to: {execution.output_path}[/dim]")

    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def show(
    name: Annotated[
        str,
        typer.Argument(help="Name of the script"),
    ],
) -> None:
    """Show details of a script."""
    manager = ScriptManager()
    script = manager.get(name=name)

    if not script:
        console.print(f"[red]Error:[/red] Script '{name}' not found")
        raise typer.Exit(1)

    console.print(f"\n[bold]{script.name}[/bold]")
    console.print(f"[dim]{'-' * 50}[/dim]")
    console.print(f"Description: {script.description or '(none)'}")
    console.print(f"Path: {script.path}")
    console.print(f"Type: {script.script_type.value}")
    console.print(f"Category: {script.category}")
    console.print(f"Active: {'Yes' if script.is_active else 'No'}")
    console.print(f"Created: {script.created_at}")

    if script.parameters:
        console.print("\n[bold]Parameters:[/bold]")
        table = Table(show_header=True, header_style="bold")
        table.add_column("Name", style="cyan")
        table.add_column("Type", width=10)
        table.add_column("Required", width=10)
        table.add_column("Default")
        table.add_column("Description")

        for param in script.parameters:
            table.add_row(
                param.name,
                param.param_type.value,
                "Yes" if param.required else "No",
                str(param.default) if param.default is not None else "-",
                param.description,
            )

        console.print(table)


@app.command()
def history(
    name: Annotated[
        str | None,
        typer.Argument(help="Script name (optional, shows all if not specified)"),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", "-n", help="Maximum number of entries"),
    ] = 20,
) -> None:
    """Show script execution history."""
    executor = ScriptExecutor()
    history = executor.get_history(script_name=name, limit=limit)

    if not history:
        console.print("[yellow]No execution history found.[/yellow]")
        return

    table = Table(title="Execution History", show_header=True, header_style="bold")
    table.add_column("ID", width=6, justify="right")
    table.add_column("Started", width=20)
    table.add_column("Status", width=10)
    table.add_column("Type", width=8)
    table.add_column("Name", width=20)
    table.add_column("Duration")

    status_styles = {
        "success": "green",
        "failed": "red",
        "running": "yellow",
    }

    for entry in history:
        status = entry.status.value
        style = status_styles.get(status, "white")

        # Calculate duration
        duration = ""
        if entry.started_at and entry.completed_at:
            delta = entry.completed_at - entry.started_at
            duration = f"{delta.total_seconds():.1f}s"

        # Get name
        if entry.execution_type.value == "script":
            manager = ScriptManager()
            script = manager.get(script_id=entry.script_id) if entry.script_id else None
            item_name = script.name if script else f"(ID: {entry.script_id})"
        else:
            item_name = entry.tool_name or "unknown"

        table.add_row(
            str(entry.id),
            str(entry.started_at)[:19] if entry.started_at else "",
            f"[{style}]{status.upper()}[/{style}]",
            entry.execution_type.value,
            item_name,
            duration,
        )

    console.print(table)


@app.command()
def delete(
    name: Annotated[
        str,
        typer.Argument(help="Name of the script to delete"),
    ],
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Skip confirmation"),
    ] = False,
) -> None:
    """Delete a registered script permanently."""
    manager = ScriptManager()
    script = manager.get(name=name)

    if not script:
        console.print(f"[red]Error:[/red] Script '{name}' not found")
        raise typer.Exit(1)

    if not force:
        console.print(f"[yellow]Warning:[/yellow] This action is irreversible!")
        console.print(f"  Script: {name}")
        console.print(f"  Path: {script.path}")
        confirm = typer.confirm("Are you sure you want to permanently delete this script?")
        if not confirm:
            console.print("[yellow]Cancelled[/yellow]")
            raise typer.Exit(0)

    if manager.delete(name):
        console.print(f"[green]Script permanently deleted:[/green] {name}")
    else:
        console.print(f"[red]Error:[/red] Failed to delete script")
        raise typer.Exit(1)


@app.command()
def import_script(
    source: Annotated[
        Path,
        typer.Argument(help="Path to script file to import"),
    ],
    name: Annotated[
        str | None,
        typer.Option("--name", "-n", help="Name for the script (defaults to filename)"),
    ] = None,
) -> None:
    """Import a script from an external location."""
    if not source.exists():
        console.print(f"[red]Error:[/red] Source file not found: {source}")
        raise typer.Exit(1)

    manager = ScriptManager()

    try:
        script = manager.import_script(str(source), name)
        console.print(f"[green]Script imported:[/green] {script.name}")
        console.print(f"  Copied to: {script.path}")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def categories() -> None:
    """List all script categories."""
    manager = ScriptManager()
    categories = manager.get_categories()

    if not categories:
        console.print("[yellow]No categories found.[/yellow]")
        return

    console.print("[bold]Script Categories:[/bold]")
    for category in categories:
        scripts = manager.list(category=category)
        console.print(f"  {category}: {len(scripts)} scripts")
