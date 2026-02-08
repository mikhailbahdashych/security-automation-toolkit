"""Dashboard screen for the TUI."""

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Static

from security_toolkit.core.database import get_database


class DashboardScreen(Screen):
    """Main dashboard screen showing stats and recent activity."""

    def compose(self) -> ComposeResult:
        """Compose the dashboard layout."""
        with Container(id="main-content"):
            yield Static("[bold]Dashboard[/bold]", classes="box-title")

            with Horizontal(id="stats-row"):
                with Vertical(classes="box", id="stats-box"):
                    yield Static("[bold cyan]Statistics[/bold cyan]")
                    yield Static(id="stats-content")

                with Vertical(classes="box", id="tools-box"):
                    yield Static("[bold cyan]Available Tools[/bold cyan]")
                    yield Static(
                        """
[bold]access-review[/bold]
  AWS IAM access analysis

[bold]vuln-scan[/bold]
  Parse vulnerability scans

[bold]compliance[/bold]
  Evidence collection

[bold]log-analyzer[/bold]
  Security log analysis
                        """,
                        id="tools-list",
                    )

            with Vertical(classes="box", id="activity-box"):
                yield Static("[bold cyan]Recent Activity[/bold cyan]")
                yield DataTable(id="activity-table")

    def on_mount(self) -> None:
        """Load data when screen mounts."""
        self._load_stats()
        self._load_activity()

    def on_screen_resume(self) -> None:
        """Refresh data when screen resumes."""
        self._load_stats()
        self._load_activity()

    def _load_stats(self) -> None:
        """Load and display statistics."""
        db = get_database()
        stats = db.get_stats()

        stats_text = f"""
[bold]Scripts:[/bold] {stats.get('active_scripts', 0)} active

[bold]Executions:[/bold]
  Total: {stats.get('total_executions', 0)}
  Last 24h: {stats.get('executions_last_24h', 0)}
"""
        # Add status breakdown
        by_status = stats.get("executions_by_status", {})
        if by_status:
            stats_text += "\n[bold]By Status:[/bold]\n"
            for status, count in by_status.items():
                style = "green" if status == "success" else "red" if status == "failed" else "yellow"
                stats_text += f"  [{style}]{status}[/{style}]: {count}\n"

        self.query_one("#stats-content", Static).update(stats_text)

    def _load_activity(self) -> None:
        """Load and display recent activity."""
        db = get_database()
        history = db.list_executions(limit=10)

        table = self.query_one("#activity-table", DataTable)
        table.clear(columns=True)

        table.add_columns("Time", "Type", "Name", "Status")

        for entry in history:
            status = entry.status.value
            status_style = (
                "[green]" if status == "success"
                else "[red]" if status == "failed"
                else "[yellow]"
            )

            # Get name
            if entry.tool_name:
                name = entry.tool_name
            elif entry.script_id:
                script = db.get_script(script_id=entry.script_id)
                name = script.name if script else f"Script #{entry.script_id}"
            else:
                name = "Unknown"

            time_str = ""
            if entry.started_at:
                time_str = entry.started_at.strftime("%H:%M:%S")

            table.add_row(
                time_str,
                entry.execution_type.value,
                name,
                f"{status_style}{status}[/]",
            )
