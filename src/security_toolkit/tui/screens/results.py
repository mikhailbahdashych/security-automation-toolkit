"""Results viewer screen for the TUI."""

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Select, Static, TextArea

from security_toolkit.core.config import get_settings
from security_toolkit.core.database import get_database


class ResultsScreen(Screen):
    """Results viewer screen."""

    def __init__(self) -> None:
        super().__init__()
        self._selected_result: int | None = None

    def compose(self) -> ComposeResult:
        """Compose the results layout."""
        with Container(id="main-content"):
            yield Static("[bold]Results Viewer[/bold]", classes="box-title")

            with Horizontal():
                # Filters panel
                with Vertical(classes="box", id="filters"):
                    yield Static("[bold cyan]Filters[/bold cyan]")
                    yield Select(
                        [
                            ("All", "all"),
                            ("Tools", "tool"),
                            ("Scripts", "script"),
                        ],
                        value="all",
                        id="type-filter",
                    )
                    yield Select(
                        [
                            ("All Statuses", "all"),
                            ("Success", "success"),
                            ("Failed", "failed"),
                            ("Running", "running"),
                        ],
                        value="all",
                        id="status-filter",
                    )
                    yield Button("Refresh", id="refresh-results")

                # Results list
                with Vertical(classes="box", id="results-list"):
                    yield Static("[bold cyan]Execution Results[/bold cyan]")
                    yield DataTable(id="results-table")

            # Details panel
            with Vertical(classes="box", id="details-panel"):
                yield Static("[bold cyan]Details[/bold cyan]")
                yield TextArea(id="result-details", read_only=True)

            # Actions
            with Horizontal(id="actions"):
                yield Button("View Output", id="view-output", disabled=True)
                yield Button("Export JSON", id="export-json", disabled=True)
                yield Button("Export CSV", id="export-csv", disabled=True)
                yield Button("Export HTML", id="export-html", disabled=True)

    def on_mount(self) -> None:
        """Load data when screen mounts."""
        self._load_results()

    def on_screen_resume(self) -> None:
        """Refresh data when screen resumes."""
        self._load_results()

    def _load_results(self) -> None:
        """Load and display results."""
        db = get_database()

        # Get filter values
        try:
            type_filter = self.query_one("#type-filter", Select).value
            status_filter = self.query_one("#status-filter", Select).value
        except Exception:
            type_filter = "all"
            status_filter = "all"

        # Build query parameters
        kwargs = {"limit": 50}
        if status_filter and status_filter != "all":
            from security_toolkit.core.models import ExecutionStatus
            kwargs["status"] = ExecutionStatus(status_filter)

        history = db.list_executions(**kwargs)

        # Filter by type if needed
        if type_filter and type_filter != "all":
            history = [h for h in history if h.execution_type.value == type_filter]

        table = self.query_one("#results-table", DataTable)
        table.clear(columns=True)

        table.add_columns("ID", "Time", "Type", "Name", "Status", "Duration")

        from security_toolkit.scripts.manager import ScriptManager
        manager = ScriptManager()

        for entry in history:
            status = entry.status.value
            status_str = (
                f"[green]{status}[/green]" if status == "success"
                else f"[red]{status}[/red]" if status == "failed"
                else f"[yellow]{status}[/yellow]"
            )

            # Get name
            if entry.tool_name:
                name = entry.tool_name
            elif entry.script_id:
                script = manager.get(script_id=entry.script_id)
                name = script.name if script else f"Script #{entry.script_id}"
            else:
                name = "Unknown"

            # Calculate duration
            duration = ""
            if entry.started_at and entry.completed_at:
                delta = entry.completed_at - entry.started_at
                duration = f"{delta.total_seconds():.1f}s"

            time_str = entry.started_at.strftime("%Y-%m-%d %H:%M") if entry.started_at else ""

            table.add_row(
                str(entry.id),
                time_str,
                entry.execution_type.value,
                name,
                status_str,
                duration,
                key=str(entry.id),
            )

    def on_select_changed(self, event: Select.Changed) -> None:
        """Handle filter changes."""
        self._load_results()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle result selection."""
        if event.data_table.id == "results-table":
            try:
                self._selected_result = int(event.row_key.value) if event.row_key else None
            except (ValueError, TypeError):
                self._selected_result = None
            self._update_details()

    def _update_details(self) -> None:
        """Update details panel."""
        if not self._selected_result:
            self.query_one("#result-details", TextArea).load_text("")
            self._set_actions_enabled(False)
            return

        db = get_database()
        execution = db.get_execution(self._selected_result)

        if not execution:
            self.query_one("#result-details", TextArea).load_text("[red]Result not found[/red]")
            self._set_actions_enabled(False)
            return

        import json

        details = [
            f"ID: {execution.id}",
            f"Type: {execution.execution_type.value}",
            f"Status: {execution.status.value}",
            f"Started: {execution.started_at}",
            f"Completed: {execution.completed_at}",
            "",
        ]

        if execution.tool_name:
            details.append(f"Tool: {execution.tool_name}")
        if execution.script_id:
            from security_toolkit.scripts.manager import ScriptManager
            manager = ScriptManager()
            script = manager.get(script_id=execution.script_id)
            if script:
                details.append(f"Script: {script.name}")

        if execution.parameters:
            details.append("")
            details.append("Parameters:")
            details.append(json.dumps(execution.parameters, indent=2))

        if execution.output_path:
            details.append("")
            details.append(f"Output: {execution.output_path}")

        if execution.error_message:
            details.append("")
            details.append(f"[red]Error: {execution.error_message}[/red]")

        self.query_one("#result-details", TextArea).load_text("\n".join(details))
        self._set_actions_enabled(True)

    def _set_actions_enabled(self, enabled: bool) -> None:
        """Enable or disable action buttons."""
        for button_id in ["view-output", "export-json", "export-csv", "export-html"]:
            try:
                self.query_one(f"#{button_id}", Button).disabled = not enabled
            except Exception:
                pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press."""
        if event.button.id == "refresh-results":
            self._load_results()
        elif event.button.id == "view-output":
            self._view_output()
        elif event.button.id.startswith("export-"):
            format_type = event.button.id.replace("export-", "")
            self._export_result(format_type)

    def _view_output(self) -> None:
        """View the output of selected result."""
        if not self._selected_result:
            return

        db = get_database()
        execution = db.get_execution(self._selected_result)

        if not execution or not execution.output_path:
            self.query_one("#result-details", TextArea).load_text("No output file available")
            return

        output_path = Path(execution.output_path)
        if not output_path.exists():
            self.query_one("#result-details", TextArea).load_text(f"Output file not found: {output_path}")
            return

        with open(output_path) as f:
            content = f.read()

        self.query_one("#result-details", TextArea).load_text(content)

    def _export_result(self, format_type: str) -> None:
        """Export the selected result."""
        if not self._selected_result:
            return

        db = get_database()
        execution = db.get_execution(self._selected_result)

        if not execution:
            return

        settings = get_settings()
        output_dir = settings.output_dir / "exports"
        output_dir.mkdir(parents=True, exist_ok=True)

        import json
        from datetime import datetime

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = execution.tool_name or f"script_{execution.script_id}"

        data = {
            "id": execution.id,
            "type": execution.execution_type.value,
            "name": name,
            "status": execution.status.value,
            "started_at": str(execution.started_at),
            "completed_at": str(execution.completed_at),
            "parameters": execution.parameters,
            "error_message": execution.error_message,
        }

        if format_type == "json":
            output_path = output_dir / f"{name}_{timestamp}.json"
            with open(output_path, "w") as f:
                json.dump(data, f, indent=2)
        elif format_type == "csv":
            import csv
            output_path = output_dir / f"{name}_{timestamp}.csv"
            with open(output_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=data.keys())
                writer.writeheader()
                writer.writerow({k: str(v) for k, v in data.items()})
        elif format_type == "html":
            output_path = output_dir / f"{name}_{timestamp}.html"
            html_content = f"""<!DOCTYPE html>
<html>
<head><title>Execution Result</title></head>
<body>
<h1>{name}</h1>
<table border="1">
{"".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in data.items())}
</table>
</body>
</html>"""
            with open(output_path, "w") as f:
                f.write(html_content)
        else:
            return

        self.query_one("#result-details", TextArea).load_text(f"Exported to: {output_path}")
