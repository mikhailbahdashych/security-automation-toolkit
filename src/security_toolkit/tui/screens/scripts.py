"""Scripts management screen for the TUI."""

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Input, Label, Static, TextArea

from security_toolkit.scripts.executor import ScriptExecutor
from security_toolkit.scripts.manager import ScriptManager


class ScriptsScreen(Screen):
    """Scripts management screen."""

    def __init__(self) -> None:
        super().__init__()
        self._selected_script: str | None = None

    def compose(self) -> ComposeResult:
        """Compose the scripts layout."""
        with Container(id="main-content"):
            yield Static("[bold]Custom Scripts[/bold]", classes="box-title")

            with Horizontal():
                # Scripts list panel
                with Vertical(classes="box", id="scripts-list"):
                    yield Static("[bold cyan]Registered Scripts[/bold cyan]")
                    yield DataTable(id="scripts-table")
                    yield Button("Refresh", id="refresh-scripts")

                # Script details panel
                with Vertical(classes="box", id="script-details"):
                    yield Static("[bold cyan]Script Details[/bold cyan]")
                    yield Static(id="script-info")

                    yield Label("Parameters:")
                    yield Input(placeholder="--param1 value1 --param2 value2", id="script-params")
                    yield Button("Run Script", variant="primary", id="run-script", disabled=True)

            # Output panel
            with Vertical(classes="box", id="output-panel"):
                yield Static("[bold cyan]Output[/bold cyan]")
                yield TextArea(id="script-output", read_only=True)

            # History panel
            with Vertical(classes="box", id="history-panel"):
                yield Static("[bold cyan]Execution History[/bold cyan]")
                yield DataTable(id="history-table")

    def on_mount(self) -> None:
        """Load data when screen mounts."""
        self._load_scripts()
        self._load_history()

    def on_screen_resume(self) -> None:
        """Refresh data when screen resumes."""
        self._load_scripts()
        self._load_history()

    def _load_scripts(self) -> None:
        """Load and display scripts."""
        manager = ScriptManager()
        scripts = manager.list()

        table = self.query_one("#scripts-table", DataTable)
        table.clear(columns=True)

        table.add_columns("Name", "Type", "Category", "Params")

        for script in scripts:
            table.add_row(
                script.name,
                script.script_type.value,
                script.category,
                str(len(script.parameters)),
                key=script.name,
            )

    def _load_history(self) -> None:
        """Load execution history."""
        executor = ScriptExecutor()
        history = executor.get_history(limit=10)

        table = self.query_one("#history-table", DataTable)
        table.clear(columns=True)

        table.add_columns("Time", "Script", "Status", "Duration")

        for entry in history:
            status = entry.status.value
            status_str = (
                f"[green]{status}[/green]" if status == "success"
                else f"[red]{status}[/red]" if status == "failed"
                else f"[yellow]{status}[/yellow]"
            )

            # Get script name
            manager = ScriptManager()
            script = manager.get(script_id=entry.script_id) if entry.script_id else None
            name = script.name if script else "Unknown"

            # Calculate duration
            duration = ""
            if entry.started_at and entry.completed_at:
                delta = entry.completed_at - entry.started_at
                duration = f"{delta.total_seconds():.1f}s"

            time_str = entry.started_at.strftime("%H:%M:%S") if entry.started_at else ""

            table.add_row(time_str, name, status_str, duration)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle script selection."""
        if event.data_table.id == "scripts-table":
            self._selected_script = str(event.row_key.value) if event.row_key else None
            self._update_script_details()

    def _update_script_details(self) -> None:
        """Update script details panel."""
        if not self._selected_script:
            self.query_one("#script-info", Static).update("")
            self.query_one("#run-script", Button).disabled = True
            return

        manager = ScriptManager()
        script = manager.get(name=self._selected_script)

        if not script:
            self.query_one("#script-info", Static).update("[red]Script not found[/red]")
            self.query_one("#run-script", Button).disabled = True
            return

        info_lines = [
            f"[bold]{script.name}[/bold]",
            f"Description: {script.description or '(none)'}",
            f"Path: {script.path}",
            f"Type: {script.script_type.value}",
            f"Category: {script.category}",
            "",
        ]

        if script.parameters:
            info_lines.append("[bold]Parameters:[/bold]")
            for param in script.parameters:
                required = " [red](required)[/red]" if param.required else ""
                info_lines.append(f"  --{param.name}: {param.description}{required}")

        self.query_one("#script-info", Static).update("\n".join(info_lines))
        self.query_one("#run-script", Button).disabled = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press."""
        if event.button.id == "run-script":
            self._run_script()
        elif event.button.id == "refresh-scripts":
            self._load_scripts()
            self._load_history()

    def _run_script(self) -> None:
        """Run the selected script."""
        if not self._selected_script:
            return

        # Parse parameters from input
        params_input = self.query_one("#script-params", Input).value
        params = {}

        if params_input:
            # Simple parsing of --key value pairs
            parts = params_input.split()
            i = 0
            while i < len(parts):
                if parts[i].startswith("--"):
                    key = parts[i][2:]
                    if i + 1 < len(parts) and not parts[i + 1].startswith("--"):
                        params[key] = parts[i + 1]
                        i += 2
                    else:
                        params[key] = True
                        i += 1
                else:
                    i += 1

        output_area = self.query_one("#script-output", TextArea)
        output_area.load_text(f"Running {self._selected_script}...\n")

        try:
            executor = ScriptExecutor()
            execution, stdout, stderr = executor.run(
                script_name=self._selected_script,
                parameters=params,
            )

            output_lines = [
                f"Status: {execution.status.value}",
                f"Started: {execution.started_at}",
                f"Completed: {execution.completed_at}",
                "",
            ]

            if stdout:
                output_lines.append("--- Output ---")
                output_lines.append(stdout)

            if stderr:
                output_lines.append("--- Errors ---")
                output_lines.append(stderr)

            output_area.load_text("\n".join(output_lines))

            # Refresh history
            self._load_history()

        except Exception as e:
            output_area.load_text(f"Error running script: {e}")
