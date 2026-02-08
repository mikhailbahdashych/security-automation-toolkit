"""Main Textual application for Security Toolkit TUI."""

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, Header

from security_toolkit.tui.screens.dashboard import DashboardScreen
from security_toolkit.tui.screens.results import ResultsScreen
from security_toolkit.tui.screens.scripts import ScriptsScreen
from security_toolkit.tui.screens.tools import ToolsScreen


class SecurityToolkitApp(App):
    """Security Automation Toolkit TUI Application."""

    TITLE = "Security Automation Toolkit"
    SUB_TITLE = "SecOps Automation"
    CSS_PATH = None  # Using inline CSS

    BINDINGS = [
        Binding("d", "switch_screen('dashboard')", "Dashboard", show=True),
        Binding("t", "switch_screen('tools')", "Tools", show=True),
        Binding("s", "switch_screen('scripts')", "Scripts", show=True),
        Binding("r", "switch_screen('results')", "Results", show=True),
        Binding("q", "quit", "Quit", show=True),
        Binding("?", "show_help", "Help", show=True),
    ]

    CSS = """
    Screen {
        background: $surface;
    }

    Header {
        dock: top;
        height: 3;
        background: $primary;
    }

    Footer {
        dock: bottom;
        height: 1;
    }

    #main-content {
        height: 100%;
        padding: 1;
    }

    .box {
        border: solid $primary;
        padding: 1;
        margin: 1;
    }

    .box-title {
        text-style: bold;
        color: $text;
        padding: 0 1;
    }

    .stat-value {
        text-style: bold;
        color: $success;
    }

    .severity-critical {
        color: red;
        text-style: bold;
    }

    .severity-high {
        color: $error;
    }

    .severity-medium {
        color: $warning;
    }

    .severity-low {
        color: $success;
    }

    .severity-info {
        color: $primary;
    }

    DataTable {
        height: auto;
        max-height: 20;
    }

    DataTable > .datatable--header {
        background: $primary 30%;
        text-style: bold;
    }

    DataTable > .datatable--cursor {
        background: $primary 50%;
    }

    Button {
        margin: 1 2;
    }

    Button.primary {
        background: $primary;
    }

    Input {
        margin: 1 0;
    }

    Select {
        margin: 1 0;
    }

    .error {
        color: $error;
        text-style: bold;
    }

    .success {
        color: $success;
    }

    .warning {
        color: $warning;
    }

    #tool-output {
        height: 15;
        border: solid $primary;
        padding: 1;
        overflow-y: auto;
    }

    .menu-item {
        padding: 1 2;
        margin: 0 1;
    }

    .menu-item:hover {
        background: $primary 20%;
    }

    .menu-item.-selected {
        background: $primary 40%;
    }

    ProgressBar {
        padding: 1;
    }

    #status-bar {
        dock: bottom;
        height: 1;
        background: $surface-darken-1;
        padding: 0 1;
    }
    """

    SCREENS = {
        "dashboard": DashboardScreen,
        "tools": ToolsScreen,
        "scripts": ScriptsScreen,
        "results": ResultsScreen,
    }

    def compose(self) -> ComposeResult:
        """Compose the application layout."""
        yield Header()
        yield Footer()

    def on_mount(self) -> None:
        """Handle application mount."""
        self.push_screen("dashboard")

    def action_switch_screen(self, screen_name: str) -> None:
        """Switch to a different screen."""
        if screen_name in self.SCREENS:
            self.switch_screen(screen_name)

    def action_show_help(self) -> None:
        """Show help dialog."""
        from textual.widgets import Static
        from textual.screen import ModalScreen
        from textual.containers import Container
        from textual.widgets import Button

        class HelpScreen(ModalScreen):
            """Help modal screen."""

            BINDINGS = [("escape", "dismiss", "Close")]

            def compose(self) -> ComposeResult:
                with Container(id="help-dialog"):
                    yield Static(
                        """
[bold]Security Automation Toolkit[/bold]

[bold cyan]Keyboard Shortcuts:[/bold cyan]
  [bold]d[/bold] - Dashboard
  [bold]t[/bold] - Tools
  [bold]s[/bold] - Scripts
  [bold]r[/bold] - Results
  [bold]q[/bold] - Quit
  [bold]?[/bold] - Help

[bold cyan]Available Tools:[/bold cyan]
  - Access Review: AWS IAM analysis
  - Vuln Scan: Parse vulnerability scans
  - Compliance: Evidence collection
  - Log Analyzer: Security log analysis

[bold cyan]Scripts:[/bold cyan]
  Register and run custom Python/Shell scripts
  with parameter validation and history tracking.

Press [bold]Escape[/bold] to close this help.
                        """,
                        id="help-content",
                    )
                    yield Button("Close", variant="primary", id="close-help")

            def on_button_pressed(self, event: Button.Pressed) -> None:
                if event.button.id == "close-help":
                    self.dismiss()

        self.push_screen(HelpScreen())
