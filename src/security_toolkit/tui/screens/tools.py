"""Tools screen for the TUI."""

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Input, Label, Select, Static, TextArea

from security_toolkit.tools.access_review import AccessReviewTool
from security_toolkit.tools.compliance import ComplianceTool
from security_toolkit.tools.log_analyzer import LogAnalyzerTool
from security_toolkit.tools.vuln_scan import VulnScanTool


class ToolsScreen(Screen):
    """Tools screen for running security tools."""

    TOOLS = {
        "access-review": {
            "class": AccessReviewTool,
            "description": "AWS IAM access analysis and permission review",
            "params": [
                ("inactive_days", "int", "90", "Days threshold for inactivity"),
            ],
        },
        "vuln-scan": {
            "class": VulnScanTool,
            "description": "Parse Nessus, Qualys, OpenVAS vulnerability scans",
            "params": [
                ("input_file", "file", "", "Path to scan file"),
                ("scanner_type", "choice", "auto", "Scanner type"),
                ("min_severity", "choice", "info", "Minimum severity"),
            ],
        },
        "compliance": {
            "class": ComplianceTool,
            "description": "Collect SOC2, ISO27001, PCI-DSS compliance evidence",
            "params": [
                ("framework", "choice", "soc2", "Compliance framework"),
            ],
        },
        "log-analyzer": {
            "class": LogAnalyzerTool,
            "description": "Analyze auth.log, syslog, CloudTrail logs",
            "params": [
                ("input_file", "file", "", "Path to log file"),
                ("log_type", "choice", "auto", "Log type"),
            ],
        },
    }

    def __init__(self) -> None:
        super().__init__()
        self._selected_tool: str | None = None
        self._output: str = ""

    def compose(self) -> ComposeResult:
        """Compose the tools layout."""
        with Container(id="main-content"):
            yield Static("[bold]Security Tools[/bold]", classes="box-title")

            with Horizontal():
                # Tool selection panel
                with Vertical(classes="box", id="tool-select"):
                    yield Static("[bold cyan]Select Tool[/bold cyan]")
                    yield Select(
                        [(name, name) for name in self.TOOLS.keys()],
                        prompt="Choose a tool",
                        id="tool-selector",
                    )
                    yield Static(id="tool-description")

                # Parameters panel
                with Vertical(classes="box", id="tool-params"):
                    yield Static("[bold cyan]Parameters[/bold cyan]")
                    yield Container(id="params-container")
                    yield Button("Run Tool", variant="primary", id="run-tool", disabled=True)

            # Output panel
            with Vertical(classes="box", id="output-panel"):
                yield Static("[bold cyan]Output[/bold cyan]")
                yield TextArea(id="tool-output", read_only=True)

    def on_select_changed(self, event: Select.Changed) -> None:
        """Handle tool selection."""
        if event.select.id == "tool-selector":
            self._selected_tool = str(event.value) if event.value else None
            self._update_tool_ui()

    def _update_tool_ui(self) -> None:
        """Update UI based on selected tool."""
        if not self._selected_tool or self._selected_tool not in self.TOOLS:
            self.query_one("#tool-description", Static).update("")
            self.query_one("#run-tool", Button).disabled = True
            return

        tool_info = self.TOOLS[self._selected_tool]

        # Update description
        self.query_one("#tool-description", Static).update(
            f"\n{tool_info['description']}"
        )

        # Update parameters
        params_container = self.query_one("#params-container", Container)
        params_container.remove_children()

        for param_name, param_type, default, description in tool_info["params"]:
            label = Label(f"{param_name}: {description}")
            params_container.mount(label)

            if param_type == "choice":
                if param_name == "framework":
                    options = [("soc2", "soc2"), ("iso27001", "iso27001"), ("pci-dss", "pci-dss")]
                elif param_name == "scanner_type":
                    options = [("auto", "auto"), ("nessus", "nessus"), ("qualys", "qualys"), ("openvas", "openvas")]
                elif param_name == "min_severity":
                    options = [("info", "info"), ("low", "low"), ("medium", "medium"), ("high", "high"), ("critical", "critical")]
                elif param_name == "log_type":
                    options = [("auto", "auto"), ("auth", "auth"), ("syslog", "syslog"), ("cloudtrail", "cloudtrail")]
                else:
                    options = []

                select = Select(options, value=default, id=f"param-{param_name}")
                params_container.mount(select)
            else:
                input_widget = Input(value=default, placeholder=description, id=f"param-{param_name}")
                params_container.mount(input_widget)

        self.query_one("#run-tool", Button).disabled = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press."""
        if event.button.id == "run-tool":
            self._run_tool()

    def _run_tool(self) -> None:
        """Run the selected tool."""
        if not self._selected_tool or self._selected_tool not in self.TOOLS:
            return

        tool_info = self.TOOLS[self._selected_tool]
        tool_class = tool_info["class"]

        # Collect parameters
        params = {}
        for param_name, param_type, _, _ in tool_info["params"]:
            widget_id = f"param-{param_name}"
            try:
                widget = self.query_one(f"#{widget_id}")
                if isinstance(widget, Input):
                    value = widget.value
                elif isinstance(widget, Select):
                    value = widget.value
                else:
                    continue

                if value:
                    if param_type == "int":
                        params[param_name] = int(value)
                    else:
                        params[param_name] = value
            except Exception:
                pass

        # Update output
        output_area = self.query_one("#tool-output", TextArea)
        output_area.load_text(f"Running {self._selected_tool}...\n")

        try:
            tool = tool_class()
            result = tool.execute(**params)

            # Format output
            output_lines = [
                f"Tool: {result.tool_name}",
                f"Status: {'Success' if result.success else 'Failed'}",
                f"Started: {result.started_at}",
                f"Completed: {result.completed_at}",
                "",
                "--- Summary ---",
            ]

            for key, value in result.summary.items():
                output_lines.append(f"{key}: {value}")

            if result.errors:
                output_lines.append("")
                output_lines.append("--- Errors ---")
                for error in result.errors:
                    output_lines.append(f"ERROR: {error}")

            if result.findings:
                output_lines.append("")
                output_lines.append(f"--- Findings ({len(result.findings)}) ---")
                for finding in result.findings[:10]:
                    if isinstance(finding, dict):
                        severity = finding.get("severity", "info").upper()
                        title = finding.get("title") or finding.get("finding_type") or finding.get("control_id", "")
                        output_lines.append(f"[{severity}] {title}")

                if len(result.findings) > 10:
                    output_lines.append(f"... and {len(result.findings) - 10} more")

            output_area.load_text("\n".join(output_lines))

        except Exception as e:
            output_area.load_text(f"Error running tool: {e}")
