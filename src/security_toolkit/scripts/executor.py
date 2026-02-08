"""Script executor for running custom scripts."""

import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from security_toolkit.core.config import get_settings
from security_toolkit.core.database import get_database
from security_toolkit.core.models import (
    ExecutionHistory,
    ExecutionStatus,
    ExecutionType,
    Script,
    ScriptType,
)
from security_toolkit.scripts.manager import ScriptManager


class ScriptExecutor:
    """Executor for custom scripts."""

    def __init__(self) -> None:
        """Initialize the script executor."""
        self.db = get_database()
        self.settings = get_settings()
        self.manager = ScriptManager()

    def run(
        self,
        script_name: str,
        parameters: dict[str, Any] | None = None,
        timeout: int | None = None,
        capture_output: bool = True,
    ) -> tuple[ExecutionHistory, str, str]:
        """
        Run a script by name.

        Returns:
            Tuple of (execution record, stdout, stderr)
        """
        script = self.manager.get(name=script_name)
        if not script:
            raise ValueError(f"Script '{script_name}' not found")

        if not script.is_active:
            raise ValueError(f"Script '{script_name}' is inactive")

        params = parameters or {}

        # Validate parameters
        valid, errors = self.manager.validate_parameters(script, params)
        if not valid:
            raise ValueError(f"Parameter validation failed: {'; '.join(errors)}")

        # Apply default values
        for param_def in script.parameters:
            if param_def.name not in params and param_def.default is not None:
                params[param_def.name] = param_def.default

        # Create execution record
        execution = self.db.create_execution(
            ExecutionHistory(
                script_id=script.id,
                execution_type=ExecutionType.SCRIPT,
                parameters=params,
                status=ExecutionStatus.RUNNING,
            )
        )

        try:
            stdout, stderr = self._execute_script(
                script, params, timeout or self.settings.max_script_runtime, capture_output
            )

            execution.status = ExecutionStatus.SUCCESS
            execution.completed_at = datetime.now()

            # Save output if requested
            if capture_output and stdout:
                output_file = self._save_output(script.name, execution.id or 0, stdout)
                execution.output_path = str(output_file)

        except subprocess.TimeoutExpired:
            execution.status = ExecutionStatus.FAILED
            execution.completed_at = datetime.now()
            execution.error_message = f"Script timed out after {timeout or self.settings.max_script_runtime} seconds"
            stdout, stderr = "", execution.error_message

        except subprocess.CalledProcessError as e:
            execution.status = ExecutionStatus.FAILED
            execution.completed_at = datetime.now()
            execution.error_message = f"Script exited with code {e.returncode}"
            stdout = e.stdout if e.stdout else ""
            stderr = e.stderr if e.stderr else str(e)

        except Exception as e:
            execution.status = ExecutionStatus.FAILED
            execution.completed_at = datetime.now()
            execution.error_message = str(e)
            stdout, stderr = "", str(e)

        self.db.update_execution(execution)
        return execution, stdout, stderr

    def _execute_script(
        self,
        script: Script,
        params: dict[str, Any],
        timeout: int,
        capture_output: bool,
    ) -> tuple[str, str]:
        """Execute a script with parameters."""
        script_path = Path(script.path)

        if not script_path.exists():
            raise FileNotFoundError(f"Script file not found: {script_path}")

        # Build command based on script type
        if script.script_type == ScriptType.PYTHON:
            cmd = [sys.executable, str(script_path)]
        elif script.script_type == ScriptType.SHELL:
            cmd = ["/bin/bash", str(script_path)]
        else:
            raise ValueError(f"Unsupported script type: {script.script_type}")

        # Add parameters as arguments
        for name, value in params.items():
            if isinstance(value, bool):
                if value:
                    cmd.append(f"--{name}")
            else:
                cmd.extend([f"--{name}", str(value)])

        # Set up environment
        env = os.environ.copy()
        env["SECKIT_SCRIPT_NAME"] = script.name
        env["SECKIT_SCRIPT_PATH"] = str(script_path)

        # Add parameters as environment variables too
        for name, value in params.items():
            env[f"SECKIT_PARAM_{name.upper()}"] = str(value)

        # Execute
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            env=env,
            cwd=script_path.parent,
        )

        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode,
                cmd,
                result.stdout,
                result.stderr,
            )

        return result.stdout or "", result.stderr or ""

    def _save_output(self, script_name: str, execution_id: int, output: str) -> Path:
        """Save script output to file."""
        output_dir = self.settings.output_dir / "scripts"
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = output_dir / f"{script_name}_{execution_id}_{timestamp}.txt"

        with open(output_file, "w") as f:
            f.write(output)

        return output_file

    def get_history(
        self,
        script_name: str | None = None,
        limit: int = 50,
    ) -> list[ExecutionHistory]:
        """Get execution history for scripts."""
        script_id = None
        if script_name:
            script = self.manager.get(name=script_name)
            if script:
                script_id = script.id

        return self.db.list_executions(script_id=script_id, limit=limit)

    def get_execution(self, execution_id: int) -> ExecutionHistory | None:
        """Get a specific execution record."""
        return self.db.get_execution(execution_id)

    def get_output(self, execution_id: int) -> str | None:
        """Get the output of a script execution."""
        execution = self.db.get_execution(execution_id)
        if not execution or not execution.output_path:
            return None

        output_path = Path(execution.output_path)
        if not output_path.exists():
            return None

        with open(output_path) as f:
            return f.read()
