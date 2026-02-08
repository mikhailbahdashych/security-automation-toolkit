"""Script manager for CRUD operations on custom scripts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from security_toolkit.core.config import get_settings
from security_toolkit.core.database import get_database
from security_toolkit.core.models import Parameter, ParameterType, Script, ScriptType


class ScriptManager:
    """Manager for custom script CRUD operations."""

    def __init__(self) -> None:
        """Initialize the script manager."""
        self.db = get_database()
        self.settings = get_settings()

    def register(
        self,
        name: str,
        path: str,
        description: str = "",
        category: str = "uncategorized",
        parameters: list[dict[str, Any]] | None = None,
    ) -> Script:
        """Register a new script."""
        # Validate path
        script_path = Path(path)
        if not script_path.is_absolute():
            script_path = self.settings.scripts_dir / path

        if not script_path.exists():
            raise FileNotFoundError(f"Script file not found: {script_path}")

        # Detect script type
        suffix = script_path.suffix.lower()
        if suffix == ".py":
            script_type = ScriptType.PYTHON
        elif suffix in [".sh", ".bash"]:
            script_type = ScriptType.SHELL
        else:
            raise ValueError(f"Unsupported script type: {suffix}. Use .py or .sh")

        # Parse parameters
        parsed_params: list[Parameter] = []
        if parameters:
            for param in parameters:
                param_type = ParameterType(param.get("type", "string"))
                parsed_params.append(
                    Parameter(
                        name=param["name"],
                        param_type=param_type,
                        required=param.get("required", False),
                        default=param.get("default"),
                        description=param.get("description", ""),
                        choices=param.get("choices"),
                    )
                )

        # Check if script already exists
        existing = self.db.get_script(name=name)
        if existing:
            raise ValueError(f"Script '{name}' already exists. Use update() to modify.")

        script = Script(
            name=name,
            description=description,
            path=str(script_path),
            script_type=script_type,
            category=category,
            parameters=parsed_params,
        )

        return self.db.create_script(script)

    def get(self, name: str | None = None, script_id: int | None = None) -> Script | None:
        """Get a script by name or ID."""
        return self.db.get_script(script_id=script_id, name=name)

    def list(
        self,
        category: str | None = None,
        include_inactive: bool = False,
    ) -> list[Script]:
        """List all scripts."""
        return self.db.list_scripts(category=category, active_only=not include_inactive)

    def update(
        self,
        name: str,
        description: str | None = None,
        category: str | None = None,
        parameters: list[dict[str, Any]] | None = None,
        is_active: bool | None = None,
    ) -> Script:
        """Update an existing script."""
        script = self.db.get_script(name=name)
        if not script:
            raise ValueError(f"Script '{name}' not found")

        if description is not None:
            script.description = description
        if category is not None:
            script.category = category
        if is_active is not None:
            script.is_active = is_active

        if parameters is not None:
            parsed_params: list[Parameter] = []
            for param in parameters:
                param_type = ParameterType(param.get("type", "string"))
                parsed_params.append(
                    Parameter(
                        name=param["name"],
                        param_type=param_type,
                        required=param.get("required", False),
                        default=param.get("default"),
                        description=param.get("description", ""),
                        choices=param.get("choices"),
                    )
                )
            script.parameters = parsed_params

        return self.db.update_script(script)

    def delete(self, name: str) -> bool:
        """Delete a script (soft delete)."""
        script = self.db.get_script(name=name)
        if not script or script.id is None:
            return False
        return self.db.delete_script(script.id)

    def get_categories(self) -> list[str]:
        """Get all unique categories."""
        scripts = self.db.list_scripts(active_only=True)
        categories = set(s.category for s in scripts)
        return sorted(categories)

    def validate_parameters(
        self, script: Script, params: dict[str, Any]
    ) -> tuple[bool, list[str]]:
        """Validate parameters against script definition."""
        errors: list[str] = []

        for param_def in script.parameters:
            value = params.get(param_def.name)

            # Check required parameters
            if param_def.required and value is None:
                errors.append(f"Missing required parameter: {param_def.name}")
                continue

            if value is None:
                continue

            # Type validation
            if param_def.param_type == ParameterType.INT:
                try:
                    int(value)
                except (ValueError, TypeError):
                    errors.append(f"Parameter '{param_def.name}' must be an integer")

            elif param_def.param_type == ParameterType.BOOL:
                if not isinstance(value, bool) and value not in ["true", "false", "1", "0"]:
                    errors.append(f"Parameter '{param_def.name}' must be a boolean")

            elif param_def.param_type == ParameterType.FILE:
                if not Path(value).exists():
                    errors.append(f"File not found for parameter '{param_def.name}': {value}")

            elif param_def.param_type == ParameterType.CHOICE:
                if param_def.choices and value not in param_def.choices:
                    errors.append(
                        f"Invalid value for '{param_def.name}'. Must be one of: {', '.join(param_def.choices)}"
                    )

        return len(errors) == 0, errors

    def import_script(self, source_path: str, name: str | None = None) -> Script:
        """Import a script from an external location."""
        source = Path(source_path)
        if not source.exists():
            raise FileNotFoundError(f"Source script not found: {source_path}")

        # Use filename as name if not provided
        if name is None:
            name = source.stem

        # Copy to scripts directory
        dest = self.settings.scripts_dir / source.name
        dest.parent.mkdir(parents=True, exist_ok=True)

        import shutil
        shutil.copy2(source, dest)

        # Register the script
        return self.register(name=name, path=str(dest))

    def export_script(self, name: str, dest_path: str) -> Path:
        """Export a script to an external location."""
        script = self.db.get_script(name=name)
        if not script:
            raise ValueError(f"Script '{name}' not found")

        source = Path(script.path)
        dest = Path(dest_path)

        if dest.is_dir():
            dest = dest / source.name

        import shutil
        shutil.copy2(source, dest)

        return dest
