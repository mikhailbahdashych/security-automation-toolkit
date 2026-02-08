"""Base class for security tools."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from security_toolkit.core.database import get_database
from security_toolkit.core.models import ExecutionHistory, ExecutionStatus, ExecutionType


class ToolResult(BaseModel):
    """Result from tool execution."""

    success: bool = True
    tool_name: str
    started_at: datetime = Field(default_factory=datetime.now)
    completed_at: datetime | None = None
    data: Any = None
    findings: list[Any] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    def finish(self, success: bool = True) -> "ToolResult":
        """Mark the result as finished."""
        self.completed_at = datetime.now()
        self.success = success
        return self


class BaseTool(ABC):
    """Abstract base class for security tools."""

    name: str = "base_tool"
    description: str = "Base security tool"
    version: str = "1.0.0"

    def __init__(self) -> None:
        """Initialize the tool."""
        self.db = get_database()
        self._execution: ExecutionHistory | None = None

    @abstractmethod
    def run(self, **kwargs: Any) -> ToolResult:
        """Run the tool with the given parameters."""
        pass

    def execute(self, **kwargs: Any) -> ToolResult:
        """Execute the tool with tracking."""
        # Create execution record
        self._execution = self.db.create_execution(
            ExecutionHistory(
                tool_name=self.name,
                execution_type=ExecutionType.TOOL,
                parameters=kwargs,
                status=ExecutionStatus.RUNNING,
            )
        )

        try:
            result = self.run(**kwargs)
            result.finish(success=len(result.errors) == 0)

            # Update execution record
            self._execution.status = (
                ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILED
            )
            self._execution.completed_at = result.completed_at
            if result.errors:
                self._execution.error_message = "; ".join(result.errors)

        except Exception as e:
            result = ToolResult(
                tool_name=self.name,
                success=False,
                errors=[str(e)],
            ).finish(success=False)

            self._execution.status = ExecutionStatus.FAILED
            self._execution.completed_at = datetime.now()
            self._execution.error_message = str(e)

        self.db.update_execution(self._execution)
        return result

    def get_parameter_schema(self) -> dict[str, Any]:
        """Get the parameter schema for this tool."""
        return {}

    @classmethod
    def get_info(cls) -> dict[str, str]:
        """Get tool information."""
        return {
            "name": cls.name,
            "description": cls.description,
            "version": cls.version,
        }
