"""Pydantic models for the security toolkit."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ScriptType(str, Enum):
    """Type of script."""

    PYTHON = "python"
    SHELL = "shell"


class ParameterType(str, Enum):
    """Type of script parameter."""

    STRING = "string"
    INT = "int"
    BOOL = "bool"
    FILE = "file"
    CHOICE = "choice"


class ExecutionType(str, Enum):
    """Type of execution."""

    SCRIPT = "script"
    TOOL = "tool"


class ExecutionStatus(str, Enum):
    """Execution status."""

    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"


class Parameter(BaseModel):
    """Script parameter definition."""

    name: str = Field(..., description="Parameter name")
    param_type: ParameterType = Field(default=ParameterType.STRING, description="Parameter type")
    required: bool = Field(default=False, description="Whether parameter is required")
    default: Any = Field(default=None, description="Default value")
    description: str = Field(default="", description="Parameter description")
    choices: list[str] | None = Field(default=None, description="Valid choices for choice type")


class Script(BaseModel):
    """Custom script model."""

    id: int | None = Field(default=None, description="Database ID")
    name: str = Field(..., description="Unique script name")
    description: str = Field(default="", description="Script description")
    path: str = Field(..., description="Path to script file")
    script_type: ScriptType = Field(..., description="Script type (python/shell)")
    category: str = Field(default="uncategorized", description="Script category")
    parameters: list[Parameter] = Field(default_factory=list, description="Script parameters")
    is_active: bool = Field(default=True, description="Whether script is active")
    created_at: datetime | None = Field(default=None, description="Creation timestamp")


class ExecutionHistory(BaseModel):
    """Execution history record."""

    id: int | None = Field(default=None, description="Database ID")
    script_id: int | None = Field(default=None, description="Script ID if script execution")
    tool_name: str | None = Field(default=None, description="Tool name if tool execution")
    execution_type: ExecutionType = Field(..., description="Type of execution")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Execution parameters")
    status: ExecutionStatus = Field(default=ExecutionStatus.RUNNING, description="Execution status")
    started_at: datetime = Field(default_factory=datetime.now, description="Start timestamp")
    completed_at: datetime | None = Field(default=None, description="Completion timestamp")
    output_path: str | None = Field(default=None, description="Path to output file")
    error_message: str | None = Field(default=None, description="Error message if failed")


# Tool-specific models


class IAMUser(BaseModel):
    """IAM user information."""

    user_name: str
    user_id: str
    arn: str
    created_at: datetime
    password_last_used: datetime | None = None
    access_keys: list[dict[str, Any]] = Field(default_factory=list)
    mfa_enabled: bool = False
    groups: list[str] = Field(default_factory=list)
    policies: list[str] = Field(default_factory=list)
    last_activity: datetime | None = None


class IAMRole(BaseModel):
    """IAM role information."""

    role_name: str
    role_id: str
    arn: str
    created_at: datetime
    description: str = ""
    assume_role_policy: dict[str, Any] = Field(default_factory=dict)
    attached_policies: list[str] = Field(default_factory=list)
    last_used: datetime | None = None


class AccessReviewFinding(BaseModel):
    """Finding from access review."""

    finding_type: str
    severity: str  # critical, high, medium, low, info
    resource_type: str
    resource_id: str
    resource_name: str
    description: str
    recommendation: str
    details: dict[str, Any] = Field(default_factory=dict)


class Vulnerability(BaseModel):
    """Normalized vulnerability from scanner output."""

    vuln_id: str
    plugin_id: str | None = None
    title: str
    severity: str  # critical, high, medium, low, info
    cvss_score: float | None = None
    cve_ids: list[str] = Field(default_factory=list)
    host: str
    port: int | None = None
    protocol: str | None = None
    description: str = ""
    solution: str = ""
    see_also: list[str] = Field(default_factory=list)
    plugin_output: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class ComplianceEvidence(BaseModel):
    """Compliance evidence item."""

    control_id: str
    control_name: str
    framework: str  # soc2, iso27001, pci-dss
    status: str  # pass, fail, partial, not_applicable
    evidence_type: str
    collected_at: datetime = Field(default_factory=datetime.now)
    source: str
    data: dict[str, Any] = Field(default_factory=dict)
    notes: str = ""


class LogEvent(BaseModel):
    """Parsed log event."""

    timestamp: datetime
    source: str
    event_type: str
    severity: str
    message: str
    user: str | None = None
    source_ip: str | None = None
    destination: str | None = None
    action: str | None = None
    status: str | None = None
    raw_data: dict[str, Any] = Field(default_factory=dict)


class LogAnalysisResult(BaseModel):
    """Log analysis result."""

    total_events: int
    time_range_start: datetime | None = None
    time_range_end: datetime | None = None
    events_by_type: dict[str, int] = Field(default_factory=dict)
    events_by_severity: dict[str, int] = Field(default_factory=dict)
    anomalies: list[dict[str, Any]] = Field(default_factory=list)
    top_users: list[dict[str, Any]] = Field(default_factory=list)
    top_sources: list[dict[str, Any]] = Field(default_factory=list)
    failed_attempts: list[LogEvent] = Field(default_factory=list)
