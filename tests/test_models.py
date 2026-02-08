"""Tests for Pydantic models."""

from datetime import datetime

import pytest

from security_toolkit.core.models import (
    AccessReviewFinding,
    ComplianceEvidence,
    ExecutionHistory,
    ExecutionStatus,
    ExecutionType,
    IAMRole,
    IAMUser,
    LogAnalysisResult,
    LogEvent,
    Parameter,
    ParameterType,
    Script,
    ScriptType,
    Vulnerability,
)


class TestModels:
    """Tests for Pydantic models."""

    def test_parameter_model(self):
        """Test Parameter model."""
        param = Parameter(
            name="input_file",
            param_type=ParameterType.FILE,
            required=True,
            description="Input file path",
        )

        assert param.name == "input_file"
        assert param.param_type == ParameterType.FILE
        assert param.required is True

    def test_parameter_with_choices(self):
        """Test Parameter with choices."""
        param = Parameter(
            name="format",
            param_type=ParameterType.CHOICE,
            choices=["json", "csv", "html"],
            default="json",
        )

        assert param.choices == ["json", "csv", "html"]
        assert param.default == "json"

    def test_script_model(self):
        """Test Script model."""
        script = Script(
            name="test-script",
            description="A test script",
            path="/path/to/script.py",
            script_type=ScriptType.PYTHON,
            category="testing",
        )

        assert script.name == "test-script"
        assert script.script_type == ScriptType.PYTHON
        assert script.is_active is True

    def test_script_with_parameters(self):
        """Test Script with parameters."""
        script = Script(
            name="param-script",
            path="/path/script.py",
            script_type=ScriptType.PYTHON,
            parameters=[
                Parameter(name="input", param_type=ParameterType.FILE, required=True),
                Parameter(name="verbose", param_type=ParameterType.BOOL, default=False),
            ],
        )

        assert len(script.parameters) == 2

    def test_execution_history_model(self):
        """Test ExecutionHistory model."""
        execution = ExecutionHistory(
            tool_name="access-review",
            execution_type=ExecutionType.TOOL,
            parameters={"check_mfa": True},
            status=ExecutionStatus.RUNNING,
        )

        assert execution.tool_name == "access-review"
        assert execution.execution_type == ExecutionType.TOOL
        assert execution.status == ExecutionStatus.RUNNING

    def test_iam_user_model(self):
        """Test IAMUser model."""
        user = IAMUser(
            user_name="testuser",
            user_id="AIDA123456",
            arn="arn:aws:iam::123456789:user/testuser",
            created_at=datetime.now(),
            mfa_enabled=True,
            groups=["Developers"],
        )

        assert user.user_name == "testuser"
        assert user.mfa_enabled is True

    def test_iam_role_model(self):
        """Test IAMRole model."""
        role = IAMRole(
            role_name="AdminRole",
            role_id="AROA123456",
            arn="arn:aws:iam::123456789:role/AdminRole",
            created_at=datetime.now(),
            attached_policies=["AdministratorAccess"],
        )

        assert role.role_name == "AdminRole"

    def test_access_review_finding(self):
        """Test AccessReviewFinding model."""
        finding = AccessReviewFinding(
            finding_type="mfa_disabled",
            severity="high",
            resource_type="IAM User",
            resource_id="AIDA123",
            resource_name="testuser",
            description="User has no MFA enabled",
            recommendation="Enable MFA",
        )

        assert finding.severity == "high"
        assert finding.finding_type == "mfa_disabled"

    def test_vulnerability_model(self):
        """Test Vulnerability model."""
        vuln = Vulnerability(
            vuln_id="NESSUS-12345",
            plugin_id="12345",
            title="SSH Weak Cipher",
            severity="medium",
            cvss_score=5.3,
            cve_ids=["CVE-2021-1234"],
            host="192.168.1.1",
            port=22,
        )

        assert vuln.severity == "medium"
        assert vuln.cvss_score == 5.3

    def test_compliance_evidence_model(self):
        """Test ComplianceEvidence model."""
        evidence = ComplianceEvidence(
            control_id="CC6.1",
            control_name="Access Control",
            framework="soc2",
            status="pass",
            evidence_type="aws_iam",
            source="AWS IAM",
            data={"users": 10, "mfa_enabled": 8},
        )

        assert evidence.framework == "soc2"
        assert evidence.status == "pass"

    def test_log_event_model(self):
        """Test LogEvent model."""
        event = LogEvent(
            timestamp=datetime.now(),
            source="auth.log",
            event_type="failed_password",
            severity="warning",
            message="Failed password for admin",
            user="admin",
            source_ip="192.168.1.100",
        )

        assert event.event_type == "failed_password"
        assert event.user == "admin"

    def test_log_analysis_result(self):
        """Test LogAnalysisResult model."""
        result = LogAnalysisResult(
            total_events=100,
            events_by_type={"failed_password": 20, "accepted_password": 80},
            events_by_severity={"warning": 20, "info": 80},
        )

        assert result.total_events == 100
        assert result.events_by_type["failed_password"] == 20
