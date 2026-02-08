"""Compliance Evidence Collection tool for SOC2, ISO27001, and PCI-DSS."""

from datetime import datetime
from pathlib import Path
from typing import Any

from security_toolkit.core.config import get_settings
from security_toolkit.core.models import ComplianceEvidence
from security_toolkit.tools.base import BaseTool, ToolResult


class ComplianceTool(BaseTool):
    """Tool for collecting compliance evidence."""

    name = "compliance"
    description = "Collect compliance evidence for SOC2, ISO27001, and PCI-DSS frameworks"
    version = "1.0.0"

    # Framework control definitions
    FRAMEWORKS = {
        "soc2": {
            "name": "SOC 2 Type II",
            "controls": {
                "CC6.1": "Logical and Physical Access Controls",
                "CC6.2": "System Access Management",
                "CC6.3": "Access Removal",
                "CC6.6": "Malicious Software Prevention",
                "CC6.7": "Transmission Protection",
                "CC7.1": "Configuration Management",
                "CC7.2": "Change Management",
                "CC8.1": "Incident Management",
            },
        },
        "iso27001": {
            "name": "ISO 27001:2022",
            "controls": {
                "A.5.15": "Access Control",
                "A.5.17": "Authentication Information",
                "A.5.18": "Access Rights",
                "A.8.2": "Privileged Access Rights",
                "A.8.3": "Information Access Restriction",
                "A.8.9": "Configuration Management",
                "A.8.15": "Logging",
                "A.8.16": "Monitoring Activities",
            },
        },
        "pci-dss": {
            "name": "PCI DSS v4.0",
            "controls": {
                "1.2": "Network Security Controls",
                "2.2": "Secure Configuration Standards",
                "7.2": "Access Control Systems",
                "8.2": "User Identification",
                "8.3": "Authentication Factors",
                "10.2": "Audit Log Implementation",
                "10.3": "Audit Log Protection",
                "11.3": "Vulnerability Scanning",
            },
        },
    }

    def __init__(self) -> None:
        """Initialize the compliance tool."""
        super().__init__()
        self._settings = get_settings()
        self._aws_clients: dict[str, Any] = {}

    def _get_aws_client(self, service: str) -> Any:
        """Get or create AWS client."""
        if service not in self._aws_clients:
            import boto3

            session_kwargs: dict[str, Any] = {"region_name": self._settings.aws_region}
            if self._settings.aws_profile:
                session_kwargs["profile_name"] = self._settings.aws_profile

            session = boto3.Session(**session_kwargs)
            self._aws_clients[service] = session.client(service)
        return self._aws_clients[service]

    def run(
        self,
        framework: str,
        controls: list[str] | None = None,
        output_dir: str | None = None,
        include_aws: bool = True,
        **kwargs: Any,
    ) -> ToolResult:
        """Collect compliance evidence for the specified framework."""
        result = ToolResult(tool_name=self.name)

        framework = framework.lower()
        if framework not in self.FRAMEWORKS:
            result.errors.append(
                f"Unsupported framework: {framework}. Supported: {', '.join(self.FRAMEWORKS.keys())}"
            )
            return result

        framework_info = self.FRAMEWORKS[framework]
        available_controls = framework_info["controls"]

        # Filter controls if specified
        if controls:
            target_controls = {c: available_controls[c] for c in controls if c in available_controls}
            unknown = [c for c in controls if c not in available_controls]
            if unknown:
                result.warnings.append(f"Unknown controls skipped: {', '.join(unknown)}")
        else:
            target_controls = available_controls

        evidence_list: list[ComplianceEvidence] = []

        # Collect evidence for each control
        for control_id, control_name in target_controls.items():
            try:
                evidence = self._collect_evidence(framework, control_id, control_name, include_aws)
                evidence_list.extend(evidence)
            except Exception as e:
                result.warnings.append(f"Error collecting evidence for {control_id}: {e}")

        # Save evidence if output directory specified
        if output_dir:
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            self._save_evidence(evidence_list, output_path, framework)
            result.data = {"output_dir": str(output_path)}

        result.findings = [e.model_dump() for e in evidence_list]
        result.summary = self._generate_summary(evidence_list, framework_info)

        return result

    def _collect_evidence(
        self,
        framework: str,
        control_id: str,
        control_name: str,
        include_aws: bool,
    ) -> list[ComplianceEvidence]:
        """Collect evidence for a specific control."""
        evidence: list[ComplianceEvidence] = []

        # Map controls to evidence collection methods
        if framework == "soc2":
            evidence.extend(self._collect_soc2_evidence(control_id, control_name, include_aws))
        elif framework == "iso27001":
            evidence.extend(self._collect_iso27001_evidence(control_id, control_name, include_aws))
        elif framework == "pci-dss":
            evidence.extend(self._collect_pci_evidence(control_id, control_name, include_aws))

        return evidence

    def _collect_soc2_evidence(
        self, control_id: str, control_name: str, include_aws: bool
    ) -> list[ComplianceEvidence]:
        """Collect SOC 2 specific evidence."""
        evidence: list[ComplianceEvidence] = []

        if control_id == "CC6.1" and include_aws:
            # Logical and Physical Access Controls
            evidence.extend(self._collect_iam_evidence("soc2", control_id, control_name))

        elif control_id == "CC6.2" and include_aws:
            # System Access Management
            evidence.extend(self._collect_iam_policies_evidence("soc2", control_id, control_name))

        elif control_id == "CC7.1" and include_aws:
            # Configuration Management
            evidence.extend(self._collect_config_evidence("soc2", control_id, control_name))

        elif control_id == "CC8.1" and include_aws:
            # Incident Management
            evidence.extend(self._collect_securityhub_evidence("soc2", control_id, control_name))

        else:
            # Create placeholder evidence for manual collection
            evidence.append(
                ComplianceEvidence(
                    control_id=control_id,
                    control_name=control_name,
                    framework="soc2",
                    status="not_applicable",
                    evidence_type="manual",
                    source="manual_collection_required",
                    notes="This control requires manual evidence collection",
                )
            )

        return evidence

    def _collect_iso27001_evidence(
        self, control_id: str, control_name: str, include_aws: bool
    ) -> list[ComplianceEvidence]:
        """Collect ISO 27001 specific evidence."""
        evidence: list[ComplianceEvidence] = []

        if control_id in ["A.5.15", "A.5.18", "A.8.2"] and include_aws:
            evidence.extend(self._collect_iam_evidence("iso27001", control_id, control_name))

        elif control_id == "A.8.9" and include_aws:
            evidence.extend(self._collect_config_evidence("iso27001", control_id, control_name))

        elif control_id in ["A.8.15", "A.8.16"] and include_aws:
            evidence.extend(self._collect_cloudtrail_evidence("iso27001", control_id, control_name))

        else:
            evidence.append(
                ComplianceEvidence(
                    control_id=control_id,
                    control_name=control_name,
                    framework="iso27001",
                    status="not_applicable",
                    evidence_type="manual",
                    source="manual_collection_required",
                    notes="This control requires manual evidence collection",
                )
            )

        return evidence

    def _collect_pci_evidence(
        self, control_id: str, control_name: str, include_aws: bool
    ) -> list[ComplianceEvidence]:
        """Collect PCI-DSS specific evidence."""
        evidence: list[ComplianceEvidence] = []

        if control_id in ["7.2", "8.2", "8.3"] and include_aws:
            evidence.extend(self._collect_iam_evidence("pci-dss", control_id, control_name))

        elif control_id == "2.2" and include_aws:
            evidence.extend(self._collect_config_evidence("pci-dss", control_id, control_name))

        elif control_id in ["10.2", "10.3"] and include_aws:
            evidence.extend(self._collect_cloudtrail_evidence("pci-dss", control_id, control_name))

        else:
            evidence.append(
                ComplianceEvidence(
                    control_id=control_id,
                    control_name=control_name,
                    framework="pci-dss",
                    status="not_applicable",
                    evidence_type="manual",
                    source="manual_collection_required",
                    notes="This control requires manual evidence collection",
                )
            )

        return evidence

    def _collect_iam_evidence(
        self, framework: str, control_id: str, control_name: str
    ) -> list[ComplianceEvidence]:
        """Collect IAM-related evidence."""
        evidence: list[ComplianceEvidence] = []

        try:
            iam = self._get_aws_client("iam")

            # Get account summary
            summary = iam.get_account_summary()
            summary_data = summary.get("SummaryMap", {})

            evidence.append(
                ComplianceEvidence(
                    control_id=control_id,
                    control_name=control_name,
                    framework=framework,
                    status="pass",
                    evidence_type="aws_iam_summary",
                    source="AWS IAM",
                    data={
                        "users": summary_data.get("Users", 0),
                        "groups": summary_data.get("Groups", 0),
                        "roles": summary_data.get("Roles", 0),
                        "policies": summary_data.get("Policies", 0),
                        "mfa_enabled": summary_data.get("MFADevices", 0),
                    },
                )
            )

            # Get password policy
            try:
                password_policy = iam.get_account_password_policy()
                policy = password_policy.get("PasswordPolicy", {})

                evidence.append(
                    ComplianceEvidence(
                        control_id=control_id,
                        control_name=control_name,
                        framework=framework,
                        status="pass" if policy.get("RequireMFA", False) else "partial",
                        evidence_type="aws_password_policy",
                        source="AWS IAM",
                        data={
                            "minimum_length": policy.get("MinimumPasswordLength"),
                            "require_symbols": policy.get("RequireSymbols"),
                            "require_numbers": policy.get("RequireNumbers"),
                            "require_uppercase": policy.get("RequireUppercaseCharacters"),
                            "require_lowercase": policy.get("RequireLowercaseCharacters"),
                            "allow_users_to_change": policy.get("AllowUsersToChangePassword"),
                            "max_password_age": policy.get("MaxPasswordAge"),
                            "password_reuse_prevention": policy.get("PasswordReusePrevention"),
                        },
                    )
                )
            except iam.exceptions.NoSuchEntityException:
                evidence.append(
                    ComplianceEvidence(
                        control_id=control_id,
                        control_name=control_name,
                        framework=framework,
                        status="fail",
                        evidence_type="aws_password_policy",
                        source="AWS IAM",
                        notes="No password policy configured",
                    )
                )

        except ImportError:
            evidence.append(
                ComplianceEvidence(
                    control_id=control_id,
                    control_name=control_name,
                    framework=framework,
                    status="not_applicable",
                    evidence_type="error",
                    source="AWS IAM",
                    notes="boto3 not installed",
                )
            )
        except Exception as e:
            evidence.append(
                ComplianceEvidence(
                    control_id=control_id,
                    control_name=control_name,
                    framework=framework,
                    status="not_applicable",
                    evidence_type="error",
                    source="AWS IAM",
                    notes=f"Error: {e}",
                )
            )

        return evidence

    def _collect_iam_policies_evidence(
        self, framework: str, control_id: str, control_name: str
    ) -> list[ComplianceEvidence]:
        """Collect IAM policies evidence."""
        evidence: list[ComplianceEvidence] = []

        try:
            iam = self._get_aws_client("iam")

            # List customer managed policies
            policies = []
            paginator = iam.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local"):
                for policy in page.get("Policies", []):
                    policies.append({
                        "name": policy["PolicyName"],
                        "arn": policy["Arn"],
                        "attachment_count": policy.get("AttachmentCount", 0),
                    })

            evidence.append(
                ComplianceEvidence(
                    control_id=control_id,
                    control_name=control_name,
                    framework=framework,
                    status="pass",
                    evidence_type="aws_iam_policies",
                    source="AWS IAM",
                    data={
                        "total_policies": len(policies),
                        "policies": policies[:20],  # Limit for readability
                    },
                )
            )

        except Exception as e:
            evidence.append(
                ComplianceEvidence(
                    control_id=control_id,
                    control_name=control_name,
                    framework=framework,
                    status="not_applicable",
                    evidence_type="error",
                    source="AWS IAM",
                    notes=f"Error: {e}",
                )
            )

        return evidence

    def _collect_config_evidence(
        self, framework: str, control_id: str, control_name: str
    ) -> list[ComplianceEvidence]:
        """Collect AWS Config evidence."""
        evidence: list[ComplianceEvidence] = []

        try:
            config = self._get_aws_client("config")

            # Get Config recorders
            recorders = config.describe_configuration_recorders()
            recorder_data = recorders.get("ConfigurationRecorders", [])

            # Get compliance summary
            try:
                compliance = config.get_compliance_summary_by_config_rule()
                compliance_data = compliance.get("ComplianceSummary", {})
            except Exception:
                compliance_data = {}

            evidence.append(
                ComplianceEvidence(
                    control_id=control_id,
                    control_name=control_name,
                    framework=framework,
                    status="pass" if recorder_data else "fail",
                    evidence_type="aws_config",
                    source="AWS Config",
                    data={
                        "recorders_enabled": len(recorder_data),
                        "recorders": [r.get("name") for r in recorder_data],
                        "compliant_rules": compliance_data.get("CompliantResourceCount", {}).get("CappedCount", 0),
                        "non_compliant_rules": compliance_data.get("NonCompliantResourceCount", {}).get("CappedCount", 0),
                    },
                )
            )

        except Exception as e:
            evidence.append(
                ComplianceEvidence(
                    control_id=control_id,
                    control_name=control_name,
                    framework=framework,
                    status="not_applicable",
                    evidence_type="error",
                    source="AWS Config",
                    notes=f"Error: {e}",
                )
            )

        return evidence

    def _collect_cloudtrail_evidence(
        self, framework: str, control_id: str, control_name: str
    ) -> list[ComplianceEvidence]:
        """Collect CloudTrail evidence."""
        evidence: list[ComplianceEvidence] = []

        try:
            cloudtrail = self._get_aws_client("cloudtrail")

            # Get trails
            trails = cloudtrail.describe_trails()
            trail_list = trails.get("trailList", [])

            for trail in trail_list:
                # Get trail status
                try:
                    status = cloudtrail.get_trail_status(Name=trail["TrailARN"])
                    is_logging = status.get("IsLogging", False)
                except Exception:
                    is_logging = False

                evidence.append(
                    ComplianceEvidence(
                        control_id=control_id,
                        control_name=control_name,
                        framework=framework,
                        status="pass" if is_logging else "fail",
                        evidence_type="aws_cloudtrail",
                        source="AWS CloudTrail",
                        data={
                            "trail_name": trail.get("Name"),
                            "is_multi_region": trail.get("IsMultiRegionTrail", False),
                            "is_logging": is_logging,
                            "log_file_validation": trail.get("LogFileValidationEnabled", False),
                            "s3_bucket": trail.get("S3BucketName"),
                            "kms_key_id": trail.get("KmsKeyId"),
                        },
                    )
                )

            if not trail_list:
                evidence.append(
                    ComplianceEvidence(
                        control_id=control_id,
                        control_name=control_name,
                        framework=framework,
                        status="fail",
                        evidence_type="aws_cloudtrail",
                        source="AWS CloudTrail",
                        notes="No CloudTrail trails configured",
                    )
                )

        except Exception as e:
            evidence.append(
                ComplianceEvidence(
                    control_id=control_id,
                    control_name=control_name,
                    framework=framework,
                    status="not_applicable",
                    evidence_type="error",
                    source="AWS CloudTrail",
                    notes=f"Error: {e}",
                )
            )

        return evidence

    def _collect_securityhub_evidence(
        self, framework: str, control_id: str, control_name: str
    ) -> list[ComplianceEvidence]:
        """Collect Security Hub evidence."""
        evidence: list[ComplianceEvidence] = []

        try:
            securityhub = self._get_aws_client("securityhub")

            # Get Security Hub status
            try:
                hub = securityhub.describe_hub()
                hub_arn = hub.get("HubArn", "")

                # Get findings summary
                findings = securityhub.get_findings(
                    Filters={
                        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                    },
                    MaxResults=100,
                )

                severity_counts: dict[str, int] = {}
                for finding in findings.get("Findings", []):
                    sev = finding.get("Severity", {}).get("Label", "UNKNOWN")
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1

                evidence.append(
                    ComplianceEvidence(
                        control_id=control_id,
                        control_name=control_name,
                        framework=framework,
                        status="pass",
                        evidence_type="aws_securityhub",
                        source="AWS Security Hub",
                        data={
                            "hub_arn": hub_arn,
                            "active_findings": len(findings.get("Findings", [])),
                            "findings_by_severity": severity_counts,
                        },
                    )
                )

            except securityhub.exceptions.InvalidAccessException:
                evidence.append(
                    ComplianceEvidence(
                        control_id=control_id,
                        control_name=control_name,
                        framework=framework,
                        status="fail",
                        evidence_type="aws_securityhub",
                        source="AWS Security Hub",
                        notes="Security Hub not enabled",
                    )
                )

        except Exception as e:
            evidence.append(
                ComplianceEvidence(
                    control_id=control_id,
                    control_name=control_name,
                    framework=framework,
                    status="not_applicable",
                    evidence_type="error",
                    source="AWS Security Hub",
                    notes=f"Error: {e}",
                )
            )

        return evidence

    def _save_evidence(
        self, evidence: list[ComplianceEvidence], output_path: Path, framework: str
    ) -> None:
        """Save evidence to files."""
        import json

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save JSON
        json_file = output_path / f"{framework}_evidence_{timestamp}.json"
        with open(json_file, "w") as f:
            json.dump([e.model_dump() for e in evidence], f, indent=2, default=str)

        # Save summary
        summary_file = output_path / f"{framework}_summary_{timestamp}.txt"
        with open(summary_file, "w") as f:
            f.write(f"Compliance Evidence Collection - {framework.upper()}\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write("=" * 60 + "\n\n")

            for e in evidence:
                f.write(f"Control: {e.control_id} - {e.control_name}\n")
                f.write(f"Status: {e.status.upper()}\n")
                f.write(f"Source: {e.source}\n")
                if e.notes:
                    f.write(f"Notes: {e.notes}\n")
                f.write("-" * 40 + "\n")

    def _generate_summary(
        self, evidence: list[ComplianceEvidence], framework_info: dict[str, Any]
    ) -> dict[str, Any]:
        """Generate summary statistics."""
        status_counts: dict[str, int] = {}
        source_counts: dict[str, int] = {}

        for e in evidence:
            status_counts[e.status] = status_counts.get(e.status, 0) + 1
            source_counts[e.source] = source_counts.get(e.source, 0) + 1

        return {
            "framework": framework_info["name"],
            "total_evidence": len(evidence),
            "by_status": status_counts,
            "by_source": source_counts,
            "pass_rate": f"{status_counts.get('pass', 0) / len(evidence) * 100:.1f}%" if evidence else "0%",
        }

    def get_parameter_schema(self) -> dict[str, Any]:
        """Get the parameter schema for this tool."""
        return {
            "framework": {
                "type": "choice",
                "choices": list(self.FRAMEWORKS.keys()),
                "required": True,
                "description": "Compliance framework",
            },
            "controls": {
                "type": "string",
                "description": "Comma-separated list of control IDs (optional)",
            },
            "output_dir": {
                "type": "string",
                "description": "Directory to save evidence files",
            },
            "include_aws": {
                "type": "bool",
                "default": True,
                "description": "Include AWS evidence collection",
            },
        }
