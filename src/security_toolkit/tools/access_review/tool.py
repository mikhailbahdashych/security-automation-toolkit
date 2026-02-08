"""Access Review tool for AWS IAM analysis."""

from datetime import datetime, timedelta, timezone
from typing import Any

from security_toolkit.core.config import get_settings
from security_toolkit.core.models import AccessReviewFinding, IAMRole, IAMUser
from security_toolkit.tools.base import BaseTool, ToolResult


class AccessReviewTool(BaseTool):
    """Tool for reviewing AWS IAM access and permissions."""

    name = "access-review"
    description = "Analyze AWS IAM users, roles, and permissions for security issues"
    version = "1.0.0"

    def __init__(self) -> None:
        """Initialize the access review tool."""
        super().__init__()
        self._iam_client: Any = None
        self._settings = get_settings()

    def _get_iam_client(self) -> Any:
        """Get or create IAM client."""
        if self._iam_client is None:
            import boto3

            session_kwargs: dict[str, Any] = {"region_name": self._settings.aws_region}
            if self._settings.aws_profile:
                session_kwargs["profile_name"] = self._settings.aws_profile

            session = boto3.Session(**session_kwargs)
            self._iam_client = session.client("iam")
        return self._iam_client

    def run(
        self,
        check_unused_users: bool = True,
        check_unused_roles: bool = True,
        check_mfa: bool = True,
        check_access_keys: bool = True,
        check_policies: bool = True,
        inactive_days: int = 90,
        **kwargs: Any,
    ) -> ToolResult:
        """Run the access review analysis."""
        result = ToolResult(tool_name=self.name)
        findings: list[AccessReviewFinding] = []

        try:
            iam = self._get_iam_client()

            users = self._list_users(iam)
            roles = self._list_roles(iam)

            result.data = {
                "users": [u.model_dump() for u in users],
                "roles": [r.model_dump() for r in roles],
            }

            if check_unused_users:
                findings.extend(self._check_unused_users(users, inactive_days))

            if check_unused_roles:
                findings.extend(self._check_unused_roles(roles, inactive_days))

            if check_mfa:
                findings.extend(self._check_mfa_status(iam, users))

            if check_access_keys:
                findings.extend(self._check_access_keys(iam, users, inactive_days))

            if check_policies:
                findings.extend(self._check_admin_policies(iam, users, roles))

            result.findings = [f.model_dump() for f in findings]
            result.summary = self._generate_summary(findings, users, roles)

        except ImportError:
            result.errors.append(
                "boto3 is required for AWS integration. Install with: pip install boto3"
            )
        except Exception as e:
            error_msg = str(e)
            if "NoCredentialsError" in type(e).__name__ or "credentials" in error_msg.lower():
                result.errors.append(
                    "AWS credentials not configured. Run 'aws configure' or set environment variables."
                )
            else:
                result.errors.append(f"Error during access review: {error_msg}")

        return result

    def _list_users(self, iam: Any) -> list[IAMUser]:
        """List all IAM users with details."""
        users: list[IAMUser] = []
        paginator = iam.get_paginator("list_users")

        for page in paginator.paginate():
            for user_data in page["Users"]:
                # Get additional user details
                groups = self._get_user_groups(iam, user_data["UserName"])
                policies = self._get_user_policies(iam, user_data["UserName"])
                access_keys = self._get_access_keys(iam, user_data["UserName"])
                mfa_enabled = self._check_user_mfa(iam, user_data["UserName"])

                user = IAMUser(
                    user_name=user_data["UserName"],
                    user_id=user_data["UserId"],
                    arn=user_data["Arn"],
                    created_at=user_data["CreateDate"],
                    password_last_used=user_data.get("PasswordLastUsed"),
                    access_keys=access_keys,
                    mfa_enabled=mfa_enabled,
                    groups=groups,
                    policies=policies,
                )
                users.append(user)

        return users

    def _list_roles(self, iam: Any) -> list[IAMRole]:
        """List all IAM roles with details."""
        roles: list[IAMRole] = []
        paginator = iam.get_paginator("list_roles")

        for page in paginator.paginate():
            for role_data in page["Roles"]:
                # Skip service-linked roles
                if role_data.get("Path", "").startswith("/aws-service-role/"):
                    continue

                attached_policies = self._get_role_policies(iam, role_data["RoleName"])

                # Get last used info
                try:
                    role_details = iam.get_role(RoleName=role_data["RoleName"])
                    last_used_data = role_details["Role"].get("RoleLastUsed", {})
                    last_used = last_used_data.get("LastUsedDate")
                except Exception:
                    last_used = None

                role = IAMRole(
                    role_name=role_data["RoleName"],
                    role_id=role_data["RoleId"],
                    arn=role_data["Arn"],
                    created_at=role_data["CreateDate"],
                    description=role_data.get("Description", ""),
                    assume_role_policy=role_data.get("AssumeRolePolicyDocument", {}),
                    attached_policies=attached_policies,
                    last_used=last_used,
                )
                roles.append(role)

        return roles

    def _get_user_groups(self, iam: Any, username: str) -> list[str]:
        """Get groups for a user."""
        try:
            response = iam.list_groups_for_user(UserName=username)
            return [g["GroupName"] for g in response.get("Groups", [])]
        except Exception:
            return []

    def _get_user_policies(self, iam: Any, username: str) -> list[str]:
        """Get attached policies for a user."""
        policies: list[str] = []
        try:
            # Attached managed policies
            response = iam.list_attached_user_policies(UserName=username)
            policies.extend([p["PolicyName"] for p in response.get("AttachedPolicies", [])])

            # Inline policies
            response = iam.list_user_policies(UserName=username)
            policies.extend(response.get("PolicyNames", []))
        except Exception:
            pass
        return policies

    def _get_role_policies(self, iam: Any, role_name: str) -> list[str]:
        """Get attached policies for a role."""
        policies: list[str] = []
        try:
            response = iam.list_attached_role_policies(RoleName=role_name)
            policies.extend([p["PolicyName"] for p in response.get("AttachedPolicies", [])])

            response = iam.list_role_policies(RoleName=role_name)
            policies.extend(response.get("PolicyNames", []))
        except Exception:
            pass
        return policies

    def _get_access_keys(self, iam: Any, username: str) -> list[dict[str, Any]]:
        """Get access keys for a user."""
        try:
            response = iam.list_access_keys(UserName=username)
            keys = []
            for key in response.get("AccessKeyMetadata", []):
                # Get last used info
                try:
                    last_used = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                    key_info = {
                        "access_key_id": key["AccessKeyId"],
                        "status": key["Status"],
                        "created_at": key["CreateDate"].isoformat(),
                        "last_used": last_used.get("AccessKeyLastUsed", {}).get("LastUsedDate"),
                    }
                except Exception:
                    key_info = {
                        "access_key_id": key["AccessKeyId"],
                        "status": key["Status"],
                        "created_at": key["CreateDate"].isoformat(),
                    }
                keys.append(key_info)
            return keys
        except Exception:
            return []

    def _check_user_mfa(self, iam: Any, username: str) -> bool:
        """Check if user has MFA enabled."""
        try:
            response = iam.list_mfa_devices(UserName=username)
            return len(response.get("MFADevices", [])) > 0
        except Exception:
            return False

    def _check_unused_users(
        self, users: list[IAMUser], inactive_days: int
    ) -> list[AccessReviewFinding]:
        """Check for unused user accounts."""
        findings: list[AccessReviewFinding] = []
        threshold = datetime.now(timezone.utc) - timedelta(days=inactive_days)

        for user in users:
            last_activity = user.password_last_used

            # Check access key usage
            for key in user.access_keys:
                if key.get("last_used"):
                    key_last_used = key["last_used"]
                    if isinstance(key_last_used, str):
                        key_last_used = datetime.fromisoformat(
                            key_last_used.replace("Z", "+00:00")
                        )
                    if last_activity is None or key_last_used > last_activity:
                        last_activity = key_last_used

            if last_activity is None:
                findings.append(
                    AccessReviewFinding(
                        finding_type="unused_user",
                        severity="medium",
                        resource_type="IAM User",
                        resource_id=user.user_id,
                        resource_name=user.user_name,
                        description=f"User '{user.user_name}' has never been used",
                        recommendation="Review if this user is still needed and consider removal",
                        details={"created_at": user.created_at.isoformat()},
                    )
                )
            elif last_activity.replace(tzinfo=timezone.utc) < threshold:
                days_inactive = (datetime.now(timezone.utc) - last_activity.replace(tzinfo=timezone.utc)).days
                findings.append(
                    AccessReviewFinding(
                        finding_type="inactive_user",
                        severity="low",
                        resource_type="IAM User",
                        resource_id=user.user_id,
                        resource_name=user.user_name,
                        description=f"User '{user.user_name}' inactive for {days_inactive} days",
                        recommendation="Review user activity and consider disabling if no longer needed",
                        details={
                            "last_activity": last_activity.isoformat(),
                            "days_inactive": days_inactive,
                        },
                    )
                )

        return findings

    def _check_unused_roles(
        self, roles: list[IAMRole], inactive_days: int
    ) -> list[AccessReviewFinding]:
        """Check for unused IAM roles."""
        findings: list[AccessReviewFinding] = []
        threshold = datetime.now(timezone.utc) - timedelta(days=inactive_days)

        for role in roles:
            if role.last_used is None:
                # Role never used
                days_old = (datetime.now(timezone.utc) - role.created_at.replace(tzinfo=timezone.utc)).days
                if days_old > inactive_days:
                    findings.append(
                        AccessReviewFinding(
                            finding_type="unused_role",
                            severity="low",
                            resource_type="IAM Role",
                            resource_id=role.role_id,
                            resource_name=role.role_name,
                            description=f"Role '{role.role_name}' created {days_old} days ago but never used",
                            recommendation="Review if this role is still needed and consider removal",
                            details={"created_at": role.created_at.isoformat()},
                        )
                    )
            elif role.last_used.replace(tzinfo=timezone.utc) < threshold:
                days_inactive = (datetime.now(timezone.utc) - role.last_used.replace(tzinfo=timezone.utc)).days
                findings.append(
                    AccessReviewFinding(
                        finding_type="inactive_role",
                        severity="low",
                        resource_type="IAM Role",
                        resource_id=role.role_id,
                        resource_name=role.role_name,
                        description=f"Role '{role.role_name}' not used for {days_inactive} days",
                        recommendation="Review role usage and consider removal if no longer needed",
                        details={
                            "last_used": role.last_used.isoformat(),
                            "days_inactive": days_inactive,
                        },
                    )
                )

        return findings

    def _check_mfa_status(self, iam: Any, users: list[IAMUser]) -> list[AccessReviewFinding]:
        """Check MFA status for all users."""
        findings: list[AccessReviewFinding] = []

        for user in users:
            if not user.mfa_enabled:
                # Check if user has console access
                try:
                    iam.get_login_profile(UserName=user.user_name)
                    has_console_access = True
                except Exception:
                    has_console_access = False

                if has_console_access:
                    findings.append(
                        AccessReviewFinding(
                            finding_type="mfa_disabled",
                            severity="high",
                            resource_type="IAM User",
                            resource_id=user.user_id,
                            resource_name=user.user_name,
                            description=f"User '{user.user_name}' has console access without MFA",
                            recommendation="Enable MFA for this user immediately",
                            details={"has_console_access": True},
                        )
                    )

        return findings

    def _check_access_keys(
        self, iam: Any, users: list[IAMUser], inactive_days: int
    ) -> list[AccessReviewFinding]:
        """Check access key security issues."""
        findings: list[AccessReviewFinding] = []
        now = datetime.now(timezone.utc)
        rotation_threshold = timedelta(days=90)

        for user in users:
            active_keys = [k for k in user.access_keys if k.get("status") == "Active"]

            # Check for multiple active keys
            if len(active_keys) > 1:
                findings.append(
                    AccessReviewFinding(
                        finding_type="multiple_access_keys",
                        severity="medium",
                        resource_type="IAM User",
                        resource_id=user.user_id,
                        resource_name=user.user_name,
                        description=f"User '{user.user_name}' has {len(active_keys)} active access keys",
                        recommendation="Review and remove unused access keys",
                        details={"active_key_count": len(active_keys)},
                    )
                )

            # Check for old access keys
            for key in active_keys:
                created_str = key.get("created_at", "")
                if created_str:
                    created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                    age = now - created.replace(tzinfo=timezone.utc)

                    if age > rotation_threshold:
                        findings.append(
                            AccessReviewFinding(
                                finding_type="old_access_key",
                                severity="medium",
                                resource_type="IAM Access Key",
                                resource_id=key["access_key_id"],
                                resource_name=f"{user.user_name}/{key['access_key_id'][:8]}...",
                                description=f"Access key is {age.days} days old (threshold: 90 days)",
                                recommendation="Rotate this access key",
                                details={
                                    "user": user.user_name,
                                    "key_age_days": age.days,
                                    "created_at": created_str,
                                },
                            )
                        )

        return findings

    def _check_admin_policies(
        self, iam: Any, users: list[IAMUser], roles: list[IAMRole]
    ) -> list[AccessReviewFinding]:
        """Check for overly permissive admin policies."""
        findings: list[AccessReviewFinding] = []
        admin_policies = {"AdministratorAccess", "PowerUserAccess", "IAMFullAccess"}

        for user in users:
            admin_attached = [p for p in user.policies if p in admin_policies]
            if admin_attached:
                findings.append(
                    AccessReviewFinding(
                        finding_type="admin_user",
                        severity="high",
                        resource_type="IAM User",
                        resource_id=user.user_id,
                        resource_name=user.user_name,
                        description=f"User '{user.user_name}' has admin policies: {', '.join(admin_attached)}",
                        recommendation="Review if admin access is necessary; apply least privilege",
                        details={"admin_policies": admin_attached},
                    )
                )

        for role in roles:
            admin_attached = [p for p in role.attached_policies if p in admin_policies]
            if admin_attached:
                findings.append(
                    AccessReviewFinding(
                        finding_type="admin_role",
                        severity="medium",
                        resource_type="IAM Role",
                        resource_id=role.role_id,
                        resource_name=role.role_name,
                        description=f"Role '{role.role_name}' has admin policies: {', '.join(admin_attached)}",
                        recommendation="Review if admin access is necessary; apply least privilege",
                        details={"admin_policies": admin_attached},
                    )
                )

        return findings

    def _generate_summary(
        self,
        findings: list[AccessReviewFinding],
        users: list[IAMUser],
        roles: list[IAMRole],
    ) -> dict[str, Any]:
        """Generate summary of the access review."""
        severity_counts: dict[str, int] = {}
        type_counts: dict[str, int] = {}

        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            type_counts[finding.finding_type] = type_counts.get(finding.finding_type, 0) + 1

        return {
            "total_users": len(users),
            "total_roles": len(roles),
            "total_findings": len(findings),
            "findings_by_severity": severity_counts,
            "findings_by_type": type_counts,
            "users_without_mfa": sum(1 for u in users if not u.mfa_enabled),
            "users_with_admin": sum(
                1
                for u in users
                if any(
                    p in u.policies
                    for p in ["AdministratorAccess", "PowerUserAccess", "IAMFullAccess"]
                )
            ),
        }

    def get_parameter_schema(self) -> dict[str, Any]:
        """Get the parameter schema for this tool."""
        return {
            "check_unused_users": {
                "type": "bool",
                "default": True,
                "description": "Check for unused user accounts",
            },
            "check_unused_roles": {
                "type": "bool",
                "default": True,
                "description": "Check for unused IAM roles",
            },
            "check_mfa": {
                "type": "bool",
                "default": True,
                "description": "Check MFA status for users",
            },
            "check_access_keys": {
                "type": "bool",
                "default": True,
                "description": "Check access key security",
            },
            "check_policies": {
                "type": "bool",
                "default": True,
                "description": "Check for overly permissive policies",
            },
            "inactive_days": {
                "type": "int",
                "default": 90,
                "description": "Days of inactivity threshold",
            },
        }
