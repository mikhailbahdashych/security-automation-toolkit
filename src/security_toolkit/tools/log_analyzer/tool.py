"""Log Analyzer tool for security log analysis."""

import gzip
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from security_toolkit.core.models import LogAnalysisResult, LogEvent
from security_toolkit.tools.base import BaseTool, ToolResult


class LogAnalyzerTool(BaseTool):
    """Tool for analyzing security logs."""

    name = "log-analyzer"
    description = "Analyze auth.log, syslog, and CloudTrail logs for security events"
    version = "1.0.0"

    # Patterns for different log types
    AUTH_LOG_PATTERNS = {
        "failed_password": re.compile(
            r"(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+\S+\[\d+\]:\s+Failed password for (?:invalid user )?(\S+) from (\S+)"
        ),
        "accepted_password": re.compile(
            r"(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+\S+\[\d+\]:\s+Accepted password for (\S+) from (\S+)"
        ),
        "accepted_publickey": re.compile(
            r"(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+\S+\[\d+\]:\s+Accepted publickey for (\S+) from (\S+)"
        ),
        "invalid_user": re.compile(
            r"(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+\S+\[\d+\]:\s+Invalid user (\S+) from (\S+)"
        ),
        "session_opened": re.compile(
            r"(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+\S+\[\d+\]:\s+pam_unix\(\S+\):\s+session opened for user (\S+)"
        ),
        "session_closed": re.compile(
            r"(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+\S+\[\d+\]:\s+pam_unix\(\S+\):\s+session closed for user (\S+)"
        ),
        "sudo": re.compile(
            r"(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+sudo\[\d+\]:\s+(\S+)\s+:\s+.*COMMAND=(.*)"
        ),
    }

    # CloudTrail event types of interest
    CLOUDTRAIL_EVENTS = {
        "ConsoleLogin",
        "CreateUser",
        "DeleteUser",
        "CreateAccessKey",
        "DeleteAccessKey",
        "AttachUserPolicy",
        "DetachUserPolicy",
        "CreateRole",
        "DeleteRole",
        "AssumeRole",
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "AuthorizeSecurityGroupIngress",
        "RevokeSecurityGroupIngress",
        "StopLogging",
        "DeleteTrail",
    }

    def run(
        self,
        input_file: str,
        log_type: str = "auto",
        pattern: str | None = None,
        time_range: str | None = None,
        **kwargs: Any,
    ) -> ToolResult:
        """Analyze log file for security events."""
        result = ToolResult(tool_name=self.name)

        input_path = Path(input_file)
        if not input_path.exists():
            result.errors.append(f"Input file not found: {input_file}")
            return result.finish(success=False)

        # Auto-detect log type if needed
        if log_type == "auto":
            log_type = self._detect_log_type(input_path)
            if log_type == "unknown":
                result.errors.append(
                    "Could not auto-detect log type. Please specify: auth, syslog, or cloudtrail"
                )
                return result.finish(success=False)

        try:
            if log_type == "auth":
                events = self._parse_auth_log(input_path, pattern)
            elif log_type == "syslog":
                events = self._parse_syslog(input_path, pattern)
            elif log_type == "cloudtrail":
                events = self._parse_cloudtrail(input_path, pattern)
            else:
                result.errors.append(f"Unsupported log type: {log_type}")
                return result.finish(success=False)

            # Filter by time range if specified
            if time_range:
                events = self._filter_by_time(events, time_range)

            # Analyze events
            analysis = self._analyze_events(events)

            result.findings = [e.model_dump() for e in analysis.failed_attempts]
            result.data = {
                "log_type": log_type,
                "input_file": str(input_path),
                "events": [e.model_dump() for e in events[:100]],  # Limit for output
            }
            result.summary = {
                "total_events": analysis.total_events,
                "time_range": {
                    "start": analysis.time_range_start.isoformat() if analysis.time_range_start else None,
                    "end": analysis.time_range_end.isoformat() if analysis.time_range_end else None,
                },
                "events_by_type": analysis.events_by_type,
                "events_by_severity": analysis.events_by_severity,
                "anomalies": analysis.anomalies,
                "top_users": analysis.top_users,
                "top_sources": analysis.top_sources,
                "failed_attempts_count": len(analysis.failed_attempts),
            }

        except Exception as e:
            result.errors.append(f"Error analyzing logs: {e}")

        return result

    def _detect_log_type(self, path: Path) -> str:
        """Auto-detect log type from file content."""
        try:
            # Handle gzipped files
            if path.suffix == ".gz":
                with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as f:
                    header = f.read(4096)
            else:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    header = f.read(4096)

            # Check for CloudTrail JSON
            if '"Records"' in header and '"eventVersion"' in header:
                return "cloudtrail"

            # Check for auth.log patterns
            if "sshd" in header or "pam_unix" in header or "sudo" in header:
                return "auth"

            # Check for syslog patterns
            if re.search(r"\w+\s+\d+\s+\d+:\d+:\d+", header):
                return "syslog"

        except Exception:
            pass

        return "unknown"

    def _parse_auth_log(self, path: Path, pattern: str | None) -> list[LogEvent]:
        """Parse auth.log format."""
        events: list[LogEvent] = []
        year = datetime.now().year  # Auth logs don't include year

        # Handle gzipped files
        if path.suffix == ".gz":
            opener = lambda p: gzip.open(p, "rt", encoding="utf-8", errors="ignore")
        else:
            opener = lambda p: open(p, "r", encoding="utf-8", errors="ignore")

        with opener(path) as f:
            for line in f:
                event = self._parse_auth_line(line, year)
                if event:
                    # Apply pattern filter
                    if pattern:
                        if pattern == "failed-logins" and event.event_type not in [
                            "failed_password",
                            "invalid_user",
                        ]:
                            continue
                        elif pattern == "successful-logins" and event.event_type not in [
                            "accepted_password",
                            "accepted_publickey",
                        ]:
                            continue
                        elif pattern == "sudo" and event.event_type != "sudo":
                            continue
                    events.append(event)

        return events

    def _parse_auth_line(self, line: str, year: int) -> LogEvent | None:
        """Parse a single auth.log line."""
        for event_type, pattern in self.AUTH_LOG_PATTERNS.items():
            match = pattern.search(line)
            if match:
                groups = match.groups()

                # Parse timestamp
                try:
                    timestamp_str = f"{year} {groups[0]}"
                    timestamp = datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
                except (ValueError, IndexError):
                    timestamp = datetime.now()

                # Determine severity
                severity = "info"
                if event_type in ["failed_password", "invalid_user"]:
                    severity = "warning"
                elif event_type == "sudo":
                    severity = "info"

                # Extract fields based on event type
                user = None
                source_ip = None
                action = None

                if event_type in ["failed_password", "accepted_password", "accepted_publickey", "invalid_user"]:
                    user = groups[2] if len(groups) > 2 else None
                    source_ip = groups[3] if len(groups) > 3 else None
                    action = "login_attempt"
                elif event_type in ["session_opened", "session_closed"]:
                    user = groups[2] if len(groups) > 2 else None
                    action = "session"
                elif event_type == "sudo":
                    user = groups[2] if len(groups) > 2 else None
                    action = groups[3] if len(groups) > 3 else None

                status = "success" if event_type.startswith("accepted") or event_type == "session_opened" else "failed"

                return LogEvent(
                    timestamp=timestamp,
                    source="auth.log",
                    event_type=event_type,
                    severity=severity,
                    message=line.strip(),
                    user=user,
                    source_ip=source_ip,
                    action=action,
                    status=status,
                )

        return None

    def _parse_syslog(self, path: Path, pattern: str | None) -> list[LogEvent]:
        """Parse syslog format."""
        events: list[LogEvent] = []
        year = datetime.now().year

        syslog_pattern = re.compile(
            r"(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s*(.*)"
        )

        # Handle gzipped files
        if path.suffix == ".gz":
            opener = lambda p: gzip.open(p, "rt", encoding="utf-8", errors="ignore")
        else:
            opener = lambda p: open(p, "r", encoding="utf-8", errors="ignore")

        with opener(path) as f:
            for line in f:
                match = syslog_pattern.match(line)
                if match:
                    timestamp_str, host, service, message = match.groups()

                    try:
                        timestamp = datetime.strptime(f"{year} {timestamp_str}", "%Y %b %d %H:%M:%S")
                    except ValueError:
                        timestamp = datetime.now()

                    # Apply pattern filter
                    if pattern and pattern.lower() not in message.lower():
                        continue

                    # Determine severity from message content
                    severity = "info"
                    if any(word in message.lower() for word in ["error", "fail", "denied"]):
                        severity = "warning"
                    elif any(word in message.lower() for word in ["critical", "emergency", "alert"]):
                        severity = "critical"

                    events.append(
                        LogEvent(
                            timestamp=timestamp,
                            source=f"syslog:{host}",
                            event_type=service,
                            severity=severity,
                            message=message,
                            destination=host,
                        )
                    )

        return events

    def _parse_cloudtrail(self, path: Path, pattern: str | None) -> list[LogEvent]:
        """Parse CloudTrail JSON format."""
        events: list[LogEvent] = []

        # Handle gzipped files
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as f:
                data = json.load(f)
        else:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

        records = data.get("Records", [])

        for record in records:
            event_name = record.get("eventName", "")

            # Filter by pattern or interesting events
            if pattern:
                if pattern.lower() not in event_name.lower():
                    continue
            elif event_name not in self.CLOUDTRAIL_EVENTS:
                continue

            # Parse timestamp
            timestamp_str = record.get("eventTime", "")
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.now()

            # Determine severity
            severity = "info"
            if event_name in ["StopLogging", "DeleteTrail", "DeleteUser", "DeleteRole"]:
                severity = "high"
            elif event_name in ["ConsoleLogin", "CreateAccessKey", "AttachUserPolicy"]:
                severity = "medium"

            # Check for errors
            error_code = record.get("errorCode")
            error_message = record.get("errorMessage")
            status = "failed" if error_code else "success"

            # Get user identity
            user_identity = record.get("userIdentity", {})
            user = user_identity.get("userName") or user_identity.get("principalId", "unknown")

            # Get source IP
            source_ip = record.get("sourceIPAddress")

            events.append(
                LogEvent(
                    timestamp=timestamp,
                    source="cloudtrail",
                    event_type=event_name,
                    severity=severity,
                    message=f"{event_name}: {record.get('eventSource', '')}",
                    user=user,
                    source_ip=source_ip,
                    action=event_name,
                    status=status,
                    raw_data={
                        "event_source": record.get("eventSource"),
                        "aws_region": record.get("awsRegion"),
                        "request_parameters": record.get("requestParameters"),
                        "response_elements": record.get("responseElements"),
                        "error_code": error_code,
                        "error_message": error_message,
                    },
                )
            )

        return events

    def _filter_by_time(self, events: list[LogEvent], time_range: str) -> list[LogEvent]:
        """Filter events by time range."""
        # Parse time range (e.g., "1h", "24h", "7d")
        match = re.match(r"(\d+)([hdm])", time_range)
        if not match:
            return events

        value, unit = int(match.group(1)), match.group(2)
        from datetime import timedelta

        if unit == "h":
            delta = timedelta(hours=value)
        elif unit == "d":
            delta = timedelta(days=value)
        elif unit == "m":
            delta = timedelta(minutes=value)
        else:
            return events

        cutoff = datetime.now() - delta
        return [e for e in events if e.timestamp >= cutoff]

    def _analyze_events(self, events: list[LogEvent]) -> LogAnalysisResult:
        """Analyze events for patterns and anomalies."""
        if not events:
            return LogAnalysisResult(total_events=0)

        # Count by type and severity
        type_counter: Counter[str] = Counter()
        severity_counter: Counter[str] = Counter()
        user_counter: Counter[str] = Counter()
        source_counter: Counter[str] = Counter()
        failed_attempts: list[LogEvent] = []

        timestamps: list[datetime] = []

        for event in events:
            type_counter[event.event_type] += 1
            severity_counter[event.severity] += 1
            timestamps.append(event.timestamp)

            if event.user:
                user_counter[event.user] += 1
            if event.source_ip:
                source_counter[event.source_ip] += 1

            # Track failed attempts
            if event.status == "failed" or event.event_type in ["failed_password", "invalid_user"]:
                failed_attempts.append(event)

        # Detect anomalies
        anomalies: list[dict[str, Any]] = []

        # Check for brute force attempts (many failures from same IP)
        for ip, count in source_counter.most_common(10):
            if ip and count >= 5:
                ip_failures = sum(1 for e in failed_attempts if e.source_ip == ip)
                if ip_failures >= 5:
                    anomalies.append({
                        "type": "brute_force_attempt",
                        "source_ip": ip,
                        "failed_attempts": ip_failures,
                        "severity": "high",
                    })

        # Check for unusual login times (outside business hours)
        after_hours = sum(1 for e in events if e.timestamp.hour < 6 or e.timestamp.hour > 22)
        if after_hours > len(events) * 0.3:  # More than 30% after hours
            anomalies.append({
                "type": "after_hours_activity",
                "count": after_hours,
                "percentage": f"{after_hours / len(events) * 100:.1f}%",
                "severity": "medium",
            })

        # Check for privilege escalation patterns
        sudo_events = [e for e in events if e.event_type == "sudo"]
        if len(sudo_events) > 20:
            anomalies.append({
                "type": "high_sudo_usage",
                "count": len(sudo_events),
                "severity": "medium",
            })

        return LogAnalysisResult(
            total_events=len(events),
            time_range_start=min(timestamps) if timestamps else None,
            time_range_end=max(timestamps) if timestamps else None,
            events_by_type=dict(type_counter),
            events_by_severity=dict(severity_counter),
            anomalies=anomalies,
            top_users=[{"user": u, "count": c} for u, c in user_counter.most_common(10)],
            top_sources=[{"source": s, "count": c} for s, c in source_counter.most_common(10)],
            failed_attempts=failed_attempts[:50],  # Limit for output
        )

    def get_parameter_schema(self) -> dict[str, Any]:
        """Get the parameter schema for this tool."""
        return {
            "input_file": {
                "type": "file",
                "required": True,
                "description": "Path to log file (supports .gz)",
            },
            "log_type": {
                "type": "choice",
                "choices": ["auto", "auth", "syslog", "cloudtrail"],
                "default": "auto",
                "description": "Log type (auto-detected if not specified)",
            },
            "pattern": {
                "type": "choice",
                "choices": ["failed-logins", "successful-logins", "sudo"],
                "description": "Filter pattern for auth logs",
            },
            "time_range": {
                "type": "string",
                "description": "Time range filter (e.g., '1h', '24h', '7d')",
            },
        }
