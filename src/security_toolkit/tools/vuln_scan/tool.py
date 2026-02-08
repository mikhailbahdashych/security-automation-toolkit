"""Vulnerability Scanner tool for parsing Nessus, Qualys, and OpenVAS outputs."""

import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any

from security_toolkit.core.models import Vulnerability
from security_toolkit.tools.base import BaseTool, ToolResult


class VulnScanTool(BaseTool):
    """Tool for parsing vulnerability scanner outputs."""

    name = "vuln-scan"
    description = "Parse Nessus, Qualys, and OpenVAS vulnerability scan outputs"
    version = "1.0.0"

    SEVERITY_MAP = {
        "4": "critical",
        "3": "high",
        "2": "medium",
        "1": "low",
        "0": "info",
    }

    def run(
        self,
        input_file: str,
        scanner_type: str = "auto",
        min_severity: str = "info",
        **kwargs: Any,
    ) -> ToolResult:
        """Parse vulnerability scan output file."""
        result = ToolResult(tool_name=self.name)

        input_path = Path(input_file)
        if not input_path.exists():
            result.errors.append(f"Input file not found: {input_file}")
            return result.finish(success=False)

        # Auto-detect scanner type if needed
        if scanner_type == "auto":
            scanner_type = self._detect_scanner_type(input_path)
            if scanner_type == "unknown":
                result.errors.append(
                    "Could not auto-detect scanner type. Please specify: nessus, qualys, or openvas"
                )
                return result.finish(success=False)

        try:
            if scanner_type == "nessus":
                vulns = self._parse_nessus(input_path)
            elif scanner_type == "qualys":
                vulns = self._parse_qualys(input_path)
            elif scanner_type == "openvas":
                vulns = self._parse_openvas(input_path)
            else:
                result.errors.append(f"Unsupported scanner type: {scanner_type}")
                return result.finish(success=False)

            # Filter by minimum severity
            severity_order = ["info", "low", "medium", "high", "critical"]
            min_idx = severity_order.index(min_severity.lower())
            vulns = [v for v in vulns if severity_order.index(v.severity) >= min_idx]

            result.findings = [v.model_dump() for v in vulns]
            result.summary = self._generate_summary(vulns)
            result.data = {"scanner_type": scanner_type, "input_file": str(input_path)}

        except ET.ParseError as e:
            result.errors.append(f"XML parsing error: {e}")
        except Exception as e:
            result.errors.append(f"Error parsing scan output: {e}")

        return result

    def _detect_scanner_type(self, path: Path) -> str:
        """Auto-detect scanner type from file content."""
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                # Read first 5KB to detect format
                header = f.read(5120)

            if "NessusClientData_v2" in header or "<NessusClientData" in header:
                return "nessus"
            elif "QUALYS" in header or "<SCAN>" in header:
                return "qualys"
            elif "openvas" in header.lower() or "<report" in header.lower():
                return "openvas"
        except Exception:
            pass

        return "unknown"

    def _parse_nessus(self, path: Path) -> list[Vulnerability]:
        """Parse Nessus XML format (.nessus)."""
        vulns: list[Vulnerability] = []
        tree = ET.parse(path)
        root = tree.getroot()

        for report_host in root.findall(".//ReportHost"):
            host_name = report_host.get("name", "unknown")

            # Get host properties
            host_props: dict[str, str] = {}
            for tag in report_host.findall("HostProperties/tag"):
                tag_name = tag.get("name", "")
                if tag_name and tag.text:
                    host_props[tag_name] = tag.text

            for item in report_host.findall("ReportItem"):
                plugin_id = item.get("pluginID", "")
                severity = item.get("severity", "0")
                port = item.get("port", "0")
                protocol = item.get("protocol", "")
                plugin_name = item.get("pluginName", "")

                # Skip informational if severity is 0
                if severity == "0":
                    continue

                # Extract CVE IDs
                cve_ids = [cve.text for cve in item.findall("cve") if cve.text]

                # Extract CVSS score
                cvss_elem = item.find("cvss3_base_score")
                if cvss_elem is None:
                    cvss_elem = item.find("cvss_base_score")
                cvss_score = float(cvss_elem.text) if cvss_elem is not None and cvss_elem.text else None

                # Extract description and solution
                desc_elem = item.find("description")
                description = desc_elem.text if desc_elem is not None and desc_elem.text else ""

                solution_elem = item.find("solution")
                solution = solution_elem.text if solution_elem is not None and solution_elem.text else ""

                output_elem = item.find("plugin_output")
                plugin_output = output_elem.text if output_elem is not None and output_elem.text else ""

                # See also references
                see_also: list[str] = []
                see_also_elem = item.find("see_also")
                if see_also_elem is not None and see_also_elem.text:
                    see_also = [url.strip() for url in see_also_elem.text.split("\n") if url.strip()]

                vuln = Vulnerability(
                    vuln_id=f"NESSUS-{plugin_id}-{host_name}-{port}",
                    plugin_id=plugin_id,
                    title=plugin_name,
                    severity=self.SEVERITY_MAP.get(severity, "info"),
                    cvss_score=cvss_score,
                    cve_ids=cve_ids,
                    host=host_name,
                    port=int(port) if port.isdigit() else None,
                    protocol=protocol,
                    description=description,
                    solution=solution,
                    see_also=see_also,
                    plugin_output=plugin_output,
                )
                vulns.append(vuln)

        return vulns

    def _parse_qualys(self, path: Path) -> list[Vulnerability]:
        """Parse Qualys XML format."""
        vulns: list[Vulnerability] = []
        tree = ET.parse(path)
        root = tree.getroot()

        # Handle Qualys scan report format
        for host in root.findall(".//HOST") or root.findall(".//IP"):
            host_ip = host.find("IP")
            host_name = host_ip.text if host_ip is not None and host_ip.text else "unknown"

            for vuln_elem in host.findall(".//VULN") or host.findall(".//CAT"):
                qid = ""
                title = ""
                severity = "info"

                qid_elem = vuln_elem.find("QID")
                if qid_elem is not None and qid_elem.text:
                    qid = qid_elem.text

                title_elem = vuln_elem.find("TITLE")
                if title_elem is not None and title_elem.text:
                    title = title_elem.text

                sev_elem = vuln_elem.find("SEVERITY")
                if sev_elem is not None and sev_elem.text:
                    sev_num = sev_elem.text
                    severity = self.SEVERITY_MAP.get(sev_num, "info")

                # Extract CVE IDs
                cve_ids: list[str] = []
                cve_elem = vuln_elem.find("CVE_ID_LIST")
                if cve_elem is not None:
                    for cve in cve_elem.findall(".//CVE_ID/ID"):
                        if cve.text:
                            cve_ids.append(cve.text)

                # Extract CVSS
                cvss_score = None
                cvss_elem = vuln_elem.find("CVSS_BASE")
                if cvss_elem is not None and cvss_elem.text:
                    try:
                        cvss_score = float(cvss_elem.text)
                    except ValueError:
                        pass

                port_elem = vuln_elem.find("PORT")
                port = int(port_elem.text) if port_elem is not None and port_elem.text and port_elem.text.isdigit() else None

                result_elem = vuln_elem.find("RESULT")
                plugin_output = result_elem.text if result_elem is not None and result_elem.text else ""

                vuln = Vulnerability(
                    vuln_id=f"QUALYS-{qid}-{host_name}",
                    plugin_id=qid,
                    title=title,
                    severity=severity,
                    cvss_score=cvss_score,
                    cve_ids=cve_ids,
                    host=host_name,
                    port=port,
                    plugin_output=plugin_output,
                )
                vulns.append(vuln)

        return vulns

    def _parse_openvas(self, path: Path) -> list[Vulnerability]:
        """Parse OpenVAS XML format."""
        vulns: list[Vulnerability] = []
        tree = ET.parse(path)
        root = tree.getroot()

        for result in root.findall(".//result") or root.findall(".//results/result"):
            # Get host
            host_elem = result.find("host")
            host = host_elem.text if host_elem is not None and host_elem.text else "unknown"

            # Get NVT details
            nvt = result.find("nvt")
            if nvt is None:
                continue

            oid = nvt.get("oid", "")
            name_elem = nvt.find("name")
            title = name_elem.text if name_elem is not None and name_elem.text else ""

            # Get severity/threat
            threat_elem = result.find("threat")
            threat = threat_elem.text.lower() if threat_elem is not None and threat_elem.text else "info"
            severity_map = {"high": "high", "medium": "medium", "low": "low", "log": "info"}
            severity = severity_map.get(threat, "info")

            # Get CVSS
            cvss_elem = nvt.find("cvss_base")
            cvss_score = float(cvss_elem.text) if cvss_elem is not None and cvss_elem.text else None

            # Get CVEs
            cve_ids: list[str] = []
            refs = nvt.find("refs")
            if refs is not None:
                for ref in refs.findall("ref"):
                    ref_type = ref.get("type", "")
                    ref_id = ref.get("id", "")
                    if ref_type == "cve" and ref_id:
                        cve_ids.append(ref_id)

            # Get port
            port_elem = result.find("port")
            port = None
            protocol = None
            if port_elem is not None and port_elem.text:
                port_match = re.match(r"(\d+)/(\w+)", port_elem.text)
                if port_match:
                    port = int(port_match.group(1))
                    protocol = port_match.group(2)

            # Get description
            desc_elem = result.find("description")
            description = desc_elem.text if desc_elem is not None and desc_elem.text else ""

            vuln = Vulnerability(
                vuln_id=f"OPENVAS-{oid}-{host}",
                plugin_id=oid,
                title=title,
                severity=severity,
                cvss_score=cvss_score,
                cve_ids=cve_ids,
                host=host,
                port=port,
                protocol=protocol,
                description=description,
            )
            vulns.append(vuln)

        return vulns

    def _generate_summary(self, vulns: list[Vulnerability]) -> dict[str, Any]:
        """Generate summary statistics."""
        severity_counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        hosts: set[str] = set()
        cves: set[str] = set()

        for vuln in vulns:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
            hosts.add(vuln.host)
            cves.update(vuln.cve_ids)

        return {
            "total_vulnerabilities": len(vulns),
            "unique_hosts": len(hosts),
            "unique_cves": len(cves),
            "by_severity": severity_counts,
            "hosts": list(hosts),
            "top_cves": list(cves)[:10],
        }

    def get_parameter_schema(self) -> dict[str, Any]:
        """Get the parameter schema for this tool."""
        return {
            "input_file": {
                "type": "file",
                "required": True,
                "description": "Path to vulnerability scan output file",
            },
            "scanner_type": {
                "type": "choice",
                "choices": ["auto", "nessus", "qualys", "openvas"],
                "default": "auto",
                "description": "Scanner type (auto-detected if not specified)",
            },
            "min_severity": {
                "type": "choice",
                "choices": ["info", "low", "medium", "high", "critical"],
                "default": "info",
                "description": "Minimum severity to include",
            },
        }
