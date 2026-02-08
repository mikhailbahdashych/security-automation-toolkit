"""Pytest fixtures for tests."""

import tempfile
from pathlib import Path

import pytest

from security_toolkit.core.database import Database


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)

    db = Database(db_path)
    yield db

    # Cleanup
    db_path.unlink(missing_ok=True)


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def sample_script(temp_dir):
    """Create a sample Python script for testing."""
    script_path = temp_dir / "sample_script.py"
    script_path.write_text("""#!/usr/bin/env python3
import argparse
import sys

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', default='World')
    parser.add_argument('--count', type=int, default=1)
    args = parser.parse_args()

    for i in range(args.count):
        print(f"Hello, {args.name}!")

if __name__ == '__main__':
    main()
""")
    return script_path


@pytest.fixture
def sample_nessus_xml(temp_dir):
    """Create a sample Nessus XML file for testing."""
    xml_path = temp_dir / "sample.nessus"
    xml_path.write_text("""<?xml version="1.0" ?>
<NessusClientData_v2>
<Report name="Test Report">
<ReportHost name="192.168.1.1">
<HostProperties>
<tag name="host-ip">192.168.1.1</tag>
</HostProperties>
<ReportItem port="22" severity="2" pluginID="12345" pluginName="SSH Weak Cipher">
<description>The SSH server supports weak ciphers.</description>
<solution>Configure the SSH server to use strong ciphers only.</solution>
<cve>CVE-2021-1234</cve>
<cvss3_base_score>5.3</cvss3_base_score>
</ReportItem>
<ReportItem port="443" severity="3" pluginID="12346" pluginName="SSL Certificate Expired">
<description>The SSL certificate has expired.</description>
<solution>Renew the SSL certificate.</solution>
<cvss3_base_score>7.5</cvss3_base_score>
</ReportItem>
</ReportHost>
</Report>
</NessusClientData_v2>
""")
    return xml_path


@pytest.fixture
def sample_auth_log(temp_dir):
    """Create a sample auth.log file for testing."""
    log_path = temp_dir / "auth.log"
    log_path.write_text("""Jan 15 10:23:45 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2
Jan 15 10:23:50 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2
Jan 15 10:24:01 server sshd[12346]: Accepted password for john from 192.168.1.50 port 22 ssh2
Jan 15 10:25:00 server sudo[12347]: john : TTY=pts/0 ; PWD=/home/john ; USER=root ; COMMAND=/usr/bin/apt update
Jan 15 10:30:00 server sshd[12348]: Failed password for root from 10.0.0.5 port 22 ssh2
""")
    return log_path


@pytest.fixture
def sample_cloudtrail_json(temp_dir):
    """Create a sample CloudTrail JSON file for testing."""
    import json

    json_path = temp_dir / "cloudtrail.json"
    data = {
        "Records": [
            {
                "eventVersion": "1.08",
                "eventTime": "2024-01-15T10:30:00Z",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "192.168.1.1",
                "userIdentity": {
                    "type": "IAMUser",
                    "userName": "admin",
                    "principalId": "AIDAEXAMPLE",
                },
            },
            {
                "eventVersion": "1.08",
                "eventTime": "2024-01-15T10:35:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateUser",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "192.168.1.1",
                "userIdentity": {
                    "type": "IAMUser",
                    "userName": "admin",
                    "principalId": "AIDAEXAMPLE",
                },
                "requestParameters": {"userName": "newuser"},
            },
        ]
    }
    json_path.write_text(json.dumps(data))
    return json_path
