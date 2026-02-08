#!/usr/bin/env python3
"""
Sample security check script for demonstration.

This script can be registered with seckit and executed with parameters.

Usage:
    seckit scripts register sample-check --path examples/sample_security_check.py \
        --description "Sample security check" --category "examples" \
        --params '[{"name": "target", "type": "string", "required": true, "description": "Target to check"},
                   {"name": "verbose", "type": "bool", "default": false, "description": "Verbose output"}]'

    seckit scripts run sample-check --param target=192.168.1.1 --param verbose=true
"""

import argparse
import json
import os
import sys
from datetime import datetime


def run_security_check(target: str, verbose: bool = False) -> dict:
    """Run a sample security check against a target."""
    results = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "checks": [],
        "summary": {"passed": 0, "failed": 0, "warnings": 0},
    }

    # Sample checks
    checks = [
        {
            "name": "connectivity",
            "description": "Check if target is reachable",
            "status": "passed",
            "details": f"Target {target} is assumed reachable (sample check)",
        },
        {
            "name": "port_scan",
            "description": "Check for open ports",
            "status": "warning",
            "details": "Common ports: 22, 80, 443 (sample data)",
        },
        {
            "name": "ssl_check",
            "description": "Verify SSL/TLS configuration",
            "status": "passed",
            "details": "SSL configuration appears valid (sample check)",
        },
    ]

    for check in checks:
        results["checks"].append(check)
        if check["status"] == "passed":
            results["summary"]["passed"] += 1
        elif check["status"] == "failed":
            results["summary"]["failed"] += 1
        else:
            results["summary"]["warnings"] += 1

        if verbose:
            print(f"[{check['status'].upper()}] {check['name']}: {check['description']}")
            print(f"         {check['details']}")

    return results


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Sample security check script")
    parser.add_argument("--target", required=True, help="Target to check")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    print(f"Running security check against: {args.target}")
    print("-" * 50)

    results = run_security_check(args.target, args.verbose)

    print("-" * 50)
    print(f"Summary: {results['summary']['passed']} passed, "
          f"{results['summary']['failed']} failed, "
          f"{results['summary']['warnings']} warnings")

    # Output JSON for further processing
    if os.environ.get("SECKIT_OUTPUT_JSON"):
        print("\nJSON Output:")
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
