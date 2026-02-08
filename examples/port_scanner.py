#!/usr/bin/env python3
"""
Simple port scanner for demonstration purposes.

This script performs basic TCP port scanning for security assessments.
For authorized security testing only.

Usage:
    seckit scripts register port-scan --path examples/port_scanner.py \
        --description "Simple TCP port scanner" --category "network" \
        --params '[{"name": "target", "type": "string", "required": true, "description": "Target host"},
                   {"name": "ports", "type": "string", "default": "22,80,443,8080", "description": "Comma-separated ports"},
                   {"name": "timeout", "type": "int", "default": 1, "description": "Connection timeout in seconds"}]'

    seckit scripts run port-scan --param target=192.168.1.1 --param ports=22,80,443
"""

import argparse
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


def scan_port(host: str, port: int, timeout: int = 1) -> dict:
    """Scan a single port."""
    result = {
        "port": port,
        "status": "closed",
        "service": get_service_name(port),
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        connection = sock.connect_ex((host, port))

        if connection == 0:
            result["status"] = "open"
            # Try to get banner
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode("utf-8", errors="ignore")
                if banner:
                    result["banner"] = banner[:100]
            except Exception:
                pass

        sock.close()
    except socket.timeout:
        result["status"] = "filtered"
    except socket.error as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result


def get_service_name(port: int) -> str:
    """Get common service name for a port."""
    services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
    }
    return services.get(port, "unknown")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Simple TCP port scanner")
    parser.add_argument("--target", required=True, help="Target host")
    parser.add_argument(
        "--ports",
        default="22,80,443,8080",
        help="Comma-separated list of ports",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=1,
        help="Connection timeout in seconds",
    )

    args = parser.parse_args()

    # Parse ports
    try:
        ports = [int(p.strip()) for p in args.ports.split(",")]
    except ValueError:
        print("Error: Invalid port number")
        return 1

    print(f"Port Scan Report")
    print(f"================")
    print(f"Target: {args.target}")
    print(f"Ports: {len(ports)}")
    print(f"Timeout: {args.timeout}s")
    print(f"Started: {datetime.now().isoformat()}")
    print("-" * 50)

    results = {
        "host": args.target,
        "timestamp": datetime.now().isoformat(),
        "ports": [],
        "summary": {"open": 0, "closed": 0, "filtered": 0},
    }

    # Scan ports in parallel
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(scan_port, args.target, port, args.timeout): port
            for port in ports
        }

        for future in as_completed(futures):
            result = future.result()
            results["ports"].append(result)

            status = result["status"]
            results["summary"][status] = results["summary"].get(status, 0) + 1

            if status == "open":
                service = result.get("service", "unknown")
                print(f"[OPEN]     {result['port']:>5}/tcp  {service}")
            elif status == "filtered":
                print(f"[FILTERED] {result['port']:>5}/tcp")

    # Sort results by port
    results["ports"].sort(key=lambda x: x["port"])

    print("-" * 50)
    print(f"Summary: {results['summary']['open']} open, "
          f"{results['summary']['closed']} closed, "
          f"{results['summary']['filtered']} filtered")
    print(f"Completed: {datetime.now().isoformat()}")

    # Output JSON for integration
    print("\n--- JSON Output ---")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
