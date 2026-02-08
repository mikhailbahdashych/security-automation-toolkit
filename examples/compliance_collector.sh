#!/bin/bash
# Sample compliance evidence collection script
#
# This script can be registered with seckit and executed with parameters.
#
# Usage:
#   seckit scripts register compliance-collect --path examples/compliance_collector.sh \
#       --description "Collect system compliance evidence" --category "compliance" \
#       --params '[{"name": "output_dir", "type": "string", "required": true, "description": "Output directory"},
#                  {"name": "framework", "type": "choice", "choices": ["soc2", "iso27001", "pci-dss"], "default": "soc2"}]'
#
#   seckit scripts run compliance-collect --param output_dir=/tmp/evidence --param framework=soc2

set -e

# Parse arguments
OUTPUT_DIR=""
FRAMEWORK="soc2"

while [[ $# -gt 0 ]]; do
    case $1 in
        --output_dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --framework)
            FRAMEWORK="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

if [ -z "$OUTPUT_DIR" ]; then
    echo "Error: --output_dir is required"
    exit 1
fi

echo "Collecting $FRAMEWORK compliance evidence..."
echo "Output directory: $OUTPUT_DIR"
echo "============================================"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Collect system information
echo "Collecting system information..."
{
    echo "=== System Information ==="
    echo "Hostname: $(hostname)"
    echo "Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "Kernel: $(uname -a)"
    echo ""
    echo "=== Users ==="
    cat /etc/passwd 2>/dev/null || echo "Unable to read /etc/passwd"
    echo ""
    echo "=== Groups ==="
    cat /etc/group 2>/dev/null || echo "Unable to read /etc/group"
} > "$OUTPUT_DIR/system_info.txt"

# Collect network information
echo "Collecting network information..."
{
    echo "=== Network Interfaces ==="
    ifconfig 2>/dev/null || ip addr 2>/dev/null || echo "Unable to get network info"
    echo ""
    echo "=== Listening Ports ==="
    netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null || echo "Unable to get port info"
    echo ""
    echo "=== Firewall Rules ==="
    iptables -L 2>/dev/null || echo "Unable to get firewall rules (may need root)"
} > "$OUTPUT_DIR/network_info.txt"

# Collect security configuration
echo "Collecting security configuration..."
{
    echo "=== SSH Configuration ==="
    cat /etc/ssh/sshd_config 2>/dev/null || echo "Unable to read SSH config"
    echo ""
    echo "=== PAM Configuration ==="
    ls -la /etc/pam.d/ 2>/dev/null || echo "Unable to list PAM config"
    echo ""
    echo "=== Sudoers ==="
    cat /etc/sudoers 2>/dev/null || echo "Unable to read sudoers (may need root)"
} > "$OUTPUT_DIR/security_config.txt"

# Collect log samples
echo "Collecting log samples..."
{
    echo "=== Recent Auth Log ==="
    tail -100 /var/log/auth.log 2>/dev/null || \
    tail -100 /var/log/secure 2>/dev/null || \
    echo "Unable to read auth logs"
    echo ""
    echo "=== Recent Syslog ==="
    tail -100 /var/log/syslog 2>/dev/null || \
    tail -100 /var/log/messages 2>/dev/null || \
    echo "Unable to read syslog"
} > "$OUTPUT_DIR/log_samples.txt"

# Generate summary
echo "Generating summary..."
{
    echo "Compliance Evidence Collection Summary"
    echo "======================================"
    echo "Framework: $FRAMEWORK"
    echo "Collection Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "Hostname: $(hostname)"
    echo ""
    echo "Files Collected:"
    ls -la "$OUTPUT_DIR"
} > "$OUTPUT_DIR/summary.txt"

echo ""
echo "============================================"
echo "Evidence collection complete!"
echo "Files saved to: $OUTPUT_DIR"
echo ""
cat "$OUTPUT_DIR/summary.txt"
