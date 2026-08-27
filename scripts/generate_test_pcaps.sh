#!/usr/bin/env bash
# generate_test_pcaps.sh
# Generates labeled test PCAPs for SecureMailScope validation.
#
# Strategy: Uses Docker Compose to spin up Postfix/Dovecot servers with
# deliberately varied TLS configurations, then captures traffic with tcpdump.
#
# Prerequisites:
#   - Docker & Docker Compose installed
#   - tcpdump or dumpcap installed
#   - swaks (for SMTP testing) and openssl (for s_client)
#
# For development without Docker, use the synthetic PCAP generator:
#   python -m tests.generate_synthetic_pcaps
#
# Usage: ./scripts/generate_test_pcaps.sh [output_dir]

set -euo pipefail

OUTPUT_DIR="${1:-tests/fixtures/pcaps}"
mkdir -p "$OUTPUT_DIR"

echo "========================================="
echo " SecureMailScope Test PCAP Generator"
echo "========================================="
echo ""
echo "NOTE: This script requires Docker and Docker Compose."
echo "For development without Docker, use the synthetic generator:"
echo "  python -m tests.generate_synthetic_pcaps"
echo ""
echo "Output directory: $OUTPUT_DIR"
echo ""

# Check prerequisites
for cmd in docker docker-compose tcpdump swaks openssl; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "ERROR: Required tool '$cmd' not found. Please install it first."
        exit 1
    fi
done

echo "All prerequisites found. Docker-based PCAP generation is not yet implemented."
echo "Please use the synthetic PCAP generator for development:"
echo "  python -m tests.generate_synthetic_pcaps"
