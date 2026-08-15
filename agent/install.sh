#!/bin/bash
set -euo pipefail

# Ensure running as root
if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="/opt/vanguard-agent"
SERVICE_FILE="$SCRIPT_DIR/vanguard-agent.service"

# Setup directory
install -d -m 0750 "$AGENT_DIR" /var/lib/vanguard-agent
install -m 0644 "$SCRIPT_DIR/agent.py" "$SCRIPT_DIR/requirements.txt" "$AGENT_DIR/"
if [ -f "$SCRIPT_DIR/.env" ]; then
  install -m 0600 "$SCRIPT_DIR/.env" "$AGENT_DIR/.env"
elif [ ! -f "$AGENT_DIR/.env" ]; then
  install -m 0600 "$SCRIPT_DIR/.env.example" "$AGENT_DIR/.env"
  echo "Created $AGENT_DIR/.env. Configure it, then rerun this installer."
  exit 1
fi

# Setup python environment
cd "$AGENT_DIR"
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
./venv/bin/pip install -r requirements.txt

# Install service
install -m 0644 "$SERVICE_FILE" /etc/systemd/system/vanguard-agent.service
systemctl daemon-reload
systemctl enable vanguard-agent
systemctl restart vanguard-agent

echo "Installation complete. Check status with: systemctl status vanguard-agent"
