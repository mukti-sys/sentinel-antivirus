#!/usr/bin/env bash
# ==============================================================================
# Sentinel Antivirus — Linux Installer
# Installs Sentinel to /opt/sentinel with systemd daemon support
# ==============================================================================
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="/opt/sentinel"
DATA_DIR="/var/lib/sentinel"
LOG_DIR="/var/log/sentinel"
RUN_DIR="/var/run/sentinel"
SYSTEMD_DIR="/etc/systemd/system"

echo -e "${CYAN}"
echo "============================================================"
echo "         Sentinel Antivirus — Linux Installer v2.1"
echo "============================================================"
echo -e "${NC}"

# Check root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] This installer must be run as root (use sudo)${NC}"
    exit 1
fi

# Check if dist/Sentinel exists (built binaries)
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DIST_DIR="${SCRIPT_DIR}/dist/Sentinel"

if [[ ! -d "$DIST_DIR" ]]; then
    echo -e "${RED}[!] Build directory not found: ${DIST_DIR}${NC}"
    echo "    Run 'python build_dist.py --target linux' first."
    exit 1
fi

echo -e "${GREEN}[*] Installing Sentinel Antivirus to ${INSTALL_DIR}...${NC}"

# Create directories
echo "[*] Creating directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$DATA_DIR/quarantine"
mkdir -p "$LOG_DIR"
mkdir -p "$RUN_DIR"

# Copy binaries
echo "[*] Copying Sentinel binaries..."
cp -r "${DIST_DIR}/"* "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/sentinel_service"
chmod +x "$INSTALL_DIR/sentinel_cli"
chmod +x "$INSTALL_DIR/sentinel_gui" 2>/dev/null || true

# Create symlinks for CLI access
echo "[*] Creating CLI symlinks..."
ln -sf "$INSTALL_DIR/sentinel_cli" /usr/local/bin/sentinel
ln -sf "$INSTALL_DIR/sentinel_cli" /usr/local/bin/sentinel-scan

# Install systemd service
echo "[*] Installing systemd service..."
cat > "${SYSTEMD_DIR}/sentinel.service" << EOF
[Unit]
Description=Sentinel Antivirus Core Detection Service
Documentation=https://github.com/mukti-sys/sentinel-antivirus
After=network.target auditd.service
Wants=auditd.service

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/sentinel_service --standalone
WorkingDirectory=${INSTALL_DIR}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sentinel

# Security hardening
ProtectSystem=strict
ReadWritePaths=${DATA_DIR} ${RUN_DIR} ${LOG_DIR}
ProtectHome=read-only
NoNewPrivileges=false
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_NET_ADMIN
AmbientCapabilities=CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
EOF

# Set capabilities for fanotify (alternative to running as root)
echo "[*] Setting capabilities for fanotify support..."
setcap cap_sys_admin+ep "$INSTALL_DIR/sentinel_service" 2>/dev/null || \
    echo -e "${YELLOW}    [!] Could not set capabilities — run service as root for fanotify${NC}"

# Reload systemd and enable
systemctl daemon-reload
systemctl enable sentinel.service

echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}         Sentinel Antivirus installed successfully!${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo -e "  ${CYAN}Start service:${NC}    sudo systemctl start sentinel"
echo -e "  ${CYAN}Stop service:${NC}     sudo systemctl stop sentinel"
echo -e "  ${CYAN}Check status:${NC}     sudo systemctl status sentinel"
echo -e "  ${CYAN}View logs:${NC}        journalctl -u sentinel -f"
echo -e "  ${CYAN}Scan a file:${NC}      sentinel scan /path/to/file"
echo -e "  ${CYAN}Full scan:${NC}        sentinel scan --full /"
echo ""
echo -e "  ${CYAN}Installation:${NC}     ${INSTALL_DIR}"
echo -e "  ${CYAN}Data directory:${NC}   ${DATA_DIR}"
echo -e "  ${CYAN}Logs:${NC}             ${LOG_DIR}"
echo ""
