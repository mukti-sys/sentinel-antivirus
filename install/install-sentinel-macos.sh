#!/usr/bin/env bash
# ==============================================================================
# Sentinel Antivirus — macOS Installer
# Installs Sentinel to /usr/local/sentinel with launchd daemon support
# ==============================================================================
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="/usr/local/sentinel"
DATA_DIR="$HOME/Library/Application Support/Sentinel"
LOG_DIR="$HOME/Library/Logs/Sentinel"
PLIST_DIR="$HOME/Library/LaunchAgents"
PLIST_NAME="com.sentinel.antivirus.plist"

echo -e "${CYAN}"
echo "============================================================"
echo "       Sentinel Antivirus — macOS Installer v2.1"
echo "============================================================"
echo -e "${NC}"

# Check if dist/Sentinel exists
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DIST_DIR="${SCRIPT_DIR}/dist/Sentinel"

if [[ ! -d "$DIST_DIR" ]]; then
    echo -e "${RED}[!] Build directory not found: ${DIST_DIR}${NC}"
    echo "    Run 'python build_dist.py --target macos' first."
    exit 1
fi

echo -e "${GREEN}[*] Installing Sentinel Antivirus to ${INSTALL_DIR}...${NC}"

# Create directories
echo "[*] Creating directories..."
sudo mkdir -p "$INSTALL_DIR"
mkdir -p "$DATA_DIR/quarantine"
mkdir -p "$LOG_DIR"
mkdir -p "$PLIST_DIR"

# Copy binaries
echo "[*] Copying Sentinel binaries..."
sudo cp -r "${DIST_DIR}/"* "$INSTALL_DIR/"
sudo chmod +x "$INSTALL_DIR/sentinel_service"
sudo chmod +x "$INSTALL_DIR/sentinel_cli"
sudo chmod +x "$INSTALL_DIR/sentinel_gui" 2>/dev/null || true

# Create symlinks for CLI access
echo "[*] Creating CLI symlinks..."
sudo ln -sf "$INSTALL_DIR/sentinel_cli" /usr/local/bin/sentinel
sudo ln -sf "$INSTALL_DIR/sentinel_cli" /usr/local/bin/sentinel-scan

# Install launchd plist
echo "[*] Installing launchd agent..."
cat > "${PLIST_DIR}/${PLIST_NAME}" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sentinel.antivirus</string>

    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/sentinel_service</string>
        <string>--standalone</string>
    </array>

    <key>WorkingDirectory</key>
    <string>${INSTALL_DIR}</string>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>StandardOutPath</key>
    <string>${LOG_DIR}/sentinel.log</string>

    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/sentinel.err.log</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
</dict>
</plist>
EOF

echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}      Sentinel Antivirus installed successfully!${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo -e "  ${CYAN}Start service:${NC}    launchctl load ~/${PLIST_DIR##$HOME/}/${PLIST_NAME}"
echo -e "  ${CYAN}Stop service:${NC}     launchctl unload ~/${PLIST_DIR##$HOME/}/${PLIST_NAME}"
echo -e "  ${CYAN}Scan a file:${NC}      sentinel scan /path/to/file"
echo -e "  ${CYAN}Full scan:${NC}        sentinel scan --full /"
echo ""
echo -e "  ${CYAN}Installation:${NC}     ${INSTALL_DIR}"
echo -e "  ${CYAN}Data directory:${NC}   ${DATA_DIR}"
echo -e "  ${CYAN}Logs:${NC}             ${LOG_DIR}"
echo ""
echo -e "${YELLOW}Note: For real-time file monitoring, grant Full Disk Access to${NC}"
echo -e "${YELLOW}      sentinel_service in System Settings > Privacy & Security.${NC}"
echo ""
