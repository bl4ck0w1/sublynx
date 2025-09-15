#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

# ──────────────────────────────────────────────────────────────────────────────
# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ──────────────────────────────────────────────────────────────────────────────
# Config (you can override via env)
VERSION="${VERSION:-1.0.0}"
INSTALL_DIR="${INSTALL_DIR:-/opt/sublynx}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-$HOME/.sublynx}"
DATA_DIR="${DATA_DIR:-/var/lib/sublynx}"
REPO_URL="${REPO_URL:-https://github.com/bl4ck0w1/sublynx.git}"

# The user who owns config/data (prefer caller, even under sudo)
OWNER="${SUDO_USER:-$(whoami)}"
OWNER_HOME="$(getent passwd "$OWNER" | cut -d: -f6 || echo "$HOME")"

# ──────────────────────────────────────────────────────────────────────────────
# Root check (needed for system paths)
if [[ "${EUID}" -ne 0 ]]; then
  echo -e "${RED}Please run as root (use sudo).${NC}"
  exit 1
fi

# ──────────────────────────────────────────────────────────────────────────────
# Banner
echo -e "${BLUE}"
echo "   ▄████████ ███    █▄  ▀█████████▄   ▄█       ▄██   ▄   ███▄▄▄▄   ▀████    ▐████▀ ";
echo "  ███    ███ ███    ███   ███    ███ ███       ███   ██▄ ███▀▀▀██▄   ███▌   ████▀  ";
echo "  ███    █▀  ███    ███   ███    ███ ███       ███▄▄▄███ ███   ███    ███  ▐███    ";
echo "  ███        ███    ███  ▄███▄▄▄██▀  ███       ▀▀▀▀▀▀███ ███   ███    ▀███▄███▀    ";
echo "▀███████████ ███    ███ ▀▀███▀▀▀██▄  ███       ▄██   ███ ███   ███    ████▀██▄     ";
echo "         ███ ███    ███   ███    ██▄ ███       ███   ███ ███   ███   ▐███  ▀███    ";
echo "   ▄█    ███ ███    ███   ███    ███ ███▌    ▄ ███   ███ ███   ███  ▄███     ███▄  ";
echo " ▄████████▀  ████████▀  ▄█████████▀  █████▄▄██  ▀█████▀   ▀█   █▀  ████       ███▄ ";
echo "                                     ▀                                             ";
echo -e "${NC}"
echo "SubLynx Advanced Subdomain Discovery Platform v${VERSION}"
echo "============================================================="

# ──────────────────────────────────────────────────────────────────────────────
# Dependencies
echo -e "${YELLOW}Checking dependencies...${NC}"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo -e "${RED}Error: '$1' is required but not installed.${NC}"
    exit 1
  fi
}

need go
need git

# python is optional unless you plan model training; warn only
if ! command -v python3 >/dev/null 2>&1; then
  echo -e "${YELLOW}Warning: 'python3' not found. Model training functionality will be unavailable.${NC}"
fi

# ──────────────────────────────────────────────────────────────────────────────
# Create directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p "${INSTALL_DIR}" "${BIN_DIR}" "${CONFIG_DIR}" "${DATA_DIR}"

# ──────────────────────────────────────────────────────────────────────────────
# Clone or update repository
if [[ -d "${INSTALL_DIR}/.git" ]]; then
  echo -e "${YELLOW}Updating existing installation...${NC}"
  git -C "${INSTALL_DIR}" fetch --all --tags
  git -C "${INSTALL_DIR}" pull --ff-only
else
  echo -e "${YELLOW}Cloning repository...${NC}"
  git clone "${REPO_URL}" "${INSTALL_DIR}"
fi

# ──────────────────────────────────────────────────────────────────────────────
# Build (single-target, local platform)
echo -e "${YELLOW}Building SubLynx...${NC}"
pushd "${INSTALL_DIR}" >/dev/null

mkdir -p bin
LDFLAGS="-X main.version=${VERSION} -X main.commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown) -X main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
env CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS}" -o ./bin/sublynx ./cmd/sublynx

popd >/dev/null

# ──────────────────────────────────────────────────────────────────────────────
# Install binary
echo -e "${YELLOW}Installing binary...${NC}"
install -m 0755 "${INSTALL_DIR}/bin/sublynx" "${BIN_DIR}/sublynx"

# ──────────────────────────────────────────────────────────────────────────────
# Install configuration
echo -e "${YELLOW}Installing configuration...${NC}"
CFG_FILE="${CONFIG_DIR}/config.yaml"
if [[ ! -f "${CFG_FILE}" ]]; then
  # Use project template if available; otherwise generate a minimal, sane default
  if [[ -f "${INSTALL_DIR}/configs/config.yaml" ]]; then
    cp -f "${INSTALL_DIR}/configs/config.yaml" "${CFG_FILE}"
  else
    cat > "${CFG_FILE}" <<'YAML'
log_level: info
log_format: json
max_concurrent_scans: 5
default_timeout: 30m
output_directory: ./reports
data_directory: ./data
temp_directory: /tmp/sublynx
scan:
  methods: [all]
  validation: [all]
  depth: 2
  stealth: false
  config_profile: default
YAML
  fi
  echo -e "${YELLOW}Default configuration installed at ${CFG_FILE}${NC}"
else
  echo -e "${YELLOW}Existing configuration preserved at ${CFG_FILE}.${NC}"
fi

# ──────────────────────────────────────────────────────────────────────────────
# Install data files (if repo has /data)
if [[ -d "${INSTALL_DIR}/data" ]]; then
  echo -e "${YELLOW}Installing data files...${NC}"
  rsync -a --delete "${INSTALL_DIR}/data/" "${DATA_DIR}/" 2>/dev/null || cp -a "${INSTALL_DIR}/data/." "${DATA_DIR}/"
fi

# Ownership for non-root user
chown -R "${OWNER}:${OWNER}" "${CONFIG_DIR}" "${DATA_DIR}"

# ──────────────────────────────────────────────────────────────────────────────
# Systemd service (skipped because no 'api' command yet)
if command -v systemctl >/dev/null 2>&1; then
  echo -e "${YELLOW}Note:${NC} API/server mode is not available yet, so a systemd service will not be installed."
  echo -e "      You can still run one-off scans, e.g.: ${GREEN}sublynx scan example.com${NC}"
fi

# ──────────────────────────────────────────────────────────────────────────────
# Complete
echo -e "${GREEN}Installation completed successfully!${NC}"
echo -e "${GREEN}Binary:         ${BIN_DIR}/sublynx${NC}"
echo -e "${GREEN}Config folder:  ${CONFIG_DIR}${NC}"
echo -e "${GREEN}Data folder:    ${DATA_DIR}${NC}"
echo
echo -e "${YELLOW}Next steps:${NC}"
echo "1) Edit your configuration: ${CFG_FILE}"
echo "2) Verify the install:      sublynx version"
echo "3) Run a scan:              sublynx scan example.com"
