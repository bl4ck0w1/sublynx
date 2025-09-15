#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Config
VERSION="${VERSION:-1.0.0}"
BUILD_DIR="${BUILD_DIR:-./bin}"
PKG_DIR="${PKG_DIR:-./bin/pkg}"

PLATFORMS=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
  "windows/arm64"
)

# Helpers
sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file"
  else
    echo -e "${RED}No sha256 tool found (sha256sum or shasum).${NC}" >&2
    return 1
  fi
}

# Banner
echo -e "${YELLOW}Building SubLynx v${VERSION}\n============================${NC}"

# Clean
echo -e "${YELLOW}Cleaning build directory...${NC}"
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}" "${PKG_DIR}"

# LDFLAGS
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILDDATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILDDATE}"

# Build
for platform in "${PLATFORMS[@]}"; do
  IFS='/'; read -r GOOS GOARCH <<< "${platform}"; IFS=$'\n\t'
  OUT="${BUILD_DIR}/sublynx-${GOOS}-${GOARCH}"
  [[ "${GOOS}" == "windows" ]] && OUT="${OUT}.exe"

  echo -e "${YELLOW}Building for ${GOOS}/${GOARCH}...${NC}"
  env GOOS="${GOOS}" GOARCH="${GOARCH}" CGO_ENABLED=0 \
    go build -trimpath -ldflags "${LDFLAGS}" -o "${OUT}" ./cmd/sublynx

  # Package
  echo -e "${YELLOW}Packaging...${NC}"
  PKG_NAME="sublynx-${VERSION}-${GOOS}-${GOARCH}"
  if [[ "${GOOS}" == "windows" ]]; then
    if command -v zip >/dev/null 2>&1; then
      (cd "${BUILD_DIR}" && zip -q "${PKG_NAME}.zip" "$(basename "${OUT}")")
      ART="${BUILD_DIR}/${PKG_NAME}.zip"
    else
      echo -e "${YELLOW}zip not found; packaging as tar.gz instead.${NC}"
      (cd "${BUILD_DIR}" && tar -czf "${PKG_NAME}.tar.gz" "$(basename "${OUT}")")
      ART="${BUILD_DIR}/${PKG_NAME}.tar.gz"
    fi
  else
    (cd "${BUILD_DIR}" && tar -czf "${PKG_NAME}.tar.gz" "$(basename "${OUT}")")
    ART="${BUILD_DIR}/${PKG_NAME}.tar.gz"
  fi

  # Checksum
  echo -e "${YELLOW}Checksum...${NC}"
  sha256_file "${ART}" >> "${BUILD_DIR}/checksums.txt"
done

# Docker
if command -v docker >/dev/null 2>&1; then
  echo -e "${YELLOW}Building Docker image...${NC}"
  docker build -t "sublynx:${VERSION}" -t "sublynx:latest" .
else
  echo -e "${YELLOW}Docker not found; skipping Docker image build.${NC}"
fi

echo -e "${GREEN}Build complete!${NC}"
echo -e "${GREEN}Artifacts: ${BUILD_DIR}${NC}"
echo -e "${GREEN}Checksums: ${BUILD_DIR}/checksums.txt${NC}"
