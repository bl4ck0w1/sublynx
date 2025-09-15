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
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${DATA_DIR:-${ROOT_DIR}/data}"
MODEL_DIR="${MODEL_DIR:-${ROOT_DIR}/data/trained_models/subdomain_predictor}"
TRAINING_SCRIPT="${TRAINING_SCRIPT:-${ROOT_DIR}/internal/discovery/ai/model/train.py}"
REQS_FILE="${REQS_FILE:-${ROOT_DIR}/requirements.txt}"
USE_VENV="${USE_VENV:-1}" # set to 0 to skip venv

# Banner
echo -e "${YELLOW}SubLynx Model Training v${VERSION}\n===================================${NC}"

# Checks
need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo -e "${RED}Error: '$1' is required but not installed.${NC}"
    exit 1
  fi
}

need python3
need pip3

if [[ ! -f "${TRAINING_SCRIPT}" ]]; then
  echo -e "${RED}Training script not found at:${NC} ${TRAINING_SCRIPT}"
  echo -e "This repo currently does not include the Python model pipeline."
  echo -e "Please add it or adjust TRAINING_SCRIPT before running."
  exit 1
fi

mkdir -p "${DATA_DIR}" "${MODEL_DIR}"

# Optional venv
if [[ "${USE_VENV}" == "1" ]]; then
  echo -e "${YELLOW}Creating/using Python virtualenv...${NC}"
  python3 -m venv "${ROOT_DIR}/.venv"
  # shellcheck source=/dev/null
  source "${ROOT_DIR}/.venv/bin/activate"
fi

# Requirements (optional)
if [[ -f "${REQS_FILE}" ]]; then
  echo -e "${YELLOW}Installing Python dependencies...${NC}"
  pip3 install --upgrade pip
  pip3 install -r "${REQS_FILE}"
else
  echo -e "${YELLOW}requirements.txt not found; continuing with system/venv packages.${NC}"
fi

# Prepare data
echo -e "${YELLOW}Preparing training data...${NC}"
python3 "${TRAINING_SCRIPT}" prepare-data \
  --ct-logs "${DATA_DIR}/ctlogs" \
  --dns-data "${DATA_DIR}/passive_dns" \
  --output "${DATA_DIR}/training_data.csv" \
  --max-samples 2500000

# Train
echo -e "${YELLOW}Training model...${NC}"
python3 "${TRAINING_SCRIPT}" train \
  --data "${DATA_DIR}/training_data.csv" \
  --output-dir "${MODEL_DIR}" \
  --epochs 10 \
  --batch-size 32 \
  --learning-rate 0.001 \
  --hidden-size 512 \
  --num-layers 6 \
  --num-heads 8 \
  --dropout 0.1

# Evaluate
echo -e "${YELLOW}Evaluating model...${NC}"
python3 "${TRAINING_SCRIPT}" evaluate \
  --model-dir "${MODEL_DIR}" \
  --test-data "${DATA_DIR}/training_data.csv" \
  --batch-size 32

# Export ONNX
echo -e "${YELLOW}Exporting to ONNX...${NC}"
python3 "${TRAINING_SCRIPT}" export-onnx \
  --model-dir "${MODEL_DIR}" \
  --output "${MODEL_DIR}/model.onnx"

# Vocabulary
echo -e "${YELLOW}Generating vocabulary...${NC}"
python3 "${TRAINING_SCRIPT}" generate-vocabulary \
  --data "${DATA_DIR}/training_data.csv" \
  --output "${MODEL_DIR}/vocabulary.txt" \
  --max-size 50000

# Done
[[ "${USE_VENV}" == "1" ]] && deactivate || true

echo -e "${GREEN}Model training completed successfully!${NC}"
echo -e "${GREEN}Model dir: ${MODEL_DIR}${NC}"
echo -e "${GREEN}ONNX:      ${MODEL_DIR}/model.onnx${NC}"
echo -e "${GREEN}Vocab:     ${MODEL_DIR}/vocabulary.txt${NC}"
