#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "${ROOT_DIR}/config/ntk_backend.env" ]]; then
  set -a
  source "${ROOT_DIR}/config/ntk_backend.env"
  set +a
fi

HOST="${NTK_BACKEND_HOST:-127.0.0.1}"
PORT="${NTK_BACKEND_PORT:-8765}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
export NTK_STORAGE_DIR="${NTK_STORAGE_DIR:-${ROOT_DIR}/persisted_api_store}"
export NTK_EXT4_CACHE_DIR="${NTK_EXT4_CACHE_DIR:-${HOME}/.cache/ntk_iris_scan_cache_v1}"

mkdir -p "${NTK_STORAGE_DIR}" "${NTK_EXT4_CACHE_DIR}"
cd "${ROOT_DIR}"
exec "${PYTHON_BIN}" -u scripts/ntk_web_backend_service.py \
  --serve-http \
  --host "${HOST}" \
  --port "${PORT}" \
  --storage-dir "${NTK_STORAGE_DIR}"
