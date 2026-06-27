#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="${ROOT_DIR}/src:${PYTHONPATH:-}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"
PYTHON_BIN="${PYTHON:-python}"

# Run FastAPI app via uvicorn from repo root.
cd "${ROOT_DIR}"
"${PYTHON_BIN}" -m uvicorn aiaf.api.app:app --host "${HOST}" --port "${PORT}" --reload
