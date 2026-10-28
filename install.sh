#!/usr/bin/env bash
# Create a local virtual environment and install ChronoRecon.
set -euo pipefail

cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "error: $PYTHON not found; install Python 3.9+ first" >&2
    exit 1
fi

echo "[*] Creating virtual environment in .venv"
"$PYTHON" -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

echo "[*] Updating pip"
python -m pip install --upgrade pip >/dev/null

echo "[*] Installing ChronoRecon"
pip install -e .

echo
echo "[+] Installed. Activate the environment with:"
echo "      source .venv/bin/activate"
echo "    Then run:"
echo "      chronorecon example.com"
