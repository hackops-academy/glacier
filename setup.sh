#!/bin/bash
# setup.sh - one-time setup for glacier.
# Run this once after cloning: ./setup.sh
set -e
cd "$(dirname "$0")"

echo "[*] Creating Python virtual environment..."
python3 -m venv venv
. venv/bin/activate

echo "[*] Installing Python dependencies..."
pip install --quiet -r requirements.txt

echo "[*] Installing HUD (Electron) dependencies..."
cd hud
npm install
cd ..

echo ""
echo "Setup complete."
echo "Run ./start.sh to launch the proxy, API, and HUD together."
