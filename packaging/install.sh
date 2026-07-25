#!/bin/bash
# install.sh - installs Glacier as a desktop application on Kali Linux
# (or any Debian-based distro with a freedesktop-compliant menu).
#
# Installs per-user (no root needed for the app itself - only for
# missing system packages, via sudo, if you approve it):
#   ~/.local/share/glacier          app files, venv, node_modules, the db
#   ~/.local/bin/glacier            launcher command
#   ~/.local/share/applications/    Glacier.desktop menu entry
#   ~/.local/share/icons/hicolor/   app icon, all sizes
#
# Run from inside the extracted glacier-main folder:
#   ./packaging/install.sh
set -euo pipefail

PACKAGING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$PACKAGING_DIR/.." && pwd)"
INSTALL_DIR="$HOME/.local/share/glacier"
BIN_DIR="$HOME/.local/bin"
APPS_DIR="$HOME/.local/share/applications"
ICON_BASE="$HOME/.local/share/icons/hicolor"
PIXMAPS_DIR="$HOME/.local/share/pixmaps"

echo "=========================================="
echo "  Glacier installer - HackOps Academy"
echo "=========================================="
echo

# ---------------------------------------------------------------------
# 1. Check / install system dependencies
# ---------------------------------------------------------------------
missing=()
command -v python3 >/dev/null 2>&1 || missing+=("python3")
python3 -c "import venv" >/dev/null 2>&1 || missing+=("python3-venv")
command -v pip3 >/dev/null 2>&1 || missing+=("python3-pip")
command -v node >/dev/null 2>&1 || missing+=("nodejs")
command -v npm >/dev/null 2>&1 || missing+=("npm")
command -v rsync >/dev/null 2>&1 || missing+=("rsync")

if [ "${#missing[@]}" -gt 0 ]; then
    echo "[*] Missing system packages: ${missing[*]}"
    if command -v apt-get >/dev/null 2>&1; then
        read -rp "    Install them now with sudo apt-get? [Y/n] " ans
        if [[ "$ans" =~ ^[Nn]$ ]]; then
            echo "Aborting - install the packages above manually and re-run."
            exit 1
        fi
        sudo apt-get update
        sudo apt-get install -y "${missing[@]}"
    else
        echo "apt-get not found - install these packages manually: ${missing[*]}"
        exit 1
    fi
fi
echo "[*] System dependencies OK."
echo

# ---------------------------------------------------------------------
# 2. Copy application files into the per-user install directory
# ---------------------------------------------------------------------
echo "[*] Installing app files to $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"
rsync -a --delete \
    --exclude 'packaging' \
    --exclude '.git' \
    --exclude 'venv' \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    --exclude 'hud/node_modules' \
    --exclude 'hud/dist' \
    --exclude '*.db' --exclude '*.db-shm' --exclude '*.db-wal' --exclude '*.db-journal' \
    "$REPO_ROOT"/ "$INSTALL_DIR"/

# ---------------------------------------------------------------------
# 3. Python venv + deps
# ---------------------------------------------------------------------
echo "[*] Creating Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
echo "[*] Installing Python dependencies..."
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"

# ---------------------------------------------------------------------
# 4. HUD (Electron) deps
# ---------------------------------------------------------------------
echo "[*] Installing HUD dependencies (this downloads Electron, may take a bit)..."
(cd "$INSTALL_DIR/hud" && npm install --no-audit --no-fund)

# ---------------------------------------------------------------------
# 5. Icon
# ---------------------------------------------------------------------
echo "[*] Installing icon..."
for size_dir in "$PACKAGING_DIR"/icons/hicolor/*/apps; do
    size_name="$(basename "$(dirname "$size_dir")")"
    mkdir -p "$ICON_BASE/$size_name/apps"
    cp "$size_dir/glacier.png" "$ICON_BASE/$size_name/apps/glacier.png"
done
mkdir -p "$PIXMAPS_DIR"
cp "$PACKAGING_DIR/icons/glacier.png" "$PIXMAPS_DIR/glacier.png"

if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$HOME/.local/share/icons/hicolor" >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------
# 6. Launcher command
# ---------------------------------------------------------------------
echo "[*] Installing launcher to $BIN_DIR/glacier ..."
mkdir -p "$BIN_DIR"
cp "$PACKAGING_DIR/bin/glacier" "$BIN_DIR/glacier"
chmod +x "$BIN_DIR/glacier"

# ---------------------------------------------------------------------
# 7. Desktop menu entry
# ---------------------------------------------------------------------
echo "[*] Installing menu entry..."
mkdir -p "$APPS_DIR"
sed "s|__LAUNCHER__|$BIN_DIR/glacier|" "$PACKAGING_DIR/glacier.desktop" > "$APPS_DIR/glacier.desktop"
chmod +x "$APPS_DIR/glacier.desktop"

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPS_DIR" >/dev/null 2>&1 || true
fi

echo
echo "=========================================="
echo "  Glacier installed."
echo "=========================================="
echo
echo "Launch it from your Applications menu (search 'Glacier'),"
echo "or from any terminal with:  glacier"
echo

if ! echo "$PATH" | tr ':' '\n' | grep -qx "$BIN_DIR"; then
    echo "NOTE: $BIN_DIR is not on your PATH yet, so the 'glacier' command"
    echo "won't work from a terminal until you add it. The Applications menu"
    echo "entry will work regardless. To fix the terminal command, add this"
    echo "to ~/.bashrc or ~/.zshrc:"
    echo
    echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo
fi

echo "First run: once the HUD opens and you hit Connect, point your"
echo "browser's proxy at 127.0.0.1:8081 and visit http://mitm.it through"
echo "it once to trust mitmproxy's CA cert (needed for HTTPS interception)."
echo
echo "To test the active scanner safely first, run the bundled vulnerable"
echo "target:  $INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/tools/vulnerable_test_app.py"
