#!/bin/bash
# uninstall.sh - removes everything install.sh created.
set -uo pipefail

INSTALL_DIR="$HOME/.local/share/glacier"
RUN_DIR="$HOME/.local/share/glacier-run"
BIN_DIR="$HOME/.local/bin"
APPS_DIR="$HOME/.local/share/applications"
ICON_BASE="$HOME/.local/share/icons/hicolor"
PIXMAPS_DIR="$HOME/.local/share/pixmaps"

read -rp "This removes Glacier and ALL captured traffic/findings in $INSTALL_DIR. Continue? [y/N] " ans
if [[ ! "$ans" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

rm -rf "$INSTALL_DIR"
rm -rf "$RUN_DIR"
rm -f "$BIN_DIR/glacier"
rm -f "$APPS_DIR/glacier.desktop"
find "$ICON_BASE" -type f -name "glacier.png" -exec rm -f {} \; 2>/dev/null || true
rm -f "$PIXMAPS_DIR/glacier.png"

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPS_DIR" >/dev/null 2>&1 || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$HOME/.local/share/icons/hicolor" >/dev/null 2>&1 || true
fi

echo "Glacier uninstalled."
