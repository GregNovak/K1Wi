#!/usr/bin/env bash
set -euo pipefail

APP_NAME="k1wi"
PREFIX="/usr/local"
BIN_PATH="$PREFIX/bin/$APP_NAME"
DOC_DIR="$PREFIX/share/doc/k1wi"

echo "[K1Wi Uninstaller]"
echo "Removing K1Wi Framework..."

if [[ -f "$BIN_PATH" ]]; then
    echo "Removing binary: $BIN_PATH"
    sudo rm -f "$BIN_PATH"
else
    echo "Binary not found: $BIN_PATH"
fi

if [[ -d "$DOC_DIR" ]]; then
    echo "Removing docs: $DOC_DIR"
    sudo rm -rf "$DOC_DIR"
else
    echo "Docs not found: $DOC_DIR"
fi

echo
echo "K1Wi uninstall complete."
