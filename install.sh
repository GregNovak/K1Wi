#!/usr/bin/env bash
set -euo pipefail

APP_NAME="k1wi"
PREFIX="/usr/local"
BIN_DIR="$PREFIX/bin"
DOC_DIR="$PREFIX/share/doc/k1wi"

echo "[K1Wi Installer]"
echo "Installing K1Wi Framework..."

if [[ ! -f "Makefile" && ! -f "makefile" && ! -f "GNUmakefile" ]]; then
    echo "ERROR: makefile not found. Run this script from the K1Wi project root."
    exit 1
fi

echo "[1/5] Building K1Wi..."
make clean
make

if [[ ! -x "./bin/k1wi" ]]; then
    echo "ERROR: ./bin/k1wi was not built successfully."
    exit 1
fi

echo "[2/5] Creating install directories..."
sudo mkdir -p "$BIN_DIR"
sudo mkdir -p "$DOC_DIR"

echo "[3/5] Installing binary..."
sudo install -m 755 ./bin/k1wi "$BIN_DIR/$APP_NAME"

echo "[4/5] Installing documentation..."
sudo install -m 644 README.md "$DOC_DIR/README.md"
sudo install -m 644 LICENSE "$DOC_DIR/LICENSE"
sudo install -m 644 DISCLAIMER.md "$DOC_DIR/DISCLAIMER.md"

echo "[5/5] Verifying install..."
"$BIN_DIR/$APP_NAME" version

echo
echo "K1Wi installed successfully."
echo "Run with:"
echo "  k1wi"
