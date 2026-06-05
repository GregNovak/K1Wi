#!/usr/bin/env bash
set -euo pipefail

BIN="./bin/opus"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "[PASS] $1"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "[FAIL] $1"
    echo
    echo "============================================================"
    echo "FEATURE MATRIX SUMMARY"
    echo "============================================================"
    echo "PASS: $PASS_COUNT"
    echo "FAIL: $FAIL_COUNT"
    echo "SKIP: $SKIP_COUNT"
    exit 1
}

skip() {
    SKIP_COUNT=$((SKIP_COUNT + 1))
    echo "[SKIP] $1"
}

require_output() {
    local label="$1"
    local output="$2"
    local needle="$3"

    if echo "$output" | grep -Fq "$needle"; then
        pass "$label"
    else
        echo "$output"
        fail "$label missing expected output: $needle"
    fi
}

require_success() {
    local label="$1"
    local command="$2"

    set +e
    OUT=$(eval "$command" 2>&1)
    RC=$?
    set -e

    echo "$OUT"

    if [ "$RC" -eq 0 ]; then
        pass "$label"
    else
        fail "$label exited with status $RC"
    fi
}

echo "============================================================"
echo "K1Wi FEATURE MATRIX"
echo "============================================================"

if [ ! -x "$BIN" ]; then
    fail "opus binary not found. Run make first."
fi

echo
echo "[WAVE 1] File / Utility / Hash / Search"

echo
echo "[TEST] READ text file"
OUT=$($BIN read testdata/text/hello.txt 2>&1)
echo "$OUT"
require_output "READ opens text fixture" "$OUT" "hello"

echo
echo "[TEST] SEARCH ASCII pattern"
OUT=$($BIN search testdata/text/hello.txt hello 2>&1)
echo "$OUT"
require_output "SEARCH finds ASCII pattern" "$OUT" "hello"

echo
echo "[TEST] MD5 file"
OUT=$($BIN md5 testdata/crypto/md5_input.txt 2>&1)
echo "$OUT"
require_output "MD5 produces digest" "$OUT" "MD5"

echo
echo "[TEST] SHA256 file"
OUT=$($BIN sha256 testdata/crypto/sha256_input.txt 2>&1)
echo "$OUT"
require_output "SHA256 produces digest" "$OUT" "SHA256"

echo
echo "[TEST] MAGIC JPEG"
OUT=$($BIN magic testdata/lyzer/embedded_zip.jpg 2>&1)
echo "$OUT"
require_output "MAGIC detects JPEG" "$OUT" "JPEG"

echo
echo "[TEST] ABOUT / VERSION"
OUT=$($BIN about 2>&1)
echo "$OUT"
require_output "ABOUT reports K1Wi" "$OUT" "K1Wi"

echo
echo "[TEST] SPLASH"
OUT=$($BIN splash 2>&1)
echo "$OUT" | head -20
require_output "SPLASH prints banner" "$OUT" "K1Wi"

echo
echo "[TEST] TIME"
OUT=$($BIN time 2>&1)
echo "$OUT"
require_output "TIME prints system time" "$OUT" "Time"

echo
echo "============================================================"
echo "FEATURE MATRIX COMPLETE"
echo "============================================================"

echo
echo "============================================================"
echo "FEATURE MATRIX SUMMARY"
echo "============================================================"
echo "PASS: $PASS_COUNT"
echo "FAIL: $FAIL_COUNT"
echo "SKIP: $SKIP_COUNT"
