#!/usr/bin/env bash
set -euo pipefail

BIN="./bin/k1wi"

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
    echo "REGRESSION TEST SUMMARY"
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


require_failure_output() {
    local label="$1"
    local command="$2"
    local needle="$3"

    set +e
    OUT=$(eval "$command" 2>&1)
    RC=$?
    set -e

    echo "$OUT"

    if [ "$RC" -eq 0 ]; then
        fail "$label expected failure but command exited 0"
    fi

    if echo "$OUT" | grep -Fq "$needle"; then
        pass "$label"
    else
        fail "$label missing expected error output: $needle"
    fi
}
echo "============================================================"
echo "K1Wi REGRESSION TESTS"
echo "============================================================"

if [ ! -x "$BIN" ]; then
    fail "K1Wi binary not found. Run make first."
fi

echo
echo "[TEST] STRING basic text"
OUT=$($BIN string "hello K1Wi")
echo "$OUT"
require_output "STRING basic UTF-8 detection" "$OUT" "Detected Type: UTF"

echo
echo "[TEST] STRING shifted hex private key marker"
OUT=$($BIN string "R2d2d2d2d2d424547494e2050524956415445204b45592d")
echo "$OUT"
require_output "STRING shifted hex private key detection" "$OUT" "Shifted hex encoded private key"

echo
echo "[TEST] EXTRACT sample zip"

ARCHIVE_SAMPLE="testdata/archives/sample.zip"

if [ -f "$ARCHIVE_SAMPLE" ]; then
    OUT=$($BIN extract --recursive "$ARCHIVE_SAMPLE" 2>&1)
    echo "$OUT"
    require_output "EXTRACT recursive completion" "$OUT" "EXTRACT COMPLETE"
    require_output "EXTRACT carved file count" "$OUT" "Files  : 2"
else
    skip "$ARCHIVE_SAMPLE not found"
fi




echo
echo "[TEST] LYZER sample image/file if available"

LYZER_IMG="testdata/lyzer/embedded_zip.jpg"
if [ -f "$LYZER_IMG" ]; then
    OUT=$($BIN lyzer "$LYZER_IMG" ALL 2>&1)
    echo "$OUT"
    require_output "LYZER detects JPEG" "$OUT" "Detected format: JPEG"
    require_output "LYZER string intelligence" "$OUT" "String Intelligence"
    require_output "LYZER embedded signatures" "$OUT" "Embedded Signatures"

    OUT=$($BIN lyzer "$LYZER_IMG" 2>&1)
    require_output "LYZER default mode is summary" "$OUT" "K1Wi LYZER Summary"
    require_output "LYZER default summary reports next steps" "$OUT" "Next steps"

    OUT=$($BIN lyzer "$LYZER_IMG" h 2>&1)
    require_output "LYZER lowercase h mode works" "$OUT" "Entropy Heatmap"

    OUT=$($BIN lyzer "$LYZER_IMG" all 2>&1)
    require_output "LYZER lowercase all mode runs carver" "$OUT" "File Carver"
    require_output "LYZER lowercase all mode runs strings" "$OUT" "String Intelligence"
    
    OUT=$($BIN lyzer "$LYZER_IMG" --full 2>&1)
    require_output "LYZER --full alias runs carver" "$OUT" "File Carver"
    require_output "LYZER --full alias runs strings" "$OUT" "String Intelligence"

    OUT=$($BIN lyzer "$LYZER_IMG" --verbose 2>&1)
    require_output "LYZER --verbose alias runs carver" "$OUT" "File Carver"
    require_output "LYZER --verbose alias runs strings" "$OUT" "String Intelligence"

    OUT=$($BIN lyzer "$LYZER_IMG" --summary 2>&1)
    require_output "LYZER --summary alias works" "$OUT" "K1Wi LYZER Summary"
    require_output "LYZER --summary reports next steps" "$OUT" "Next steps"
    
else
    skip "$LYZER_IMG not found"
fi   

echo
echo "[TEST] ENTROPY sample image"

if [ -f "$LYZER_IMG" ]; then
    OUT=$($BIN entropy "$LYZER_IMG" 2>&1)
    echo "$OUT"
    require_output "ENTROPY reports global entropy" "$OUT" "Global entropy"
    require_output "ENTROPY reports bits per byte" "$OUT" "bits/byte"
else
    skip "$LYZER_IMG not found"
fi
    
echo
echo "[TEST] ELFINFO tiny ELF sample"

ELF_SAMPLE="/tmp/k1wi_regression_hello_elf"
cat > /tmp/k1wi_regression_hello.c <<'EOF'
#include <stdio.h>
int main(void) {
    puts("hello");
    return 0;
}
EOF

cc /tmp/k1wi_regression_hello.c -o "$ELF_SAMPLE"

OUT=$($BIN elfinfo "$ELF_SAMPLE" 2>&1)
set -euo pipefail

require_output \
    "ELF reports ELFINFO header" \
    "$OUT" \
    "ELFINFO"

require_output \
    "ELF detects 64-bit binary" \
    "$OUT" \
    "64-bit"

echo
echo "[TEST] PIECALC symbol list"

OUT=$($BIN PIECALC --bin "$ELF_SAMPLE" --list 2>&1)
sed -n '1,40p' <<< "$OUT"

require_output \
    "PIECALC lists symbols" \
    "$OUT" \
    "main"

require_output \
    "PIECALC lists offsets" \
    "$OUT" \
    "0x"

echo
echo "[TEST] PIETIME basic analysis"

OUT=$($BIN PIETIME -IN ./bin/k1wi -LEAK 0x401000 -BASE 0x400000 2>&1)
sed -n '1,20p' <<< "$OUT"

require_output "PIETIME reports analysis" "$OUT" "[PIETIME] ANALYSIS"
require_output "PIETIME reports binary" "$OUT" "binary:"
require_output "PIETIME reports offset" "$OUT" "offset:"

echo
echo "[TEST] MAGIC sample ZIP"

if [ -f "$ARCHIVE_SAMPLE" ]; then
    OUT=$($BIN magic "$ARCHIVE_SAMPLE" 2>&1)
    echo "$OUT"

    require_output \
        "MAGIC detects ZIP archive" \
        "$OUT" \
        "ZIP"
else
    skip "$ARCHIVE_SAMPLE not found"
fi

echo
echo "[TEST] SEARCH basic ASCII pattern"

OUT=$($BIN SEARCH testdata/text/hello.txt hello 2>&1)
echo "$OUT"

require_output \
    "SEARCH finds ASCII pattern" \
    "$OUT" \
    "hello"

echo
echo "[TEST] MD5 basic hash"

OUT=$($BIN md5 testdata/text/hello.txt 2>&1)
echo "$OUT"

require_output \
    "MD5 reports digest" \
    "$OUT" \
    "MD5("
    
echo
echo "[TEST] MD5 compare"

OUT=$($BIN md5 -compare testdata/text/hello.txt testdata/text/hello.txt 2>&1)
echo "$OUT"

require_output \
    "MD5 compare match" \
    "$OUT" \
    "MD5 MATCH"
    
echo
echo "[TEST] SHA256 basic hash"

OUT=$($BIN sha256 testdata/text/hello.txt 2>&1)
echo "$OUT"

require_output \
    "SHA256 reports digest" \
    "$OUT" \
    "SHA256("

echo
echo "[TEST] SHA256 compare"

OUT=$($BIN sha256 -compare testdata/text/hello.txt testdata/text/hello.txt 2>&1)
echo "$OUT"

require_output \
    "SHA256 compare match" \
    "$OUT" \
    "SHA256 MATCH"
    
echo
echo "[TEST] RSA known p/q sample"

OUT=$($BIN RSA-KNOWNPQ ./testdata/rsa/rsa_61_53_e17.txt 61 53 2>&1)
echo "$OUT"

require_output "RSA-KNOWNPQ recovers plaintext" "$OUT" "[+] m (int) = 123"
require_output "RSA-KNOWNPQ command succeeds" "$OUT" "rsa-knownpq: success"    

echo
echo "[TEST] RSA check p/q sample"

OUT=$($BIN RSA-CHECKPQ 61 53 2>&1)
echo "$OUT"

require_output \
    "RSA-CHECKPQ validates p" \
    "$OUT" \
    "p is prime"

require_output \
    "RSA-CHECKPQ validates q" \
    "$OUT" \
    "q is prime"

echo
echo "[TEST] RSA derive d from p/q/e sample"

OUT=$($BIN RSA-DFROMPQ 61 53 17 2>&1)
echo "$OUT"

require_output \
    "RSA-DFROMPQ computes phi" \
    "$OUT" \
    "phi = 3120"

require_output \
    "RSA-DFROMPQ computes d" \
    "$OUT" \
    "d = 2753"

echo
echo "[TEST] RSA Pollard Rho sample"

OUT=$($BIN RSA-RHO ./testdata/rsa/rsa_61_53_e17.txt 2>&1)
echo "$OUT"

require_output \
    "RSA-RHO finds p" \
    "$OUT" \
    "[+] p ="

require_output \
    "RSA-RHO finds q" \
    "$OUT" \
    "[+] q ="

require_output \
    "RSA-RHO recovers plaintext" \
    "$OUT" \
    "m = 123"

echo
echo "[TEST] RSA mini negative sample"

set +e
OUT=$($BIN RSA-MINI ./testdata/rsa/rsa_61_53_e17.txt 2>&1)
RC=$?
set -e

echo "$OUT"

require_output \
    "RSA-MINI rejects unsupported exponent" \
    "$OUT" \
    "only e=3 supported"

if [ "$RC" -eq 0 ]; then
    fail "RSA-MINI expected non-zero for unsupported exponent"
fi

pass "RSA-MINI negative path completed"


echo
echo "[TEST] COPY sample file"

rm -f /tmp/k1wi_copy_test.txt

OUT=$($BIN COPY testdata/text/hello.txt /tmp/k1wi_copy_test.txt 2>&1)
echo "$OUT"

require_output \
    "COPY reports success" \
    "$OUT" \
    "COPY: success"

if [ ! -f /tmp/k1wi_copy_test.txt ]; then
    fail "COPY destination file not created"
fi

grep -Fq "CTF{TEST_FLAG}" /tmp/k1wi_copy_test.txt \
    && pass "COPY content verified" \
    || fail "COPY content verification failed"


echo
echo "[TEST] CREATE secure empty file"

rm -f /tmp/k1wi_create_test.txt

OUT=$($BIN CREATE /tmp/k1wi_create_test.txt 2>&1)
echo "$OUT"

require_output \
    "CREATE reports secure file" \
    "$OUT" \
    "Created secure empty file"

if [ ! -f /tmp/k1wi_create_test.txt ]; then
    fail "CREATE did not create file"
fi

if [ -s /tmp/k1wi_create_test.txt ]; then
    fail "CREATE file is not empty"
fi

pass "CREATE created empty file"


echo
echo "[TEST] DEL secure delete sample"

cp testdata/text/hello.txt k1wi_del_test.txt

OUT=$($BIN DEL k1wi_del_test.txt -s 2 -y 2>&1)
echo "$OUT"

require_output \
    "DEL reports secure deletion" \
    "$OUT" \
    "Secure deletion complete"

if [ -f k1wi_del_test.txt ]; then
    fail "DEL did not remove file"
fi

pass "DEL removed file"

echo
echo "[TEST] WIPEFS CLI safety stub"

OUT=$($BIN WIPEFS 2>&1)
echo "$OUT"

require_output \
    "WIPEFS CLI remains safety-stubbed" \
    "$OUT" \
    "legacy CLI stub"
    
echo
echo "[TEST] READ basic file"

OUT=$($BIN READ testdata/text/hello.txt 2>&1)
echo "$OUT"

require_output \
    "READ displays file content" \
    "$OUT" \
    "CTF{TEST_FLAG}"  


echo
echo "[TEST] RSA factor sample"

set +e
OUT=$($BIN RSA-FACTOR ./testdata/rsa/rsa_61_53_e17.txt 2>&1)
RC=$?
set -e

echo "$OUT"

require_output "RSA factor finds p" "$OUT" "[+] p ="
require_output "RSA factor finds q" "$OUT" "[+] q ="
require_output "RSA recovers plaintext" "$OUT" "m = 123"

if [ "$RC" -ne 0 ] && [ "$RC" -ne 1 ]; then
    fail "RSA exited with unexpected status: $RC"
fi

pass "RSA factor command completed"

echo
echo "[TEST] RSA small-e negative sample"

set +e
OUT=$($BIN RSA-SMALL-E ./testdata/rsa/rsa_61_53_e17.txt 2>&1)
RC=$?
set -e

echo "$OUT"

require_output \
    "RSA-SMALL-E detects non-applicable attack" \
    "$OUT" \
    "attack not applicable"

if [ "$RC" -eq 0 ]; then
    fail "RSA-SMALL-E expected non-zero for non-applicable attack"
fi

pass "RSA-SMALL-E negative path completed"

echo
echo "[TEST] RSA Wiener negative sample"

set +e
OUT=$($BIN RSA-WIENER ./testdata/rsa/rsa_61_53_e17.txt 2>&1)
RC=$?
set -e

echo "$OUT"

require_output \
    "RSA-WIENER detects non-small d" \
    "$OUT" \
    "Wiener attack failed"

if [ "$RC" -eq 0 ]; then
    fail "RSA-WIENER expected non-zero for non-vulnerable sample"
fi

pass "RSA-WIENER negative path completed"

echo
echo "[TEST] RSA ECM small factor sample"

set +e
OUT=$(timeout 5s $BIN RSA-ECM testdata/rsa/rsa_ecm_small_factor.txt 2>&1)
RC=$?
set -e

echo "$OUT"

if [ "$RC" -eq 124 ]; then
    fail "RSA-ECM timed out"
fi

require_output \
    "RSA-ECM finds factor" \
    "$OUT" \
    "RSA-ECM: found factor"

require_output \
    "RSA-ECM finds cofactor" \
    "$OUT" \
    "RSA-ECM: cofactor"


echo
echo "[TEST] HELP"

OUT=$($BIN help 2>&1)

require_output "HELP shows LYZER" "$OUT" "LYZER"
require_output "HELP shows RSA" "$OUT" "RSA"
require_output "HELP shows PIECALC" "$OUT" "PIECALC"

echo
echo "[TEST] Individual HELP pages"

OUT=$($BIN help PIETIME 2>&1)
echo "$OUT"
require_output "HELP PIETIME page" "$OUT" "PIETIME - PIE Runtime Address Analyzer"

OUT=$($BIN help LYZER 2>&1)
echo "$OUT"
require_output "HELP LYZER page" "$OUT" "LYZER - Image Forensics and Steganography Analyzer"

OUT=$($BIN help EXTRACT 2>&1)
echo "$OUT"
require_output "HELP EXTRACT page" "$OUT" "EXTRACT - Recursive Extraction Engine"

OUT=$($BIN help MAGIC 2>&1)
echo "$OUT"
require_output "HELP MAGIC page" "$OUT" "MAGIC - Magic Byte Detector"

echo
echo "[TEST] VERSION banner"

OUT=$($BIN --version 2>&1)
echo "$OUT"

require_output "VERSION reports K1Wi" "$OUT" "K1Wi Framework"
require_output "VERSION reports v1.0.0" "$OUT" "v1.0.0"
require_output "VERSION reports K1Wi release" "$OUT" "Release Name: K1Wi"

echo
echo "[TEST] HELP output"

OUT=$($BIN help 2>&1)
echo "$OUT"

require_output "HELP shows LYZER" "$OUT" "LYZER"
require_output "HELP shows RSA" "$OUT" "RSA"
require_output "HELP shows PIECALC" "$OUT" "PIECALC"


require_failure_output \
    "STRING missing argument fails" \
    "$BIN string" \
    "STRING: missing argument"

require_failure_output \
    "ENTROPY missing file fails" \
    "$BIN entropy does_not_exist.bin" \
    "Failed to open"

require_failure_output \
    "ELFINFO missing file fails" \
    "$BIN elfinfo" \
    "Usage: k1wi elfinfo <file>"

require_failure_output \
    "EXTRACT missing argument fails" \
    "$BIN extract" \
    "extract requires a file path"

require_failure_output \
    "RSA-FACTOR missing argument fails" \
    "$BIN RSA-FACTOR" \
    "Usage: k1wi rsa-factor <rsa_file>"

    
        
echo
echo "============================================================"
echo "REGRESSION TESTS COMPLETE"
echo "============================================================"


echo
echo "============================================================"
echo "REGRESSION TEST SUMMARY"
echo "============================================================"
echo "PASS: $PASS_COUNT"
echo "FAIL: $FAIL_COUNT"
echo "SKIP: $SKIP_COUNT"
