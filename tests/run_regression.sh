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


require_not_output() {
    local name="$1"
    local output="$2"
    local needle="$3"

    if printf "%s" "$output" | grep -Fq -- "$needle"; then
        fail "$name"
        echo "Did not expect to find: $needle"
    else
        pass "$name"
    fi
}

skip() {
    SKIP_COUNT=$((SKIP_COUNT + 1))
    echo "[SKIP] $1"
}

require_output() {
    local label="$1"
    local output="$2"
    local needle="$3"

    if echo "$output" | grep -Fq -- "$needle"; then
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

    if echo "$OUT" | grep -Fq -- "$needle"; then
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

OUT=$($BIN STRING --decode 'cGljb0NURntwdXp6bDNkX20zdGFkYXRhX2YwdW5kIV9lZTQ1NDk1MH0\075' 2>&1)
printf "%s\n" "$OUT"
require_output "STRING decodes escaped Base64 padding" "$OUT" "Detected Type: Base64"
require_output "STRING escaped Base64 reveals decoded text" "$OUT" "picoCTF{puzzl3d_m3tadata_f0und!_ee454950}"

OUT=$($BIN STRING --decode '111111111101100011111111111000000000000000010000010010100100011001001001010001100000000000000001000000010000000000000000000000010000000000000001000000000000000011111111110110110000000001000011000000000000100000000110000001100000011100000110000001010000100' 2>&1)
printf "%s\n" "$OUT"
require_output "STRING detects malformed binary bitstream" "$OUT" "Binary-like string (not byte-aligned)"
if printf "%s\n" "$OUT" | grep -q "Shifted hex"; then
    fail "STRING malformed binary avoids shifted hex"
else
    pass "STRING malformed binary avoids shifted hex"
fi

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

    OUT=$($BIN lyzer "$LYZER_IMG" --quiet 2>&1)
    require_output "LYZER --quiet alias works" "$OUT" "K1Wi LYZER Quiet"
    require_output "LYZER --quiet reports assessment" "$OUT" "Assessment"
    require_not_output "LYZER --quiet hides heatmap" "$OUT" "Entropy Heatmap"
    require_not_output "LYZER --quiet hides carver" "$OUT" "File Carver"

    OUT=$($BIN lyzer "$LYZER_IMG" --json 2>&1)
    echo "$OUT"
    require_output "LYZER --json reports JSON tool" "$OUT" '"tool": "LYZER"'
    require_output "LYZER --json reports JSON mode" "$OUT" '"mode": "json"'
    require_output "LYZER --json reports JPEG format" "$OUT" '"format": "JPEG"'
    require_output "LYZER --json reports file size" "$OUT" '"size_bytes":'
    require_output "LYZER --json reports entropy" "$OUT" '"entropy":'
    require_output "LYZER --json reports assessment" "$OUT" '"assessment":'
    require_output "LYZER --json reports null error" "$OUT" '"error": null'
    
    OUT=$(printf "LYZER %s --summary\nEXIT\n" "$LYZER_IMG" | $BIN 2>&1)
    require_output "LYZER shell --summary alias works" "$OUT" "K1Wi LYZER Summary"
    require_output "LYZER shell --summary reports next steps" "$OUT" "Next steps"

    OUT=$(printf "LYZER %s --quiet\nEXIT\n" "$LYZER_IMG" | $BIN 2>&1)
    require_output "LYZER shell --quiet alias works" "$OUT" "K1Wi LYZER Quiet"
    require_output "LYZER shell --quiet reports assessment" "$OUT" "Assessment"
    require_not_output "LYZER shell --quiet hides heatmap" "$OUT" "Entropy Heatmap"
    require_not_output "LYZER shell --quiet hides carver" "$OUT" "File Carver"

    OUT=$(printf "LYZER %s --json\nEXIT\n" "$LYZER_IMG" | $BIN 2>&1)
    require_output "LYZER shell --json reports JSON tool" "$OUT" '"tool": "LYZER"'
    require_output "LYZER shell --json reports JSON mode" "$OUT" '"mode": "json"'
    require_output "LYZER shell --json reports JPEG format" "$OUT" '"format": "JPEG"'

    OUT=$(printf "LYZER %s --full\nEXIT\n" "$LYZER_IMG" | $BIN 2>&1)
    require_output "LYZER shell --full alias runs carver" "$OUT" "File Carver"
    require_output "LYZER shell --full alias runs strings" "$OUT" "String Intelligence"
    
    
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
    
        OUT=$($BIN ENTROPY "$LYZER_IMG" --window 2>&1)
    echo "$OUT"
    require_output "ENTROPY file-first --window reports sliding-window output" "$OUT" "Sliding-window entropy"

    OUT=$($BIN ENTROPY "$LYZER_IMG" --heatmap 2>&1)
    echo "$OUT"
    require_output "ENTROPY file-first --heatmap reports heatmap output" "$OUT" "Entropy heatmap"
    require_output "ENTROPY file-first --heatmap reports anomaly detection" "$OUT" "Entropy Anomaly Detection"

    OUT=$($BIN ENTROPY --window "$LYZER_IMG" 2>&1)
    echo "$OUT"
    require_output "ENTROPY flag-first --window reports sliding-window output" "$OUT" "Sliding-window entropy"

    OUT=$($BIN ENTROPY --heatmap "$LYZER_IMG" 2>&1)
    echo "$OUT"
    require_output "ENTROPY flag-first --heatmap reports heatmap output" "$OUT" "Entropy heatmap"
    require_output "ENTROPY flag-first --heatmap reports anomaly detection" "$OUT" "Entropy Anomaly Detection"
else
    skip "$LYZER_IMG not found"
fi
  
  
  echo "[TEST] PCAP synthetic time-order TCP Base64 reconstruction"

PCAP_FIXTURE="testdata/pcap/k1wi_time_order_tcp_base64.pcap"

if [ -f "$PCAP_FIXTURE" ]; then
    OUT=$($BIN PCAP "$PCAP_FIXTURE" 2>&1)
    require_output "PCAP synthetic reports packet count" "$OUT" "Packets: 3"
    require_output "PCAP synthetic reports TCP packet count" "$OUT" "TCP packets: 3"
    require_output "PCAP synthetic reports TCP flags summary" "$OUT" "TCP Flags Summary"
    require_output "PCAP synthetic reports SYN flag count" "$OUT" "SYN packets: 0"
    require_output "PCAP synthetic reports ACK flag count" "$OUT" "ACK packets: 3"
    require_output "PCAP synthetic reports FIN flag count" "$OUT" "FIN packets: 0"
    require_output "PCAP synthetic reports RST flag count" "$OUT" "RST packets: 0"
    require_output "PCAP synthetic reports PSH flag count" "$OUT" "PSH packets: 3"
    require_output "PCAP synthetic reports URG flag count" "$OUT" "URG packets: 0"
    require_output "PCAP synthetic reports Base64 payload count" "$OUT" "Base64-like TCP payload packets: 3"
    require_output "PCAP synthetic reports sequence reconstruction" "$OUT" "Decoded TCP Payload Reconstruction by Sequence"
    require_output "PCAP synthetic sequence order differs from time order" "$OUT" "{time_order}K1Wi"
    require_output "PCAP synthetic reports time reconstruction" "$OUT" "Decoded TCP Payload Reconstruction by Time"
    require_output "PCAP synthetic reconstructs time-order payload" "$OUT" "K1Wi{time_order}"

    OUT=$($BIN PCAP --full "$PCAP_FIXTURE" 2>&1)
    require_output "PCAP synthetic full mode reports TCP detail line" "$OUT" "TCP 10.1.1.10:4444 -> 10.1.1.20:80"
    require_output "PCAP synthetic full mode reports TCP sequence" "$OUT" "seq=3000"
    require_output "PCAP synthetic full mode reports TCP flags" "$OUT" "flags=PSH,ACK"
    require_output "PCAP synthetic full mode reports payload size" "$OUT" "payload=8"
    require_output "PCAP synthetic full mode reports payload preview" "$OUT" "Payload ASCII preview"
    require_output "PCAP synthetic full mode reports decoded preview" "$OUT" "Base64 decoded preview"
    require_output "PCAP synthetic full mode reconstructs time-order payload" "$OUT" "K1Wi{time_order}"
else
    fail "PCAP synthetic fixture missing"
fi
  
echo
echo "[TEST] PCAP synthetic Ethernet IPv4 parsing"

PCAP_ETH_FIXTURE="testdata/pcap/k1wi_ethernet_time_order_tcp_base64.pcap"

if [ -f "$PCAP_ETH_FIXTURE" ]; then
    OUT=$($BIN PCAP "$PCAP_ETH_FIXTURE" 2>&1)

    require_output "PCAP Ethernet reports Ethernet link type" \
        "$OUT" "Link type: 1 (Ethernet)"

    require_output "PCAP Ethernet reports packet count" \
        "$OUT" "Packets: 3"

    require_output "PCAP Ethernet reports IPv4 packet count" \
        "$OUT" "IPv4 packets: 3"

    require_output "PCAP Ethernet reports TCP packet count" \
        "$OUT" "TCP packets: 3"

    require_output "PCAP Ethernet reports ACK flag count" \
        "$OUT" "ACK packets: 3"

    require_output "PCAP Ethernet reports PSH flag count" \
        "$OUT" "PSH packets: 3"

    require_output "PCAP Ethernet reconstructs time-order payload" \
        "$OUT" "K1Wi{time_order}"

    require_output "PCAP Ethernet reports source MAC table" \
        "$OUT" "Top Ethernet Source MACs"

    require_output "PCAP Ethernet reports source MAC count" \
        "$OUT" "66:77:88:99:aa:bb  3"

    require_output "PCAP Ethernet reports destination MAC table" \
        "$OUT" "Top Ethernet Destination MACs"

    require_output "PCAP Ethernet reports destination MAC count" \
        "$OUT" "00:11:22:33:44:55  3"

    OUT=$($BIN PCAP --full "$PCAP_ETH_FIXTURE" 2>&1)

    require_output "PCAP Ethernet full mode reports MAC addresses" \
        "$OUT" "Ethernet 66:77:88:99:aa:bb -> 00:11:22:33:44:55"

    require_output "PCAP Ethernet full mode reports IPv4 EtherType" \
        "$OUT" "EtherType=0x0800 (IPv4)"

    require_output "PCAP Ethernet full mode reports TCP endpoints" \
        "$OUT" "TCP 10.1.1.10:4444 -> 10.1.1.20:80"

    require_output "PCAP Ethernet full mode reports TCP flags" \
        "$OUT" "flags=PSH,ACK"

    require_output "PCAP Ethernet full mode reports payload size" \
        "$OUT" "payload=12"
else
    fail "PCAP Ethernet synthetic fixture missing"
fi
  
echo
echo
echo "[TEST] PCAP Ethernet UDP details"

PCAP_UDP_FIXTURE="testdata/pcap/k1wi_ethernet_udp.pcap"

if [ -f "$PCAP_UDP_FIXTURE" ]; then
    OUT=$($BIN PCAP "$PCAP_UDP_FIXTURE" 2>&1)

    require_output "PCAP UDP reports packet count" \
        "$OUT" "Packets: 1"

    require_output "PCAP UDP reports UDP packet count" \
        "$OUT" "UDP packets: 1"

    require_output "PCAP UDP reports source port" \
        "$OUT" "5353"

    require_output "PCAP UDP reports destination port" \
        "$OUT" "53"

    OUT=$($BIN PCAP --full "$PCAP_UDP_FIXTURE" 2>&1)

    require_output "PCAP UDP full mode reports endpoints" \
        "$OUT" "UDP 10.1.1.10:5353 -> 10.1.1.20:53"

    require_output "PCAP UDP full mode reports length" \
        "$OUT" "length=17"

    require_output "PCAP UDP full mode reports payload size" \
        "$OUT" "payload=9"
else
    fail "PCAP UDP fixture missing"
fi

echo
echo "[TEST] PCAP Ethernet ICMP details"

PCAP_ICMP_FIXTURE="testdata/pcap/k1wi_ethernet_icmp_echo.pcap"

if [ -f "$PCAP_ICMP_FIXTURE" ]; then
    OUT=$($BIN PCAP "$PCAP_ICMP_FIXTURE" 2>&1)

    require_output "PCAP ICMP reports packet count" \
        "$OUT" "Packets: 1"

    require_output "PCAP ICMP reports IPv4 packet count" \
        "$OUT" "IPv4 packets: 1"

    require_output "PCAP ICMP reports ICMP packet count" \
        "$OUT" "ICMP packets: 1"

    OUT=$($BIN PCAP --full "$PCAP_ICMP_FIXTURE" 2>&1)

    require_output "PCAP ICMP full mode reports endpoints" \
        "$OUT" "ICMP 10.1.1.10 -> 10.1.1.20"

    require_output "PCAP ICMP full mode reports type and code" \
        "$OUT" "type=8 code=0"

    require_output "PCAP ICMP full mode reports friendly type name" \
        "$OUT" "(Echo Request)"
else
    fail "PCAP ICMP fixture missing"
fi

echo
echo "[TEST] PCAP Ethernet ARP details"

PCAP_ARP_FIXTURE="testdata/pcap/k1wi_ethernet_arp_request_reply.pcap"

if [ -f "$PCAP_ARP_FIXTURE" ]; then
    OUT=$($BIN PCAP "$PCAP_ARP_FIXTURE" 2>&1)

    require_output "PCAP ARP reports packet count" \
        "$OUT" "Packets: 2"

    require_output "PCAP ARP reports ARP frame count" \
        "$OUT" "ARP frames: 2"

    OUT=$($BIN PCAP --full "$PCAP_ARP_FIXTURE" 2>&1)

    require_output "PCAP ARP full mode reports request sender" \
        "$OUT" "ARP request: 192.168.1.10 (66:77:88:99:aa:bb)"

    require_output "PCAP ARP full mode reports requested target" \
        "$OUT" "asks for 192.168.1.1"

    require_output "PCAP ARP full mode reports reply sender" \
        "$OUT" "ARP reply: 192.168.1.1 is at 00:11:22:33:44:55"

    require_output "PCAP ARP full mode reports reply target" \
        "$OUT" "(target 192.168.1.10, 66:77:88:99:aa:bb)"
else
    fail "PCAP ARP fixture missing"
fi

echo
echo "[TEST] PCAP Ethernet IPv6 details"

PCAP_IPV6_FIXTURE="testdata/pcap/k1wi_ethernet_ipv6_udp.pcap"

if [ -f "$PCAP_IPV6_FIXTURE" ]; then
    OUT=$($BIN PCAP "$PCAP_IPV6_FIXTURE" 2>&1)

    require_output "PCAP IPv6 reports packet count" \
        "$OUT" "Packets: 1"

    require_output "PCAP IPv6 reports IPv6 frame count" \
        "$OUT" "IPv6 frames: 1"

    OUT=$($BIN PCAP --full "$PCAP_IPV6_FIXTURE" 2>&1)

    require_output "PCAP IPv6 full mode reports endpoints" \
        "$OUT" "IPv6 2001:db8::10 -> 2001:db8::20"

    require_output "PCAP IPv6 full mode reports next header" \
        "$OUT" "next-header=17 (UDP)"

    require_output "PCAP IPv6 full mode reports payload length" \
        "$OUT" "payload=18"
else
    fail "PCAP IPv6 fixture missing"
fi

echo "[TEST] PCAP mixed Ethernet EtherType summary"

PCAP_MIXED_ETH_FIXTURE="testdata/pcap/k1wi_ethernet_mixed_ethertypes.pcap"

if [ -f "$PCAP_MIXED_ETH_FIXTURE" ]; then
    OUT=$($BIN PCAP "$PCAP_MIXED_ETH_FIXTURE" 2>&1)

    require_output "PCAP mixed Ethernet reports packet count" \
        "$OUT" "Packets: 6"

    require_output "PCAP mixed Ethernet reports summary heading" \
        "$OUT" "Ethernet Protocol Summary"

    require_output "PCAP mixed Ethernet reports IPv4 frame count" \
        "$OUT" "IPv4 frames: 3"

    require_output "PCAP mixed Ethernet reports ARP frame count" \
        "$OUT" "ARP frames: 1"

    require_output "PCAP mixed Ethernet reports IPv6 frame count" \
        "$OUT" "IPv6 frames: 1"

    require_output "PCAP mixed Ethernet reports other EtherType count" \
        "$OUT" "Other EtherTypes: 1"
else
    fail "PCAP mixed Ethernet fixture missing"
fi
  
echo
echo "[TEST] PCAP VLAN-tagged Ethernet IPv4 parsing"

PCAP_VLAN_FIXTURE="testdata/pcap/k1wi_vlan_time_order_tcp_base64.pcap"

if [ -f "$PCAP_VLAN_FIXTURE" ]; then
    OUT=$($BIN PCAP "$PCAP_VLAN_FIXTURE" 2>&1)

    require_output "PCAP VLAN reports Ethernet link type" \
        "$OUT" "Link type: 1 (Ethernet)"

    require_output "PCAP VLAN reports packet count" \
        "$OUT" "Packets: 3"

    require_output "PCAP VLAN reports IPv4 frame count" \
        "$OUT" "IPv4 frames: 3"

    require_output "PCAP VLAN reports IPv4 packet count" \
        "$OUT" "IPv4 packets: 3"

    require_output "PCAP VLAN reports TCP packet count" \
        "$OUT" "TCP packets: 3"

    require_output "PCAP VLAN reports TCP flags" \
        "$OUT" "PSH packets: 3"

    require_output "PCAP VLAN reconstructs time-order payload" \
        "$OUT" "K1Wi{time_order}"

        require_output "PCAP VLAN reports VLAN summary heading" \
        "$OUT" "VLAN Summary"

    require_output "PCAP VLAN reports tagged frame count" \
        "$OUT" "Tagged frames: 3"

    require_output "PCAP VLAN reports single-tagged frame count" \
        "$OUT" "Single-tagged frames: 3"

    require_output "PCAP VLAN reports stacked-tagged frame count" \
        "$OUT" "Stacked-tagged frames: 0"

    require_output "PCAP VLAN reports 802.1Q tag count" \
        "$OUT" "802.1Q tags: 3"

    require_output "PCAP VLAN reports 802.1ad tag count" \
        "$OUT" "802.1ad tags: 0"

    require_output "PCAP VLAN reports VLAN ID 100" \
        "$OUT" "VLAN 100: 3 tag(s)"

    OUT=$($BIN PCAP --full "$PCAP_VLAN_FIXTURE" 2>&1)

    require_output "PCAP VLAN full mode reports VLAN details" \
        "$OUT" "VLAN tags: 802.1Q VLAN 100"

    require_output "PCAP VLAN full mode reports outer EtherType" \
        "$OUT" "EtherType=0x8100 (802.1Q VLAN)"

    require_output "PCAP VLAN full mode reports encapsulated EtherType" \
        "$OUT" "VLAN encapsulated EtherType: 0x0800 (IPv4)"

    require_output "PCAP VLAN full mode reports TCP endpoints" \
        "$OUT" "TCP 10.1.1.10:4444 -> 10.1.1.20:80"

    require_output "PCAP VLAN full mode reports TCP flags" \
        "$OUT" "flags=PSH,ACK"

    require_output "PCAP VLAN full mode reports payload size" \
        "$OUT" "payload=12"
else
    fail "PCAP VLAN fixture missing"
fi

echo
echo "[TEST] PCAP QinQ stacked-VLAN IPv4 parsing"

PCAP_QINQ_FIXTURE="testdata/pcap/k1wi_qinq_time_order_tcp_base64.pcap"

if [ -f "$PCAP_QINQ_FIXTURE" ]; then
    OUT=$($BIN PCAP "$PCAP_QINQ_FIXTURE" 2>&1)

    require_output "PCAP QinQ reports Ethernet link type" \
        "$OUT" "Link type: 1 (Ethernet)"

    require_output "PCAP QinQ reports packet count" \
        "$OUT" "Packets: 3"

    require_output "PCAP QinQ reports IPv4 frame count" \
        "$OUT" "IPv4 frames: 3"

    require_output "PCAP QinQ reports IPv4 packet count" \
        "$OUT" "IPv4 packets: 3"

    require_output "PCAP QinQ reports TCP packet count" \
        "$OUT" "TCP packets: 3"

    require_output "PCAP QinQ reports PSH count" \
        "$OUT" "PSH packets: 3"

    require_output "PCAP QinQ reconstructs time-order payload" \
        "$OUT" "K1Wi{time_order}"
        
        require_output "PCAP QinQ reports VLAN summary heading" \
        "$OUT" "VLAN Summary"

    require_output "PCAP QinQ reports tagged frame count" \
        "$OUT" "Tagged frames: 3"

    require_output "PCAP QinQ reports single-tagged frame count" \
        "$OUT" "Single-tagged frames: 0"

    require_output "PCAP QinQ reports stacked-tagged frame count" \
        "$OUT" "Stacked-tagged frames: 3"

    require_output "PCAP QinQ reports 802.1Q tag count" \
        "$OUT" "802.1Q tags: 3"

    require_output "PCAP QinQ reports 802.1ad tag count" \
        "$OUT" "802.1ad tags: 3"

    require_output "PCAP QinQ reports outer VLAN ID 10" \
        "$OUT" "VLAN 10: 3 tag(s)"

    require_output "PCAP QinQ reports inner VLAN ID 100" \
        "$OUT" "VLAN 100: 3 tag(s)"    

    OUT=$($BIN PCAP --full "$PCAP_QINQ_FIXTURE" 2>&1)

    require_output "PCAP QinQ full mode reports stacked VLAN details" \
        "$OUT" "VLAN tags: 802.1ad VLAN 10 PCP 0 DEI 0, 802.1Q VLAN 100 PCP 0 DEI 0"

    require_output "PCAP QinQ full mode reports outer EtherType" \
        "$OUT" "EtherType=0x88a8 (802.1ad QinQ)"

    require_output "PCAP QinQ full mode reports encapsulated EtherType" \
        "$OUT" "VLAN encapsulated EtherType: 0x0800 (IPv4)"

    require_output "PCAP QinQ full mode reports TCP endpoints" \
        "$OUT" "TCP 10.1.1.10:4444 -> 10.1.1.20:80"

    require_output "PCAP QinQ full mode reports TCP flags" \
        "$OUT" "flags=PSH,ACK"

    require_output "PCAP QinQ full mode reports payload size" \
        "$OUT" "payload=12"
else
    fail "PCAP QinQ fixture missing"
fi
    
echo
echo
echo "[TEST] PCAP truncated VLAN handling"

PCAP_TRUNCATED_VLAN_FIXTURE="testdata/pcap/k1wi_truncated_vlan.pcap"

if [ -f "$PCAP_TRUNCATED_VLAN_FIXTURE" ]; then
    OUT=$($BIN PCAP "$PCAP_TRUNCATED_VLAN_FIXTURE" 2>&1)

    require_output "PCAP truncated VLAN reports packet count" \
        "$OUT" "Packets: 1"

    require_output "PCAP truncated VLAN reports zero tagged frames" \
        "$OUT" "Tagged frames: 0"

    require_output "PCAP truncated VLAN reports malformed frame count" \
        "$OUT" "Malformed VLAN frames: 1"

    OUT=$($BIN PCAP --full "$PCAP_TRUNCATED_VLAN_FIXTURE" 2>&1)

    require_output "PCAP truncated VLAN full mode reports warning" \
        "$OUT" "Warning: truncated 802.1Q VLAN tag"
else
    fail "PCAP truncated VLAN fixture missing"
fi
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

echo "[TEST] MAGIC ASCII binary digit stream"
OUT=$($BIN MAGIC ./testdata/forensics/binary_digits_jpeg.bin 2>&1)
printf "%s\n" "$OUT"
require_output "MAGIC detects ASCII binary digit stream" "$OUT" "Detected raw format: ASCII binary digit stream"
require_output "MAGIC bitstream decoded magic is JPEG" "$OUT" "Decoded magic: JPEG"

echo "[TEST] MAGIC ASCII binary digit stream recovery"
RECOVERED="/tmp/k1wi_binary_digits_recovered.jpg"
rm -f "$RECOVERED"

OUT=$($BIN MAGIC ./testdata/forensics/binary_digits_jpeg.bin --recover "$RECOVERED" 2>&1)
printf "%s\n" "$OUT"
require_output "MAGIC recover reports output path" "$OUT" "Recovered decoded bitstream to:"
require_output "MAGIC recover reports byte count" "$OUT" "Recovered bytes: 8877"

OUT=$($BIN MAGIC "$RECOVERED" 2>&1)
printf "%s\n" "$OUT"
require_output "MAGIC recovered file is JPEG" "$OUT" "Detected format: JPEG"

rm -f "$RECOVERED"

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
echo "[TEST] RSA private key decrypt helper"
RSA_KEY_FIXTURE="/tmp/k1wi_rsa_key_test.pem"
RSA_KEY_PLAIN="/tmp/k1wi_rsa_key_plain.txt"
RSA_KEY_CIPHER="/tmp/k1wi_rsa_key_cipher.bin"

rm -f "$RSA_KEY_FIXTURE" "$RSA_KEY_PLAIN" "$RSA_KEY_CIPHER"
printf 'CTF{RSA_KEY_TEST}\n' > "$RSA_KEY_PLAIN"

if openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$RSA_KEY_FIXTURE" >/dev/null 2>&1 &&
   openssl pkeyutl -encrypt -inkey "$RSA_KEY_FIXTURE" -in "$RSA_KEY_PLAIN" -out "$RSA_KEY_CIPHER" >/dev/null 2>&1; then
    OUT=$($BIN RSA-KEY "$RSA_KEY_FIXTURE" "$RSA_KEY_CIPHER" 2>&1)
    printf "%s\n" "$OUT"
    require_output "RSA-KEY decrypts generated ciphertext" "$OUT" "RSA-KEY: decrypt success"
    require_output "RSA-KEY prints recovered plaintext" "$OUT" "CTF{RSA_KEY_TEST}"
else
    skip "RSA-KEY generated OpenSSL fixture unavailable"
fi

rm -f "$RSA_KEY_FIXTURE" "$RSA_KEY_PLAIN" "$RSA_KEY_CIPHER"

echo "[TEST] CONVERT / NUMCONV helper"
OUT=$("$BIN" CONVERT --hex-to-int ff 2>&1)
echo "$OUT"
require_output "CONVERT hex-to-int" "$OUT" "Integer: 255"

OUT=$("$BIN" CONVERT --int-to-hex 255 2>&1)
echo "$OUT"
require_output "CONVERT int-to-hex" "$OUT" "Hex: ff"

printf 'ABC' > /tmp/k1wi_convert_abc.bin
OUT=$("$BIN" CONVERT --bytes-to-long /tmp/k1wi_convert_abc.bin 2>&1)
echo "$OUT"
require_output "CONVERT bytes-to-long" "$OUT" "Integer: 4276803"

OUT=$("$BIN" CONVERT --long-to-bytes 4276803 2>&1)
echo "$OUT"
require_output "CONVERT long-to-bytes hex" "$OUT" "Hex: 414243"
require_output "CONVERT long-to-bytes ascii" "$OUT" "ASCII: ABC"

OUT=$("$BIN" CONVERT --ascii-to-hex K1Wi 2>&1)
echo "$OUT"
require_output "CONVERT ascii-to-hex" "$OUT" "Hex: 4b315769"

OUT=$("$BIN" CONVERT --hex-to-ascii 4b315769 2>&1)
echo "$OUT"
require_output "CONVERT hex-to-ascii" "$OUT" "ASCII: K1Wi"

OUT=$("$BIN" CONVERT --base64-to-hex SzFXaQ== 2>&1)
echo "$OUT"
require_output "CONVERT base64-to-hex" "$OUT" "Hex: 4b315769"

OUT=$("$BIN" CONVERT --hex-to-base64 4b315769 2>&1)
echo "$OUT"
require_output "CONVERT hex-to-base64" "$OUT" "Base64: SzFXaQ=="

printf 'crypto{Immut4ble_m3ssag1ng}' > /tmp/k1wi_convert_msg.txt
OUT=$("$BIN" CONVERT --sha256-to-int /tmp/k1wi_convert_msg.txt 2>&1)
echo "$OUT"
require_output "CONVERT sha256-to-int digest" "$OUT" "SHA256: 99b4c7bb814cc630c4199e4814ffed85a835f64ffc82aadaa6388d9df9aeb2cb"
require_output "CONVERT sha256-to-int integer" "$OUT" "Integer: 69523276807549773371481917516452638375664281433555793080445569568100703974091"

OUT=$("$BIN" CONVERT --sha256-text-to-int 'crypto{Immut4ble_m3ssag1ng}' 2>&1)
echo "$OUT"
require_output "CONVERT sha256-text-to-int digest" "$OUT" "SHA256: 99b4c7bb814cc630c4199e4814ffed85a835f64ffc82aadaa6388d9df9aeb2cb"
require_output "CONVERT sha256-text-to-int integer" "$OUT" "Integer: 69523276807549773371481917516452638375664281433555793080445569568100703974091"

OUT=$("$BIN" NUMCONV --hex-to-int ff 2>&1)
echo "$OUT"
require_output "NUMCONV alias works" "$OUT" "Integer: 255"

OUT=$("$BIN" CONVERT --hex-to-ascii 41 42 43 2>&1)
echo "$OUT"
require_output "CONVERT unquoted spaced hex to ASCII" "$OUT" "ASCII: ABC"

OUT=$("$BIN" CONVERT --hex-to-ascii "41:42:43" 2>&1)
echo "$OUT"
require_output "CONVERT colon-separated hex to ASCII" "$OUT" "ASCII: ABC"

OUT=$("$BIN" CONVERT --hex-to-ascii "41-42-43" 2>&1)
echo "$OUT"
require_output "CONVERT dash-separated hex to ASCII" "$OUT" "ASCII: ABC"

OUT=$("$BIN" CONVERT --hex-to-ascii "41_42_43" 2>&1)
echo "$OUT"
require_output "CONVERT underscore-separated hex to ASCII" "$OUT" "ASCII: ABC"

OUT=$("$BIN" CONVERT --hex-to-int 41 41 41 2>&1)
echo "$OUT"
require_output "CONVERT unquoted spaced hex to int" "$OUT" "Integer: 4276545"

OUT=$("$BIN" CONVERT --ascii-to-hex A B C 2>&1)
echo "$OUT"
require_output "CONVERT unquoted spaced ASCII to hex" "$OUT" "Hex: 4120422043"

OUT=$(printf 'CONVERT --hex-to-int ff\nNUMCONV --int-to-hex 255\nEXIT\n' | "$BIN" 2>&1)
require_output "CONVERT shell works" "$OUT" "Integer: 255"
require_output "NUMCONV shell works" "$OUT" "Hex: ff"

OUT=$("$BIN" HELP CONVERT 2>&1)
echo "$OUT"
require_output "HELP CONVERT page" "$OUT" "CONVERT - Numeric / Encoding Conversion Helper"
require_output "HELP CONVERT sha256 mode" "$OUT" "CONVERT --sha256-text-to-int <text>"

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
echo "[TEST] COPY forensic verified file copy"

rm -f /tmp/k1wi_copy_test.txt

OUT=$($BIN COPY testdata/text/hello.txt /tmp/k1wi_copy_test.txt 2>&1)
echo "$OUT"

require_output \
    "COPY reports success" \
    "$OUT" \
    "COPY: success"

require_output \
    "COPY verification report present" \
    "$OUT" \
    "COPY Verification Report"

require_output \
    "COPY SHA-256 source reported" \
    "$OUT" \
    "Source SHA256"

require_output \
    "COPY SHA-256 destination reported" \
    "$OUT" \
    "Dest SHA256"

require_output \
    "COPY MD5 source reported" \
    "$OUT" \
    "Source MD5"

require_output \
    "COPY MD5 destination reported" \
    "$OUT" \
    "Dest MD5"

require_output \
    "COPY verification passes" \
    "$OUT" \
    "Verification : PASS"

if [ ! -f /tmp/k1wi_copy_test.txt ]; then
    fail "COPY destination file not created"
fi

grep -Fq "CTF{TEST_FLAG}" /tmp/k1wi_copy_test.txt \
    && pass "COPY content verified" \
    || fail "COPY content verification failed"

OUT=$($BIN COPY testdata/text/hello.txt /tmp/k1wi_copy_test.txt 2>&1 || true)
echo "$OUT"

require_output \
    "COPY refuses overwrite by default" \
    "$OUT" \
    "refusing overwrite"

OUT=$($BIN COPY testdata/text/hello.txt /tmp/k1wi_copy_test.txt --force 2>&1)
echo "$OUT"

require_output \
    "COPY force overwrite succeeds" \
    "$OUT" \
    "COPY: success"

require_output \
    "COPY force verification passes" \
    "$OUT" \
    "Verification : PASS"

require_output \
    "COPY force MD5 match reported" \
    "$OUT" \
    "MD5 match    : yes"

OUT=$($BIN HELP COPY 2>&1)
echo "$OUT"

require_output \
    "COPY help documents force option" \
    "$OUT" \
    "--force"

require_output \
    "COPY help documents recursive option" \
    "$OUT" \
    "--recursive"

rm -rf /tmp/k1wi_copy_tree_test

OUT=$($BIN COPY testdata /tmp/k1wi_copy_tree_test 2>&1 || true)
echo "$OUT"

require_output \
    "COPY directory requires recursive option" \
    "$OUT" \
    "recursive copy requires --recursive"

OUT=$($BIN COPY testdata /tmp/k1wi_copy_tree_test --recursive 2>&1)
echo "$OUT"

require_output \
    "COPY recursive report present" \
    "$OUT" \
    "COPY Recursive Verification Report"

require_output \
    "COPY recursive result passes" \
    "$OUT" \
    "Result          : PASS"

require_output \
    "COPY recursive SHA-256 manifest reported" \
    "$OUT" \
    "Manifest SHA256"

require_output \
    "COPY recursive MD5 manifest reported" \
    "$OUT" \
    "Manifest MD5"

require_output \
    "COPY recursive hash algorithm reported" \
    "$OUT" \
    "Hash algorithm  : SHA-256, MD5"

if [ ! -f /tmp/k1wi_copy_tree_test/K1Wi_COPY_MANIFEST.txt ]; then
    fail "COPY recursive manifest not created"
fi

pass "COPY recursive manifest created"

PASS_RECORDS=$(grep -c '^PASS |' /tmp/k1wi_copy_tree_test/K1Wi_COPY_MANIFEST.txt)
EXPECTED_PASS_RECORDS=$(find testdata -type f | wc -l)

if [ "$PASS_RECORDS" != "$EXPECTED_PASS_RECORDS" ]; then
    fail "COPY recursive manifest expected $EXPECTED_PASS_RECORDS PASS records, got $PASS_RECORDS"
fi

pass "COPY recursive manifest contains expected PASS records"


pass "COPY recursive manifest contains expected PASS records"

OUT=$($BIN COPY testdata /tmp/k1wi_copy_tree_test --recursive 2>&1 || true)
echo "$OUT"

require_output \
    "COPY recursive refuses existing destination" \
    "$OUT" \
    "destination directory already exists"

OUT=$($BIN COPY testdata /tmp/k1wi_copy_tree_test --recursive --force 2>&1)
echo "$OUT"

require_output \
    "COPY recursive force succeeds" \
    "$OUT" \
    "COPY: success"

require_output \
    "COPY recursive force result passes" \
    "$OUT" \
    "Result          : PASS"

rm -rf /tmp/k1wi_copy_tree_test



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

CREATE_MODE=$(stat -c "%a" /tmp/k1wi_create_test.txt)
if [ "$CREATE_MODE" != "600" ]; then
    fail "CREATE permissions expected 600, got $CREATE_MODE"
fi

pass "CREATE uses 0600 permissions"

rm -f /tmp/k1wi_create_existing.txt
echo "do not overwrite me" > /tmp/k1wi_create_existing.txt

set +e
OUT=$($BIN CREATE /tmp/k1wi_create_existing.txt 2>&1)
RC=$?
set -e
echo "$OUT"

if [ "$RC" -eq 0 ]; then
    fail "CREATE overwrote existing file"
fi

if ! grep -q "do not overwrite me" /tmp/k1wi_create_existing.txt; then
    fail "CREATE changed existing file contents"
fi

pass "CREATE rejects existing file"
pass "CREATE preserves existing file contents"

rm -f /tmp/k1wi_create_test.txt /tmp/k1wi_create_existing.txt


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
echo "[TEST] DEL rejects unsafe targets"

rm -rf k1wi_del_dir_test k1wi_del_real_target.txt k1wi_del_symlink.txt
mkdir -p k1wi_del_dir_test
echo "real target must survive" > k1wi_del_real_target.txt
ln -s k1wi_del_real_target.txt k1wi_del_symlink.txt

set +e
OUT=$($BIN DEL k1wi_del_dir_test -s 2 -y 2>&1)
set -e
echo "$OUT"

require_output \
    "DEL reports failure for directory target" \
    "$OUT" \
    "Secure delete failed"

if [ ! -d k1wi_del_dir_test ]; then
    fail "DEL removed directory target"
fi

pass "DEL rejects directory target"

set +e
OUT=$($BIN DEL k1wi_del_symlink.txt -s 2 -y 2>&1)
set -e
echo "$OUT"

require_output \
    "DEL reports failure for symlink target" \
    "$OUT" \
    "Secure delete failed"

if [ ! -f k1wi_del_real_target.txt ]; then
    fail "DEL removed symlink target"
fi

if ! grep -q "real target must survive" k1wi_del_real_target.txt; then
    fail "DEL modified symlink target"
fi

if [ ! -L k1wi_del_symlink.txt ]; then
    fail "DEL removed symlink itself"
fi

pass "DEL rejects symlink target and preserves real file"

rm -rf k1wi_del_dir_test k1wi_del_real_target.txt k1wi_del_symlink.txt

echo



echo
echo "[TEST] DEL custom pass count"

printf "custom pass regression\n" > k1wi_del_custom_pass.txt
del_custom_output="$(./bin/k1wi DEL k1wi_del_custom_pass.txt -p 7 -y 2>&1 || true)"
require_output "DEL custom pass reports completion" "$del_custom_output" "using 7 custom passes"
if [[ ! -e k1wi_del_custom_pass.txt ]]; then
    pass "DEL custom pass removed file"
else
    fail "DEL custom pass removed file"
    rm -f k1wi_del_custom_pass.txt
fi

printf "bad pass regression\n" > k1wi_del_bad_pass_zero.txt
del_bad_zero_output="$(./bin/k1wi DEL k1wi_del_bad_pass_zero.txt -p 0 -y 2>&1 || true)"
require_output "DEL rejects zero custom pass count" "$del_bad_zero_output" "between 1 and 33"
if [[ -e k1wi_del_bad_pass_zero.txt ]]; then
    pass "DEL zero pass preserves file"
else
    fail "DEL zero pass preserves file"
fi
rm -f k1wi_del_bad_pass_zero.txt

printf "bad pass regression\n" > k1wi_del_bad_pass_high.txt
del_bad_high_output="$(./bin/k1wi DEL k1wi_del_bad_pass_high.txt --passes 34 -y 2>&1 || true)"
require_output "DEL rejects high custom pass count" "$del_bad_high_output" "between 1 and 33"
if [[ -e k1wi_del_bad_pass_high.txt ]]; then
    pass "DEL high pass preserves file"
else
    fail "DEL high pass preserves file"
fi
rm -f k1wi_del_bad_pass_high.txt

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

OUT=$($BIN RSA-FACTOR ./testdata/rsa/rsa_61_53_e17.txt TIME 1 2>&1)
printf "%s\n" "$OUT"
require_output "RSA factor accepts TIME minutes option" "$OUT" "[*] RSA-Factor: time limit set to 1 minute(s)"
require_output "RSA factor TIME option still recovers plaintext" "$OUT" "Decoded ASCII:"
require_output "RSA factor TIME option recovers brace" "$OUT" "{"

OUT=$($BIN RSA-FACTOR ./testdata/rsa/rsa_61_53_e17.txt --time 1 2>&1)
printf "%s\n" "$OUT"
require_output "RSA factor accepts --time option" "$OUT" "[*] RSA-Factor: time limit set to 1 minute(s)"

OUT=$($BIN RSA-FACTOR ./testdata/rsa/rsa_61_53_e17.txt --minutes 1 2>&1)
printf "%s\n" "$OUT"
require_output "RSA factor accepts --minutes option" "$OUT" "[*] RSA-Factor: time limit set to 1 minute(s)"

OUT=$($BIN RSA-FACTOR ./testdata/rsa/rsa_61_53_e17.txt -t 1 2>&1)
printf "%s\n" "$OUT"
require_output "RSA factor accepts -t option" "$OUT" "[*] RSA-Factor: time limit set to 1 minute(s)"

OUT=$($BIN RSA-FACTOR ./testdata/rsa/rsa_61_53_e17.txt TIME 0 2>&1 || true)
printf "%s\n" "$OUT"
require_output "RSA factor rejects zero TIME option" "$OUT" "rsa-factor: time limit must be a positive number of minutes"

OUT=$($BIN RSA-FACTOR ./testdata/rsa/rsa_61_53_e17.txt banana 1 2>&1 || true)
printf "%s\n" "$OUT"
require_output "RSA factor rejects unknown time option" "$OUT" "rsa-factor: unknown option 'banana'"

echo "[TEST] RSA-ROOTS exact root sample"

OUT=$($BIN RSA-ROOTS ./testdata/rsa/rsa_root_e3_exact.txt 2>&1)
printf "%s\n" "$OUT"
require_output "RSA-ROOTS recovers exact root" "$OUT" "[+] RSA-ROOTS: recovered plaintext via exact integer 3-th root"
require_output "RSA-ROOTS reports plaintext hex" "$OUT" "Plaintext (hex): 2a"
require_output "RSA-ROOTS reports plaintext ASCII" "$OUT" "Plaintext (ASCII): *"

OUT=$($BIN RSA-ROOTS ./testdata/rsa/rsa_root_e3_exact_spaced.txt 2>&1)
printf "%s\n" "$OUT"
require_output "RSA parser accepts spaced lowercase labels" "$OUT" "[+] RSA-ROOTS: recovered plaintext via exact integer 3-th root"

OUT=$($BIN RSA-ROOTS ./testdata/rsa/rsa_root_e3_colon_mixed_order.txt 2>&1)
printf "%s\n" "$OUT"
require_output "RSA parser accepts colon mixed-order labels" "$OUT" "[+] RSA-ROOTS: recovered plaintext via exact integer 3-th root"

OUT=$($BIN RSA-ROOTS ./testdata/rsa/rsa_root_e3_oneline.txt 2>&1)
printf "%s\n" "$OUT"
require_output "RSA parser accepts one-line fields" "$OUT" "[+] RSA-ROOTS: recovered plaintext via exact integer 3-th root"

OUT=$($BIN RSA-ROOTS ./testdata/rsa/rsa_root_e3_mixed_delimiters.txt 2>&1)
printf "%s\n" "$OUT"
require_output "RSA parser accepts mixed delimiters and case" "$OUT" "[+] RSA-ROOTS: recovered plaintext via exact integer 3-th root"

OUT=$($BIN RSA-ROOTS ./testdata/rsa/rsa_root_e3_oneline_shuffled.txt 2>&1)
printf "%s\n" "$OUT"
require_output "RSA parser accepts shuffled one-line fields" "$OUT" "[+] RSA-ROOTS: recovered plaintext via exact integer 3-th root"

OUT=$($BIN RSA-ROOTS ./testdata/rsa/rsa_root_even_e16.txt 2>&1)
printf "%s\n" "$OUT"
require_output "RSA-ROOTS warns on even exponent" "$OUT" "[!] RSA-ROOTS: even public exponent detected"
require_output "RSA-ROOTS recovers even exponent exact root" "$OUT" "[+] RSA-ROOTS: recovered plaintext via exact integer 16-th root"

OUT=$($BIN HELP RSA-ROOTS 2>&1)
printf "%s\n" "$OUT"
require_output "HELP RSA-ROOTS page" "$OUT" "RSA-ROOTS - RSA Exact Root / Even-Exponent Helper"

OUT=$($BIN HELP RSA-KEY 2>&1)
printf "%s\n" "$OUT"
require_output "HELP RSA-KEY page" "$OUT" "RSA-KEY - RSA Private Key Decrypt Helper"
require_output "HELP RSA-KEY usage" "$OUT" "RSA-KEY <private_key.pem> <ciphertext_file>"

echo "[TEST] RSA-RHO interactive shell dispatch"
OUT=$(printf 'RSA-RHO testdata/rsa/rsa_61_53_e17.txt\nEXIT\n' | "$BIN" 2>&1)
require_output "RSA-RHO shell starts" "$OUT" "RSA-RHO: starting Pollard Rho factorization"
require_output "RSA-RHO shell succeeds" "$OUT" "rsa-rho: success"

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
echo "[TEST] RSA ECM shell and bounds handling"

OUT=$(printf "RSA-ECM ./testdata/rsa/rsa_ecm_small_factor.txt\nEXIT\n" | $BIN 2>&1)
printf "%s\n" "$OUT"
require_output "RSA-ECM shell command starts" "$OUT" "[*] RSA-ECM: starting ECM factorization"
require_output "RSA-ECM shell command finds factor" "$OUT" "[+] RSA-ECM: found factor f ="
require_output "RSA-ECM shell command succeeds" "$OUT" "rsa-ecm: success"


OUT=$($BIN RSA-ECM ./testdata/rsa/rsa_ecm_small_factor.txt --curves 50 --bound 10000 2>&1)
printf "%s\n" "$OUT"
require_output "RSA-ECM CLI accepts curves and bound" "$OUT" "[*] RSA-ECM: curves=50, B1=10000"
require_output "RSA-ECM CLI bounds mode finds factor" "$OUT" "[+] RSA-ECM: found factor f ="

OUT=$($BIN RSA-ECM ./testdata/rsa/rsa_ecm_small_factor.txt --curves 0 2>&1 || true)
printf "%s\n" "$OUT"
require_output "RSA-ECM CLI rejects zero curves" "$OUT" "rsa-ecm: --curves requires a positive number"

OUT=$($BIN RSA-ECM ./testdata/rsa/rsa_ecm_small_factor.txt --bound abc 2>&1 || true)
printf "%s\n" "$OUT"
require_output "RSA-ECM CLI rejects bad bound" "$OUT" "rsa-ecm: --bound requires a positive number"

OUT=$($BIN RSA-ECM ./testdata/rsa/rsa_ecm_small_factor.txt -c 50 -b 10000 2>&1)
printf "%s\n" "$OUT"
require_output "RSA-ECM CLI accepts short aliases" "$OUT" "[*] RSA-ECM: curves=50, B1=10000"
require_output "RSA-ECM CLI short aliases find cofactor" "$OUT" "[+] RSA-ECM: cofactor q ="

OUT=$($BIN RSA-ECM ./testdata/rsa/rsa_ecm_small_factor.txt --b1 10000 2>&1)
printf "%s\n" "$OUT"
require_output "RSA-ECM CLI accepts --b1 alias" "$OUT" "[*] RSA-ECM: curves=20, B1=10000"
require_output "RSA-ECM CLI --b1 alias finds cofactor" "$OUT" "[+] RSA-ECM: cofactor q ="

OUT=$(printf "RSA-ECM ./testdata/rsa/rsa_ecm_small_factor.txt --curves 50 --bound 10000\nEXIT\n" | $BIN 2>&1)
printf "%s\n" "$OUT"
require_output "RSA-ECM shell accepts curves and bound" "$OUT" "[*] RSA-ECM: curves=50, B1=10000"
require_output "RSA-ECM shell bounds mode succeeds" "$OUT" "rsa-ecm: success"

OUT=$(printf "RSA-ECM ./testdata/rsa/rsa_ecm_small_factor.txt --curves 0\nEXIT\n" | $BIN 2>&1)
printf "%s\n" "$OUT"
require_output "RSA-ECM shell rejects zero curves" "$OUT" "rsa-ecm: --curves requires a positive number"

echo "[TEST] RSA ECM rejects non-divisor false positive"

OUT=$(timeout 20s $BIN RSA-ECM ./testdata/rsa/rsa_ecm_reject_nondivisor.txt --curves 1000 --bound 500000 2>&1 || true)
printf "%s\n" "$OUT"

if echo "$OUT" | grep -q "\[+\] RSA-ECM: found factor f = 40"; then
    fail "RSA-ECM rejects non-divisor candidate"
else
    pass "RSA-ECM rejects non-divisor candidate"
fi

if echo "$OUT" | grep -q "rsa-ecm: success"; then
    fail "RSA-ECM does not report success for invalid candidate"
else
    pass "RSA-ECM does not report success for invalid candidate"
fi


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
require_output "HELP shows AUTO" "$OUT" "AUTO"

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
echo "[TEST] AUTO input detection"

AUTO_RSA_SAMPLE="/tmp/k1wi_auto_regression_rsa.txt"
cat > "$AUTO_RSA_SAMPLE" <<'EOF'
n = 3233
e = 17
ct = 855
EOF

OUT=$($BIN AUTO "$AUTO_RSA_SAMPLE" 2>&1)
echo "$OUT"

require_output "AUTO detects RSA challenge" "$OUT" "Detected type: RSA challenge data"
require_output "AUTO finds RSA n" "$OUT" "RSA modulus n        : yes"
require_output "AUTO finds RSA e" "$OUT" "RSA exponent e       : yes"
require_output "AUTO finds RSA ciphertext" "$OUT" "RSA ciphertext field : yes"
require_output "AUTO previews RSA public sample" "$OUT" "RSA ciphertext       : 855"

AUTO_ECC_SAMPLE="/tmp/k1wi_auto_regression_ecc.txt"
cat > "$AUTO_ECC_SAMPLE" <<'EOF'
Alice's public key: Point(x=155781055760279718382374741001148850818103179141959728567110540865590463, y=73794785561346677848810778233901832813072697504335306937799336126503714)
Bob's public key: Point(x=171226959585314864221294077932510094779925634276949970785138593200069419, y=54353971839516652938533335476115503436865545966356461292708042305317630)
Encrypted flag: {'iv': '64bc75c8b38017e1397c46f85d4e332b', 'encrypted_flag': '13e4d200708b786d8f7c3bd2dc5de0201f0d7879192e6603d7c5d6b963e1df2943e3ff75f7fda9c30a92171bbbc5acbf'}
EOF

OUT=$($BIN AUTO "$AUTO_ECC_SAMPLE" 2>&1)
echo "$OUT"

require_output "AUTO detects ECC challenge" "$OUT" "Detected type: ECC / ECDH-style encrypted challenge data"
require_output "AUTO finds ECC point" "$OUT" "ECC point/public key : yes"
require_output "AUTO finds generic ciphertext" "$OUT" "Generic ciphertext   : yes"
require_output "AUTO avoids false RSA ciphertext" "$OUT" "RSA ciphertext field : no"
require_output "AUTO avoids IV false MD5" "$OUT" "MD5 hash             : no"
require_output "AUTO previews ECC IV" "$OUT" "IV / nonce           :"
require_output "AUTO previews encrypted flag" "$OUT" "Encrypted flag       :"


AUTO_HASH_SAMPLE="/tmp/k1wi_auto_regression_hash_encoding.txt"
cat > "$AUTO_HASH_SAMPLE" <<'EOF'
MD5: 046e85f6fe460de94fd46198feef4d07
SHA256: b03a7ac0c7065b04e4ddf773192f300cc6528c8128ef55c31c0de77692298226
base64: Q1RGe0sxV2lfQVVUT190ZXN0fQ==
hex: 4354467b4b3157695f4155544f5f746573747d
EOF

OUT=$($BIN AUTO "$AUTO_HASH_SAMPLE" 2>&1)
echo "$OUT"

require_output "AUTO detects hash encoded data" "$OUT" "Detected type: hash / encoded data"
require_output "AUTO finds MD5" "$OUT" "MD5 hash             : yes"
require_output "AUTO finds SHA256" "$OUT" "SHA256 hash          : yes"
require_output "AUTO finds hex blob" "$OUT" "Hex blob             : yes"
require_output "AUTO finds base64 blob" "$OUT" "Base64 blob          : yes"


AUTO_RAW_HASH_SAMPLE="/tmp/k1wi_auto_regression_raw_hashes.txt"
cat > "$AUTO_RAW_HASH_SAMPLE" <<'EOF'
046e85f6fe460de94fd46198feef4d07
b03a7ac0c7065b04e4ddf773192f300cc6528c8128ef55c31c0de77692298226
EOF

OUT=$($BIN AUTO "$AUTO_RAW_HASH_SAMPLE" 2>&1)
echo "$OUT"

require_output "AUTO detects raw hash data" "$OUT" "Detected type: hash / encoded data"
require_output "AUTO finds raw MD5" "$OUT" "MD5 hash             : yes"
require_output "AUTO finds raw SHA256" "$OUT" "SHA256 hash          : yes"
require_output "AUTO finds raw hex blob" "$OUT" "Hex blob             : yes"
require_output "AUTO raw hashes avoid base64 false positive" "$OUT" "Base64 blob          : no"



AUTO_RAW_BASE64_SAMPLE="/tmp/k1wi_auto_regression_raw_base64.txt"
cat > "$AUTO_RAW_BASE64_SAMPLE" <<'EOF'
Q1RGe0sxV2lfQVVUT190ZXN0fQ==
EOF

OUT=$($BIN AUTO "$AUTO_RAW_BASE64_SAMPLE" 2>&1)
echo "$OUT"

require_output "AUTO detects raw base64 data" "$OUT" "Detected type: hash / encoded data"
require_output "AUTO finds raw base64 blob" "$OUT" "Base64 blob          : yes"
require_output "AUTO raw base64 avoids MD5" "$OUT" "MD5 hash             : no"


AUTO_RSA_PRIVATE_D_SAMPLE="/tmp/k1wi_auto_regression_rsa_private_d.txt"
cat > "$AUTO_RSA_PRIVATE_D_SAMPLE" <<'EOF'
N = 15216583654836731327639981224133918855895948374072384050848479908982286890731769486609085918857664046075375253168955058743185664390273058074450390236774324903305663479046566232967297765731625328029814055635316002591227570271271445226094919864475407884459980489638001092788574811554149774028950310695112688723853763743238753349782508121985338746755237819373178699343135091783992299561827389745132880022259873387524273298850340648779897909381979714026837172003953221052431217940632552930880000919436507245150726543040714721553361063311954285289857582079880295199632757829525723874753306371990452491305564061051059885803
d = 11175901210643014262548222473449533091378848269490518850474399681690547281665059317155831692300453197335735728459259392366823302405685389586883670043744683993709123180805154631088513521456979317628012721881537154107239389466063136007337120599915456659758559300673444689263854921332185562706707573660658164991098457874495054854491474065039621922972671588299315846306069845169959451250821044417886630346229021305410340100401530146135418806544340908355106582089082980533651095594192031411679866134256418292249592135441145384466261279428795408721990564658703903787956958168449841491667690491585550160457893350536334242689
EOF

OUT=$($BIN AUTO "$AUTO_RSA_PRIVATE_D_SAMPLE" 2>&1)
echo "$OUT"

require_output "AUTO detects RSA private exponent data" "$OUT" "Detected type: RSA private exponent data"
require_output "AUTO finds RSA private N" "$OUT" "RSA modulus n        : yes"
require_output "AUTO finds RSA private d" "$OUT" "RSA private d        : yes"
require_output "AUTO private d has no public e" "$OUT" "RSA exponent e       : no"
require_output "AUTO private d has no ciphertext" "$OUT" "RSA ciphertext field : no"
require_output "AUTO previews RSA private fields" "$OUT" "Field previews"
require_output "AUTO previews RSA private d" "$OUT" "RSA private d        :"


OUT=$($BIN help AUTO 2>&1)
echo "$OUT"
require_output "HELP AUTO page" "$OUT" "AUTO - Input Detection and Parser"


echo
echo "[TEST] VERSION banner"

OUT=$($BIN --version 2>&1)
echo "$OUT"

require_output "VERSION reports K1Wi" "$OUT" "K1Wi Framework"
require_output "VERSION reports v1.2.0" "$OUT" "v1.2.0"
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
    "Usage: k1wi RSA-FACTOR <rsa_file>"

    
        
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
