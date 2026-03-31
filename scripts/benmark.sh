#!/bin/bash
# LinkFlow Industry Benchmark Tool

FILE_SIZE="1GB"
TEST_FILE="static_files/dummy1gb.bin"
SERVER_IP="127.0.0.1"

echo "--- Starting Industry Standard Benchmarking ---"

# 1. LAN Throughput Test (0% Loss)
echo "[Test 1] LAN Throughput (Target: >95 MB/s)"
# Start server in background
./databeam/src/server.exe > /dev/null &
SERVER_PID=$!
sleep 2

# Measure client time
START=$(date +%s)
./databeam/src/client.exe $TEST_FILE $SERVER_IP
END=$(date +%s)

kill $SERVER_PID
DURATION=$((END-START))
SPEED=$(echo "1024 / $DURATION" | bc -l)
echo "Result: $SPEED MB/s in $DURATION seconds" [cite: 543]

# 2. Integrity Check (MD5)
echo "[Test 2] Integrity Validation"
ORIGINAL=$(md5sum $TEST_FILE | awk '{print $1}')
RECEIVED=$(md5sum received/1GB_file.bin | awk '{print $1}')

if [ "$ORIGINAL" == "$RECEIVED" ]; then
    echo "Result: PASS (Hashes Match)" [cite: 537]
else
    echo "Result: FAIL (Hash Mismatch!)"
fi

# 3. Resilience Test (20% Loss)
echo "[Test 3] 20% Packet Loss Resilience (Target: >45 MB/s)"
sudo tc qdisc add dev lo root netem loss 20% [cite: 545]
# ... repeat transfer logic ...
sudo tc qdisc del dev lo root [cite: 539]
