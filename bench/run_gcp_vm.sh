#!/usr/bin/env bash
# Run from the repository root on a Linux VM with /dev/net/tun available.
set -euo pipefail

PAYLOAD_MIB="${PAYLOAD_MIB:-4}"
WARMUP_TRIALS="${WARMUP_TRIALS:-1}"
MEASURED_TRIALS="${MEASURED_TRIALS:-5}"
RESULT_DIR="${RESULT_DIR:-bench/results/gcp}"
RESULT_JSON="$RESULT_DIR/echo.json"
PLOT_PNG="$RESULT_DIR/echo-throughput.png"
TOTAL_CONNECTIONS=$((WARMUP_TRIALS + MEASURED_TRIALS))
SERVER_PID=""

cleanup() {
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        sudo kill "$SERVER_PID" || true
        wait "$SERVER_PID" || true
    fi
    sudo ./scripts/teardown_tun.sh tun0 || true
}
trap cleanup EXIT

sudo apt-get update
sudo apt-get install -y build-essential iproute2 python3 python3-matplotlib

cargo build --release
mkdir -p "$RESULT_DIR"
git rev-parse HEAD >"$RESULT_DIR/git-revision.txt"
uname -a >"$RESULT_DIR/uname.txt"
lscpu >"$RESULT_DIR/lscpu.txt"

sudo ./scripts/setup_tun.sh tun0 10.0.0.1 10.0.0.2
sudo ./target/release/bench_echo_server --connections "$TOTAL_CONNECTIONS" >"$RESULT_DIR/server.log" 2>&1 &
SERVER_PID=$!

for _ in {1..20}; do
    if ping -c 1 -W 1 10.0.0.2 >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

python3 bench/run_echo_benchmark.py \
    --payload-mib "$PAYLOAD_MIB" \
    --warmup "$WARMUP_TRIALS" \
    --trials "$MEASURED_TRIALS" \
    --output "$RESULT_JSON"
python3 bench/plot_results.py --input "$RESULT_JSON" --output "$PLOT_PNG"

wait "$SERVER_PID"
SERVER_PID=""
echo "Wrote $RESULT_JSON and $PLOT_PNG"
