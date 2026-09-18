#!/usr/bin/env bash
#
# ue_benchmark_matrix.sh -- automated iperf3 traffic generator, run from
# oai-nr-ue, driving BOTH uplink and downlink against a single already-
# running `iperf3 -s` on the DN side (downlink uses `-R`, so no second
# server is ever needed).
#
# Usage:
#   ./ue_benchmark_matrix.sh <server_ip> <bind_ip> <mode_label> [reps]
#
# Example (matches this project's topology):
#   # On oai-ext-dn, once, before running this script:
#   iperf3 -s
#
#   # On oai-nr-ue:
#   ./ue_benchmark_matrix.sh 192.168.72.135 12.1.1.2 offload  3
#   ./ue_benchmark_matrix.sh 192.168.72.135 12.1.1.2 baseline 3
#
# `mode_label` is just a filename tag (e.g. "offload"/"baseline") --
# it does NOT control the CU; run cu_benchmark_run.sh in the matching
# mode on the CU at the same time, for the same duration (see the
# runtime-calculation note further down for exactly how long that is).
#
# Packet-size matrix: kept strictly within the URLLC-relevant range,
# stopping at (not exceeding) the 512-byte fast-path cutoff (see the
# project journal, bug #6) -- 100/200/300/400 comfortably under the cap,
# 500 right at the edge. If you also want to confirm graceful bypass
# behavior above the cap (still correct, just not offloaded), add e.g.
# 800 or 1400 back into this array -- just recompute the CU-side
# monitoring duration below if you do, since it changes the total
# runtime.
#
# Requires: iperf3 on both this host and the DN-side server.
set -u

SERVER_IP="${1:-}"
BIND_IP="${2:-}"
MODE_LABEL="${3:-run}"
REPS="${4:-3}"

if [[ -z "$SERVER_IP" || -z "$BIND_IP" ]]; then
    echo "Usage: $0 <server_ip> <bind_ip> <mode_label> [reps]"
    echo "Example: $0 192.168.72.135 12.1.1.2 offload 3"
    exit 1
fi

command -v iperf3 >/dev/null 2>&1 || { echo "Error: iperf3 not found."; exit 1; }

PKT_SIZES=(100 200 300 400 500)             # bytes, UDP payload (-l) --
                                              # URLLC-relevant range only,
                                              # trimmed to stop at (not
                                              # exceed) the 512-byte
                                              # fast-path cutoff
RATE="1M"                                    # target bitrate (-b); URLLC
                                              # profile: modest, steady rate
                                              # rather than link-saturating
DURATION=15                                  # seconds per individual run

TS="$(date +%Y%m%d_%H%M%S)"
OUTDIR="ue_bench_results/${TS}_${MODE_LABEL}"
mkdir -p "$OUTDIR"

echo "=== UE traffic matrix ==="
echo "Server:     $SERVER_IP"
echo "Bind (UE):  $BIND_IP"
echo "Mode label: $MODE_LABEL"
echo "Reps:       $REPS per (direction, packet size) combination"
echo "Rate:       $RATE"
echo "Duration:   ${DURATION}s per run"
echo "Output:     $OUTDIR"
echo

run_one() {
    local direction="$1"   # "ul" or "dl"
    local pkt_size="$2"
    local rep="$3"
    local extra_flag=""
    local fname="${OUTDIR}/${direction}_pkt${pkt_size}_rep${rep}.json"

    if [[ "$direction" == "dl" ]]; then
        extra_flag="-R"
    fi

    echo "[$direction] pkt=${pkt_size}B rep=${rep}/${REPS} -> $fname"

    iperf3 -c "$SERVER_IP" -B "$BIND_IP" -u \
        -l "$pkt_size" -b "$RATE" -t "$DURATION" \
        $extra_flag --json > "$fname" 2>"${fname%.json}.err"

    if [[ $? -ne 0 ]]; then
        echo "  !! iperf3 exited non-zero -- check ${fname%.json}.err"
    fi

    # Small gap between runs so back-to-back tests don't interfere.
    sleep 2
}

for pkt_size in "${PKT_SIZES[@]}"; do
    for rep in $(seq 1 "$REPS"); do
        run_one "ul" "$pkt_size" "$rep"
    done
done

for pkt_size in "${PKT_SIZES[@]}"; do
    for rep in $(seq 1 "$REPS"); do
        run_one "dl" "$pkt_size" "$rep"
    done
done

echo
echo "=== Summary (throughput / loss / jitter, averaged across reps) ==="
printf "%-4s %8s %12s %10s %10s\n" "dir" "pkt(B)" "Mbps" "loss(%)" "jitter(ms)"

SUMMARY_CSV="${OUTDIR}/summary.csv"
echo "mode,direction,pkt_size,mbps,loss_pct,jitter_ms" > "$SUMMARY_CSV"

for direction in ul dl; do
    for pkt_size in "${PKT_SIZES[@]}"; do
        python3 - "$OUTDIR" "$direction" "$pkt_size" "$REPS" "$MODE_LABEL" "$SUMMARY_CSV" <<'PYEOF'
import json, sys, glob

outdir, direction, pkt_size, reps, mode_label, csv_path = sys.argv[1:7]
files = sorted(glob.glob(f"{outdir}/{direction}_pkt{pkt_size}_rep*.json"))

mbps_vals, loss_vals, jitter_vals = [], [], []
for f in files:
    try:
        with open(f) as fh:
            d = json.load(fh)
        summ = d["end"]["sum"]
        mbps_vals.append(summ["bits_per_second"] / 1e6)
        loss_vals.append(summ.get("lost_percent", 0.0))
        jitter_vals.append(summ.get("jitter_ms", 0.0))
    except Exception:
        continue

if mbps_vals:
    avg = lambda l: sum(l) / len(l)
    m, l, j = avg(mbps_vals), avg(loss_vals), avg(jitter_vals)
    print(f"{direction:<4} {pkt_size:>8} {m:>12.3f} {l:>10.3f} {j:>10.3f}")
    with open(csv_path, "a") as fh:
        fh.write(f"{mode_label},{direction},{pkt_size},{m:.6f},{l:.6f},{j:.6f}\n")
else:
    print(f"{direction:<4} {pkt_size:>8} {'--':>12} {'--':>10} {'--':>10}  (no valid results)")
PYEOF
    done
done

echo
echo "Raw JSON per run saved in: $OUTDIR"
echo "Machine-readable summary:  $SUMMARY_CSV"
echo "Remember to also grab the matching CU-side results (cu_benchmark_run.sh)"
echo "for the same mode/duration, and a concurrent 'ping $SERVER_IP' or"
echo "'ping <UE tunnel IP>' sample for RTT, since iperf3 alone won't give you"
echo "one-way/RTT latency."
