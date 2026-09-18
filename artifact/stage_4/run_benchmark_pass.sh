#!/usr/bin/env bash
#
# run_benchmark_pass.sh -- HOST-SIDE. Does exactly ONE thing: starts the
# CU monitor and the UE traffic generator with correct, exact timing
# (monitor starts just before traffic, stops the instant traffic ends),
# so you never have to guess a duration. Nothing else.
#
# This script does NOT:
#   - start, stop, or configure the XDP loader (you run that yourself,
#     in your own terminal, before bringing up the DU/UE, exactly as
#     you already do: DISABLE_OFFLOAD=1 FORCE_SKB_MODE=1
#     ./xdp_gtp_inner_parser_user eth0 | tee loader.log)
#   - touch DISABLE_OFFLOAD at all
#   - docker cp anything
#   - generate any plots
#
# Prerequisites before you run this script:
#   1. The loader is already running in the CU container (your own
#      terminal), and the DU/UE have already attached (F1AP/NGAP
#      watchers have already learned what they need to).
#   2. cu_benchmark_run.sh already sits in the CU container's workdir.
#   3. ue_benchmark_matrix.sh already sits in the UE container's workdir.
#   4. You've filled in BIND_IP below with the UE's actual tunnel IP
#      (found manually, as you do).
#
# Usage:
#   ./run_benchmark_pass.sh <mode_label>
#
# Example:
#   ./run_benchmark_pass.sh baseline
#   (restart the loader yourself in offload mode, re-attach the UE, then:)
#   ./run_benchmark_pass.sh offload
#
# After each pass finishes, results sit inside the containers exactly as
# cu_benchmark_run.sh / ue_benchmark_matrix.sh normally leave them:
#   CU: <CU_WORKDIR>/bench_results/<timestamp>_live/
#   UE: <UE_WORKDIR>/ue_bench_results/<timestamp>_<mode_label>/
# `docker cp` and plotting are entirely up to you, whenever you're ready.

set -u

# ============================== CONFIG ==============================
CU_CONTAINER="rfsim5g-oai-cu"
UE_CONTAINER="rfsim5g-oai-nr-ue"

CU_WORKDIR="/opt/oai-gnb/stage_3"   # where cu_benchmark_run.sh + loader.log live
UE_WORKDIR="/opt/oai-nr-ue"          # where ue_benchmark_matrix.sh lives

LOADER_LOG="loader.log"             # relative to CU_WORKDIR -- matches
                                     # your own `| tee loader.log` run

SERVER_IP="192.168.72.135"          # DN-side iperf3 -s address
BIND_IP="12.1.1.2"                  # <-- fill in the UE's actual tunnel IP
REPS=3

CU_UP_TARGET=""                     # optional: PID or process-name
                                     # pattern for pidstat. Leave empty to
                                     # auto-detect via `ss` (who's
                                     # listening on 2152/2153); set it
                                     # explicitly if auto-detect ever
                                     # misfires.
# ======================================================================

MODE_LABEL="${1:-}"
if [[ -z "$MODE_LABEL" ]]; then
    echo "Usage: $0 <mode_label>"
    echo "Example: $0 baseline"
    exit 1
fi

log() { echo "[$(date +%H:%M:%S)] $*"; }

cu_exec()   { docker exec "$CU_CONTAINER" bash -c "$1"; }
cu_exec_d() { docker exec -d "$CU_CONTAINER" bash -c "$1"; }
ue_exec()   { docker exec "$UE_CONTAINER" bash -c "$1"; }

detect_cu_up_pid() {
    cu_exec "ss -tulnp 2>/dev/null | grep -E ':(2152|2153)\\b'" \
        | grep -oP 'pid=\K[0-9]+' | head -n1
}

echo "=================================================================="
log "Benchmark pass: $MODE_LABEL"
echo "=================================================================="
echo "Assuming: loader already running in $CU_CONTAINER, DU/UE already attached."
echo

CU_UP_PID="$CU_UP_TARGET"
if [[ -z "$CU_UP_PID" ]]; then
    log "Auto-detecting CU-UP PID (listening on 2152/2153)..."
    CU_UP_PID="$(detect_cu_up_pid)"
fi
if [[ -z "$CU_UP_PID" ]]; then
    log "WARNING: could not determine CU-UP PID -- pidstat will be skipped this run."
else
    log "CU-UP PID: $CU_UP_PID"
fi

STOP_FILE="/tmp/cu_benchmark_stop_signal_${MODE_LABEL}"
cu_exec "rm -f $STOP_FILE"

log "Starting CU monitor (live mode, detached)..."
# 'exec' so the process docker/pgrep sees is cu_benchmark_run.sh itself,
# not a wrapper shell. Stopped via the stop-file below, not a signal --
# see cu_benchmark_run.sh's own header comment for why the stop-file is
# the reliable mechanism here.
cu_exec_d "cd $CU_WORKDIR && exec ./cu_benchmark_run.sh live ${CU_UP_PID:-} $CU_WORKDIR/$LOADER_LOG $STOP_FILE > $CU_WORKDIR/monitor_stdout_${MODE_LABEL}.log 2>&1"
sleep 2   # let mpstat/pidstat actually attach before traffic starts

log "Starting UE traffic (mode=$MODE_LABEL) -- this call BLOCKS until finished..."
ue_exec "cd $UE_WORKDIR && ./ue_benchmark_matrix.sh $SERVER_IP $BIND_IP $MODE_LABEL $REPS"

log "UE traffic finished -- stopping CU monitor NOW (exact-timing stop-file)..."
cu_exec "touch $STOP_FILE"
sleep 3   # let mpstat/pidstat/cu_benchmark_run.sh finish writing meta.txt
cu_exec "rm -f $STOP_FILE"

echo
log "Pass '$MODE_LABEL' complete."
echo "Results are sitting in the containers -- nothing was copied out or plotted:"
echo "  CU: $CU_CONTAINER:$CU_WORKDIR/bench_results/<latest>/"
echo "  UE: $UE_CONTAINER:$UE_WORKDIR/ue_bench_results/<latest>_${MODE_LABEL}/"
echo "docker cp them out and run plot_benchmark_results.py whenever you're ready."
