#!/usr/bin/env bash
#
# cu_benchmark_run.sh -- MONITOR ONLY. Does not start, stop, or touch the
# XDP loader in any way. Run the loader yourself, exactly as you always
# have, in its own terminal:
#
#   FORCE_SKB_MODE=1 ./xdp_gtp_inner_parser_user eth0 | tee loader.log
#   (add DISABLE_OFFLOAD=1 before that for a baseline/no-offload run)
#
# Then, in a SECOND terminal, run this script to capture CPU utilization
# and (optionally) summarize the loader's log for offload-hit coverage.
#
# Two modes:
#
#   FIXED DURATION -- <duration_sec> is a plain positive integer. Monitors
#   for exactly that many seconds, then stops automatically. Use this only
#   when you know the exact total runtime of your UE-side traffic in
#   advance (see ue_benchmark_matrix.sh's header comment for the formula)
#   -- padding this with extra "just in case" seconds is NOT harmless: any
#   idle time after traffic actually stops drags the averaged CPU% down
#   toward zero, understating the real utilization.
#
#   LIVE / UNTIL YOU STOP IT -- pass "live" instead of a number. Runs
#   indefinitely; start it at the same moment you start the UE traffic.
#   Stop it either by pressing Ctrl+C on this script directly (works for
#   a human at a real terminal), or -- for automated orchestration --
#   by creating the stop-file (4th argument, default
#   /tmp/cu_benchmark_stop_signal) from elsewhere, e.g.:
#       docker exec <cu_container> touch /tmp/cu_benchmark_stop_signal
#   The stop-file is the more robust mechanism: a script launched
#   through a nested background/exec chain (as an orchestrator using
#   `docker exec -d` may do) can end up with SIGINT already inherited as
#   ignored, which bash's own `trap` cannot override for that process's
#   lifetime -- a confirmed real shell quirk, not specific to this
#   script. The stop-file has no such dependency.
#
# Usage:
#   ./cu_benchmark_run.sh <duration_sec|live> [cu_up_pid_or_name] [loader_log_path] [stop_file]
#
# Examples:
#   ./cu_benchmark_run.sh live oai_cuup loader.log
#   ./cu_benchmark_run.sh live oai_cuup loader.log /tmp/my_stop_signal
#   ./cu_benchmark_run.sh 60 oai_cuup loader.log
#
# Output: a timestamped results directory under ./bench_results/ containing:
#   mpstat.log   -- system-wide per-core CPU utilization, 1s samples
#   pidstat.log  -- CU-UP process CPU utilization, 1s samples (if a
#                   PID/name was given and found)
#   meta.txt     -- mode, start/end timestamps, and (if a loader log path
#                   was given) offload hit count vs total GTP-U count
#
# Requires: sysstat (mpstat, pidstat) -- apt-get install sysstat
set -u

DURATION_ARG="${1:-30}"
CU_UP_TARGET="${2:-}"
LOADER_LOG="${3:-}"
STOP_FILE="${4:-/tmp/cu_benchmark_stop_signal}"

LIVE_MODE=0
if [[ "$DURATION_ARG" == "live" ]]; then
    LIVE_MODE=1
elif ! [[ "$DURATION_ARG" =~ ^[0-9]+$ ]]; then
    echo "Usage: $0 <duration_sec|live> [cu_up_pid_or_name] [loader_log_path]"
    exit 1
fi

command -v mpstat >/dev/null 2>&1 || { echo "Error: mpstat not found (apt-get install sysstat)"; exit 1; }

TS="$(date +%Y%m%d_%H%M%S)"
LABEL=$([[ "$LIVE_MODE" -eq 1 ]] && echo "live" || echo "${DURATION_ARG}s")
OUTDIR="bench_results/${TS}_${LABEL}"
mkdir -p "$OUTDIR"

echo "=== CU resource monitor (loader must already be running elsewhere) ==="
if [[ "$LIVE_MODE" -eq 1 ]]; then
    echo "Mode:        live -- press Ctrl+C here the moment UE traffic finishes"
else
    echo "Mode:        fixed duration (${DURATION_ARG}s)"
fi
echo "Output:      $OUTDIR"
echo

# Resolve a real PID for pidstat, if a name was given instead of a number.
CU_UP_PID=""
if [[ -n "$CU_UP_TARGET" ]]; then
    if [[ "$CU_UP_TARGET" =~ ^[0-9]+$ ]]; then
        CU_UP_PID="$CU_UP_TARGET"
    else
        CU_UP_PID="$(pgrep -n -f "$CU_UP_TARGET" 2>/dev/null || true)"
    fi
    if [[ -z "$CU_UP_PID" ]]; then
        echo "Warning: could not resolve a PID for '$CU_UP_TARGET' -- per-process" \
             "CPU (pidstat.log) will be skipped this run. System-wide mpstat" \
             "will still be captured."
    else
        echo "CU-UP PID resolved: $CU_UP_PID"
    fi
fi

START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

MPSTAT_PID=""
PIDSTAT_PID=""
ALREADY_REPORTED=0

cleanup_and_report() {
    # Guard against running twice (e.g. both the stop-file poll loop and
    # a SIGINT trap firing for the same stop event).
    [[ "$ALREADY_REPORTED" -eq 1 ]] && return
    ALREADY_REPORTED=1

    # Forward SIGINT to the monitoring children so they each print their
    # own "Average:" summary line before exiting, then wait for them.
    [[ -n "$MPSTAT_PID" ]] && kill -INT "$MPSTAT_PID" 2>/dev/null
    [[ -n "$PIDSTAT_PID" ]] && kill -INT "$PIDSTAT_PID" 2>/dev/null
    [[ -n "$MPSTAT_PID" ]] && wait "$MPSTAT_PID" 2>/dev/null
    [[ -n "$PIDSTAT_PID" ]] && wait "$PIDSTAT_PID" 2>/dev/null

    END_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    TOTAL_GTPU="none (no loader_log_path given)"
    TOTAL_HITS="none"
    if [[ -n "$LOADER_LOG" && -f "$LOADER_LOG" ]]; then
        TOTAL_GTPU="$(grep -c "^GTP-U packet found" "$LOADER_LOG" || true)"
        TOTAL_HITS="$(grep -c "Fast-path offload: HIT" "$LOADER_LOG" || true)"
    elif [[ -n "$LOADER_LOG" ]]; then
        echo "Warning: loader log path '$LOADER_LOG' not found -- skipping offload-coverage summary."
    fi

    {
        echo "mode=$([[ "$LIVE_MODE" -eq 1 ]] && echo live || echo fixed)"
        echo "duration_arg=$DURATION_ARG"
        echo "cu_up_target=${CU_UP_TARGET:-none}"
        echo "cu_up_pid=${CU_UP_PID:-none}"
        echo "start_utc=$START_TS"
        echo "end_utc=$END_TS"
        echo "total_gtpu_packets=$TOTAL_GTPU"
        echo "total_offload_hits=$TOTAL_HITS"
    } > "$OUTDIR/meta.txt"

    echo
    echo "=== Done ==="
    echo "GTP-U packets seen:  $TOTAL_GTPU"
    echo "Offload hits:        $TOTAL_HITS"
    echo "Results saved in:    $OUTDIR"
}

if [[ "$LIVE_MODE" -eq 1 ]]; then
    trap cleanup_and_report SIGINT
    rm -f "$STOP_FILE"   # clear any stale stop-file from a previous run
    echo "Monitoring LIVE -- start your UE traffic now."
    echo "Stop it either by pressing Ctrl+C here, or (for automated"
    echo "orchestration) by creating: $STOP_FILE"
    mpstat -P ALL 1 > "$OUTDIR/mpstat.log" &
    MPSTAT_PID=$!
    if [[ -n "$CU_UP_PID" ]]; then
        pidstat -p "$CU_UP_PID" 1 > "$OUTDIR/pidstat.log" &
        PIDSTAT_PID=$!
    fi
    # Poll for the stop-file rather than relying solely on SIGINT
    # reaching this process. This matters because a script launched
    # through certain nested background/exec chains (as an automated
    # orchestrator may do via `docker exec -d`) can inherit SIGINT
    # already set to be ignored, in which case bash's own `trap` is
    # unable to override that for the life of this process -- a real,
    # confirmed POSIX/bash shell quirk, not a bug in this script's trap
    # itself. The stop-file mechanism has no dependency on signal
    # disposition at all, so it works regardless of how this script was
    # launched. The SIGINT trap above is kept as a convenience for
    # direct interactive use (a human running this at a real terminal).
    while [[ ! -f "$STOP_FILE" ]]; do
        sleep 1
    done
    cleanup_and_report
    rm -f "$STOP_FILE"
else
    echo "Monitoring for ${DURATION_ARG}s -- make sure your iperf3 traffic is running now."
    mpstat -P ALL 1 "$DURATION_ARG" > "$OUTDIR/mpstat.log" &
    MPSTAT_PID=$!
    if [[ -n "$CU_UP_PID" ]]; then
        pidstat -p "$CU_UP_PID" 1 "$DURATION_ARG" > "$OUTDIR/pidstat.log" &
        PIDSTAT_PID=$!
    fi
    wait "$MPSTAT_PID" 2>/dev/null
    [[ -n "$PIDSTAT_PID" ]] && wait "$PIDSTAT_PID" 2>/dev/null
    cleanup_and_report
fi
