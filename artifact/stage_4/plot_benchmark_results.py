#!/usr/bin/env python3
"""
plot_benchmark_results.py -- run this on the HOST (not in a container).

Workflow this matches:
  1. Run the baseline pass (loader with DISABLE_OFFLOAD=1, cu_benchmark_run.sh,
     ue_benchmark_matrix.sh baseline), then `docker cp` EVERYTHING produced
     (the cu-side bench_results/ dir AND the ue-side ue_bench_results/ dir)
     into one folder on the host, e.g. ./results/baseline/
       (subfolder layout inside doesn't matter -- this script searches
       recursively for summary.csv / mpstat.log / pidstat.log wherever
       docker cp happened to put them)
  2. Repeat for the offload pass -> ./results/offload/
  3. Run this script once, pointing at those two folders:

       python3 plot_benchmark_results.py ./results/baseline ./results/offload [outdir]

Produces (in outdir, default "./plots"):
    throughput_ul.png, throughput_dl.png
    loss_ul.png,       loss_dl.png
    jitter_ul.png,     jitter_dl.png
    cpu_comparison.png   (system-wide, and CU-UP process if pidstat data found)

Requires: pandas, matplotlib (pip install pandas matplotlib)
"""
import sys
import os
import glob
import pandas as pd
import matplotlib.pyplot as plt


def find_files(root, filename):
    return sorted(glob.glob(os.path.join(root, "**", filename), recursive=True))


def load_summaries(root, mode_label):
    files = find_files(root, "summary.csv")
    if not files:
        print(f"Warning: no summary.csv found anywhere under {root}")
        return pd.DataFrame(columns=["mode", "direction", "pkt_size",
                                       "mbps", "loss_pct", "jitter_ms"])

    frames = []
    for f in files:
        df = pd.read_csv(f)
        mismatched = df["mode"].unique().tolist()
        if mismatched != [mode_label]:
            print(f"Note: {f} has mode label(s) {mismatched}; treating all "
                  f"rows in it as '{mode_label}' since it was found under "
                  f"{root}.")
        df["mode"] = mode_label
        frames.append(df)
        print(f"  found {f} ({len(df)} rows)")

    combined = pd.concat(frames, ignore_index=True)
    # Average across reps AND across multiple summary.csv files (in case
    # the traffic matrix was run more than once for this pass).
    return combined.groupby(["mode", "direction", "pkt_size"], as_index=False).agg(
        mbps=("mbps", "mean"),
        loss_pct=("loss_pct", "mean"),
        jitter_ms=("jitter_ms", "mean"),
    )


def parse_mpstat_avg_all(path):
    """Return overall (100 - %idle) from an mpstat -P ALL log's Average/all row."""
    try:
        with open(path) as fh:
            for line in fh:
                tokens = line.split()
                if len(tokens) >= 3 and tokens[0] == "Average:" and tokens[1] == "all":
                    idle = float(tokens[-1])
                    return 100.0 - idle
    except Exception as e:
        print(f"  warning: failed to parse {path}: {e}")
    print(f"  warning: no 'Average: all' row found in {path}")
    return None


def parse_pidstat_avg_cpu(path):
    """Return the process's average %CPU from a pidstat log's Average row."""
    try:
        with open(path) as fh:
            header_tokens = None
            for line in fh:
                tokens = line.split()
                if not tokens:
                    continue
                if header_tokens is None and "%CPU" in tokens:
                    header_tokens = tokens
                    continue
                if header_tokens and tokens[0] == "Average:":
                    idx = header_tokens.index("%CPU")
                    return float(tokens[idx])
    except Exception as e:
        print(f"  warning: failed to parse {path}: {e}")
    print(f"  warning: no usable Average row found in {path}")
    return None


def load_cpu_metrics(root, label):
    mpstat_files = find_files(root, "mpstat.log")
    pidstat_files = find_files(root, "pidstat.log")

    sys_vals = []
    for f in mpstat_files:
        v = parse_mpstat_avg_all(f)
        if v is not None:
            print(f"  {f}: system CPU busy = {v:.2f}%")
            sys_vals.append(v)

    proc_vals = []
    for f in pidstat_files:
        v = parse_pidstat_avg_cpu(f)
        if v is not None:
            print(f"  {f}: process CPU = {v:.2f}%")
            proc_vals.append(v)

    sys_avg = sum(sys_vals) / len(sys_vals) if sys_vals else None
    proc_avg = sum(proc_vals) / len(proc_vals) if proc_vals else None
    return sys_avg, proc_avg


def plot_metric(df, direction, metric, ylabel, title, outpath):
    sub = df[df["direction"] == direction].sort_values("pkt_size")
    if sub.empty:
        print(f"  (skipping {outpath}: no data for direction={direction})")
        return

    fig, ax = plt.subplots(figsize=(7, 4.5))
    for mode, grp in sub.groupby("mode"):
        grp = grp.sort_values("pkt_size")
        ax.plot(grp["pkt_size"], grp[metric], marker="o", label=mode)

    if sub["pkt_size"].max() > 512:
        ax.axvline(512, color="gray", linestyle="--", linewidth=1)
        ax.text(512, ax.get_ylim()[1] * 0.95, " 512B fast-path cutoff",
                 rotation=90, va="top", ha="left", fontsize=8, color="gray")

    ax.set_xlabel("Inner payload size (bytes)")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(outpath, dpi=150)
    plt.close(fig)
    print(f"  wrote {outpath}")


def plot_cpu_comparison(baseline_sys, baseline_proc, offload_sys, offload_proc, outpath):
    categories = []
    baseline_vals = []
    offload_vals = []

    if baseline_sys is not None or offload_sys is not None:
        categories.append("System CPU (%)")
        baseline_vals.append(baseline_sys or 0)
        offload_vals.append(offload_sys or 0)

    if baseline_proc is not None or offload_proc is not None:
        categories.append("CU-UP process CPU (%)")
        baseline_vals.append(baseline_proc or 0)
        offload_vals.append(offload_proc or 0)

    if not categories:
        print("  (skipping cpu_comparison.png: no mpstat/pidstat data found on either side)")
        return

    import numpy as np
    x = np.arange(len(categories))
    width = 0.35

    fig, ax = plt.subplots(figsize=(6.5, 4.5))
    ax.bar(x - width / 2, baseline_vals, width, label="baseline")
    ax.bar(x + width / 2, offload_vals, width, label="offload")
    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    ax.set_ylabel("CPU utilization (%)")
    ax.set_title("CPU utilization: offload vs. baseline")
    ax.legend()
    ax.grid(True, axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(outpath, dpi=150)
    plt.close(fig)
    print(f"  wrote {outpath}")


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <baseline_dir> <offload_dir> [outdir]")
        sys.exit(1)

    baseline_dir = sys.argv[1]
    offload_dir = sys.argv[2]
    outdir = sys.argv[3] if len(sys.argv) > 3 else "./plots"
    os.makedirs(outdir, exist_ok=True)

    print(f"Scanning baseline dir: {baseline_dir}")
    baseline_df = load_summaries(baseline_dir, "baseline")
    print(f"Scanning offload dir:  {offload_dir}")
    offload_df = load_summaries(offload_dir, "offload")
    combined = pd.concat([baseline_df, offload_df], ignore_index=True)

    print("\nParsing CPU logs (baseline)...")
    baseline_sys, baseline_proc = load_cpu_metrics(baseline_dir, "baseline")
    print("Parsing CPU logs (offload)...")
    offload_sys, offload_proc = load_cpu_metrics(offload_dir, "offload")

    metrics = [
        ("mbps", "Throughput (Mbps)", "throughput"),
        ("loss_pct", "Packet loss (%)", "loss"),
        ("jitter_ms", "Jitter (ms)", "jitter"),
    ]

    print(f"\nPlotting into {outdir}/ ...")
    for direction, dir_label in [("ul", "Uplink"), ("dl", "Downlink")]:
        for metric, ylabel, fname_prefix in metrics:
            title = f"{dir_label}: {ylabel} vs. packet size (offload vs. baseline)"
            outpath = os.path.join(outdir, f"{fname_prefix}_{direction}.png")
            plot_metric(combined, direction, metric, ylabel, title, outpath)

    plot_cpu_comparison(baseline_sys, baseline_proc, offload_sys, offload_proc,
                         os.path.join(outdir, "cpu_comparison.png"))

    print("\nDone.")


if __name__ == "__main__":
    main()
