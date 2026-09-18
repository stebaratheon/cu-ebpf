# Stage 4 — Offload vs. Baseline Benchmark

A/B benchmark comparing the eBPF fast-path (downlink N3 → F1-U offload)
against the CU's normal, non-offloaded path: throughput, packet loss and
jitter (iperf3, measured from the UE) across a URLLC-relevant packet-size
matrix, plus CPU utilization (mpstat/pidstat, measured on the CU) for
both modes.

The loader here (`xdp_gtp_inner_parser.bpf.c` / `_user.c`) is the same
program as stage_3's, plus two additions specific to benchmarking:

- **`DISABLE_OFFLOAD`** env var — when set, the F1AP/NGAP watchers still
  run and learn exactly as before (so parsing/logging overhead is
  identical), but the three functions that actually *write* a real entry
  into `session_map`/`ul_session_map` become no-ops. Since the kernel
  side strictly requires a map hit before it will rewrite/redirect
  anything, this makes every packet take the same `XDP_PASS` path as if
  the program weren't attached at all — a clean baseline.
- **`MAX_INNER_MOVE_BYTES` lowered from 1400 to 512** — matches the
  packet-size matrix below, which deliberately stops at 500B (see
  "Known caveats").

---

## ⚠️ Before you do anything: `FORCE_SKB_MODE` is baseline-only

`commands.txt`'s example invocation is:
```
DISABLE_OFFLOAD=1 FORCE_SKB_MODE=1 ./xdp_gtp_inner_parser_user eth0 | tee loader.log
```
That's correct **for the baseline pass only**. Generic/SKB-mode XDP has
been confirmed (separately, on this exact kernel/veth setup) to make
`bpf_redirect()` silently fail **100% of the time** — every packet gets
logged as a `HIT` (the loader can't see the failure; that's just how
`bpf_redirect()` works) but *none* of them ever actually reach the DU.

**For the offload pass, do not set `FORCE_SKB_MODE`.** Run the loader in
its default native/driver mode:
```
./xdp_gtp_inner_parser_user eth0 | tee loader.log
```
If you accidentally leave `FORCE_SKB_MODE=1` set for the offload pass,
the benchmark will silently measure "offload delivers ~0% of downlink
traffic" instead of the real fast path — and nothing in the tooling
below will flag it for you, since the loader's own `HIT` count in
`loader.log` looks identical either way (see "Known caveats").

Native mode does have a separate, known, unrelated quirk — the on-wire
`gtp->flags` byte sometimes reverts to its pre-rewrite value despite the
BPF program provably writing and retaining the correct value. This
doesn't block delivery (~94% of offloaded packets still arrived in prior
testing) and isn't a reason to fall back to `FORCE_SKB_MODE`; it's just
worth knowing about if DL numbers look slightly off from ideal.

---

## Files here

| File | Runs where | Purpose |
|---|---|---|
| `xdp_gtp_inner_parser.bpf.c` / `_user.c` | CU container | the loader itself (build/attach as usual) |
| `cu_benchmark_run.sh` | CU container | **monitor only** — captures `mpstat`/`pidstat` while you (or `run_benchmark_pass.sh`) run traffic elsewhere. Never touches the loader. |
| `ue_benchmark_matrix.sh` | UE container | drives the iperf3 UDP traffic matrix (both directions) against a single `iperf3 -s` on the DN side, writes `summary.csv` |
| `run_benchmark_pass.sh` | **host** | orchestrates one pass: starts the CU monitor, blocks on the UE traffic matrix, stops the monitor the instant traffic ends (exact timing — no guessed duration) |
| `plot_benchmark_results.py` | **host** | after `docker cp`-ing both passes' results locally, produces throughput/loss/jitter/CPU plots |
| `commands.txt` | — | the original raw step notes this README is written from; kept for reference |

---

## Prerequisites

1. **Containers up and healthy**, DU and UE already attached to the CU —
   i.e. bring up the stack in the usual order (core NFs → CU → DU → UE)
   *before* starting the loader, same as every previous stage.
2. **CU container**: `sysstat` installed (`mpstat`/`pidstat` come from
   it) — **not present by default**, confirmed via `which mpstat
   pidstat` coming back empty:
   ```
   apt-get update && apt-get install -y sysstat
   ```
3. **Deploy and build the stage_4 loader in the CU container** — nothing
   is deployed there yet (`/opt/oai-gnb/stage_4/` doesn't exist). Copy
   `xdp_gtp_inner_parser.bpf.c`, `xdp_gtp_inner_parser_user.c`, and
   `cu_benchmark_run.sh` in (e.g. to `/opt/oai-gnb/stage_4/`, mirroring
   the earlier stages' convention), then build the same way as every
   previous stage:
   ```
   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
     -I/usr/include/x86_64-linux-gnu \
     -c xdp_gtp_inner_parser.bpf.c -o xdp_gtp_inner_parser.bpf.o

   gcc -O2 -g xdp_gtp_inner_parser_user.c \
     -o xdp_gtp_inner_parser_user -lbpf -lelf -lz
   ```
4. **UE container**: `iperf3` is present by default; copy
   `ue_benchmark_matrix.sh` in (e.g. to `/opt/oai-nr-ue/`).
5. **`oai-ext-dn` container**: a single `iperf3 -s` running for the
   *entire* duration of both passes (the UE matrix uses `-R` for
   downlink, so one server handles both directions — no second server
   needed):
   ```
   iperf3 -s
   ```
6. **Host**, only if using `run_benchmark_pass.sh` and/or the plotting
   script:
   ```
   pip install pandas matplotlib
   ```
7. **Check `run_benchmark_pass.sh`'s `CONFIG` block before running it** —
   it currently has `CU_WORKDIR="/opt/oai-gnb/stage_3"`, left over from
   copying the script forward from the previous stage. Update it to
   wherever you actually deployed the stage_4 loader in step 3 (e.g.
   `/opt/oai-gnb/stage_4`), and set `BIND_IP` to the UE's *current*
   tunnel IP (`ip addr show oaitun_ue1` inside the UE container — this
   changes across UE restarts, it is **not** reliably `12.1.1.2`).

---

## Running a pass

You need **two passes**: one baseline, one offload. Each pass is: start
the loader in the right mode, then drive traffic while monitoring both
ends.

### Option A — orchestrated (`run_benchmark_pass.sh`), recommended

In the CU container, start the loader yourself first (the orchestrator
deliberately never touches it):

```bash
# Baseline pass:
DISABLE_OFFLOAD=1 FORCE_SKB_MODE=1 ./xdp_gtp_inner_parser_user eth0 | tee loader.log
```

Then, on the **host**, with prerequisite step 7 done:

```bash
./run_benchmark_pass.sh baseline
```

This starts `cu_benchmark_run.sh` in live mode (detached, in the CU
container), waits 2s for `mpstat`/`pidstat` to attach, then runs
`ue_benchmark_matrix.sh` on the UE (blocking) — 5 packet sizes × 2
directions × `REPS` reps × 15s each, so budget roughly
`5 × 2 × REPS × (15 + a few)` seconds. The instant the UE matrix
finishes, it stops the CU monitor via the stop-file mechanism (exact
timing — see `cu_benchmark_run.sh`'s header comment for why a stop-file
is used instead of a signal).

Stop the baseline loader (Ctrl+C), then restart it in offload mode
(**no `FORCE_SKB_MODE`** — see the warning above), let DU/UE re-attach
if needed, and run the offload pass:

```bash
# Offload pass:
./xdp_gtp_inner_parser_user eth0 | tee loader.log
```
```bash
./run_benchmark_pass.sh offload
```

### Option B — fully manual (matches `commands.txt`)

Useful if the orchestrator doesn't fit your setup, or you want more
control over timing.

1. Start the loader (mode-appropriate flags, per the warning above),
   piping to `loader.log`.
2. Find the CU-UP process for `pidstat`:
   ```bash
   sudo ss -tulnp | grep -E '2152|2153'
   ```
   gives you a PID from a line like
   `users:(("nr-softmodem",pid=1234,fd=27))`.
3. In a second CU terminal:
   ```bash
   ./cu_benchmark_run.sh live <cu_up_pid> loader.log
   ```
4. On the UE, in parallel:
   ```bash
   ./ue_benchmark_matrix.sh 192.168.72.135 <ue_tunnel_ip> baseline 3
   ```
   (`offload` instead of `baseline` for the second pass — this label is
   just a filename tag, it does **not** control the loader; make sure
   the loader is actually in the matching mode.)
5. When the UE matrix finishes, Ctrl+C `cu_benchmark_run.sh` (or touch
   its stop-file for scripted stops).
6. Repeat steps 1–5 for the other mode.

---

## Collecting and plotting results

Results are left sitting inside the containers — neither script copies
anything out or plots automatically.

```bash
docker cp <cu_container>:<CU_WORKDIR>/bench_results     ./results/baseline/cu   # after the baseline pass
docker cp <ue_container>:<UE_WORKDIR>/ue_bench_results   ./results/baseline/ue
docker cp <cu_container>:<CU_WORKDIR>/bench_results      ./results/offload/cu    # after the offload pass
docker cp <ue_container>:<UE_WORKDIR>/ue_bench_results   ./results/offload/ue
```
(Subfolder layout inside `./results/baseline` and `./results/offload`
doesn't matter — the plot script searches recursively for
`summary.csv`/`mpstat.log`/`pidstat.log`.)

Then, on the host:
```bash
python3 plot_benchmark_results.py ./results/baseline ./results/offload ./plots
```

Produces in `./plots/`:
- `throughput_ul.png`, `throughput_dl.png`
- `loss_ul.png`, `loss_dl.png`
- `jitter_ul.png`, `jitter_dl.png`
- `cpu_comparison.png` (system-wide, and CU-UP process if `pidstat`
  data was captured)

---

## Sanity-checking a pass before you trust it

`cu_benchmark_run.sh` writes `meta.txt` with `total_gtpu_packets` and
`total_offload_hits` (grepped from `loader.log`). Use it as a basic
sanity check:
- **Baseline pass**: `total_offload_hits` should be `0`.
- **Offload pass**: `total_offload_hits` should be a large, non-zero
  fraction of `total_gtpu_packets`.

**This does *not* catch the `FORCE_SKB_MODE`-on-offload mistake** — the
loader logs a `HIT` as soon as it *calls* `bpf_redirect()`, regardless
of whether the kernel actually delivers the packet, so the hit count
looks the same whether delivery succeeds or not. The only way to catch
that mistake is in the iperf3 numbers themselves: if the offload pass's
downlink `loss_pct` is near 100% while `total_offload_hits` looks
healthy, that's the signature — go re-check the loader was started
without `FORCE_SKB_MODE`.

---

## Known caveats

- **512-byte packet-size cutoff.** `ue_benchmark_matrix.sh`'s matrix
  (100/200/300/400/500 bytes) deliberately stays at or under the
  fast-path's `MAX_INNER_MOVE_BYTES` bound (512 in this stage's
  loader). Packets above that bound aren't offloaded (they fall back to
  `XDP_PASS`, still correct, just not accelerated) — going above 512 in
  the matrix is fine for confirming that graceful-bypass behavior, but
  changes the total UE-side runtime, so recompute the CU-side monitoring
  duration if you do (or just use live mode via `run_benchmark_pass.sh`,
  which times itself automatically).
- **Single UE / single bearer.** Same limitation as stage 3 — the
  F1AP/NGAP watchers track only the most recently announced endpoint
  each, so this benchmark setup assumes one active UE/PDU session at a
  time.
- **Uplink offload is implemented in this stage** (unlike stage 3, where
  it was recognition/learning only) — a full F1-U→N3 rewrite+redirect,
  gated on `ul_session_map`'s `ready` flag, structurally mirroring the
  downlink path (grow instead of shrink, reverse-order payload copy,
  `bpf_xdp_adjust_tail()` called *before* the move instead of after).
  So both UL and DL numbers should differ between the baseline and
  offload passes here — `DISABLE_OFFLOAD` correctly suppresses both
  (it blocks any map entry from ever becoming real/`ready`, which both
  directions' offload checks require).
