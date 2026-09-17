# Stage 3 — Uplink Pipeline (Recognition, Learning, and Offload)

This stage covers everything built on the **uplink** (DU → CU → UPF) side
of the F1-U/N3 fast-path offload. Downlink (N3 → F1-U) offload is already
working and is documented separately; this stage does not touch that path
except to make sure uplink traffic can never accidentally fall into it.

**Status: uplink offload is implemented and confirmed working end to end**
— independently verified via a UPF-side sniffer and a successful iperf3
transfer, not just the CU's own logs. See "Confirmed working" below.

---

## What this stage implements

### 1. Correct parsing of real F1-U-framed uplink packets

F1-U packets (both directions) carry a 3-byte PDCP header + 1-byte SDAP
header immediately after the mandatory 8-byte GTP-U header, with **no**
GTP-U extension header — unlike N3, which carries QFI in a GTP-U
extension (PDU Session Container) and has no PDCP/SDAP at all. The parser
previously assumed every GTP-U packet's inner IP header started right
after the mandatory header (correct for N3, wrong for F1-U), so every
real uplink packet was logged as "Inner IP: unavailable."

Fixed by classifying each packet by which port it arrived on
(`event->is_f1u`, true for port 2153), and when set, reading the 4-byte
PDCP+SDAP block first (yielding the PDCP SN and QFI) before attempting the
inner-IP parse.

### 2. `ul_session_map` — uplink session table (BPF hash map)

Keyed by TEID, reusing `struct session_ctx`. Holds everything the uplink
rewrite needs: `peer_teid`/`dst_ip`/`dst_port` (the UPF's N3 endpoint),
`dst_mac`/`src_mac`/`egress_ifindex` (resolved via ARP), and an explicit
`ready` byte (see item 5) gating whether an entry is actually safe to
offload from.

### 3. Downlink offload explicitly gated off for uplink packets

The N3→F1-U offload block and the DL auto-learn call are both re-gated
with an explicit `!event->is_f1u` / `!is_f1u` check, so uplink packets can
never be matched against the *downlink* session map or corrupt it.

### 4. F1AP + NGAP watchers learn both halves of the uplink mapping

The F1AP watcher learns the UL F1-U TEID (the CU's own advertised address
from `UEContextSetupRequest`, for the DU to send uplink traffic to). A new
NGAP watcher thread learns the UPF's N3 address and TEID from
`PDUSessionResourceSetupRequest`'s "UL NG-U UP TNL Information" IE.
`maybe_complete_ul_session_map()` ties both together, order-independent,
and upgrades the map entry once both are known.

### 5. UPF MAC resolution + explicit completeness gate

`upf_mac_refresh_thread()` (the uplink analogue of the existing DU MAC
refresh thread) resolves the UPF's MAC via ARP once the NGAP watcher
learns its address. `struct session_ctx` gained an explicit `ready` byte,
mirrored in both the kernel and userspace programs: downlink entries are
always `ready=1` (inserted complete in one shot); uplink entries start at
`ready=0` and flip to `1` only once the UPF's MAC has also been resolved.
The kernel reads this back per-packet (`event->ul_map_ready`) and — as of
item 6 below — actually gates the rewrite on it.

### 6. The uplink rewrite + redirect ("construct the N3 packet from the F1 info")

Implemented as the structural mirror image of the downlink rewrite, but
**not** a mirror-image implementation:

- Downlink *shrinks* the packet (removes a variable-length N3 extension
  header, replaces it with a fixed 4-byte PDCP+SDAP block) — net delta is
  negative, payload compacted *left* with a forward-order copy,
  `bpf_xdp_adjust_tail()` called *after* the move.
- Uplink *grows* the packet (removes the fixed 4-byte PDCP+SDAP block,
  inserts a 4-byte optional field block + 4-byte PDU Session Container
  extension = 8 bytes) — net delta is **+4 bytes**. `bpf_xdp_adjust_tail()`
  must run *first* (to have room to write into), and the inner payload is
  shifted *right* — since the regions overlap, this requires copying in
  **reverse order** (highest offset first), the opposite direction from
  the downlink loop.
- New GTP-U header fields constructed: `flags = 0x34` (E=1), the 4-byte
  optional block (seq/npdu/next-ext-type=`0x85`), and the 4-byte PDU
  Session Container extension (`length=1`, `PDU_TYPE=1 (UL)`, `QFI` from
  the SDAP byte already read, `next-ext-type=0`).
- Outer L2/L3/L4 rewrite and checksum recompute follow the same pattern as
  the downlink path.
- Strictly gated on the matched `ul_session_map` entry's `ready == 1`
  (item 5) before any of the above runs.

---

## Bugs found and fixed during this stage

1. **Inner-IP misparse on uplink** — see item 1 above.

2. **Latent DL-auto-learn corruption, caught before shipping** — fixing
   the inner-IP parse had a side effect (uplink events started reporting
   `inner_ip_present == 1`) that would have silently broken an unrelated,
   already-working code path if the call site hadn't been re-guarded with
   `!is_f1u`.

3. **`FORCE_SKB_MODE` forgotten a second time** — unrelated to uplink
   logic itself, but cost real debugging time: setting the env var as a
   bare shell variable instead of exporting/inlining it silently
   re-enabled native-mode XDP attach, reintroducing a known,
   separate downlink-side flags-corruption bug. **Second time this exact
   mistake has happened in this project** — see "What's left" item 4.

4. **NGAP field name case mismatch** — guessed
   `ngap.transportLayerAddressIPv4` by analogy with F1AP's (lowercase)
   field. The real field, confirmed against a live capture, is
   `ngap.TransportLayerAddressIPv4` — capital `T`. `tshark -e` is
   case-sensitive, so the wrong casing produced a silently empty column
   instead of an error.

5. **NGAP direction filter relied on an unconfirmed field name** — an
   attempt to discriminate `PDUSessionResourceSetupRequest` (UPF's uplink
   info, wanted) from `PDUSessionResourceSetupResponse` (gNB's own
   downlink info, not wanted) via `&& ngap.initiatingMessage` in the
   tshark filter failed silently: the field wasn't real/filterable, so
   tshark failed to parse the filter and exited immediately — **not even
   the watcher's own "capture is live" startup line printed.** Recognized
   this as the signature of "the tshark process itself never started,"
   not "the filter matched nothing." Fixed by dropping the tshark-side
   filter and discriminating in C instead (compare the extracted IP
   against `g_own_ip`), same pattern the F1AP watcher already used.

6. **LLVM BPF backend crash: "Branch target out of insn range"** — after
   implementing the uplink rewrite's reverse-copy loop (`#pragma unroll`,
   bounded by `MAX_INNER_MOVE_BYTES = 1400`, identical bound to the
   existing downlink compaction loop), the kernel program stopped
   compiling entirely. Root cause, confirmed by actually installing a
   matching clang/BPF toolchain and reproducing the crash: `#pragma
   unroll` fully unrolls a loop into straight-line instructions at compile
   time. One 1400-iteration unrolled loop (downlink) compiled fine on its
   own (every prior stage's successful builds are proof of this); a
   *second*, identically-sized loop (uplink) in the same program pushed
   the function's size past what a single relative-branch instruction can
   encode in the BPF backend — an assembler/backend limit, not a verifier
   or logic bug. Confirmed by binary search: fails at `MAX_INNER_MOVE_BYTES
   ≥ 945`, compiles cleanly at `≤ 940` (exact flags: `-O2 -g -target bpf`).

   **Fix:** reduced `MAX_INNER_MOVE_BYTES` to **512** — well clear of the
   measured cliff. This is a real, deliberate tradeoff, not a free fix:
   any packet whose *inner* payload exceeds 512 bytes now skips the fast
   path in **both** directions (falls through to plain `XDP_PASS`,
   unmodified — still correct, just not offloaded). Accepted for now
   since the target use case is URLLC traffic (small, latency-sensitive
   payloads), not bulk throughput. A structurally proper fix — splitting
   the copy loop into a `static __attribute__((noinline))` BPF subprogram
   (a real function call instead of inlined-and-duplicated unrolled code)
   — would restore full ~1450-byte coverage on both directions without
   hitting this limit again, but hasn't been implemented or verified
   against a real kernel's verifier yet. See "What's left" item 2.

7. **Stale "no offload applied yet" log line, now misleading** — the
   original info-only `UL session map: HIT/MISS` print predates the real
   rewrite (item 6) and was never re-gated once it went live, so it kept
   printing "-- info only, no offload applied yet" on every uplink packet
   even after the offload had, in fact, just been applied to that same
   packet (redundant with, and contradicting, the `Fast-path offload: HIT`
   line immediately above it). Fixed by suppressing this line whenever
   `event->offload_applied` is set; it now only prints for the genuinely
   still-relevant cases (`MISS`, `HIT, not ready`).

---

## Confirmed working (current end state of this stage)

Learning (F1AP + NGAP correlation, MAC resolution):

```
NGAP watcher: capture is live (first matching packet seen)
NGAP watcher: learned N3 UL tunnel TEID 0x00000007 @ 192.168.71.134 (the UPF's address)
F1AP watcher: capture is live (first matching packet seen) -- safe to bring up DU/UE from here on
F1AP watcher: learned UL F1-U TEID 0x6e395e28 @ 192.168.71.150 (this CU's own address)
  [auto-learned] ul_session_map: UL F1-U TEID 0x6e395e28 registered (info-only, no offload yet)
F1AP watcher: learned DL F1-U TEID 0x85911b9a @ 192.168.71.171
  [auto-learned] ul_session_map: UL F1-U TEID 0x6e395e28 updated -> N3 UL TEID 0x00000007 @ 192.168.71.134:2152 (MAC/interface still pending)
UPF MAC refresh: now targeting UPF address 192.168.71.134 (learned via NGAP)
UPF MAC (192.168.71.134) resolved/updated: 7a:43:d9:5e:f1:6d
  [auto-learned] ul_session_map: UL F1-U TEID 0x6e395e28 COMPLETE -> N3 UL TEID 0x00000007 @ 192.168.71.134:2152, MAC 7a:43:d9:5e:f1:6d, egress ifindex 2 -- ready for offload gate
```

The actual rewrite + redirect, on the CU:

```
GTP-U packet found (count: 1)
  Outer path:       192.168.71.171:2153 -> 192.168.71.150:2153
  Framing:          F1-U (PDCP+SDAP, no GTP extension)
  TEID:             1849253416 (0x6e395e28)
  Flags:            E=0 S=0 PN=0
  PDCP SN (F1-U):   0
  QFI:              1
  Fast-path offload: HIT -> new TEID 7 (0x00000007), redirected to 192.168.71.134:2152
  [debug] old_removed_bytes=4 move_len=48 delta=4 reached_rewrite=1
  [debug] gtp->flags read back: right_after_write=0x34 right_before_redirect=0x34
```

Independently confirmed by sniffing the UPF's own N3 interface (`eth0`,
`192.168.71.134`), using `sniff_udp_port_upf.py`:

```
python3 sniff_udp_port_upf.py eth0 2152 192.168.71.150
```

```
[6275] 192.168.71.150:2153 -> 192.168.71.134:2152  UDP payload 68 bytes  TEID=0x00000007 msg_type=255 gtp_flags=0x34 (E=1 S=0 PN=0)
  Framing check:    E=1 -- N3-style framing (extension header expected, first type=0x85).
    [0] PDU Session Container (len=4 bytes): PDU_TYPE=1 (UL PDU SESSION INFORMATION), QFI=1
  Inner IP header found at payload offset 16: IPv4, protocol=6 (TCP), 12.1.1.2 -> 192.168.72.135
```

Same TEID, same flags, same QFI as the CU's own log — this is the real
proof: not just "the CU claims it redirected," but "the UPF received a
well-formed N3 packet with the right header content."

End-to-end application traffic, generated from `oai-nr-ue` with:

```
iperf3 -c 192.168.72.135 -B 12.1.1.2 -u -l 200 -b 1M -t 30
```

(`-u -l 200` keeps every datagram's inner payload safely under the
512-byte fast-path cap from bug #6 above, so this traffic profile
reliably exercises the offload path rather than silently falling
through to the slow path.) The iperf3 server received the full transfer.

---

## What's left

1. **Multi-bearer / multi-UE correctness.** Both the F1AP and NGAP
   watchers currently track only a single, most-recently-announced
   endpoint each (`f1u_dl_teid`, `f1u_ul_teid`, `n3_ul_teid`/`n3_ul_ip` are
   bare globals, not tables). Adequate for the current one-UE/one-bearer
   testbed only; needs real correlation to specific UEs/PDU
   sessions/DRBs before it can handle more than one concurrent session.

2. **Restore full-size packet coverage on the fast path.**
   `MAX_INNER_MOVE_BYTES = 512` (bug #6) means any packet — either
   direction — with an inner payload over 512 bytes currently bypasses
   the fast path entirely. Fine for the current URLLC-focused target
   traffic profile, but if bulk-throughput traffic ever needs to be
   fast-pathed too, the proper fix is splitting the unrolled copy loops
   into `static __attribute__((noinline))` BPF subprograms (real function
   calls instead of inlined-and-duplicated code), which should allow
   restoring close to the original ~1450-byte bound without hitting the
   branch-range limit again. Not yet implemented or tested against a real
   kernel's verifier.

3. **Field-name/version portability.** The NGAP field names and filter
   syntax were confirmed only against one specific tshark build via a
   manual capture. If ever run against a different tshark/Wireshark
   version, re-verify with `tshark -T json` before trusting the watchers
   — the same way both NGAP bugs in this stage were actually found.

4. **`FORCE_SKB_MODE` is still an easy-to-forget environment variable**
   guarding a workaround for a real, unresolved kernel/veth bug. Given it
   has now caused two separate debugging sessions when forgotten, it's
   worth considering hardcoding SKB mode directly rather than relying on
   remembering to set it correctly every run, until the underlying
   native-mode bug is actually root-caused.
