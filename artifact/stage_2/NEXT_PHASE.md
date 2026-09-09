# Next Implementation Phase

This picks up right after Step 1 (dynamic TEID/MAC learning, validated
redirect mechanism) and the confirmed root cause of the DU crash
(Problem 10 / the N3-vs-F1-U framing diagram, both in the main README).
Ciphering-off is now confirmed (`check_pdcp_is_off/`), so PDCP header
insertion can proceed without needing to handle encryption.

## 0. Fix the DU Crash (blocking everything else)

**Goal:** stop sending N3-shaped packets into F1-U. Concretely, for every
offloaded **N3 → F1-U** packet:

1. **Remove** the GTP-U extension header entirely (the PDU Session
   Container carrying QFI) — F1-U must not carry it, per the crash.
2. **Insert** a PDCP header (and SDAP header, if this bearer's config uses
   one) directly in front of the inner IP packet.
3. Rewrite the GTP-U mandatory header: `E=0`, no optional fields, updated
   `Length` field.
4. **Resize the packet** (`bpf_xdp_adjust_tail()`), since removing the
   extension header and inserting PDCP/SDAP headers are very unlikely to
   be exactly the same size — this is new; every rewrite so far has been
   same-size, in-place editing.
5. Recompute: IP header Total Length, UDP header Length, IP checksum
   (full recompute, as now), and either a proper incremental UDP checksum
   update or continue with checksum=0 (RFC 768-legal, our current
   approach) — revisit if this stops being sufficient.

**Before writing code:** confirm the *exact* PDCP(+SDAP) header format and
length actually used by this OAI bearer's configuration (SN length: 12-bit
vs 18-bit; SDAP present or not). Do this by capturing a **real**
(non-offloaded) DL F1-U packet sent by the genuine OAI CU-UP for the same
bearer type, and comparing its header bytes against 3GPP TS 38.323 (PDCP)
and TS 37.324 (SDAP) formats — so our inserted header is byte-for-byte
what the DU already successfully accepts from the real software path,
not just "a plausible-looking PDCP header." Getting this wrong risks a
different crash, not a fix.

**Sequence numbers:** the PDCP header needs a real, incrementing sequence
number, not a placeholder. Add a per-bearer counter to `session_ctx`
(e.g. `next_dl_pdcp_sn`), incremented on every offloaded packet for that
TEID. Wrap-around behavior needs to match the configured SN bit-width.

**Testing order:** validate with a synthetic offloaded flow first (as
established earlier in this project) before touching a live iperf3
session — confirm no crash, then confirm the DU actually forwards the
packet onward to the UE (not just "doesn't crash").

## 1. Extend to the Uplink Direction (F1-U → N3)

The reverse transform: strip the PDCP (+SDAP) header from a DU→CU packet,
re-add a PDU Session Container extension header with QFI, re-tunnel with
the N3-side TEID toward the UPF. Reuses the same `session_map` mechanism,
keyed by the F1-U-side ingress TEID instead of the N3-side one.

## 2. In-Order-Only Fast Path, Slow-Path Fallback

XDP can't naturally buffer/reorder packets. Track the last-seen PDCP SN
per bearer (in `session_ctx` or a new map); if an arriving packet's SN
isn't the expected next one, `XDP_PASS` it through untouched (let the
real CU-UP's normal PDCP reordering handle it) instead of forwarding a
potentially-misordered packet through the fast path.

## 3. Multi-Bearer / Multi-UE Correctness

Current F1AP watcher assumes a single active bearer. Extend it to
correlate F1AP messages to specific UE/PDU-session identifiers (the
`gNB-CU-UE-F1AP-ID` / `gNB-DU-UE-F1AP-ID` fields already visible in the
`UEContextSetupResponse` decode we captured earlier) so multiple
concurrent bearers each get their own correct, non-clobbering
`session_map` entry.

## 4. Trigger-Based Offload Daemon

Mirror CUP4/Blink's design: instead of offloading every learned bearer
unconditionally, monitor for real CU-UP saturation/loss signals and
enable/disable fast-path offload per-flow dynamically, via the same
`bpf_map_update_elem()`/delete mechanism already in place.

## 5. Benchmarking

Once end-to-end correctness holds (real iperf3 traffic completing
successfully through the fast path), measure median/tail packet
processing latency, PPS, and packet loss vs. number of active flows —
same methodology as the CUP4/Blink papers — for a directly comparable
result table.

---

**Immediate next action:** step 0, sub-step "confirm the exact PDCP/SDAP
header format" — everything else in this phase depends on getting that
byte layout right.
