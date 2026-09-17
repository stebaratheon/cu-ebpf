# Stage 3 — Uplink Pipeline (Recognition + Learning)

This stage covers everything built so far on the **uplink** (DU → CU → UPF)
side of the F1-U/N3 fast-path offload. Downlink (N3 → F1-U) offload is
already working and is documented separately; this stage does **not**
touch that path except to make sure uplink traffic can never accidentally
fall into it.

**Status: recognition and learning are done and confirmed working end to
end. The actual uplink rewrite/redirect has not been written yet.** Every
uplink packet is still `XDP_PASS`ed through completely unmodified.

---

## What this stage implements

### 1. Correct parsing of real F1-U-framed uplink packets

F1-U packets (both directions) carry a 3-byte PDCP header + 1-byte SDAP
header immediately after the mandatory 8-byte GTP-U header, with **no**
GTP-U extension header — unlike N3, which carries QFI in a GTP-U
extension (PDU Session Container) and has no PDCP/SDAP at all. The
parser previously assumed every GTP-U packet's inner IP header started
right after the mandatory header (correct for N3, wrong for F1-U), so
every real uplink packet was logged as "Inner IP: unavailable."

Fixed by classifying each packet by which port it arrived on
(`event->is_f1u`, true for port 2153), and when set, reading the 4-byte
PDCP+SDAP block first (yielding the PDCP SN and QFI) before attempting
the inner-IP parse.

### 2. `ul_session_map` — uplink session table (BPF hash map)

A new map, keyed by TEID, reusing `struct session_ctx` for forward
compatibility with the eventual uplink rewrite. Right now it exists
purely to prove that (a) the TEID the DU actually uses matches what we
learn from signaling, and (b) userspace can populate it correctly —
**no code path reads this map for a rewrite or redirect yet.**

### 3. Downlink offload explicitly gated off for uplink packets

The existing N3→F1-U offload block (kernel) and the existing DL
auto-learn call (userspace) were both re-gated with an explicit
`!event->is_f1u` / `!is_f1u` check. Without this, once uplink packets
also started getting `inner_ip_present == 1` (from fix #1 above), the
downlink auto-learn logic would have started firing on uplink events and
corrupting the *downlink* session map with an uplink TEID as the key.
Caught and fixed before it ever shipped as a live bug.

### 4. F1AP watcher: now also learns the UL F1-U TEID

The F1AP watcher previously discarded the "UL GTP Tunnel" IE from
`UEContextSetupRequest` (the CU's own advertised address for the DU to
send uplink traffic to), treating anything that wasn't the DU's address
as noise. It now recognizes this IE by comparing the address against the
CU's own IP, and registers a (still-empty) placeholder in
`ul_session_map` keyed by that TEID.

### 5. NGAP watcher (new): learns the N3 uplink destination

A new background thread, parallel to the F1AP watcher, tails NGAP/SCTP
traffic for the `PDUSessionResourceSetupRequest`'s "UL NG-U UP TNL
Information" IE — the UPF's own N3 address and the TEID it expects for
uplink traffic. This is the piece of information nothing in the program
had access to before this stage.

`maybe_complete_ul_session_map()` ties both watchers together: once
**both** the F1-U-side key (from F1AP) and the N3-side destination (from
NGAP) are known — in either order — it upgrades the placeholder entry
with the real `peer_teid`/`dst_ip`. `egress_ifindex`/`dst_mac`/`src_mac`
are intentionally still left zero (see "What's left" below).

---

## Bugs found and fixed during this stage

1. **Inner-IP misparse on uplink** — see item 1 above. Root cause: the
   parser had no concept of F1-U's distinct PDCP+SDAP framing; it only
   understood N3's extension-header framing.

2. **Latent DL-auto-learn corruption, caught before shipping** — see
   item 3 above. Fixing the inner-IP parse had a side effect (uplink
   events started reporting `inner_ip_present == 1`) that would have
   silently broken an unrelated, already-working code path if the call
   site hadn't been re-guarded.

3. **`FORCE_SKB_MODE` forgotten a second time** — unrelated to any uplink
   logic (uplink code only logs and `XDP_PASS`es), but worth recording
   here since it fully stalled uplink testing and cost real debugging
   time before being correctly identified: setting the env var as a bare
   shell variable instead of exporting/inlining it silently re-enabled
   native-mode XDP attach, which reintroduces a known, separate
   downlink-side flags-corruption bug. **This is the second time this
   exact mistake has happened in this project.**

4. **NGAP field name case mismatch** — guessed
   `ngap.transportLayerAddressIPv4` by analogy with F1AP's (lowercase)
   field of the same purpose. The real field, confirmed against a live
   capture, is `ngap.TransportLayerAddressIPv4` — capital `T`. Since
   `tshark -e` is case-sensitive, the wrong casing produced a silently
   empty column instead of an error.

5. **NGAP direction filter relied on an unconfirmed field name** — an
   attempt to discriminate `PDUSessionResourceSetupRequest` (carries the
   UPF's uplink info, wanted) from `PDUSessionResourceSetupResponse`
   (carries the gNB's own downlink info, not wanted) via
   `&& ngap.initiatingMessage` in the tshark display filter failed
   silently: the field wasn't a real filterable name, so tshark failed
   to parse the filter and exited immediately — **not even the watcher's
   own "capture is live" startup line printed.** That specific
   symptom (a background watcher thread producing zero output at all,
   including its own startup log) is now a recognizable signature of "the
   tshark process itself never started successfully," worth checking for
   again if a similar watcher is silent in the future.

   **Fix:** dropped the tshark-side filter and reused the pattern the
   F1AP watcher already used successfully — filter loosely on
   `ngap.gTP_TEID` alone, extract the IP unconditionally, and discriminate
   in C by comparing it against the CU's own address (`g_own_ip`).

---

## Confirmed working (current end state of this stage)

```
NGAP watcher: capture is live (first matching packet seen)
NGAP watcher: learned N3 UL tunnel TEID 0x00000003 @ 192.168.71.134 (the UPF's address)
F1AP watcher: capture is live (first matching packet seen) -- safe to bring up DU/UE from here on
F1AP watcher: learned UL F1-U TEID 0x4cf10768 @ 192.168.71.150 (this CU's own address)
  [auto-learned] ul_session_map: UL F1-U TEID 0x4cf10768 registered (info-only, no offload yet)
  [auto-learned] ul_session_map: UL F1-U TEID 0x4cf10768 completed -> N3 UL TEID 0x00000003 @ 192.168.71.134:2152 (egress MAC/interface still pending)
F1AP watcher: learned DL F1-U TEID 0x8d4411a0 @ 192.168.71.171
```

Both halves of the uplink mapping are learned automatically and
correlated correctly, regardless of which signaling message arrives
first. Real uplink data packets are correctly parsed (PDCP SN, QFI,
inner IP/TCP all decode) and correctly report `HIT` against
`ul_session_map` by TEID — with zero effect on the packet itself.

---

## What's left (to be replaced by the next stage's journal entry)

Two items from this list's original version are now done, confirmed
against live traffic:

- **MAC resolution toward the UPF** — `upf_mac_refresh_thread()` (the
  uplink analogue of the existing DU MAC refresh thread) now resolves
  the UPF's MAC via ARP once the NGAP watcher learns its address, and
  `ul_session_map`'s `dst_mac`/`src_mac`/`egress_ifindex` are populated
  from it.
- **Offload gating on map completeness** — `struct session_ctx` gained
  an explicit `ready` byte (mirrored in both the kernel and userspace
  programs). `ul_session_map` entries start at `ready=0` when first
  registered and flip to `ready=1` only once the UPF's MAC has also
  been resolved. The kernel's uplink lookup already reads this back
  per-packet (`event->ul_map_ready`), confirmed on live traffic:
  the first uplink packet(s) after bearer setup correctly report
  `HIT, not ready`, and every packet after the UPF MAC resolves
  correctly flips to `HIT, READY`.

This is the honest boundary of what exists today. None of the following
is implemented yet:

1. **The actual uplink rewrite + redirect ("construct the N3 packet from
   the F1 info").** This is structurally different from the existing
   downlink rewrite, not a mirror-image reuse of it:
   - Downlink *shrinks* the packet (removes a variable-length N3
     extension header, replaces it with a fixed 4-byte PDCP+SDAP block) —
     net **delta is negative**, and the payload is compacted *left* with
     a forward-order copy, with `bpf_xdp_adjust_tail()` called *after*
     the move.
   - Uplink has to *grow* the packet (remove the fixed 4-byte PDCP+SDAP
     block, insert a 4-byte optional field block + 4-byte PDU Session
     Container extension = 8 bytes) — net **delta is +4 bytes**. This
     means `bpf_xdp_adjust_tail()` has to be called *first* (to actually
     have room to write into), and the inner payload has to be shifted
     *right*, which — because the regions overlap — requires copying in
     **reverse order** (highest offset first) instead of the existing
     loop's forward order, or source bytes get clobbered before they're
     read.
   - New GTP-U header fields to construct: `flags = 0x34` (E=1), the
     4-byte optional block (seq/npdu/next-ext-type=`0x85`), and the
     4-byte PDU Session Container extension itself
     (`length=1`, `PDU_TYPE=1 (UL)`, `QFI` from the SDAP byte already
     being read, `next-ext-type=0`) — byte layout already confirmed
     against a real captured N3 uplink packet earlier in this project.
   - Outer L2/L3/L4 rewrite (dst MAC/IP/port toward the UPF, checksum
     recompute) follows the same pattern as the existing downlink
     rewrite once the above is in place.
   - This rewrite must only fire when the matched `ul_session_map` entry
     has `ready == 1` (see above) — the gate already exists and is
     confirmed correct; the rewrite itself just needs to check it.

2. **Multi-bearer / multi-UE correctness.** Both the F1AP and NGAP
   watchers currently track only a single, most-recently-announced
   endpoint each (`f1u_dl_teid`, `f1u_ul_teid`, `n3_ul_teid`/`n3_ul_ip`
   are bare globals, not tables). This is adequate for the current
   one-UE/one-bearer testbed only, and needs real correlation to
   specific UEs/PDU sessions/DRBs before it can handle more than one
   concurrent session.

3. **Field-name/version portability.** The NGAP field names and filter
   syntax used here were confirmed only against one specific tshark
   build via a manual capture. If this is ever run against a different
   tshark/Wireshark version, re-verify with `tshark -T json` before
   trusting the watchers — the same way both NGAP bugs in this stage
   were actually found.

4. **`FORCE_SKB_MODE` is still an easy-to-forget environment variable**
   guarding a workaround for a real, unresolved kernel/veth bug. Given it
   has already caused two separate debugging sessions when forgotten,
   it's worth considering hardcoding SKB mode directly rather than
   relying on remembering to set it correctly every run, until the
   underlying native-mode bug is actually root-caused.