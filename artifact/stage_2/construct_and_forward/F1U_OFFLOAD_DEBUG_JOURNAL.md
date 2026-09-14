# F1-U Fast-Path Offload: Debugging Journal

This document records two production-blocking bugs found while bringing up
the XDP-based N3 → F1-U fast-path offload (CU side), how they were
diagnosed, and how they were fixed. It also lists follow-up items worth
tracking now that the path is working end-to-end (confirmed via a
successful `iperf3` transfer through the UE).

**Scope:** everything here is about the **downlink** offload (N3 → F1-U,
UPF-facing traffic being re-tunneled toward the DU). The reverse direction
(F1-U → N3, uplink fast-path) is not implemented yet — see `NEXT_PHASE.md`
item 1. Uplink packets are always a `session_map` miss and pass through
this program completely untouched (`XDP_PASS`), handled entirely by the
pre-existing, non-XDP CU-UP path.

## TL;DR

Two bugs stacked on top of each other, and fixing only the first one was
not enough to get real traffic through:

1. **Native-mode XDP redirect was reverting a rewritten byte on the wire**
   (fixed with a `FORCE_SKB_MODE=1` workaround — see Bug #1).
2. **Even with framing fixed, userspace was resetting the DU's expected
   PDCP sequence number on every packet**, so the DU silently discarded
   everything past the first packet or two (see Bug #2).

Only after *both* were fixed did traffic actually flow end-to-end.

---

## Symptom (starting point)

- The CU's XDP program reported `Fast-path offload: HIT` with the correct
  rewritten TEID/destination, and its own debug fields
  (`debug_flags_right_after_write`, `debug_flags_right_before_redirect`)
  both showed the correct new GTP-U flags byte (`0x30`).
- Both the CU-side and DU-side raw UDP sniffers, however, saw the *old*
  flags byte (`0x34`, i.e. `E=1`) on the wire.
- No crash on either side. Traffic simply stalled after the first packet
  — no further packets, no throughput.

---

## Bug #1 — GTP-U flags byte reverting between kernel write and wire, in native-mode XDP redirect

### Diagnosis

The mismatch was very specific: **every field survived the rewrite except
the one-byte `gtp->flags`**, and only in the gap between the kernel
program's own read-back (`0x30`, correct) and what actually left the
box (`0x34`, stale/pre-rewrite value). Because `flags` is written *after*
`bpf_xdp_adjust_tail()` shrinks the packet (to remove the old GTP-U
extension header and its optional fields, replacing them with the fixed
4-byte PDCP+SDAP header), the leading theory was a native-mode XDP +
`bpf_redirect()` interaction with `bpf_xdp_adjust_tail()` on this
veth/kernel combination — i.e. the redirect path was using a buffer view
that predated the final byte-level write.

This was already anticipated in the code as a `FORCE_SKB_MODE` diagnostic
switch, added specifically to test whether the corruption was isolated to
native (driver) mode XDP redirect vs. generic (SKB) mode.

### Confirmation

Running with:

```bash
FORCE_SKB_MODE=1 ./xdp_gtp_inner_parser_user eth0
```

(note: this must be on the *same command line*, or `export`ed first — a
bare `FORCE_SKB_MODE=1` on its own line only sets a shell variable, it
does not get inherited by a program launched in a later, separate
command)

...caused the process to print `Attached in generic (SKB) mode.`, and
from that point on, both the CU-side and DU-side sniffers correctly
showed `gtp_flags=0x30 (E=0 S=0 PN=0)` — matching the fixed F1-U framing
exactly, with the PDCP+SDAP header landing at the expected offset
(4 bytes into the PDCP PDU) and a clean plaintext IPv4 header
immediately after.

This confirmed the corruption was specific to **native-mode XDP
redirect**, on this veth/kernel, combined with a preceding
`bpf_xdp_adjust_tail()` call that shrinks the packet.

### Fix (workaround)

Run the userspace loader with `FORCE_SKB_MODE=1`, forcing generic/SKB-mode
XDP attach instead of native/driver mode. This is a **workaround**, not a
root-cause fix — the underlying kernel/veth-driver interaction between
native XDP redirect and `bpf_xdp_adjust_tail()` is still unresolved
upstream.

### Result

Framing on the wire was now correct — but this alone did **not** resolve
the original symptom (traffic stalling after the first packet). See Bug #2.

---

## Bug #2 — `next_dl_pdcp_sn` reset by userspace on every packet (auto-learn race)

### Symptom

With Bug #1 fixed, framing was now correct on the wire and many packets
arrived cleanly at the DU (visible in the sniffer's byte-level decode).
However, `iperf3` only ever printed:

```
Server listening on 5201
-----------------------------------------------------------
Accepted connection from 192.168.72.134, port 52937
```

...with no subsequent throughput lines. The TCP handshake completed, but
no application data appeared to make it through.

### Root cause

`maybe_learn_and_populate()` in the userspace program is called for
**every** downlink GTP-U event with a parsable inner IP header — i.e. on
every real user-data packet, not just the first one for a given TEID. The
function's own comment claimed it should only act "if this N3 TEID isn't
mapped yet," but the code never actually checked that:

```c
memset(&sess, 0, sizeof(sess));
...
bpf_map_update_elem(g_session_map_fd, &key, &sess, BPF_ANY);
```

Every call `memset()`-zeroed a fresh `session_ctx` (zeroing
`next_dl_pdcp_sn` in the process) and unconditionally overwrote the
*entire* existing map entry with `BPF_ANY`.

Meanwhile, the kernel-side XDP program increments that same
`next_dl_pdcp_sn` counter (via `__sync_fetch_and_add`) on every offloaded
packet, to give the DU a monotonically increasing PDCP DL sequence
number. Because the ring-buffer event for a packet reaches userspace
*after* the kernel has already used the counter for that packet, but
*before* the kernel processes the next one, userspace was continuously
racing the kernel and stomping the counter back toward zero.

Net effect: PDCP sequence numbers delivered to the DU jumped around /
reset instead of incrementing. A real PDCP entity on the DU maintains a
receive window keyed on SN continuity — SNs that repeat or go backwards
are, correctly, treated as duplicates or out-of-window and silently
discarded rather than delivered up through RLC/MAC to the UE. This
matches the symptom exactly: TCP's tiny handshake packets tolerated the
disruption well enough to complete once, but sustained application data
never got through.

### Fix

Guard the auto-learn path with a lookup-before-insert check, and use
`BPF_NOEXIST` instead of `BPF_ANY` as a second line of defense against a
race between two events for a brand-new TEID:

```c
static void maybe_learn_and_populate(const struct gtp_event *event)
{
    struct session_ctx sess;
    struct session_ctx existing;
    __u32 key;
    __u8 du_mac[ETH_ALEN];

    key = event->teid;

    /* Already mapped -- leave it alone so next_dl_pdcp_sn (owned by the
     * kernel program from here on) is never reset. */
    if (bpf_map_lookup_elem(g_session_map_fd, &key, &existing) == 0)
        return;

    pthread_mutex_lock(&f1u_lock);
    if (!f1u_dl_known) {
        pthread_mutex_unlock(&f1u_lock);
        return;
    }

    memset(&sess, 0, sizeof(sess));
    sess.peer_teid = f1u_dl_teid;
    sess.dst_ip = f1u_dl_ip;
    sess.src_ip = g_own_ip;
    pthread_mutex_unlock(&f1u_lock);

    pthread_mutex_lock(&g_du_mac_lock);
    if (!g_du_mac_valid) {
        pthread_mutex_unlock(&g_du_mac_lock);
        return; /* DU not resolved yet (e.g. not up) -- try again next packet */
    }
    memcpy(du_mac, g_du_mac, ETH_ALEN);
    pthread_mutex_unlock(&g_du_mac_lock);

    sess.dst_port = htons(F1U_PORT);
    sess.egress_ifindex = g_egress_ifindex;
    memcpy(sess.dst_mac, du_mac, ETH_ALEN);
    memcpy(sess.src_mac, g_own_mac, ETH_ALEN);
    /* next_dl_pdcp_sn stays 0 here -- this is the one-time initial
     * population; the kernel program takes over incrementing it from
     * this point on. */

    if (bpf_map_update_elem(g_session_map_fd, &key, &sess, BPF_NOEXIST) == 0) {
        char dst[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &sess.dst_ip, dst, sizeof(dst));
        printf("  [auto-learned] session_map: N3 TEID 0x%08x -> F1-U TEID 0x%08x @ %s:%u\n",
               event->teid, sess.peer_teid, dst, F1U_PORT);
    } else if (errno != EEXIST) {
        fprintf(stderr, "  [auto-learned] session_map update failed: %s\n", strerror(errno));
    }
    /* EEXIST here just means another thread/event raced us and inserted
     * it first -- benign, nothing to do. */
}
```

Key changes:

1. **Lookup-before-insert guard** — `bpf_map_lookup_elem()` at the top
   returns early once the TEID is mapped, so population happens exactly
   once per flow instead of once per packet.
2. **`BPF_ANY` → `BPF_NOEXIST`** — the kernel itself now enforces
   single-insert semantics as a second line of defense, in case two
   events for a brand-new TEID are processed close together before the
   first insert completes.
3. **`EEXIST` treated as benign** (the race-guard doing its job), not
   logged as an error.

### Result

After this fix, `iperf3` produced real, sustained throughput output
(multiple interval lines and a final summary), confirming the DL PDCP SN
now increments monotonically and the DU's PDCP layer is accepting and
delivering packets normally.

**Why a downlink-only bug stalled an uplink-direction transfer:** the
`iperf3` server ran on the external data network host (`oai-ext-dn`) in
normal (non-reverse) mode, so the bulk application data actually traveled
**uplink** (UE → DU → CU → UPF → ext-dn) — a leg this program doesn't
touch (see Scope, above). But TCP requires ACKs to flow back to the
sender to make progress, and those ACKs travel **downlink**, through this
exact fast path. With the DU silently dropping downlink packets past the
first couple (bad PDCP SNs), the UE never saw ACKs for its uploaded data
and the transfer stalled — even though the "data" itself was uplink. Do
not read "downlink offload verified" as "uplink transfer independently
verified": they're coupled through TCP's ACK path, not because uplink is
also offloaded.

---

## Things to watch out for going forward

1. **Native-mode XDP + `bpf_xdp_adjust_tail()` + `bpf_redirect()` is still
   an open issue on this kernel/veth.** The program is currently running
   in SKB (generic) mode as a workaround — this trades a little
   performance for correctness. Record the exact kernel version and veth
   driver in use, and treat native mode as unsafe for this program until
   the underlying interaction is root-caused or a kernel fix/upgrade is
   confirmed to resolve it. Don't flip `FORCE_SKB_MODE` off without
   re-verifying the flags byte on the wire again.

2. **`next_dl_pdcp_sn` wraps at 18 bits (`PDCP_SN_MAX = 0x3FFFF`).** This
   is expected/by design, but make sure whatever consumes this on the DU
   side (real PDCP receive-window logic) correctly handles wraparound
   under long-running, high-throughput traffic — not just the
   monotonic-increment case exercised by a short `iperf3` test.

3. **The F1AP watcher only tracks a single, most-recently-announced DL
   F1-U bearer** (`f1u_dl_teid` / `f1u_dl_ip` are single globals, not a
   table). This is fine for a one-UE/one-bearer testbed, but will silently
   misattribute tunnel endpoints the moment a second concurrent UE or a
   second DRB is brought up. Multi-bearer support needs correlating F1AP
   messages to specific UEs/PDU sessions/DRBs, which the current watcher
   does not attempt.

4. **Uplink (F1-U → N3) is still unimplemented.** Everything fixed and
   verified here is downlink-only; see Scope, above. Don't extrapolate
   from "iperf3 completed successfully" to "uplink fast-path works" —
   uplink packets are, and remain, a guaranteed `session_map` miss handled
   entirely by the pre-existing non-XDP path. That's tracked as its own
   phase in `NEXT_PHASE.md` (item 1).

5. **(Housekeeping, done)** The old, buggy version of
   `maybe_learn_and_populate()` — the one this journal's Bug #2 replaces —
   had been left in `xdp_gtp_inner_parser_user.c` as a block-commented-out
   dead function rather than deleted. It's been removed; if you find
   yourself tempted to leave a "just in case" commented-out version of a
   fixed function again, don't — git history already has it, and dead code
   with stray `/*`/`*/`-looking fragments inside an outer comment (as this
   one had) is a trap for the next edit.
