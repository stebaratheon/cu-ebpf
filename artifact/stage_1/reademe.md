# eBPF/XDP-Based Fast Path for 5G CU-UP

## What This Project Is Trying to Accomplish

In a disaggregated 5G RAN (Radio Access Network), the **CU (Centralized Unit)**
sits in the middle of the data path, between the **DU (Distributed Unit)** on
one side and the **UPF (User Plane Function, part of the 5G core)** on the
other. Every single user-plane packet — every byte of a UE's (User
Equipment, i.e. a phone/modem's) traffic — passes through the CU, which has
to receive it, understand which tunnel it belongs to, translate it into the
tunnel format the *other* side expects, and forward it on.

Today, this translation work is done entirely in software, by a normal Linux
userspace process (in our testbed: OpenAirInterface's `nr-softmodem`, i.e.
"OAI CU-UP"). That works, but it's slow relative to what dedicated hardware
can do — packets have to travel through the full Linux kernel networking
stack, get copied into a userspace socket buffer, get processed by a
general-purpose program, get copied back out, and sent on. Prior research
(CUP4, from NUS, and Blink, from Waterloo — both cited in our related work)
solved this by moving that translation logic onto **P4 programmable network
switches** (specialized ASIC hardware), achieving huge latency
improvements (sub-microsecond vs hundreds of microseconds).

**Our angle:** do the same kind of acceleration, but using **eBPF/XDP**
instead of a P4 switch. XDP (eXpress Data Path) lets us run a small,
verified program directly in the Linux kernel's network driver, intercepting
packets *before* they ever reach the normal kernel stack or the CU-UP
userspace process. No specialized/expensive switch hardware required — just
a commodity Linux server. This is a meaningfully different and, as far as we
can tell, unexplored point in the design space: **neither CUP4 nor Blink use
XDP for actual packet forwarding** (Blink only uses XDP for measurement
timestamping). If it works, it's a compelling "you don't need a $10K switch
to get most of this benefit" story.

### The Two Tunnels We're Translating Between

To understand anything below, you need two pieces of 5G-specific vocabulary,
explained in plain networking terms:

- **N3**: the tunnel between the UPF (core network) and the CU. Carries
  plain user IP packets (a UE's real IP traffic) wrapped in a GTP-U tunnel
  header (GTP-U = GPRS Tunnelling Protocol, User plane — think of it as "IP
  packets wrapped inside UDP packets wrapped inside another IP packet," a
  standard tunneling scheme, conceptually similar to VXLAN or GRE).
- **F1-U**: the tunnel between the CU and the DU. Also GTP-U, but instead of
  carrying a plain IP packet, it carries a **PDCP PDU** (Packet Data
  Convergence Protocol — a 5G-specific framing/security layer with its own
  small header, sequence numbers, and normally encryption).

**The CU's core job**: take a packet arriving on one tunnel, strip its
header, re-wrap it for the other tunnel (different TEID, different IP/port,
different framing), and forward it. A **TEID (Tunnel Endpoint Identifier)**
is just a 32-bit number that identifies which tunnel/session a packet
belongs to — think of it like a VLAN tag or a VPN session ID, except each
direction of each tunnel typically has its own independently-assigned TEID
value.

---

## Step 1: What We've Built So Far

We broke the work into a "pure relay" milestone first: prove that we can
intercept a real downlink flow's packets, correctly relabel and redirect
them toward the DU, using **dynamically learned** information rather than
anything hardcoded. Here's what that consists of, in the order we built it.

### 1.1 — The Packet Parser (Foundation)

**Files:** `xdp_gtp_inner_parser.bpf.c` (kernel/BPF program), `xdp_gtp_inner_parser_user.c` (userspace program)

Before doing anything clever, we needed an XDP program that could reliably
parse a GTP-U packet's structure: the outer Ethernet/IP/UDP headers, the
GTP-U header itself (version, flags, message type, length, TEID), any
optional fields (sequence number, N-PDU number), and any *extension
headers* — in particular the **PDU Session Container** extension, which (on
N3 traffic only) carries a **QFI** (QoS Flow Identifier — basically, "which
class of service does this packet belong to") and a **PDU Type** (0 =
downlink, 1 = uplink — though we found the uplink variant is essentially
never sent in practice, see the notes on this below).

**Intuitive framing:** this is exactly like writing a packet dissector for
a new/obscure protocol — you're walking a byte buffer, checking bounds at
every step (the eBPF verifier requires proof that every memory access is
safe), and extracting fields as you go.

Early refinement: we made sure the parser **never silently discards
information**. If a packet's inner payload isn't parsable as IP (which is
always true for F1-U traffic, since it's PDCP-framed, not raw IP), we still
report every other field we *could* safely extract, with an explicit "Inner
IP: unavailable/not parsable" marker — rather than just dropping that
packet's details from the log. We also extended it to report the *entire*
chain of extension headers (not just the first one), since a real packet
can have more than one chained together.

We also discovered that F1-U traffic in our specific testbed runs on UDP
port **2153**, not the "standard" GTP-U port 2152 — so the parser had to be
taught to recognize both ports as GTP-U-carrying, rather than only 2152.

### 1.2 — The Fast-Path Mechanism: `session_map` + Redirect

**The idea:** maintain a lookup table (a BPF hash map) keyed by a packet's
*incoming* TEID, whose value tells the kernel program everything it needs
to relabel and forward that packet: the new TEID to write, the new
destination IP/port, which network interface to send it out of, and the
Ethernet (MAC) addresses to use.

When a packet's TEID has an entry in this table, the kernel program:
1. Rewrites the Ethernet destination/source MAC addresses.
2. Rewrites the destination IP address and UDP port.
3. Rewrites the GTP-U TEID field.
4. Recomputes the IP header checksum (a full recompute — cheap, since the
   IP header is a fixed 20 bytes with no options in our case).
5. Sets the UDP checksum to zero (explicitly legal per RFC 768 for
   UDP-over-IPv4 — a zero checksum means "not computed," and this is a
   deliberate simplification: patching a UDP checksum *incrementally* after
   changing several fields requires more delicate bit-level math than a
   full recompute would, and IP-level checksums don't have this shortcut
   available for arbitrary-length UDP payloads within XDP's constraints).
6. Calls `bpf_redirect()`, which tells the kernel "send this packet
   straight out this other interface" — bypassing the normal socket/kernel
   stack entirely (this is *why* this approach is fast: it skips exactly
   the overhead the softwareCU-UP process normally has to pay).

If there's no map entry for a packet's TEID, the program just does what it
did before any of this existed: report the packet to a ring buffer (for
our userspace logger/monitor) and `XDP_PASS` it through to the normal
kernel stack, completely unaffected.

**Important architectural note:** in XDP, a single packet gets exactly one
verdict. You cannot both `XDP_PASS` a packet up to the real CU-UP process
*and* `XDP_REDIRECT` a copy of it elsewhere — it's one or the other. This
matters a lot for later work: fast-pathing a flow means the real CU-UP
software's own logic for that flow is now completely bypassed, for better
(speed) or worse (see the crash discussion below).

### 1.3 — Dynamic MAC Address Resolution

Early versions hardcoded the DU's MAC address as a config constant. This
turned out to be actively dangerous: Docker containers reuse the same
static IP address across restarts, but get a *new* MAC address each time —
so a hardcoded/stale MAC address silently sends frames to a device that no
longer exists.

**Fix:** resolve MAC addresses dynamically:
- The CU's *own* MAC is read via a `SIOCGIFHWADDR` ioctl call on its own
  interface (a standard, direct way to ask the kernel "what's my own
  interface's hardware address").
- The DU's MAC is resolved via the host's ARP table (`/proc/net/arp`) — but
  a background thread actively **flushes** any existing (potentially
  stale) entry and forces a fresh ARP request every few seconds, so a DU
  container restarting with a new MAC gets picked up automatically instead
  of silently reusing garbage.

### 1.4 — Dynamic TEID/IP Learning via F1AP (Replacing All Hardcoding)

This was the biggest and most iterative piece of work, and is really the
core novel contribution of Step 1: **how does the program learn the
correct TEID pairing for a real, live session, without a human hardcoding
it?**

**The insight:** the correct pairing information is genuinely only known
via **signaling** — specifically, **F1AP** (the control-plane protocol
between the CU and DU, distinct from the user-plane GTP-U tunnels we've
been discussing). When a UE attaches and a bearer (a QoS-differentiated
data flow) gets set up, the DU sends the CU a message (`UEContextSetupResponse`)
that explicitly states: "here is the TEID and IP address you (the CU)
should use when sending downlink data to me for this bearer." That's
exactly the "peer_teid" our fast path needs — read directly from real
signaling, not guessed or inferred.

**How we get at it, practically:** rather than writing a full ASN.1/F1AP
protocol decoder from scratch (a substantial undertaking on its own), we
run **`tshark`** (Wireshark's command-line packet analyzer, which already
has a complete, correct F1AP dissector) as a background subprocess inside
our userspace program, filtered to just the fields we need, and consume its
output live.

This is discussed in detail in the "Problems Encountered" section below,
because getting this exactly right took several iterations — and the
mistakes made along the way (and how we caught them) are as instructive as
the final working version.

**Design simplification we're upfront about:** the current version tracks
only a single, most-recently-learned bearer (fine for a one-UE testbed).
Correctly handling multiple concurrent UEs/bearers would require
correlating F1AP messages to specific UE/PDU-session identifiers, which is
future work, not yet implemented.

---

## Problems Encountered and How We Solved Them

This section is deliberately detailed — several of these bugs were subtle,
and understanding *why* they happened is valuable both for continuing this
work and for writing it up.

### Problem 1 — Parser Silently Dropped Detail for Non-IP Inner Payloads

**Symptom:** F1-U packets (PDCP-framed, not plain IP) showed almost no
useful information in the logs, because the original parser only printed
detailed fields when it successfully parsed an inner IPv4 header.

**Root cause:** the printing logic conditioned *most* fields on inner-IP
parse success, when in fact the outer GTP-U header fields (TEID, flags,
QFI, etc.) are available regardless of whether the inner payload is IP or
not.

**Fix:** restructured both the kernel event struct and the userspace
printer so that all safely-parsed outer-header fields are always reported,
with a distinct, explicit "Inner IP: unavailable/not parsable" marker
instead of just omitting information.

### Problem 2 — Only the First Extension Header Was Recorded

**Symptom:** a GTP-U packet with more than one chained extension header
would only have its first one visible in the logs.

**Fix:** added a bounded array (`extension_types[]`, capped at 4 to match
the existing unrolled parsing loop) that records every extension header
type actually walked, and updated the userspace printer to list all of
them.

### Problem 3 — F1-U Traffic Wasn't Recognized as GTP-U At All

**Symptom:** all uplink (DU→CU) traffic showed up as "UDP packet without
recognized GTP-U header" — meaning the parser wasn't even attempting to
read it as GTP-U.

**Root cause:** the kernel program only checked for UDP port 2152 (the
"standard" GTP-U port), but our testbed's F1-U traffic actually flows over
port **2153**.

**Fix:** added a second recognized port constant (`GTPU_PORT_ALT`), so
packets on either 2152 or 2153 get the full GTP-U parse attempted.

### Problem 4 — Hardcoded TEID Values Broke a Live Session

**Symptom:** once we wired in a hardcoded `session_map` test entry
(matching a real, live iperf3 session's TEID) to validate the
rewrite/redirect mechanism, the live iperf3 session immediately broke —
"Connection timed out."

**Root cause:** the hardcoded "peer TEID" we invented for testing had no
meaning to the real DU — there's no bearer context under that TEID — so
the DU silently dropped every redirected packet. Since `XDP_REDIRECT`
*replaces* the normal `XDP_PASS` delivery (see the architectural note in
1.2), this meant every real downlink packet for that session was being
diverted into a black hole instead of reaching the DU normally.

**This was actually useful confirmation** that the redirect/rewrite
mechanism itself worked correctly — it was *too* effective, redirecting
packets to a destination that didn't understand them. It's what motivated
building the dynamic F1AP-learning system (1.4) instead of continuing with
any hardcoded values.

### Problem 5 — Compiler Error: Wrong `bpf_map_update_elem` Symbol

**Symptom:**
```
error: too few arguments to function 'bpf_map__update_elem'
```
(note the double underscore).

**Root cause:** libbpf actually has *two* different, similarly-named
functions: a modern struct-based API (`bpf_map__update_elem`, taking a
`struct bpf_map *`) declared in `<bpf/libbpf.h>`, and the classic
fd-based syscall wrapper (`bpf_map_update_elem`, taking a plain `int` fd)
declared in `<bpf/bpf.h>`. Our code correctly called the single-underscore
version, but without `<bpf/bpf.h>` included, the compiler apparently
resolved the call against the wrong (structurally incompatible) symbol.

**Fix:** explicitly `#include <bpf/bpf.h>`.

### Problem 6 — Stale ARP Cache Reused an Old Container's MAC

**Symptom:** the DU's MAC address resolved successfully even *before* the
DU container had actually started.

**Root cause:** Docker containers reuse the same static IP across restarts,
but the host kernel's ARP/neighbor table doesn't automatically invalidate
old entries just because a container was replaced — so a leftover MAC
address from a *previous* DU container instance was silently reused.

**Fix:** a periodic background thread now explicitly deletes
(`ip neigh del`) any cached entry for the DU's IP and forces a fresh ARP
probe every few seconds, only updating (and logging) the DU's known MAC
when the resolved value actually changes.

### Problem 7 — F1AP Watcher Learned a Bogus, Zero-Value TEID

**Symptom:** the very first version of the F1AP-watching logic committed
`f1u_dl_known = 1` with a TEID of `0x00000000` and IP `0.0.0.0` — a
completely bogus mapping, which then caused a real downlink flow to be
"successfully" offloaded into another black hole.

**Root cause:** our first attempt used a loose, resilient substring search
(looking for *any* JSON key containing the word "TEID" anywhere in
`tshark`'s streamed output) rather than a precise field match. This
matched an unrelated F1AP message/field that happened to have a zero,
unset, or placeholder TEID value.

**Fix (iterative):**
1. First, we tightened the logic to require a *non-zero* TEID and a valid
   IP address present *together on the same line*, rather than accepting
   a bare TEID match alone.
2. We then captured a real, full attach sequence to a pcap file and used
   `tshark`'s verbose decode (`-V`) on the specific frame that we knew
   (from a plain-text summary view) was the right message —
   `UEContextSetupResponse` — to see the *actual* field names and value
   formats Wireshark uses for this message in our environment, rather than
   continuing to guess.
3. This revealed the real, exact field names: `f1ap.gTP_TEID` (a
   colon-separated hex byte string, e.g. `77:51:2b:d5` — no `0x` prefix)
   and `f1ap.transportLayerAddressIPv4` (a plain, ready-to-use
   dotted-decimal IP string). We rewrote the parsing logic to match these
   exact, confirmed field names via `tshark -T fields -e <field>`
   (precise field extraction), instead of text-scraping JSON output for
   substrings — a fundamentally more reliable approach.

### Problem 8 — `procedureCode==5` Matched Both Directions of the Same Procedure

**Symptom:** the watcher sometimes learned a "DL F1-U TEID" whose IP
address was the **CU's own address**, not the DU's.

**Root cause:** F1AP's `id-UEContextSetup` procedure (procedure code 5)
covers *both* the `UEContextSetupRequest` (CU→DU, which carries **uplink**
tunnel info — the CU's own address, telling the DU where to send uplink
traffic) and the `UEContextSetupResponse` (DU→CU, which carries the
**downlink** tunnel info we actually want). Since both messages expose a
`gTP_TEID` field, filtering on procedure code alone couldn't distinguish
them, and whichever one happened to be read last simply overwrote the
other in memory — a race that happened to resolve correctly by luck in
early tests, but wasn't guaranteed to.

**Fix:** since the DU's IP address is already a known config value, we
simply reject any learned entry whose IP doesn't match the DU's known
address — directly and deterministically filtering out the Request
message's (CU's own) tunnel info, regardless of message arrival order.

### Problem 9 — Wrong Destination Port for F1-U Traffic

**Symptom:** after fixing the TEID-learning logic, offloaded packets were
still not reaching the UE correctly.

**Root cause:** the offload-population code reused the same port constant
for both directions (`2152`, the N3/UPF-facing port), but — as established
back in Problem 3 — this testbed's F1-U traffic actually uses port
**2153**. So every redirected downlink packet was sent to the DU on the
wrong port entirely.

**Fix:** introduced a separate `F1U_PORT` constant (2153) distinct from
the N3-facing port constant, and used it specifically for the DU-bound
rewrite. (Note: F1AP does not signal the GTP-U port number itself — this
has to be a config value matching your specific environment's convention,
confirmed by direct packet observation, exactly as we did here.)

### Problem 10 — DU Container Crash: Missing SDAP/QFI Mismatch

**Symptom:** with TEID learning and the port fix both in place, we
confirmed (via a custom, dependency-free raw-socket sniffer script, since
`tcpdump`/`apt install` were unavailable in the restricted DU container)
that our rewritten packet — with the *exact* TEID our program had logged
as "new TEID" — genuinely arrived at the DU, on the right port. But
immediately afterward, the entire DU container crashed and exited.

**Root cause, from the DU's crash log:**
```
Assertion (qfi == (-1)) failed!
In Gtpv1uHandleGpdu() gtp_itf.cpp:1264
Non-SDAP callback configured but QFI=1 is present (ue=64501 teid=0x19fe2499)
```
F1-U traffic, by design, does **not** carry SDAP/QFI information in its
GTP-U header — SDAP (QoS-flow-to-bearer mapping) is a CU-side function; the
DU has no SDAP layer and gets its QoS/bearer mapping from F1AP signaling
instead. Our rewrite only changed the TEID/IP/port/MAC fields — it left the
**original N3-style PDU Session Container extension header (with QFI=1)
completely intact**, because that's exactly how the packet arrived from the
UPF. So we forwarded an N3-shaped packet into an F1-U-shaped slot; the DU's
own internal consistency check caught this mismatch and called `abort()`,
which — since `nr-softmodem` runs as the container's main process under
`tini` — took the entire container down with it.

**This is a genuinely useful finding, not just a bug**: it's concrete
evidence that naively relaying an N3 packet's *framing*, not just its
tunnel addressing, into F1-U is actively unsafe against a real DU, not
merely ineffective. This is exactly the kind of result worth documenting
carefully in a research write-up.

---

## Tools Built Along the Way

- **`xdp_gtp_inner_parser.bpf.c`** / **`xdp_gtp_inner_parser_user.c`** — the
  main kernel/userspace program pair described throughout this document.
- **`send_gtpu_pdu_type1.py`** (Scapy-based) and
  **`send_gtpu_pdu_type1_raw.py`** (dependency-free, stdlib-only raw-socket
  version) — synthetic packet generators, built to test PDU-Type-1
  (uplink-style) GTP-U parsing and, more generally, to safely exercise the
  fast-path mechanism without touching live UE traffic.
- **`sniff_udp_port.py`** — a minimal, dependency-free (stdlib-only)
  raw-socket UDP sniffer, built specifically because `tcpdump` could not be
  installed in the (locked-down/rootless) DU container. Supports filtering
  by destination port and source IP, and decodes the GTP-U TEID from the
  payload — which is what let us definitively correlate a specific
  redirected packet on the CU side with a specific received packet on the
  DU side.

---

## Current Status

- ✅ Full outer-header GTP-U parsing (works for both parsable-inner-IP and
  unparsable/F1-U-style packets).
- ✅ `session_map`-based TEID rewrite + `bpf_redirect()` fast-path mechanism,
  mechanically validated to work correctly (rewritten TEID confirmed
  bit-for-bit arriving at the DU).
- ✅ Fully dynamic MAC address resolution (no hardcoded MACs).
- ✅ Fully dynamic TEID/IP pairing, learned live from real F1AP signaling
  (no hardcoded TEIDs) — for a single active bearer.
- ❌ **Not yet working end-to-end**: the offloaded packet's *framing* is
  wrong for F1-U (it still looks like an N3 packet), which crashes the real
  DU when fast-pathed traffic reaches it. This is the immediate next
  problem to solve.

---

## Next Steps (Broader Roadmap)

1. **Fix the F1-U framing mismatch** (see "Immediate Next Step" below).
2. Add real **PDCP header** insertion (sequence number field; ciphering can
   remain disabled, matching the same simplification CUP4's own paper uses
   for exactly this reason) so a fast-pathed packet is fully
   indistinguishable from a real DU-originated one.
3. Extend to the **uplink direction** (F1-U → N3), which needs the reverse
   transformation: strip the PDCP header, add back a PDU Session
   Container/QFI, re-tunnel toward the UPF.
4. Add an **in-order-only fast path with slow-path fallback**: since XDP
   can't naturally buffer/reorder out-of-sequence packets the way a real
   PDCP implementation can, punt anything out-of-order back to the real
   CU-UP software rather than attempting to handle it in-kernel.
5. Extend TEID/bearer learning to handle **multiple concurrent
   UEs/bearers** correctly (current version assumes a single active
   bearer).
6. Build the **trigger-based offload daemon** (mirroring CUP4/Blink's
   design): monitor for signs of real CU-UP saturation/loss and dynamically
   turn fast-path offload on/off per flow, rather than offloading
   everything unconditionally.
7. **Benchmark** against the real OAI CU-UP (median/tail latency, packets
   per second, packet loss vs. number of active flows), using the same
   methodology as the CUP4/Blink papers, so results are directly
   comparable.

## Packet Structure Reference: N3 Framing vs. F1-U Framing

This is the exact picture behind Problem 10, and behind what the
"Immediate Next Step" below actually involves. Reading top-to-bottom as a
standard layered protocol stack (physical layer at the bottom, application
data at the top — same convention as an OSI/IETF stack diagram):

**N3 packet (UPF ↔ CU) — what we currently have:**
```
+-------------------------------------------------------------------+
| Physical Layer                                                     |
+-------------------------------------------------------------------+
| Data Link Layer (Ethernet)                                         |
+-------------------------------------------------------------------+
| Network Layer   (Outer IP: UPF <-> CU)                              |
+-------------------------------------------------------------------+
| Transport Layer (Outer UDP, port 2152)                              |
+-------------------------------------------------------------------+
| GTP-U mandatory header (flags, message type, length, TEID)         |
| + optional fields (sequence number, N-PDU number)                  |
| + Extension Header: PDU Session Container                          |
|      \_ this is where QFI lives on N3                              |
+-------------------------------------------------------------------+
| Inner IP packet (the UE's real traffic -- e.g. TCP payload)         |
+-------------------------------------------------------------------+
```

**F1-U packet (CU ↔ DU) — what the DU actually expects to receive:**
```
+-------------------------------------------------------------------+
| Physical Layer                                                     |
+-------------------------------------------------------------------+
| Data Link Layer (Ethernet)                                         |
+-------------------------------------------------------------------+
| Network Layer   (Outer IP: CU <-> DU)                               |
+-------------------------------------------------------------------+
| Transport Layer (Outer UDP, port 2153 in this testbed)               |
+-------------------------------------------------------------------+
| GTP-U mandatory header (flags, message type, length, TEID)         |
|      \_ NO extension header here -- QFI must NOT appear at this     |
|         layer on F1-U, unlike N3                                    |
+-------------------------------------------------------------------+
| PDCP Header                                                        |
|      \_ sequence number (+ encryption, normally -- disabled in      |
|         this testbed so we can still read/write it in the clear)    |
+-------------------------------------------------------------------+
| SDAP Header                                                        |
|      \_ QFI lives HERE instead, one layer deeper than on N3         |
+-------------------------------------------------------------------+
| Inner IP packet (the UE's real traffic -- e.g. TCP payload)         |
+-------------------------------------------------------------------+
```

**Why this matters:** SDAP and PDCP are RAN-internal layers that only exist
*between the CU and the UE* (i.e. on the F1-U/Uu path) — the core network
side (N3) has no SDAP/PDCP at all, and instead conveys QFI directly at the
GTP-U level via the PDU Session Container extension header. These are two
genuinely different ways of carrying the same piece of information (QFI),
at two different layers, and a receiver on one side has no reason to expect
the other side's convention.

**Our current bug in this picture:** we take an arriving N3 packet
(top diagram), and only touch the network/transport/GTP-U-mandatory-header
fields when relabeling it for the DU — the PDU Session Container extension
header (with QFI) rides along unchanged. We're sending the DU a packet
shaped exactly like the top diagram, addressed as if it were the bottom
diagram. The DU's own consistency check catches this and aborts.

**What "fixing this" concretely means:** transform the top diagram into
the bottom one before forwarding — remove the GTP-U extension header
entirely, and prepend a (minimal, since ciphering is disabled here) SDAP
header and PDCP header in front of the inner IP packet.

## Immediate Next Step

Fix Problem 10 directly: when writing an offloaded **N3 → F1-U** packet, the
kernel program must **strip the GTP-U extension header (the PDU Session
Container / QFI)** entirely before forwarding to the DU, since F1-U packets
must not carry it. Concretely, this means:

- Rebuilding the GTP-U mandatory header with `E=0` and no optional fields
  (since we're removing the very thing that made `E=1` necessary).
- Physically **shortening** the packet (using `bpf_xdp_adjust_tail()`) to
  remove those now-unwanted bytes — a new wrinkle, since every rewrite so
  far has been same-size, in-place editing; removing bytes requires
  properly recomputing the IP header's Total Length and the UDP header's
  Length fields, not just checksums.
- Before implementing this, it's also worth quickly checking whether OAI's
  DU code exposes a configuration option to simply **accept** a QFI-bearing
  extension header on F1-U (i.e., enable a "non-SDAP callback" path some
  other way) — if such a flag exists, it would be a substantially simpler
  fix than packet resizing, and should be ruled out first.