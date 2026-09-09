# Investigation: Real F1-U PDCP/SDAP Header Format (and Whether the GTP-U Extension Header Is Required)

## Goal

Before implementing the fix for the DU crash (Problem 10 in the main
README — sending an N3-shaped packet into an F1-U slot), we needed to
know, with certainty rather than assumption, two things:

1. What exact bytes does the real OAI CU-UP prepend to the inner IP
   packet on genuine F1-U downlink traffic (PDCP header format/length,
   SDAP header presence/format)?
2. Does the DU's F1-U receive path actually *require* a GTP-U extension
   header (the way N3 requires the PDU Session Container), or can it be
   safely omitted?

Getting this right matters because guessing wrong here is exactly what
caused the original crash — we want this fix built on confirmed fact, not
another assumption.

## Method

We used two independent, cross-checking approaches: (A) capture real,
non-offloaded traffic and read the bytes directly, and (B) read the
actual OAI source code that produces and consumes those bytes. Where
both agreed, we treated the result as confirmed.

### Step 1 — Capture a genuine (non-offloaded) DL F1-U packet

With the CU fast-path program *not* actively offloading this bearer
(so the packet is produced entirely by the real OAI CU-UP), we captured
on the DU side using our dependency-free sniffer (`sniff_udp_port.py`,
built earlier in this project because `tcpdump`/`apt install` were
unavailable in this container):

```bash
python3 sniff_udp_port.py eth0 2153 192.168.71.150
```

Two consecutive packets on the same bearer (TEID `0xbcae170e`):

```
[316] ... TEID=0xbcae170e ... gtp_flags=0x34 (E=1 S=0 PN=0) -> pdcp_start_used=12
   0  02 00 00 00 18 31 00 00 80 18 31 01 45 00 00 34  |.....1....1.E..4|
  16  d7 c3 40 00 3f 06 4d c8 c0 a8 48 87 0c 01 01 08  |..@.?.M...H.....|
  ...

[317] ... TEID=0xbcae170e ... gtp_flags=0x34 (E=1 S=0 PN=0) -> pdcp_start_used=12
   0  02 00 00 00 18 32 00 00 80 18 32 01 45 00 00 34  |.....2....2.E..4|
  16  d7 c4 40 00 3f 06 4d c7 c0 a8 48 87 0c 01 01 08  |..@.?.M...H.....|
  ...
```

The `gtp_flags=0x34 (E=1 ...) -> pdcp_start_used=12` line (added to the
sniffer specifically to resolve this ambiguity) confirms the script had
already correctly skipped the 8-byte mandatory GTP-U header plus 4 bytes
of optional fields — so everything shown at "offset 0" onward is *after*
that point, not GTP-mandatory-header bytes we'd misread.

**Reading the bytes:** offset 12 onward is unambiguously a real IPv4
header (confirmed separately in the PDCP-ciphering check —
`check_pdcp_is_off/README.md` — via matching known real IP addresses).
That leaves 12 bytes (offsets 0–11) of pre-IP overhead to explain.

**A byte-diff between the two consecutive packets** isolates what's
static vs. incrementing:
```
offset:        0  1  2  3  4  5  6  7  8  9  10 11
Packet 316:    02 00 00 00 18 31 00 00 80 18 31 01
Packet 317:    02 00 00 00 18 32 00 00 80 18 32 01
                              ^^^^^                ^^^^^
                     both change together, +1 each packet
```
Two independent-looking fields (offset 4–5 and offset 9–10) both hold the
value `0x1831` → `0x1832`, incrementing by exactly 1 between consecutive
packets — a strong signal that this is a real, live sequence-number
counter, appearing in two different places in the header for two
different reasons (confirmed in Step 2 below).

### Step 2 — Cross-reference against the OAI source that builds this header

We located and read the function that actually constructs an outgoing
PDCP PDU:

```bash
grep -rln "pdcp_data_req\|deliver_sdu\|nr_pdcp_entity_recv_sdu\|gtpv1u_enb_tunnel_data_req" \
  openair2/LAYER2/nr_pdcp/ openair3/ocp-gtpu/
# -> openair2/LAYER2/nr_pdcp/nr_pdcp_entity.c (among others)

grep -n "recv_sdu\|process_sdu\|generate_pdu\|sn_size\|SDAP\|sdap" \
  openair2/LAYER2/nr_pdcp/nr_pdcp_entity.c
# -> confirms sdap_header_size = 1 (always exactly 1 byte, when present)
# -> confirms header_size depends on entity->sn_size (12-bit "short" vs 18-bit "long")

sed -n '217,300p' openair2/LAYER2/nr_pdcp/nr_pdcp_entity.c
```

The relevant packing logic, `nr_pdcp_entity_process_sdu()`:

```c
/* D/C bit is only to be set for DRBs */
if (entity->type == NR_PDCP_DRB_AM || entity->type == NR_PDCP_DRB_UM) {
  dc_bit = 0x80;
} else {
  dc_bit = 0;
}

if (entity->sn_size == SHORT_SN_SIZE) {
  buf[0] = dc_bit | ((sn >> 8) & 0xf);
  buf[1] = sn & 0xff;
  header_size = SHORT_PDCP_HEADER_SIZE;
} else {
  buf[0] = dc_bit | ((sn >> 16) & 0x3);
  buf[1] = (sn >> 8) & 0xff;
  buf[2] = sn & 0xff;
  header_size = LONG_PDCP_HEADER_SIZE;
}
```

**Matching this directly against the captured bytes** at offset 8–11
(`80 18 31 01`):
- `80` → `dc_bit=0x80` (DRB, as expected) OR'd with the top 2 bits of an
  18-bit SN
- `80 18 31` as a whole decodes (per the "long"/18-bit branch above) to
  SN = `0x1831` = **6193**, incrementing to `0x1832` = 6194 in packet 317
  — matching the byte-diff observation in Step 1 exactly.
- `01` immediately after → the SDAP byte (1 byte, per
  `sdap_header_size = 1`), decoding as QFI = 1 — matching the QFI=1
  already known for this flow from its N3-side PDU Session Container.

**This confirms:** PDCP header = 3 bytes (long/18-bit SN format),
SDAP header = 1 byte, for a total of 4 bytes between the GTP-U header
and the inner IP packet.

### Step 3 — Explain the *other* copy of the SN (offset 4–5) and the remaining leading bytes

Bytes 0–7 (`02 00 00 00 18 31 00 00`) were still unaccounted for. The
structure matches a **GTP-U extension header** (per TS 29.281's generic
wrapper: `[length in 4-octet units][content][next-ext-type]`):
- `02` → length = 2×4 = 8 bytes, exactly matching the remaining byte
  count.
- Content includes `18 31` at the expected position — the *same* SN
  value, redundantly present here too.
- Final byte `00` → next-extension-type = 0 (chain ends, PDCP header
  starts immediately after).

This matches TS 38.425's **NR RAN Container** extension header
(F1-U-specific; distinct from N3's PDU Session Container). Confirmed
directly in the DU's own source:

```bash
grep -rn "NR RAN Container\|RAN_CONTAINER\|0x84\|Gtpv1uHandleGpdu" \
  openair3/ocp-gtpu/ openair2/LAYER2/nr_rlc/ openair2/F1AP/
# -> openair3/ocp-gtpu/gtp_itf.cpp:83:#define NR_RAN_CONTAINER (0x84)
```

### Step 4 — Determine whether this extension header is actually required

Read the DU's F1-U receive handler directly:

```bash
sed -n '1045,1140p' openair3/ocp-gtpu/gtp_itf.cpp
```

Key structure:
```c
int8_t qfi = -1;
...
unsigned int offset = sizeof(Gtpv1uMsgHeaderT);
if( msgHdr->E ||  msgHdr->S || msgHdr->PN)
  offset += 4;

if (msgHdr->E) {
  ... entire extension-header parsing block, including the
      NR_RAN_CONTAINER case, lives inside this "if" ...
}
```

**This is the decisive finding:** the entire extension-header parsing
block — including `NR_RAN_CONTAINER` — is only entered `if (msgHdr->E)`.
If `E=0`, none of it runs, and `qfi` simply keeps its initialized default
value of **`-1`**.

That default is exactly the value the original crash's assertion
expected: `Assertion (qfi == (-1)) failed! ... Non-SDAP callback
configured but QFI=1 is present`. The assertion passes cleanly as long as
we don't set an extension header (and therefore never set `qfi` to
anything other than -1) at all.

Additionally, the `NR_RAN_CONTAINER` case body itself, per its own log
messages ("DL Discard Blocks handling not enabled", "DL Flush handling
not enabled", "For the moment ignore"), only feeds optional QoS
monitoring / early-discard / flush features that OAI's own DU-side
implementation doesn't fully act on regardless — reinforcing that it's
safe to omit for a first working version, not merely "unenforced."

## Conclusion

**Confirmed, complete byte layout for a correctly-framed F1-U downlink
packet** (this is what we need to construct in the kernel program):

```
GTP-U mandatory header (E=0, S=0, PN=0, 8 bytes, no optional fields, no
extension header)
  -> PDCP header (3 bytes, long/18-bit SN format):
       byte0 = 0x80 | ((sn >> 16) & 0x3)
       byte1 = (sn >> 8) & 0xff
       byte2 = sn & 0xff
  -> SDAP header (1 byte): the QFI value (already available from the
     N3 packet's own PDU Session Container)
  -> original inner IP packet, byte-for-byte unchanged
```

**The GTP-U extension header (NR RAN Container) is not required** and
should simply be omitted, not replaced with an equivalent — this also
directly resolves the original crash, since omitting it is exactly what
keeps `qfi == -1` on the DU's receive path.

**State needed going forward:** a real, incrementing per-bearer PDCP
sequence number (`session_ctx` needs a new field, e.g.
`next_dl_pdcp_sn`), with wraparound matching the 18-bit SN space
(`sn_max = (1 << 18) - 1`).

This closes out the "confirm the exact PDCP/SDAP header format" gating
task from `NEXT_PHASE.md` — implementation can now proceed against a
confirmed byte layout rather than an assumed one.
