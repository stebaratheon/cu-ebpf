# Checking Whether PDCP Ciphering Is Really Off

## Why We Needed to Check This

Our XDP fast-path offload work assumes that F1-U traffic (between the DU
and CU) is **not encrypted at the PDCP layer**. This assumption matters
because our next implementation step involves inserting a PDCP header in
front of an offloaded packet before forwarding it to the DU — and that
only makes sense if the DU is genuinely expecting to read a **plaintext**
PDCP PDU, not decrypt one.

Trusting a config file setting alone isn't good enough proof — config
intent and runtime behavior can diverge (wrong file loaded, a code path
that ignores the flag, a UE-side override, etc.). So we verified it
empirically, by looking at the actual bytes on the wire.

## How We Turned Ciphering Off

In the CU's (gNB's) configuration file, under the `security` block:

```properties
security = {
  ciphering_algorithms = ( "nea0" );
  integrity_algorithms = ( "nia2", "nia0" );

  # setting 'drb_ciphering' to "no" disables ciphering for DRBs, no matter
  # what 'ciphering_algorithms' configures; same thing for 'drb_integrity'
  drb_ciphering = "no";
  drb_integrity = "no";
};
```

`drb_ciphering = "no"` is the important line — per the config file's own
comment, it unconditionally disables ciphering for **DRBs** (Data Radio
Bearers, i.e. the bearers carrying actual user IP traffic — exactly what
F1-U/PDCP-U carries), regardless of what `ciphering_algorithms` negotiates
with the UE. `ciphering_algorithms = ("nea0")` alone would only be a
*preference* (NEA0 = "no cipher" algorithm, but only chosen if the UE
supports/accepts it); `drb_ciphering = "no"` is the stronger, authoritative
override.

## How We Checked It: Look at the Actual Bytes

**The idea:** if ciphering is genuinely off, the bytes that make up an F1-U
PDCP PDU should be readable as a real structure — specifically, right
after the small PDCP (and optional SDAP) header, there should be a
recognizable, well-formed **plaintext IPv4 header** (the UE's real IP
packet). If ciphering were actually still active, that same region would
instead look like statistically random noise, with no such structure.

**The tool:** `sniff_udp_port.py`, a small dependency-free (Python
standard-library only) raw-socket sniffer, run directly inside the DU
container (where `tcpdump`/`apt install` weren't available due to a
locked-down container environment). It:
1. Captures UDP traffic on a chosen port/source filter (here: port 2153,
   source = the CU's IP), i.e. genuine downlink F1-U traffic.
2. Decodes the GTP-U header to confirm the TEID (for correlating specific
   packets against CU-side logs, used earlier in this project to confirm
   the fast-path redirect mechanism itself worked).
3. Hex-dumps the bytes immediately following the GTP-U header (i.e. the
   PDCP PDU region).
4. Scans the first ~20 bytes of that region for a byte equal to `0x45` —
   the IPv4 "Version 4, IHL 5 (no options)" byte, which is where a
   plaintext IPv4 header would begin.
5. If found, decodes the 4 bytes at the expected source-IP offset and the
   4 bytes at the expected destination-IP offset from that point, and
   prints them as candidate IP addresses.

Run as:
```bash
python3 sniff_udp_port.py eth0 2153 192.168.71.150
```

## The Result, and How to Interpret It

A real captured packet gave us:

```
[1] 192.168.71.150:2153 -> 192.168.71.171:2153  UDP payload 84 bytes  TEID=0xb892ab97 msg_type=255
  Raw bytes from start of PDCP PDU (offset relative to PDCP PDU start):
     0  02 00 00 00 00 00 00 00 80 00 00 01 45 00 00 3c  |............E..<|
    16  00 00 40 00 3f 06 25 85 c0 a8 48 87 0c 01 01 07  |..@.?.%...H.....|
    ...
  Heuristic: byte 0x45 found at PDCP-PDU offset(s) [12].
     At offset 12: candidate src=192.168.72.135 dst=12.1.1.7
```

**Why this is conclusive, not just a coincidence:** a single byte
happening to equal `0x45` by chance in random/encrypted data has roughly
1-in-256 odds — not strong evidence on its own. But here, the bytes
immediately *around* that `0x45` also parse as a completely coherent,
correctly-structured IPv4 header:

- `45` → Version 4, IHL 5 (no options) — as expected
- `00 3c` → Total Length = 60 bytes — a sane, small packet size
- `40 00` → Flags (Don't Fragment set) — a normal, valid value
- `3f` → TTL 63 — a plausible value
- `06` → Protocol = TCP — matches this being iperf3/TCP test traffic
- `c0 a8 48 87` → decodes to **192.168.72.135** — our **real, known
  ext-dn server's IP address**
- `0c 01 01 07` → decodes to **12.1.1.7** — a **real, known UE IP** from
  our address pool

Getting one random byte to match `0x45` by chance is plausible.
Getting an *entire surrounding header* to simultaneously decode into
*two specific, independently-known-correct real IP addresses* from our
actual topology is not something that happens by coincidence from
encrypted or random bytes. This is what makes the check conclusive rather
than merely suggestive.

**How to interpret future runs of this check:**
- ✅ **Confirmed off**: a `0x45` hit whose surrounding bytes decode into
  plausible, and ideally recognizable/real, IP addresses (as above).
- ⚠️ **Inconclusive**: no `0x45` found at all in the scanned window — this
  could mean ciphering is genuinely still active (bytes are random), *or*
  simply that the PDCP/SDAP header on this particular bearer is longer
  than the scanned window, and the real IP header starts a bit later.
  Widen the scan window (`scan_for_plaintext_ipv4_header`'s range) and/or
  inspect the hex dump manually before concluding ciphering is still on.
- ❌ **Confirmed on / broken assumption**: bytes throughout the PDCP-PDU
  region look uniformly random with no recognizable structure at any
  offset, and no combination of "0x45 plus surrounding bytes" ever decodes
  into plausible/known IP addresses across multiple captured packets.

For our testbed, the result above (and consistent results across multiple
separate captured packets, each showing a different but always
plausible/real destination UE IP) satisfies the "confirmed off" case.
