#!/usr/bin/env python3
"""
sniff_udp_port.py -- minimal dependency-free UDP sniffer.

No tcpdump, no scapy, no pip installs needed: uses only the Python
standard library (raw AF_PACKET socket) to confirm whether packets on a
given UDP port are actually arriving on an interface.

Usage:
    python3 sniff_udp_port.py <iface> <udp_port>

Example:
    python3 sniff_udp_port.py eth0 2153

Requires root (or CAP_NET_RAW), same as tcpdump would.
"""

import socket
import struct
import sys


def hexdump(data, max_bytes=96):
    """Classic 16-bytes-per-row hex+ASCII dump, offsets included."""
    data = data[:max_bytes]
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(16 * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {offset:4d}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


def scan_for_plaintext_ipv4_header(data):
    """
    Heuristic only, not authoritative: looks for a byte equal to 0x45
    (IPv4, IHL=5, no options -- the very common case for a plain TCP/UDP
    packet with no IP options) within the first few bytes of the PDCP PDU,
    which is roughly where an IPv4 header would start if PDCP ciphering
    is off (payload = [PDCP header][optional SDAP header][IPv4 packet]).
    If ciphering were active, this region would instead look like random
    bytes, and 0x45 appearing there would be coincidental rather than
    marking a real, structured IP header.
    """
    hits = []
    for offset in range(0, min(len(data), 20)):
        if data[offset] == 0x45:
            hits.append(offset)
    return hits


def main():
    if len(sys.argv) not in (3, 4):
        print(f"Usage: {sys.argv[0]} <iface> <udp_port> [expected_src_ip]")
        print(f"  e.g.: {sys.argv[0]} eth0 2153 192.168.71.150   # CU -> DU only")
        sys.exit(1)

    iface = sys.argv[1]
    target_port = int(sys.argv[2])
    expected_src_ip = sys.argv[3] if len(sys.argv) == 4 else None

    # ETH_P_ALL = 0x0003, ntohs so it matches on the wire
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((iface, 0))

    if expected_src_ip:
        print(f"Sniffing on {iface} for UDP dst port {target_port} "
              f"from {expected_src_ip} only (Ctrl+C to stop)...")
    else:
        print(f"Sniffing on {iface} for UDP dst port {target_port} "
              f"(any source, inbound only) (Ctrl+C to stop)...")

    count = 0
    while True:
        frame, _ = sock.recvfrom(65535)

        if len(frame) < 14:
            continue
        eth_type = struct.unpack("!H", frame[12:14])[0]
        if eth_type != 0x0800:  # only IPv4
            continue

        ip_header = frame[14:34]
        if len(ip_header) < 20:
            continue

        ihl = (ip_header[0] & 0x0F) * 4
        proto = ip_header[9]
        if proto != 17:  # UDP
            continue

        src_ip = socket.inet_ntoa(ip_header[12:16])
        dst_ip = socket.inet_ntoa(ip_header[16:20])

        udp_offset = 14 + ihl
        udp_header = frame[udp_offset:udp_offset + 8]
        if len(udp_header) < 8:
            continue

        sport, dport, length, _ = struct.unpack("!HHHH", udp_header)

        # Only the inbound direction: something sending TO this port.
        if dport != target_port:
            continue
        if expected_src_ip and src_ip != expected_src_ip:
            continue

        count += 1
        payload_len = length - 8
        payload = frame[udp_offset + 8:udp_offset + 8 + payload_len]

        teid_str = "?"
        pdcp_region = b""
        if len(payload) >= 8:
            gtp_flags = payload[0]
            gtp_msg_type = payload[1]
            gtp_teid = struct.unpack("!I", payload[4:8])[0]

            gtp_optional_present = (gtp_flags & 0x07) != 0
            pdcp_start = 12 if gtp_optional_present else 8
            pdcp_region = payload[pdcp_start:]

            teid_str = (f"TEID=0x{gtp_teid:08x} msg_type={gtp_msg_type} "
                        f"gtp_flags=0x{gtp_flags:02x} (E={( gtp_flags>>2)&1} "
                        f"S={(gtp_flags>>1)&1} PN={gtp_flags&1}) "
                        f"-> pdcp_start_used={pdcp_start}")
        else:
            teid_str = f"(payload too short for a GTP header: {len(payload)} bytes)"

        print(f"[{count}] {src_ip}:{sport} -> {dst_ip}:{dport}  "
              f"UDP payload {payload_len} bytes  {teid_str}")

        if pdcp_region:
            print("  Raw bytes from start of PDCP PDU (offset relative to PDCP PDU start):")
            print(hexdump(pdcp_region))

            hits = scan_for_plaintext_ipv4_header(pdcp_region)
            if hits:
                print(f"  Heuristic: byte 0x45 (plausible plaintext IPv4 header start, "
                      f"no options) found at PDCP-PDU offset(s) {hits}.")
                for h in hits:
                    candidate = pdcp_region[h:h + 20]
                    if len(candidate) >= 20:
                        cand_src = socket.inet_ntoa(candidate[12:16])
                        cand_dst = socket.inet_ntoa(candidate[16:20])
                        print(f"     At offset {h}: candidate src={cand_src} dst={cand_dst} "
                              f"-- if these are real, recognizable addresses from your "
                              f"topology, that's strong confirmation of a genuine "
                              f"plaintext IPv4 header (not coincidence).")
            else:
                print("  Heuristic: no 0x45 byte found in the first few bytes -- "
                      "either ciphering is active (bytes look random), or the PDCP/SDAP "
                      "header is longer than expected here. Inspect the hex dump above "
                      "manually to judge.")
            print()


if __name__ == "__main__":
    main()
