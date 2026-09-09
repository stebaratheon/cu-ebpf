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
        if len(payload) >= 8:
            gtp_flags = payload[0]
            gtp_msg_type = payload[1]
            gtp_teid = struct.unpack("!I", payload[4:8])[0]
            teid_str = f"TEID=0x{gtp_teid:08x} msg_type={gtp_msg_type}"
        else:
            teid_str = f"(payload too short for a GTP header: {len(payload)} bytes)"

        print(f"[{count}] {src_ip}:{sport} -> {dst_ip}:{dport}  "
              f"UDP payload {payload_len} bytes  {teid_str}")


if __name__ == "__main__":
    main()
