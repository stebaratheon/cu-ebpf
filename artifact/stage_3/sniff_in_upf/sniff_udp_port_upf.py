#!/usr/bin/env python3
"""
sniff_udp_port_upf.py -- raw-socket sniffer for GTP-U/N3 traffic arriving
at the UPF (e.g. from the CU's uplink offload rewrite).

Usage:
    python3 sniff_udp_port_upf.py <iface> <udp_port> [filter_src_ip]

Example (matches this project's UPF topology):
    python3 sniff_udp_port_upf.py eth0 2152 192.168.71.150

Unlike the CU/DU-side F1-U sniffers (which decode PDCP+SDAP, since F1-U
never carries a GTP-U extension header), this decodes the N3-style
extension chain instead: the mandatory 8-byte GTP-U header, the optional
4-byte seq/npdu/next-ext-type block (present whenever E/S/PN is set), and
the PDU Session Container extension itself (PDU type + QFI) -- since
that's the shape N3 traffic actually uses.

Requires root (raw AF_PACKET socket). Only decodes IPv4-over-Ethernet.
"""
import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800


def mac_str(b):
    return ":".join(f"{x:02x}" for x in b)


def ip_str(b):
    return ".".join(str(x) for x in b)


def hexdump(data, bytes_per_line=16):
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:4d}  {hex_part:<{bytes_per_line*3}}  |{ascii_part}|")
    return "\n".join(lines)


def ip_proto_name(proto):
    return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, f"proto {proto}")


def decode_packet(raw, iface, udp_port, filter_src_ip, count):
    # Ethernet header (14 bytes)
    if len(raw) < 14:
        return count
    eth_dst = raw[0:6]
    eth_src = raw[6:12]
    eth_type = struct.unpack("!H", raw[12:14])[0]
    if eth_type != ETH_P_IP:
        return count

    ip_hdr = raw[14:34]
    if len(ip_hdr) < 20:
        return count
    ver_ihl = ip_hdr[0]
    ihl = (ver_ihl & 0x0F) * 4
    proto = ip_hdr[9]
    src_ip = ip_str(ip_hdr[12:16])
    dst_ip = ip_str(ip_hdr[16:20])

    if proto != 17:  # UDP
        return count

    udp_off = 14 + ihl
    udp_hdr = raw[udp_off:udp_off + 8]
    if len(udp_hdr) < 8:
        return count
    sport, dport, udp_len = struct.unpack("!HHH", udp_hdr[0:6])

    if dport != udp_port and sport != udp_port:
        return count
    if filter_src_ip and src_ip != filter_src_ip:
        return count

    payload = raw[udp_off + 8:]
    if len(payload) < 8:
        return count

    # --- GTPv1-U mandatory header (8 bytes) ---
    flags = payload[0]
    msg_type = payload[1]
    gtp_length = struct.unpack("!H", payload[2:4])[0]
    teid = struct.unpack("!I", payload[4:8])[0]

    version = (flags >> 5) & 0x07
    pt = (flags >> 4) & 0x01
    e_flag = (flags >> 2) & 0x01
    s_flag = (flags >> 1) & 0x01
    pn_flag = flags & 0x01

    count += 1
    print(f"[{count}] {src_ip}:{sport} -> {dst_ip}:{dport}  "
          f"UDP payload {len(payload)} bytes  TEID=0x{teid:08x} "
          f"msg_type={msg_type} gtp_flags=0x{flags:02x} "
          f"(E={e_flag} S={s_flag} PN={pn_flag})")

    if version != 1 or pt != 1 or msg_type != 255:
        print("  Not a recognized GTPv1-U G-PDU header -- skipping decode.\n")
        return count

    cursor = 8  # offset into `payload`, right after the mandatory header

    if e_flag or s_flag or pn_flag:
        if len(payload) < cursor + 4:
            print("  Truncated: optional field block expected but missing.\n")
            return count
        seq = struct.unpack("!H", payload[cursor:cursor + 2])[0]
        npdu = payload[cursor + 2]
        next_ext = payload[cursor + 3]
        cursor += 4

        if s_flag:
            print(f"  Sequence number:  {seq}")
        if pn_flag:
            print(f"  N-PDU number:     {npdu}")

        if e_flag:
            print(f"  Framing check:    E=1 -- N3-style framing "
                  f"(extension header expected, first type=0x{next_ext:02x}).")
            ext_index = 0
            while next_ext != 0 and len(payload) > cursor:
                ext_len_units = payload[cursor]
                ext_bytes = ext_len_units * 4
                if ext_bytes < 4 or len(payload) < cursor + ext_bytes:
                    print(f"    [{ext_index}] type 0x{next_ext:02x}: "
                          f"malformed/truncated extension -- stopping.")
                    break

                ext_content = payload[cursor:cursor + ext_bytes]
                if next_ext == 0x85:  # PDU Session Container
                    pdu_type = (ext_content[1] >> 4) & 0x0F
                    qfi = ext_content[2] & 0x3F
                    pdu_type_name = {0: "DL PDU SESSION INFORMATION",
                                      1: "UL PDU SESSION INFORMATION"}.get(
                                          pdu_type, "other/reserved")
                    print(f"    [{ext_index}] PDU Session Container "
                          f"(len={ext_bytes} bytes): "
                          f"PDU_TYPE={pdu_type} ({pdu_type_name}), QFI={qfi}")
                else:
                    print(f"    [{ext_index}] type 0x{next_ext:02x} "
                          f"(len={ext_bytes} bytes), not decoded")

                next_ext = ext_content[-1]
                cursor += ext_bytes
                ext_index += 1

            if next_ext != 0:
                print(f"    ... more extensions remain (next_ext=0x{next_ext:02x}), "
                      f"not walked further.")
        else:
            print("  Framing check:    E=0 -- no extension chain present.")
    else:
        print("  Framing check:    E=S=PN=0 -- bare mandatory header, "
              "inner payload should start immediately after it.")

    # --- Inner IP packet ---
    inner = payload[cursor:]
    if len(inner) >= 20 and (inner[0] >> 4) == 4:
        inner_ihl = (inner[0] & 0x0F) * 4
        inner_proto = inner[9]
        inner_src = ip_str(inner[12:16])
        inner_dst = ip_str(inner[16:20])
        print(f"  Inner IP header found at payload offset {cursor}: "
              f"IPv4, protocol={inner_proto} ({ip_proto_name(inner_proto)}), "
              f"{inner_src} -> {inner_dst}")
    elif len(inner) >= 1 and (inner[0] >> 4) == 6:
        print(f"  Inner IP header found at payload offset {cursor}: "
              f"IPv6 (not decoded further by this script).")
    else:
        print(f"  Inner IP: unavailable/not parsable at payload offset {cursor} "
              f"(non-IPv4/IPv6, or truncated).")

    print("  Raw bytes from start of GTP payload (offset relative to payload start):")
    print(hexdump(payload))
    print()
    return count


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <iface> <udp_port> [filter_src_ip]")
        sys.exit(1)

    iface = sys.argv[1]
    udp_port = int(sys.argv[2])
    filter_src_ip = sys.argv[3] if len(sys.argv) > 3 else None

    filt_desc = f"from {filter_src_ip} only" if filter_src_ip else "from any source"
    print(f"Sniffing on {iface} for UDP port {udp_port} ({filt_desc}) "
          f"(Ctrl+C to stop)...")

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        sock.bind((iface, 0))
    except PermissionError:
        print("Error: raw sockets require root (try: sudo python3 ...)")
        sys.exit(1)
    except OSError as e:
        print(f"Error binding to interface '{iface}': {e}")
        sys.exit(1)

    count = 0
    try:
        while True:
            raw, _ = sock.recvfrom(65535)
            count = decode_packet(raw, iface, udp_port, filter_src_ip, count)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
