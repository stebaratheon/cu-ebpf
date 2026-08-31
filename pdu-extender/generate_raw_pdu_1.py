#!/usr/bin/env python3
"""
send_gtpu_pdu_type1_raw.py

Dependency-free version: builds a spec-correct GTPv1-U packet carrying a
PDU Session Container extension header with PDU Type = 1 (UL PDU SESSION
INFORMATION), per 3GPP TS 38.415 clause 5.5.2.2 / TS 29.281, and sends it
live on a raw AF_PACKET socket. No scapy, no pip, no apt required -- only
the Python standard library.

Must be run as root (or with CAP_NET_RAW) inside the container, e.g.:
    python3 send_gtpu_pdu_type1_raw.py
"""

import fcntl
import socket
import struct

# --------------------------------------------------------------------------
# CONFIG -- adjust these to match your environment
# --------------------------------------------------------------------------

IFACE = "eth0"

OUTER_SRC_IP = "192.168.71.134"
OUTER_DST_IP = "192.168.71.150"
OUTER_SRC_PORT = 2152
OUTER_DST_PORT = 2152

DST_MAC = None   # e.g. "aa:bb:cc:dd:ee:ff"; None = broadcast

TEID = 0x11223344
QFI = 5

INNER_SRC_IP = "12.1.1.2"
INNER_DST_IP = "192.168.72.135"
INNER_SRC_PORT = 45678
INNER_DST_PORT = 5201
INNER_PAYLOAD = b"synthetic-ul-test-payload"

PCAP_OUT = "gtpu_pdu_type1.pcap"

# --------------------------------------------------------------------------
# Checksum helper
# --------------------------------------------------------------------------

def checksum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_header(src_ip, dst_ip, payload_len, proto, ident=0):
    version_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20 + payload_len
    flags_frag = 0
    ttl = 64
    checksum = 0
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, tos, total_len, ident, flags_frag,
        ttl, proto, checksum, src, dst,
    )
    checksum = checksum16(header)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, tos, total_len, ident, flags_frag,
        ttl, proto, checksum, src, dst,
    )
    return header


def udp_header_with_checksum(src_ip, dst_ip, sport, dport, payload):
    length = 8 + len(payload)
    udp_no_checksum = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        0, socket.IPPROTO_UDP, length,
    )
    checksum = checksum16(pseudo + udp_no_checksum + payload)
    if checksum == 0:
        checksum = 0xFFFF
    return struct.pack("!HHHH", sport, dport, length, checksum)


def build_ip_udp_packet(src_ip, dst_ip, sport, dport, payload):
    udp_hdr = udp_header_with_checksum(src_ip, dst_ip, sport, dport, payload)
    udp_pkt = udp_hdr + payload
    ip_hdr = ipv4_header(src_ip, dst_ip, len(udp_pkt), socket.IPPROTO_UDP)
    return ip_hdr + udp_pkt

# --------------------------------------------------------------------------
# PDU Session Container (PDU Type 1) + GTP-U framing -- same logic as the
# scapy version, just kept dependency-free.
# --------------------------------------------------------------------------

def build_pdu_session_container_ul(qfi):
    pdu_type = 1
    octet1 = (pdu_type << 4) | 0x00
    octet2 = (0 << 7) | (0 << 6) | (qfi & 0x3F)
    return bytes([octet1, octet2])


def build_gtp_extension_header(content, next_ext_type):
    raw = bytes(content)
    total_len = 1 + len(raw) + 1
    pad_needed = (-total_len) % 4
    raw = raw + b"\x00" * pad_needed
    total_len = 1 + len(raw) + 1
    assert total_len % 4 == 0
    length_units = total_len // 4
    return bytes([length_units]) + raw + bytes([next_ext_type])


def build_gtpu_packet(teid, qfi):
    GTP_EXT_PDU_SESSION_CONTAINER = 0x85

    inner_bytes = build_ip_udp_packet(
        INNER_SRC_IP, INNER_DST_IP, INNER_SRC_PORT, INNER_DST_PORT, INNER_PAYLOAD
    )

    container_content = build_pdu_session_container_ul(qfi)
    ext_header = build_gtp_extension_header(container_content, next_ext_type=0x00)

    sequence_number = 0
    npdu_number = 0
    first_ext_type = GTP_EXT_PDU_SESSION_CONTAINER
    optional_fields = struct.pack("!HBB", sequence_number, npdu_number, first_ext_type)

    flags = (1 << 5) | (1 << 4) | (1 << 2)  # version=1, PT=1, E=1
    message_type = 0xFF

    payload_after_length_field = optional_fields + ext_header + inner_bytes
    gtp_length = len(payload_after_length_field)

    gtp_header = struct.pack("!BBHI", flags, message_type, gtp_length, teid)
    return gtp_header + payload_after_length_field

# --------------------------------------------------------------------------
# Ethernet framing + raw send
# --------------------------------------------------------------------------

def get_iface_mac(sock, iface):
    info = fcntl.ioctl(
        sock.fileno(),
        0x8927,  # SIOCGIFHWADDR
        struct.pack("256s", iface[:15].encode("utf-8")),
    )
    return info[18:24]


def build_ethernet_frame(src_mac_bytes, dst_mac_bytes, payload):
    ethertype = 0x0800  # IPv4
    header = dst_mac_bytes + src_mac_bytes + struct.pack("!H", ethertype)
    return header + payload


def mac_str_to_bytes(mac_str):
    return bytes(int(b, 16) for b in mac_str.split(":"))


def write_pcap(filename, frame_bytes):
    # Minimal classic pcap writer (no extra deps).
    global_header = struct.pack(
        "<IHHiIII",
        0xA1B2C3D4, 2, 4, 0, 0, 65535, 1,  # magic, ver_major, ver_minor,
        # thiszone, sigfigs, snaplen, linktype(1=Ethernet)
    )
    ts_sec, ts_usec = 0, 0
    rec_header = struct.pack(
        "<IIII", ts_sec, ts_usec, len(frame_bytes), len(frame_bytes)
    )
    with open(filename, "wb") as f:
        f.write(global_header)
        f.write(rec_header)
        f.write(frame_bytes)


def main():
    gtp_bytes = build_gtpu_packet(TEID, QFI)
    ip_udp_bytes = build_ip_udp_packet(
        OUTER_SRC_IP, OUTER_DST_IP, OUTER_SRC_PORT, OUTER_DST_PORT, gtp_bytes
    )

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((IFACE, 0))

    src_mac = get_iface_mac(sock, IFACE)
    dst_mac = mac_str_to_bytes(DST_MAC) if DST_MAC else b"\xff\xff\xff\xff\xff\xff"

    frame = build_ethernet_frame(src_mac, dst_mac, ip_udp_bytes)

    write_pcap(PCAP_OUT, frame)
    print(f"Wrote {PCAP_OUT} ({len(frame)} bytes) for inspection in Wireshark.")

    print(f"Sending {len(frame)}-byte frame on {IFACE} ...")
    sock.send(frame)
    print("Sent.")
    sock.close()


if __name__ == "__main__":
    main()