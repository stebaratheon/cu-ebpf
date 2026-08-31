#!/usr/bin/env python3
"""
send_gtpu_pdu_type1.py

Builds a spec-correct GTPv1-U packet carrying a PDU Session Container
extension header with PDU Type = 1 (UL PDU SESSION INFORMATION), per
3GPP TS 38.415 clause 5.5.2.2 and TS 29.281 for the outer GTP-U/extension
header framing. Writes it to a .pcap file AND sends it live on a chosen
network interface.

Requires: scapy (pip install scapy --break-system-packages), and root
privileges to send raw packets.

Run as root, e.g.:
    sudo python3 send_gtpu_pdu_type1.py
"""

import struct

from scapy.all import Ether, IP, UDP, Raw, sendp, wrpcap, conf, get_if_hwaddr

# --------------------------------------------------------------------------
# CONFIG -- adjust these to match your environment
# --------------------------------------------------------------------------

IFACE = "lo"                 # interface to send on (must be the one your
                                # XDP program is attached to, or upstream of it)

OUTER_SRC_IP = "192.168.71.134" # e.g. the gNB/DU-side IP in your setup
OUTER_DST_IP = "192.168.71.150" # e.g. the UPF-side IP in your setup
OUTER_SRC_PORT = 2152
OUTER_DST_PORT = 2152

DST_MAC = None                  # set to a specific MAC if needed, e.g.
                                 # "aa:bb:cc:dd:ee:ff"; None = broadcast
                                 # (works for many bridge/veth test setups,
                                 # but check your topology)

TEID = 0x11223344                # arbitrary uplink TEID for this test

QFI = 5                          # 6-bit QoS Flow Identifier (0-63)

# Inner "user data" packet carried inside the GTP-U tunnel (this is what
# arrives at the UPF over N3 for a real UL PDU Session Information frame).
INNER_SRC_IP = "12.1.1.2"        # e.g. UE-assigned IP
INNER_DST_IP = "192.168.72.135"  # e.g. ext-dn / iperf3 server IP
INNER_SRC_PORT = 45678
INNER_DST_PORT = 5201            # iperf3 default port
INNER_PAYLOAD = b"synthetic-ul-test-payload"

PCAP_OUT = "gtpu_pdu_type1.pcap"

# --------------------------------------------------------------------------
# Build the PDU Session Container extension header (PDU Type = 1)
# per TS 38.415 clause 5.5.2.2, minimal frame (no optional fields).
# --------------------------------------------------------------------------

def build_pdu_session_container_ul(qfi):
    """
    Octet 1: PDU Type (bits 7-4) | QMP | DL Delay Ind | UL Delay Ind | SNP
    Octet 2: N3/N9 Delay Ind | New IE Flag | QFI (6 bits)
    All optional-field flags are left at 0, so no further octets are needed
    (no time stamps, no delay results, no sequence number, no New IE Flags
    octet).
    """
    pdu_type = 1
    octet1 = (pdu_type << 4) | 0x00   # QMP=0, DL Delay Ind=0, UL Delay Ind=0, SNP=0
    octet2 = (0 << 7) | (0 << 6) | (qfi & 0x3F)  # N3/N9 Delay Ind=0, New IE Flag=0
    return bytes([octet1, octet2])


def build_gtp_extension_header(ext_type, content, next_ext_type):
    """
    Wraps `content` bytes as a GTP-U extension header (TS 29.281 clause 5.2.1):
        [length_in_4_octet_units][content...][next_extension_type]
    `content` here is the PDU Session Container's own payload (2 bytes for
    our minimal frame). Pads content to a 4-octet boundary if needed.
    """
    # total extension header length = 1 (length octet) + len(content) + 1 (next type)
    raw = bytes(content)
    total_len = 1 + len(raw) + 1
    pad_needed = (-total_len) % 4
    raw = raw + b"\x00" * pad_needed
    total_len = 1 + len(raw) + 1
    length_units = total_len // 4
    assert total_len % 4 == 0, "extension header must be a multiple of 4 octets"
    return bytes([length_units]) + raw + bytes([next_ext_type])


def build_gtpu_packet(teid, qfi):
    """
    Builds the full GTPv1-U header + PDU Session Container extension
    (PDU Type 1) + inner IP/UDP payload, per TS 29.281 (outer framing) and
    TS 38.415 5.5.2.2 (PDU Type 1 content).
    """
    GTP_EXT_PDU_SESSION_CONTAINER = 0x85

    # Inner "user data" packet (T-PDU payload)
    inner_pkt = (
        IP(src=INNER_SRC_IP, dst=INNER_DST_IP)
        / UDP(sport=INNER_SRC_PORT, dport=INNER_DST_PORT)
        / Raw(load=INNER_PAYLOAD)
    )
    inner_bytes = bytes(inner_pkt)

    # PDU Session Container content + extension header wrapper
    container_content = build_pdu_session_container_ul(qfi)
    ext_header = build_gtp_extension_header(
        GTP_EXT_PDU_SESSION_CONTAINER, container_content, next_ext_type=0x00
    )

    # Optional fields present because E flag is set: seq number (2B, unused=0),
    # N-PDU number (1B, unused=0), next extension header type (1B).
    sequence_number = 0
    npdu_number = 0
    first_ext_type = GTP_EXT_PDU_SESSION_CONTAINER
    optional_fields = struct.pack("!HBB", sequence_number, npdu_number, first_ext_type)

    # GTPv1-U mandatory header flags byte:
    #   version=1 (bits 7-5), PT=1 (bit 4), reserved=0 (bit 3),
    #   E=1 (bit 2), S=0 (bit 1), PN=0 (bit 0)
    flags = (1 << 5) | (1 << 4) | (1 << 2)
    message_type = 0xFF  # G-PDU (user data)

    payload_after_length_field = optional_fields + ext_header + inner_bytes
    gtp_length = len(payload_after_length_field)  # per TS 29.281, excludes the
                                                   # mandatory 8-byte header itself

    gtp_header = struct.pack("!BBHI", flags, message_type, gtp_length, teid)

    return gtp_header + payload_after_length_field


# --------------------------------------------------------------------------
# Assemble full Ethernet/IP/UDP/GTP-U frame
# --------------------------------------------------------------------------

def build_full_frame():
    gtp_bytes = build_gtpu_packet(TEID, QFI)

    ip_udp = (
        IP(src=OUTER_SRC_IP, dst=OUTER_DST_IP)
        / UDP(sport=OUTER_SRC_PORT, dport=OUTER_DST_PORT)
        / Raw(load=gtp_bytes)
    )

    dst_mac = DST_MAC or "ff:ff:ff:ff:ff:ff"
    try:
        src_mac = get_if_hwaddr(IFACE)
    except Exception:
        src_mac = None  # let Scapy fill it in if unavailable

    eth = Ether(dst=dst_mac) if src_mac is None else Ether(src=src_mac, dst=dst_mac)
    frame = eth / ip_udp
    return frame


def main():
    frame = build_full_frame()

    print("Built frame:")
    frame.show()

    wrpcap(PCAP_OUT, frame)
    print(f"\nWrote {PCAP_OUT} (open in Wireshark to inspect).")

    '''
    print(f"\nSending live on interface '{IFACE}' ...")
    sendp(frame, iface=IFACE, verbose=True)
    print("Sent.")
    '''

if __name__ == "__main__":
    main()