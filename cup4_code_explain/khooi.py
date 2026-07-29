import sys
import ipaddress

from scapy.all import *
'''
sys is here to modify python's module search path. ipaddress provides utilites for manipulating 
IPv4 and IPv6 addresses and networks. scapy is a powerful Python-based interactive packet manipulation program and library.
imports scapy's packet-building, sending, receiving and parsing tools
'''

sde_install = os.environ['SDE_INSTALL'] 
# this reads the SDE_INSTALL environment variable, which should point to the SDE installation directory of the intel/ 
# barefoot tofino software development environment  
sys.path.append('%s/lib/python2.7/site-packages/tofino'%(sde_install))
sys.path.append('%s/lib/python2.7/site-packages/p4testutils'%(sde_install))
sys.path.append('%s/lib/python2.7/site-packages'%(sde_install))
# python normally searches for modules in the directories listed in sys.path. By appending these paths, 
# we ensure that Python can find the necessary modules for interacting with the Tofino switch and P4 test utilities.

# Assumes valid PYTHONPATH
import grpc
# this imports general gRPC library. gRPC provides the network communication menchanism between this control-plane
# python program and the BF runtime server controlling the tofino switch. The BF runtime server is responsible for 
# managing the P4 program running on the switch, including table entries and other configurations.
import bfrt_grpc.bfruntime_pb2 as bfrt_grpc
# this imports generated protocol buffer message defintions. It contains low-level BF runtime request and response 
# message types, which are used to communicate with the BF runtime server.
# This alias means you can write brft_grpc.SomeMessageType instead of bfrt_grpc.bfruntime_pb2.SomeMessageType, which is more concise.
import bfrt_grpc.client as gc
# this imports the higher-level BF runtime client API under the shorthand gc. This API provides convenient methods 
# for interacting with the BF runtime server, such as connecting to the server, retrieving P4 program information, 
# and managing table entries.
#                                                    BF runtime over gRPC
# So the overall flow is: python control program -------------------------------> Tofino Switch

# now the following code will connect the python control program to the Tofno switch's BF runtime server and selects the switch
# pipeline it will control. The BF runtime server is responsible for managing the P4 program running on the switch, including table entries and other configurations.
# Connect to the BF Runtime server
for bfrt_client_id in range(10): # BF runtime identifies each connected controller using a client id. this is useful because a client ID might already be occupied by another controller
    try:
        interface = gc.ClientInterface(
            grpc_addr="localhost:50052",
            client_id=bfrt_client_id,
            device_id=0,
            num_tries=1,
        )
        # this attempts to create a BF runtime server on the same machine using port 50052. The client_id is used to identify this specific controller instance, and device_id=0 indicates that it is controlling the first Tofino device. num_tries=1 means it will only attempt to connect once.
        print("Connected to BF Runtime Server as client", bfrt_client_id)
        # if successful it prints the client ID and breaks out of the loop. If it fails to connect, it will try the next client ID until it finds an available one or exhausts the range.
        break
    except:
        print("Could not connect to BF Runtime Server")
        quit

# Get information about the running program
bfrt_info = interface.bfrt_info_get() # this requests metadat about the P4 program currently running on the swithc. The returned information describes things such as the P4 program name, tables, actions, and other pipeline elements. This information is essential for the control plane to interact with the data plane correctly.
print("The target is running the P4 program: {}".format(bfrt_info.p4_name_get()))
# p4_name_get() returns the name of the currently loaded p4 program

# Establish that you are the "main" client
if bfrt_client_id == 0:
    interface.bind_pipeline_config(bfrt_info.p4_name_get())
# this binds the client to the currently running p4 pipeline configuration. Binding tells BF runtime: This client intends to
# control  the tables and resource belonging to this p4 program. In this scriptbinding is performed only when the client obtained IdD 0., which authors treat as the primary controller. Other clients can still connect and read information, but they may not be able to modify table entries unless they also bind to the pipeline.

# Get the target device, currently setup for all pipes
target = gc.Target(device_id=0, pipe_id=0xffff)
# finally, this creates a Target object that represents the specific Tofino device and pipeline (pipe_id=0xffff means all 
# pipes) that the control plane will manage. This target is used in subsequent API calls to specify which device and 
# pipeline the operations should apply to.
# A tofino ASIC contains multiple independent packet-processing pipelines, called pipes. Therefore, later code such as
# table.entry_add(target, keys, actions) will use this target to specify that the table entry should be added to all pipes of device 0.
# ==============================
# CONSTANTS
# ==============================
IP_ADDR_CU = "192.168.70.144"
IP_ADDR_DU = "192.168.70.145"
IP_ADDR_UPF = "192.168.69.134"

UDP_PORT_F1 = 2153
UDP_PORT_N3 = 2152
# ==============================

# Usage (without debug): 
# 1. offline: python3 offload.py offline sample.pcap 0
# 2. online: sudo python3 offload.py online ens1 0
mode = sys.argv[1]
net_intf = sys.argv[2]

if mode == "offline" or mode == "online":
    pass
else:
    print("invalid arguments!")
    exit(1)
"""
This above part reads the command line arguments and checks if the requested execution mode is valid. The commetns
show two possible ways to run the program: offline mode, which processes packets from a pcap file, and online mode, 
which captures packets from a live network interface. The script expects two arguments: the mode 
(either "offline" or "online") and the network interface or pcap file name. If the provided mode is not valid, 
it prints an error message and exits.
sys.arv contains the command-line arguments as a list of strings. sys.argv[0] is the script name, sys.argv[1] is 
the mode, and sys.argv[2] is the network interface or pcap file.
"""

def is_f1_gtp(pkt):
    return (pkt.getlayer("UDP").sport == UDP_PORT_F1 and pkt.getlayer("UDP").dport == UDP_PORT_F1)
# This checks whether both UDP ports equal the configured F1-U GTP port (2153). A matching packet looks like:
# DU_IP:2152 <-> CU_IP:2152. This suggests the packet carries GTP traffic over F1-U. WHy can source and destination ports 
# be the same? Because GTP-U uses the same port for both sending and receiving, so both ends of the communication use 
# port 2152 for GTP-U traffic.

def is_n3_gtp(pkt):
    return (pkt.getlayer("UDP").sport == UDP_PORT_N3 and pkt.getlayer("UDP").dport == UDP_PORT_N3)
# this performs the same for CU - UPF traffic, which uses the N3 interface. A matching packet looks like:
# CU_IP:2153 <-> UPF_IP:2153. Again, both source and destination ports are the same because GTP-U uses the same port 
# for both sending and receiving.

def is_gtp(pkt):
    return is_f1_gtp(pkt) or is_n3_gtp(pkt)

def is_du_to_cu(pkt):
    return is_f1_gtp(pkt) and (pkt.getlayer("IP").dst == IP_ADDR_CU) and (pkt.getlayer("IP").src == IP_ADDR_DU)

def is_cu_to_cn(pkt):
    return is_n3_gtp(pkt) and (pkt.getlayer("IP").dst == IP_ADDR_UPF) and (pkt.getlayer("IP").src == IP_ADDR_CU)

def is_cn_to_cu(pkt):
    return is_n3_gtp(pkt) and (pkt.getlayer("IP").dst == IP_ADDR_CU) and (pkt.getlayer("IP").src == IP_ADDR_UPF)

def is_cu_to_du(pkt):
    return is_f1_gtp(pkt) and (pkt.getlayer("IP").dst == IP_ADDR_DU) and (pkt.getlayer("IP").src == IP_ADDR_CU)


def to_byte_array(pkt):
    return bytearray(bytes(pkt))

def to_hex_string(byte_array):
    return ''.join(format(x, '02x') for x in byte_array)

"""
This function takes the raw bytes of a GTP-U header, extracts selected fields using byte positions, prints them,
and returns them as integers. The fields extracted are:
- TEID (4 bytes): Unique identifier for the GTP tunnel.
- Sequence Number (2 bytes): Used for packet ordering and loss detection.
- N-PDU Number (1 byte): Used for identifying the N-PDU within a GTP session.
- Extension Header (1 byte, optional): Indicates the presence of extension headers.
- QFI (1 byte, optional): Quality of Service Flow Identifier, used in 5G networks to identify the QoS flow associated with the packet.
The function checks if the GTP header is long enough to contain the optional fields before attempting to extract them. It returns the extracted fields
as integers, which can be used for further processing or offloading to the data plane.
"""
def parse_gtp(gtp_headers):
    teid = gtp_headers[4:8]
    seq_num = gtp_headers[8:10]
    npdu = gtp_headers[10:11]
    ext_hdr = gtp_headers[11:12] if len(gtp_headers) > 11 else None
    qfi = gtp_headers[14:15] if len(gtp_headers) > 11 else None
    # does this qfi mean if the packet belongs to urLLC/ eMBB/ mMTC? or is it just a number to identify the flow? 
    # as per 3GPP TS 23.501, the QFI is a 6-bit identifier that indicates the QoS flow associated with the packet. 
    # It is used to differentiate between different QoS flows within a PDU session, allowing the network to apply 
    # appropriate QoS treatment based on the flow's characteristics. The QFI does not directly indicate whether the 
    # packet belongs to uRLLC, eMBB, or mMTC; instead, it is used in conjunction with other parameters (such as QoS parameters) 
    # to determine the specific QoS treatment for that flow.
    # QFI identifies a QoS flow, but does not directly mean URLLC or eMBB.
    # A control-plane mapping from QFI to its QoS profile is required.
    
    print("TEID", to_hex_string(teid))
    print("Sequence Number", to_hex_string(seq_num))
    print("N-PDU Number", to_hex_string(npdu))
    if len(gtp_headers) > 11:
        print("Extension Header", to_hex_string(ext_hdr))
        print("QFI", to_hex_string(qfi))
        return int.from_bytes(teid, 'big'), int.from_bytes(seq_num, 'big'), int.from_bytes(npdu, 'big'), int.from_bytes(ext_hdr, 'big'), int.from_bytes(qfi, 'big')
    else:
        return int.from_bytes(teid, 'big'), int.from_bytes(seq_num, 'big'), int.from_bytes(npdu, 'big')
'''
Important limitaiton: This parser assumes fixed byte positions. In GTPv1-U, the sequence number, N-PDU number, 
and extension-header fields are controlled \
by the S, PN, and E flag bits in the first byte: Also, the QFI is carried inside a PDU Session Container extension header. 
It is not universally located 
at byte 14, and only its lower six bits represent the QFI:
Therefore, this function works only for the exact GTP-U header format expected by its author. 
A robust parser should first inspect the flags and 
extension-header type, then calculate the QFI’s position.
'''

def is_UE_subnet(ip_addr):
    print(ip_addr)
    return ipaddress.ip_address(ip_addr) in ipaddress.ip_network("12.0.0.0/8")

du_to_cu = dict()
cu_to_cn = dict()
def learn_du_to_cu(pkt):
    '''
    This function processes one captured Du-to-CU GTP-U packet.
    '''
    udp_payload = pkt.getlayer("UDP").payload # it removes the outer ethernet, IP and UDP headers and obtains the UDP payload. 
    #For a GTP-U packet, that payload
    # contains : GTP header + encapsulated inner IP packet. The inner IP packet is the actual user data being transported 
    # over the GTP tunnel.
    gtp_headers = to_byte_array(udp_payload)[:11] # this code assumes that F1-U GTP header is 11 bytes long. 
    #First 11 bytes - GTP header
    gtp_payload = to_byte_array(udp_payload)[11:] # remaining bytes: encapsulated inner IP packet. The inner IP packet is 
    #the actual user data being transported over the GTP tunnel.
    # hexdump(gtp_headers)
    # hexdump(gtp_payload)
    gtp_fields = parse_gtp(gtp_headers) # gets the TEID, sequence number, N-PDU number, extension header, and QFI from the 
    # GTP header. These fields are used to identify and manage the GTP tunnel and its associated user data flow.
    
    ip_pkt = IP(bytes(gtp_payload)) # the encapsulated bytes are converted into a Scapy IPv4 packet so that its inner 
    # source and destination IP addresses can be inspected.
    # the packet has two sets of IP addresses: Outer IP addresses (DU and CU) and inner IP addresses (UE and CN). 
    #The outer IP addresses are used 
    #for routing the GTP packet between the DU and CU, while the inner IP addresses identify the actual endpoints of 
    #the user data flow.
    if ip_pkt.getlayer("IP").version == 4: # this line parses the inner packet
        ip_pair = ip_pkt.getlayer("IP").src, ip_pkt.getlayer("IP").dst  # it creats a tuple containing the inner source and 
        # destination IP addresses. This tuple is used as a key in the du_to_cu dictionary to associate the GTP tunnel with 
        #the specific user data flow.
        if is_UE_subnet(ip_pkt.getlayer("IP").src) or is_UE_subnet(ip_pkt.getlayer("IP").dst): # this keeps only traffic where 
        #at least one endpoint belongs to the configured UE subnet. This handles both directions: UE-> Server and Server ->UE
            du_to_cu[ip_pair] = gtp_fields
            #it saves the ampping: (inner src_ip, inner_dst_ip) -> (teid, seq_num, npdu, ext_hdr, qfi) in the 
            # du_to_cu dictionary. This mapping is used later to offload the GTP flow to the data plane.

def learn_cu_to_cn(pkt):
    """
    This function performs the same process for packets travelling: CU --> N3 --> UPF
    """
    udp_payload = pkt.getlayer("UDP").payload # here the code assumes  that the N3 GTP header is 16 bytes long, 
    # probably because it contains an extension header such as the PDU session container carrying the QFI
    # GTP basic fields | PDU session Container | Inner IP packet
    gtp_headers = to_byte_array(udp_payload)[:16]
    gtp_payload = to_byte_array(udp_payload)[16:]
    # hexdump(gtp_headers)
    # hexdump(gtp_payload)
    gtp_fields = parse_gtp(gtp_headers)

    ip_pkt = IP(bytes(gtp_payload))
    if ip_pkt.getlayer("IP").version == 4:
        ip_pair = ip_pkt.getlayer("IP").src, ip_pkt.getlayer("IP").dst
        if is_UE_subnet(ip_pkt.getlayer("IP").src) or is_UE_subnet(ip_pkt.getlayer("IP").dst):
            cu_to_cn[ip_pair] = gtp_fields
"""
The above two functions learn which GTP tunnel is associated with each UE traffic flow. I creates mappings like:
(inner_src_ip, inner_dst_ip) -> (teid, seq_num, npdu, ext_hdr, qfi)
du_to_cu and cu_to_cn are dictionaries that store these mappings for uplink traffic. The keys are tuples of the inner source and destination
IP addresses, and the values are tuples containing the extracted GTP fields. These mappings are used later to 
offload the GTP flows to the data plane.
du_to_cu = {
    ("12.1.1.2", "192.168.70.135"): (1001, 25, 0)
}

cu_to_cn = {
    ("12.1.1.2", "192.168.70.135"): (2001, 25, 0, 133, 9)
}
This allows the program to associate the same inner UE flow with its tunnel information on both sides of the CU:
F1-U TEID 1001
        ↓
UE flow: 12.1.1.2 → 192.168.70.135
        ↓
N3 TEID 2001, QFI 9
"""

cn_to_cu = dict()
cu_to_du = dict()


def learn_cn_to_cu(pkt):
    """
    This function processes one captured core-network-to-CU GTP-U packet.

    Packet direction:
        UPF/Core Network --> N3 --> CU
    """

    # Remove the outer Ethernet, IP, and UDP headers and obtain the UDP
    # payload. For a GTP-U packet, the UDP payload contains:
    #
    #     GTP header + encapsulated inner IP packet
    #
    # The inner IP packet contains the actual user data being transported.
    udp_payload = pkt.getlayer("UDP").payload

    # This code assumes that the N3 GTP header is 16 bytes long.
    # The first 16 bytes are treated as the GTP header. This header may
    # include a PDU Session Container carrying information such as the QFI.
    gtp_headers = to_byte_array(udp_payload)[:16]

    # Everything after the first 16 bytes is treated as the encapsulated
    # inner IP packet.
    gtp_payload = to_byte_array(udp_payload)[16:]

    # These lines can be enabled to display the GTP header and inner packet
    # bytes for debugging.
    # hexdump(gtp_headers)
    # hexdump(gtp_payload)

    # Extract the TEID, sequence number, N-PDU number, extension-header
    # information, and QFI from the GTP header.
    gtp_fields = parse_gtp(gtp_headers)

    # Convert the encapsulated bytes into a Scapy IPv4 packet so that the
    # inner source and destination IP addresses can be inspected.
    #
    # The complete captured packet has two sets of IP addresses:
    #   Outer IP addresses: UPF and CU
    #   Inner IP addresses: application server/CN and UE
    ip_pkt = IP(bytes(gtp_payload))

    # Continue only if the encapsulated inner packet is IPv4.
    if ip_pkt.getlayer("IP").version == 4:

        # Create a tuple containing the inner source and destination IPs.
        #
        # For downlink traffic, this will normally be:
        #     (server_ip, UE_ip)
        ip_pair = (
            ip_pkt.getlayer("IP").src,
            ip_pkt.getlayer("IP").dst,
        )

        # Keep the packet only if at least one inner endpoint belongs to the
        # configured UE subnet.
        if (
            is_UE_subnet(ip_pkt.getlayer("IP").src)
            or is_UE_subnet(ip_pkt.getlayer("IP").dst)
        ):
            # Save the mapping:
            #
            # (inner_src_ip, inner_dst_ip)
            #               -->
            # (TEID, sequence number, N-PDU, extension header, QFI)
            #
            # This stores the N3 tunnel information for the downlink flow.
            cn_to_cu[ip_pair] = gtp_fields


def learn_cu_to_du(pkt):
    """
    This function processes one captured CU-to-DU GTP-U packet.

    Packet direction:
        CU --> F1-U --> DU
    """

    # Remove the outer Ethernet, IP, and UDP headers and obtain the UDP
    # payload:
    #
    #     GTP header + encapsulated inner IP packet
    udp_payload = pkt.getlayer("UDP").payload

    # This code assumes that the F1-U GTP header is 11 bytes long.
    # The first 11 bytes are treated as the GTP header.
    gtp_headers = to_byte_array(udp_payload)[:11]

    # Everything after the first 11 bytes is treated as the encapsulated
    # inner IP packet containing the actual user traffic.
    gtp_payload = to_byte_array(udp_payload)[11:]

    # These lines can be enabled to inspect the raw bytes during debugging.
    # hexdump(gtp_headers)
    # hexdump(gtp_payload)

    # Extract the available GTP fields, such as the TEID, sequence number,
    # and N-PDU number.
    gtp_fields = parse_gtp(gtp_headers)

    # Convert the encapsulated data into a Scapy IPv4 packet to inspect its
    # inner source and destination IP addresses.
    #
    # The complete captured packet has:
    #   Outer IP addresses: CU and DU
    #   Inner IP addresses: application server/CN and UE
    ip_pkt = IP(bytes(gtp_payload))

    # Continue only if the encapsulated inner packet is IPv4.
    if ip_pkt.getlayer("IP").version == 4:

        # Create the inner IP pair. For downlink traffic, this is normally:
        #
        #     (server_ip, UE_ip)
        ip_pair = (
            ip_pkt.getlayer("IP").src,
            ip_pkt.getlayer("IP").dst,
        )

        # Keep only packets involving an IP address from the configured
        # UE subnet.
        if (
            is_UE_subnet(ip_pkt.getlayer("IP").src)
            or is_UE_subnet(ip_pkt.getlayer("IP").dst)
        ):
            # Save the mapping:
            #
            # (inner_src_ip, inner_dst_ip)
            #               -->
            # (TEID, sequence number, N-PDU, ...)
            #
            # This stores the F1-U tunnel information for the downlink flow.
            cu_to_du[ip_pair] = gtp_fields


"""
The two functions learn the GTP tunnel information associated with each
downlink UE traffic flow.

Downlink path:

    Application server/Core Network
                |
                v
        UPF --N3--> CU --F1-U--> DU --radio--> UE

The dictionaries store mappings in the following form:

    (inner_src_ip, inner_dst_ip) --> extracted GTP fields

For example:

cn_to_cu = {
    ("192.168.70.135", "12.1.1.2"): (2002, 40, 0, 133, 9)
}

cu_to_du = {
    ("192.168.70.135", "12.1.1.2"): (1002, 40, 0)
}

This means that the same downlink UE flow is carried through two different
GTP tunnels:

    N3 TEID 2002, QFI 9
              |
              v
    Flow: 192.168.70.135 --> 12.1.1.2
              |
              v
    F1-U TEID 1002

The N3 and F1-U TEIDs can differ because they identify tunnels on different
network interfaces.

These learned mappings can later be installed in the programmable data plane
to offload packet processing.
"""


# Records which UL/DL flow pairs have already been installed in the switch.
# This prevents duplicate entries from being added to the P4 tables.
is_pushed = dict()

# Assigns a unique register index to each offloaded user/flow.
# The index is used to access per-user state in the P4 register.
assigned_user_idx = 0


def push_to_data_plane(ul_key, dl_key):
    """
    Install the learned uplink and downlink GTP tunnel mappings in the
    programmable switch.

    ul_key identifies the uplink inner flow:
        (UE_IP, server_IP)

    dl_key identifies the reverse downlink flow:
        (server_IP, UE_IP)
    """

    # This function changes the global user-index counter.
    global assigned_user_idx

    print(ul_key, dl_key)

    # Combine the UL and DL keys to identify this bidirectional flow.
    index = (ul_key, dl_key)

    # Continue only if this flow has not already been offloaded.
    if index not in is_pushed:

        # ================================================================
        # UPLINK: DU --F1-U--> CU --N3--> UPF
        # ================================================================

        # Obtain the F1-U tunnel information previously learned from
        # DU-to-CU traffic.
        f1_ul_teid, f1_ul_seq_num, f1_ul_npdu = du_to_cu[ul_key]

        # Obtain the corresponding N3 tunnel information previously learned
        # from CU-to-core-network traffic.
        n3_ul_teid, n3_ul_seq_num, n3_ul_npdu, \
            n3_ul_ext_hdr, n3_ul_qfi = cu_to_cn[ul_key]

        print(f1_ul_teid, f1_ul_seq_num, f1_ul_npdu)
        print(
            n3_ul_teid,
            n3_ul_seq_num,
            n3_ul_npdu,
            n3_ul_ext_hdr,
            n3_ul_qfi,
        )

        print(
            "UPLINK TEID (F1 to N3) MAPPING",
            f1_ul_teid,
            "TO",
            n3_ul_teid,
            "with QFI",
            n3_ul_qfi,
        )

        # Obtain the P4 match-action table responsible for accelerating
        # uplink F1-U-to-N3 packets.
        fast_f1_to_n3 = bfrt_info.table_get(
            "pipe.SwitchIngress.fastpath_f1_to_n3"
        )

        # Build the table key. The switch will match an incoming packet
        # using its F1-U GTP TEID.
        fast_f1_to_n3_key = [
            fast_f1_to_n3.make_key([
                gc.KeyTuple("hdr.gtpu.teid", f1_ul_teid)
            ])
        ]

        # Build the action data. When the F1-U TEID matches, the P4 action
        # rewrites it to the corresponding N3 TEID and adds/sets the QFI.
        fast_f1_to_n3_data = [
            fast_f1_to_n3.make_data(
                [
                    gc.DataTuple("teid", n3_ul_teid),
                    gc.DataTuple("qfi", n3_ul_qfi),
                ],
                "SwitchIngress.rewrite_f1_to_n3",
            )
        ]

        # Install the uplink rule in the switch.
        #
        # Conceptually:
        #     Match:  F1-U TEID
        #     Action: rewrite it as the N3 TEID and set the QFI
        fast_f1_to_n3.entry_add(
            target,
            fast_f1_to_n3_key,
            fast_f1_to_n3_data,
        )

        # This commented line appears to be an example of installing an IPv4
        # forwarding rule for a destination address and output port.
        #
        # p4.Ingress.ipv4_forward.entry_with_send(
        #     dst_addr=ipaddress.ip_address("192.168.70.132"),
        #     port=152
        # ).push()

        # ================================================================
        # DOWNLINK: UPF --N3--> CU --F1-U--> DU
        # ================================================================

        # Perform the same lookup for the reverse direction:
        # obtain the learned N3 tunnel information from CN-to-CU traffic.
        n3_dl_teid, n3_dl_seq_num, n3_dl_npdu, \
            n3_dl_ext_hdr, n3_dl_qfi = cn_to_cu[dl_key]

        # Obtain the corresponding F1-U tunnel information learned from
        # CU-to-DU traffic.
        f1_dl_teid, f1_dl_seq_num, f1_dl_npdu = cu_to_du[dl_key]

        print(
            n3_dl_teid,
            n3_dl_seq_num,
            n3_dl_npdu,
            n3_dl_ext_hdr,
            n3_dl_qfi,
        )
        print(f1_dl_teid, f1_dl_seq_num, f1_dl_npdu)

        print(
            "DOWNLINK TEID (N3 to F1) MAPPING",
            n3_dl_teid,
            "TO",
            f1_dl_teid,
            "with SeqNumber",
            f1_dl_seq_num,
            "and NPDU",
            f1_dl_npdu,
        )

        # Obtain the P4 table responsible for accelerating downlink
        # N3-to-F1-U packets.
        fast_n3_to_f1 = bfrt_info.table_get(
            "pipe.SwitchIngress.fastpath_n3_to_f1"
        )

        # Match incoming downlink packets using their N3 GTP TEID.
        fast_n3_to_f1_key = [
            fast_n3_to_f1.make_key([
                gc.KeyTuple("hdr.gtpu.teid", n3_dl_teid)
            ])
        ]

        # Create the downlink rewrite action.
        #
        # When the N3 TEID matches, the switch:
        #   1. rewrites it to the corresponding F1-U TEID;
        #   2. sets the initial F1-U sequence number;
        #   3. associates the flow with a register index.
        fast_n3_to_f1_data = [
            fast_n3_to_f1.make_data(
                [
                    gc.DataTuple("teid", f1_dl_teid),
                    gc.DataTuple("seq_num", f1_dl_seq_num),
                    gc.DataTuple("index", assigned_user_idx),
                ],
                "SwitchIngress.rewrite_n3_to_f1",
            )
        ]

        # Install the downlink rule in the switch.
        fast_n3_to_f1.entry_add(
            target,
            fast_n3_to_f1_key,
            fast_n3_to_f1_data,
        )

        # ================================================================
        # INITIALIZE PER-FLOW N-PDU STATE
        # ================================================================

        # Obtain the P4 register that stores the F1-U N-PDU value for each
        # offloaded user/flow.
        npdu_reg = bfrt_info.table_get(
            "pipe.SwitchIngress.npdu_reg"
        )

        # Select the register cell assigned to this flow.
        npdu_keys = [
            npdu_reg.make_key([
                gc.KeyTuple("$REGISTER_INDEX", assigned_user_idx)
            ])
        ]

        # Set that register cell to the learned downlink F1-U N-PDU value.
        npdu_data = [
            npdu_reg.make_data([
                gc.DataTuple(
                    "SwitchIngress.npdu_reg.f1",
                    f1_dl_npdu,
                )
            ])
        ]

        # Modify the selected register cell in the switch.
        npdu_reg.entry_mod(
            target,
            npdu_keys,
            npdu_data,
        )

        # Reserve the next register index for the next user/flow.
        assigned_user_idx += 1

        print("offloaded!")

        # Mark this bidirectional flow as already installed.
        is_pushed[index] = True

    print("already offloaded!")


"""
This function joins the mappings learned from all four traffic directions
and installs the resulting fast-path rules in the P4 switch.

The uplink mapping is:

    Match F1-U TEID
            |
            v
    Rewrite to N3 TEID and add/set QFI

For example:

    F1-U TEID 1001 --> N3 TEID 2001, QFI 9

The downlink mapping performs the reverse translation:

    Match N3 TEID
            |
            v
    Rewrite to F1-U TEID and set F1-U state

For example:

    N3 TEID 2002 --> F1-U TEID 1002

The P4 register stores per-flow N-PDU state. Each offloaded flow receives
a unique assigned_user_idx that identifies its register cell.

The is_pushed dictionary prevents the same pair of uplink and downlink
flows from being installed more than once.
"""
def offload_gtp_flow():
    # Find uplink flows observed on both F1-U (DU→CU) and N3 (CU→UPF).
    du_to_cu_keyset = set(du_to_cu.keys())
    cu_to_cn_keyset = set(cu_to_cn.keys())
    intersect_ul = du_to_cu_keyset.intersection(cu_to_cn_keyset)

    # Find downlink flows observed on both N3 (UPF→CU) and F1-U (CU→DU).
    cn_to_cu_keyset = set(cn_to_cu.keys())
    cu_to_du_keyset = set(cu_to_du.keys())
    intersect_dl = cn_to_cu_keyset.intersection(cu_to_du_keyset)

    print("========== PREPARING TO OFFLOAD ")

    # A downlink flow has the reverse source/destination IP pair of its
    # corresponding uplink flow.
    for ul_key in intersect_ul:
        dl_key = (ul_key[1], ul_key[0])

        # Offload only after mappings for all four directions are available.
        if dl_key in intersect_dl:
            push_to_data_plane(ul_key, dl_key)


def cu_offload_callback(pkt):
    """
    Process each captured UDP packet, learn its GTP mapping, and check
    whether the complete bidirectional flow is ready for offloading.
    """

    if is_gtp(pkt):

        # Identify the packet's interface and direction, then learn its
        # inner-IP-to-GTP-tunnel mapping.
        if is_du_to_cu(pkt):
            print("========== F1-U UL ==========")
            learn_du_to_cu(pkt)

        elif is_cu_to_cn(pkt):
            print("========== N3 UL ==========")
            learn_cu_to_cn(pkt)

        elif is_cn_to_cu(pkt):
            print("========== N3 DL ==========")
            learn_cn_to_cu(pkt)

        elif is_cu_to_du(pkt):
            print("========== F1-U DL ==========")
            learn_cu_to_du(pkt)

        else:
            print("Invalid")

        # Check whether both uplink and downlink mappings are now complete.
        offload_gtp_flow()


if mode == "online":
    # Capture live UDP packets from the specified network interface.
    # prn calls cu_offload_callback() once for every captured packet.
    # store=0 prevents Scapy from keeping packets in memory.
    sniff(
        iface=net_intf,
        prn=cu_offload_callback,
        filter="udp",
        store=0,
    )

elif mode == "offline":
    # Perform the same processing using packets from a PCAP file.
    sniff(
        offline=net_intf,
        prn=cu_offload_callback,
        filter="udp",
        store=0,
    )