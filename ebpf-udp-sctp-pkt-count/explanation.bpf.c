#include <linux/bpf.h>
// Defines core eBPF data structures and constants.
// struct xdp_md is the context passed to an XDP program. It contains packet
// metadata, including pointers to the start and end of the received packet.
// This header also defines actions such as XDP_PASS and XDP_DROP.

#include <linux/if_ether.h>
// Defines Ethernet-related structures and constants.
// struct ethhdr represents an Ethernet header.
// ETH_P_IP identifies an Ethernet frame carrying an IPv4 packet.

#include <linux/ip.h>
// Defines struct iphdr, which represents an IPv4 header.
// It contains fields such as source/destination IP, protocol, TTL, and IHL.

#include <linux/udp.h>
// Defines struct udphdr, the Linux kernel's representation of a UDP header.
// It contains four fields: source port, destination port, length, and checksum.

#include <linux/in.h>
// Defines IP protocol-number constants.
// For example, IPPROTO_UDP identifies UDP and IPPROTO_SCTP identifies SCTP.

#include <bpf/bpf_endian.h>
// Provides endian-conversion helpers such as bpf_htons().
//
// Network protocols store multi-byte numbers in network byte order, which is
// big-endian. Most x86 CPUs use little-endian host byte order. Therefore,
// directly comparing a port number read from a packet with the integer 2152
// may produce the wrong result.
//
// bpf_htons means "BPF host to network short":
//   host    = the CPU's normal byte order
//   network = network/big-endian byte order
//   short   = a 16-bit value
//
// Therefore, bpf_htons(2152) converts the normal integer 2152 into the same
// byte order used by a 16-bit port number inside a network packet.

#include <bpf/bpf_helpers.h>
// Provides macros used when defining eBPF programs and maps, such as SEC(),
// __uint(), and __type(). It also declares helpers such as
// bpf_map_lookup_elem() that an eBPF program can request from the kernel.


#define GTPU_PORT 2152
// GTP-U normally uses UDP port 2152.
// On F1-U, user-plane packets between the DU and CU are transported using
// GTP-U, so this port is used to recognize those packets.

#define F1AP_PORT 38472
// F1-C carries F1AP control-plane messages over SCTP.
// The standard SCTP port associated with F1AP is 38472.


enum counter_key {
    USER_PLANE = 0,
    CONTROL_PLANE = 1,
};
// These names represent the two indexes in our array map.
// Instead of writing increment_counter(0), we can write
// increment_counter(USER_PLANE), which makes the code easier to understand.


struct sctp_common_header {
    __be16 source;
    __be16 dest;
    __be32 verification_tag;
    __be32 checksum;
};
// This structure describes the fixed common header at the beginning of every
// SCTP packet.
//
// __be16 means an unsigned 16-bit value stored in big-endian byte order.
// __be32 means an unsigned 32-bit value stored in big-endian byte order.
//
// source and dest contain the SCTP source and destination ports.
// verification_tag helps verify that the SCTP packet belongs to the correct
// association. checksum is used to detect corrupted SCTP packets.
//
// We define this small structure ourselves because this program only needs the
// SCTP ports and does not need to parse SCTP chunks or other SCTP details.


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    // Create a BPF array map. Its keys are fixed integer indexes beginning
    // from zero. Unlike a hash map, all array entries already exist.

    __uint(max_entries, 2);
    // Allocate two entries:
    // index 0 for the user-plane count and index 1 for the control-plane count.

    __type(key, __u32);
    // Each key is a 32-bit unsigned integer.

    __type(value, __u64);
    // Each stored counter is a 64-bit unsigned integer, allowing it to hold
    // a large packet count.
} plane_counter SEC(".maps");
// plane_counter is shared between the kernel-space eBPF program and the
// user-space program.
//
// The kernel program increments its entries as packets arrive. The user-space
// program obtains the map's file descriptor and reads the same entries:
//
//   plane_counter[USER_PLANE]    -> number of F1-U packets
//   plane_counter[CONTROL_PLANE] -> number of F1-C packets
//
// SEC(".maps") places this definition in the ELF section named ".maps".
// When libbpf loads the compiled object file, it finds this section and asks
// the kernel to create the corresponding BPF map.


static __always_inline void increment_counter(__u32 key)
// static means this function is used only inside this source file.
//
// __always_inline asks the compiler to insert this function's instructions
// directly at the call site. Small helper functions are commonly inlined in
// eBPF programs because it simplifies the final instructions seen by the
// eBPF verifier.
{
    __u64 *value;
    // This pointer will point to the 64-bit counter stored inside the map.

    value = bpf_map_lookup_elem(&plane_counter, &key);
    // Search plane_counter for the supplied key.
    //
    // For an array map, key 0 returns the user-plane counter and key 1 returns
    // the control-plane counter. The helper returns a pointer to the map value
    // if successful or NULL if the lookup fails.

    if (value) {
        __sync_fetch_and_add(value, 1);
        // Atomically add one to the counter.
        //
        // Atomicity is necessary because packets may be processed concurrently
        // on several CPU cores. A normal operation such as *value += 1 could
        // lose updates if two CPUs modified the value at the same time.
    }
}


SEC("xdp")
// SEC("xdp") puts the following function in the ELF section named "xdp".
// The loader uses this section name to recognize it as an XDP program that
// can be attached to the receive path of a network interface.

int count_user_and_control_plane(struct xdp_md *ctx)
// The kernel executes this function once for each incoming packet.
//
// ctx does not contain the complete packet as a normal C structure. Instead,
// it provides metadata, including integer addresses for the beginning and end
// of the packet data.
{
    void *data = (void *)(long)ctx->data;
    // data points to the first byte of the received Ethernet frame.
    //
    // ctx->data is stored as an integer in struct xdp_md. The casts convert
    // that integer into a pointer that the program can use to parse the packet.

    void *data_end = (void *)(long)ctx->data_end;
    // data_end points immediately after the packet's final byte.
    //
    // Before accessing any header, we must verify that the complete header
    // lies before data_end. This prevents out-of-bounds memory access and is
    // required by the eBPF verifier.

    struct ethhdr *eth = data;
    // struct ethhdr comes from <linux/if_ether.h>.
    // Because an Ethernet frame begins with an Ethernet header, data can be
    // interpreted as a pointer to struct ethhdr.

    struct iphdr *ip;
    // This will point to the IPv4 header after we validate the Ethernet header.

    void *transport;
    // This will point to the transport-layer header: UDP or SCTP.

    __u32 ip_header_length;
    // This will hold the complete IPv4 header length in bytes.


    /*
     * eth + 1 does not mean "add one byte."
     *
     * Because eth is a struct ethhdr pointer, adding one moves the pointer
     * forward by sizeof(struct ethhdr), normally 14 bytes. Therefore,
     * eth + 1 points immediately after the Ethernet header.
     *
     * If that position is beyond data_end, the packet is too short to contain
     * a complete Ethernet header, so reading eth->h_proto would be unsafe.
     */
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }


    /*
     * h_proto is the EtherType field of the Ethernet header. It tells us which
     * protocol is carried inside the Ethernet frame.
     *
     * ETH_P_IP represents IPv4. However, eth->h_proto came from the network
     * packet and is therefore in network byte order. ETH_P_IP is written as a
     * normal host-order C constant.
     *
     * bpf_htons() converts the 16-bit ETH_P_IP constant from host byte order
     * to network byte order, making the comparison correct.
     *
     * Packets that are not IPv4, such as ARP or IPv6 packets, are ignored.
     */
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }


    ip = (void *)(eth + 1);
    // Since Ethernet is followed by IPv4 in this packet, the byte immediately
    // after the Ethernet header is interpreted as struct iphdr.

    /*
     * Check that at least the fixed part of the IPv4 header is present before
     * accessing fields such as ip->ihl or ip->protocol.
     */
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }


    /*
     * IHL means Internet Header Length.
     *
     * The ip->ihl field is four bits wide and specifies the IPv4 header length
     * in units of 32-bit words, not bytes. One 32-bit word contains four bytes,
     * so we multiply IHL by four:
     *
     *   IHL = 5  -> 5 × 4 = 20-byte IPv4 header
     *   IHL = 6  -> 6 × 4 = 24-byte IPv4 header
     *   IHL = 15 -> 15 × 4 = 60-byte IPv4 header
     *
     * A normal IPv4 header without options has IHL 5. A larger value indicates
     * that optional IPv4 fields are present. Using IHL lets us locate the
     * transport header correctly even when IPv4 options exist.
     */
    ip_header_length = (__u32)ip->ihl * 4;


    /*
     * sizeof(*ip) is the size of the basic struct iphdr, normally 20 bytes.
     * A valid IPv4 header cannot be shorter than that. Therefore, an IHL value
     * below 5 produces an invalid header length and must not be parsed.
     */
    if (ip_header_length < sizeof(*ip)) {
        return XDP_PASS;
    }


    /*
     * Move forward by the complete IPv4 header length to locate the beginning
     * of the transport-layer header.
     *
     * We cast ip to char * because pointer arithmetic on a char pointer moves
     * one byte at a time. Therefore, adding ip_header_length advances exactly
     * that many bytes.
     */
    transport = (void *)((char *)ip + ip_header_length);


    /*
     * Verify that the calculated transport-header position is still inside
     * the received packet.
     */
    if (transport > data_end) {
        return XDP_PASS;
    }


    if (ip->protocol == IPPROTO_UDP) {
        /*
         * The protocol field in the IPv4 header identifies the next protocol.
         * IPPROTO_UDP means that a UDP header follows the IPv4 header.
         *
         * struct udphdr is a library/kernel structure defined in
         * <linux/udp.h>. It represents the layout of a UDP header:
         *
         *   source -> 16-bit source port
         *   dest   -> 16-bit destination port
         *   len    -> UDP header plus payload length
         *   check  -> UDP checksum
         *
         * Assigning transport to a struct udphdr pointer does not copy or
         * modify the packet. It only tells C to interpret those packet bytes
         * according to the layout of a UDP header.
         */
        struct udphdr *udp = transport;


        /*
         * udp + 1 points immediately after one complete UDP header.
         * If it exceeds data_end, the packet is too short to safely read the
         * UDP source and destination ports.
         */
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }


        /*
         * F1-U carries user-plane packets using GTP-U over UDP port 2152.
         *
         * udp->source and udp->dest are 16-bit values read directly from the
         * packet, so both are in network byte order. GTPU_PORT is a regular
         * host-order integer constant. bpf_htons(GTPU_PORT) converts 2152 into
         * a 16-bit network-order value before the comparison.
         *
         * For DU-to-CU traffic, 2152 may be the destination port. For CU-to-DU
         * traffic, it may be the source port. Checking both fields allows the
         * program to recognize both directions.
         */
        if (udp->source == bpf_htons(GTPU_PORT) ||
            udp->dest == bpf_htons(GTPU_PORT)) {
            increment_counter(USER_PLANE);
        }

    } else if (ip->protocol == IPPROTO_SCTP) {
        /*
         * IPPROTO_SCTP means that the transport header is an SCTP header.
         *
         * We interpret the current transport pointer using the
         * sctp_common_header structure defined earlier. This lets us access
         * the SCTP source and destination ports.
         */
        struct sctp_common_header *sctp = transport;


        /*
         * Ensure that all 12 bytes of the SCTP common header are available
         * before accessing sctp->source or sctp->dest.
         */
        if ((void *)(sctp + 1) > data_end) {
            return XDP_PASS;
        }


        /*
         * F1-C carries F1AP control-plane messages using SCTP port 38472.
         *
         * As with UDP, SCTP ports are stored in network byte order. Therefore,
         * bpf_htons() converts the host-order constant 38472 to network byte
         * order before comparison.
         *
         * Checking both source and destination ports detects traffic traveling
         * from the DU to the CU and from the CU to the DU.
         */
        if (sctp->source == bpf_htons(F1AP_PORT) ||
            sctp->dest == bpf_htons(F1AP_PORT)) {
            increment_counter(CONTROL_PLANE);
        }
    }


    return XDP_PASS;
    // Allow the packet to continue through the kernel's normal network stack.
    // This program only observes and counts packets. It does not drop, modify,
    // or redirect them.
}


char LICENSE[] SEC("license") = "GPL";
// Places the license string in the ELF "license" section.
// The kernel checks this value while loading the program because some eBPF
// helper functions are restricted to GPL-compatible eBPF programs.
/*
 * This is a global character array containing the string "GPL".
 * SEC("license") places it in a special section of the compiled eBPF
 * object file. When the program is loaded, the kernel reads this section
 * to determine the program's license. Some eBPF helpers are available
 * only to programs with a GPL-compatible license.
 */