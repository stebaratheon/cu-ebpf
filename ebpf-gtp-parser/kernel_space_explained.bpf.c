#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define GTPU_PORT 2152
/* UDP port 2152 is assigned by IANA and specified by 3GPP as the standard
 * destination port for GTP-U user-plane packets. The program checks this port
 * to distinguish likely GTP-U traffic from ordinary UDP traffic.
 */

#define GTPU_G_PDU 255
/* 3GPP assigns message-type value 255 (0xFF) to G-PDU. A G-PDU carries the
 * actual user payload, such as an encapsulated IP packet, through a GTP-U tunnel.
 */

#define GTP_EXT_PDU_SESSION_CONTAINER 0x85
/* 3GPP assigns extension-header type value 0x85 to the PDU Session Container.
 * 0x85 is simply hexadecimal notation for the standardized numeric value 133;
 * it is not calculated by this program. In 5G GTP-U traffic, this extension
 * can carry PDU-session information such as the QoS Flow Identifier (QFI).
 */

/*
 * One record sent from this kernel-space XDP program to user space.
 *
 * The program fills the outer fields for every IPv4/UDP packet. For a valid
 * GTP-U G-PDU, it also fills the GTP fields and, when available, the inner-IP
 * fields. The *_present fields tell user space which optional values are
 * valid; a zero value by itself is not enough because zero can be real data.
 */
struct gtp_event {
    __u32 outer_src_ip;
    __u32 outer_dst_ip;
    __u32 inner_src_ip;
    __u32 inner_dst_ip;
    __u32 teid;
    __u16 outer_src_port;
    __u16 outer_dst_port;
    __u16 gtp_length;
    __u8 version;
    __u8 protocol_type;
    __u8 message_type;
    __u8 flag_e;
    __u8 flag_s;
    __u8 flag_pn;
    __u8 sequence_present;
    __u8 npdu_present;
    __u16 sequence_number;
    __u8 npdu_number;
    __u8 first_extension_type;
    __u8 qfi_present;
    __u8 qfi;
    __u8 inner_ip_present;
    __u8 inner_protocol;
    __u8 is_gtpu;
    __u8 pad;
    __u64 gtpu_count;
    __u64 udp_non_gtpu_count;
};

/*
 * A ring buffer is a shared kernel-to-user-space queue. For each relevant
 * packet, XDP reserves one gtp_event here, fills it, and submits it. The
 * user-space loader consumes the records and prints them. If the buffer is
 * full, reserve fails and this packet simply produces no event.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); /* 16 MiB shared event buffer */
} events SEC(".maps");

/* Keys used to address the two cells in packet_counts. */
enum counter_index {
    COUNTER_GTPU = 0,
    COUNTER_UDP_NON_GTPU = 1,
};

/*
 * Persistent kernel-side totals. Unlike a ring-buffer record, these values
 * remain in the map after user space consumes an event. Atomic increments are
 * used because multiple CPUs may execute this XDP program simultaneously.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} packet_counts SEC(".maps");

/*
 * The mandatory eight-byte GTPv1-U header. Multi-byte fields are received in
 * network byte order and are converted before being copied into the event.
 */
struct gtpv1_base {
    __u8 flags;
    __u8 message_type;
    __be16 length;
    __be32 teid;
};

SEC("xdp")
int parse_gtpu(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *outer_ip;
    struct udphdr *udp;
    struct gtpv1_base *gtp;
    struct gtp_event *event;
    void *cursor;
    __u32 outer_ihl;
    __u8 flags, next_extension = 0;
    __u32 counter_key;
    __u64 *counter;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_PASS;
    if (outer_ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    outer_ihl = outer_ip->ihl * 4;
    if (outer_ihl < sizeof(*outer_ip))
        return XDP_PASS;
    udp = (void *)outer_ip + outer_ihl;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    gtp = (void *)(udp + 1);

    /*
     * Reserve the event before classification because both GTP-U and other
     * UDP packets must be reported. Reserved memory belongs to this program
     * until it is submitted (or explicitly discarded).
     */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    /*
    * Reserve enough writable space in the 'events' ring buffer for one
    * struct gtp_event. '&events' identifies the ring-buffer map,
    * 'sizeof(*event)' requests exactly one event record, and 0 means
    * no reserve flags. The helper returns NULL if space is unavailable.
    */
    if (!event)
        return XDP_PASS;

    /* Clear unused/optional fields so user space never reads stale bytes. */
    /*
    * Initialize every byte of the reserved event record to zero.
    * 'event' points to the beginning of the struct gtp_event memory,
    * 0 is the value written into each byte, and sizeof(*event) is the
    * total number of bytes occupied by one struct gtp_event. This prevents
    * unassigned or optional fields from containing stale data and ensures
    * that fields not found in the current packet remain zero. __builtin_memset
    * is the compiler-provided form of memset and can be safely translated
    * into instructions accepted by the eBPF verifier.
    */
    __builtin_memset(event, 0, sizeof(*event));
    event->outer_src_ip = outer_ip->saddr;
    event->outer_dst_ip = outer_ip->daddr;
    event->outer_src_port = bpf_ntohs(udp->source);
    event->outer_dst_port = bpf_ntohs(udp->dest);

    /*
     * Treat a UDP packet as GTP-U only if:
     *   1. one UDP endpoint uses the standard GTP-U port;
     *   2. the complete mandatory GTP header is inside the packet;
     *   3. the header says GTP version 1, protocol type GTP, and G-PDU
        * A packet failing any test is still emitted, but as UDP non-GTP-U.
        */
    if ((udp->source != bpf_htons(GTPU_PORT) &&
         udp->dest != bpf_htons(GTPU_PORT)) ||
        (void *)(gtp + 1) > data_end) {
        goto submit_non_gtpu;
    }
    /*
    * Reject the packet as non-GTP-U only when BOTH the source port and the
    * destination port are not 2152. Therefore, the packet passes this test if
    * either endpoint uses GTP-U port 2152, covering both traffic directions:
    *
    * source port 2152      -> packet sent from a GTP-U endpoint
    * destination port 2152 -> packet sent toward a GTP-U endpoint
    *
    * bpf_htons() converts the host-order value 2152 to the network byte order
    * used by the UDP header.
    */

    flags = gtp->flags;
    /**
    * The 8-bit GTP flags field is arranged as:
    *
    *   Bit position:   7  6  5  4  3  2  1  0
    *                   V  V  V  PT 0  E  S  PN
    *
    * Bit 4 is the Protocol Type (PT) bit, and it must be 1 for GTP:
    *
    *   0x10          = 00010000
    *   flags         = VVVPT0ESPN
    *                            ^
    *   flags & 0x10 keeps only bit 4 and clears all other bits.
    *
    * If PT = 1:
    *     flags & 0x10 gives 00010000 (nonzero), and ! makes it false.
    *     Therefore, the packet passes this rejection check.
    *
    * If PT = 0:
    *     flags & 0x10 gives 00000000 (zero), and ! makes it true.
    *     Therefore, the packet is rejected because it identifies GTP'
    *     rather than GTP.
    *
    * Bit positions are counted from right to left starting at zero. Therefore,
    * bit 4 is the fifth bit from the right.
    */
   /**
    * /*
        *   Bit position:   7  6  5   4   3   2  1   0
        *                   V  V  V   PT  0   E  S   PN
        *
        * V  = Version: three bits representing the GTP version; they should be
        *      001 for GTPv1.
        *
        * PT = Protocol Type: 1 means GTP; 0 means the older GTP' protocol.
        *
        * 0  = Reserved bit: reserved by the standard and normally set to zero.
        *
        * E  = Extension-header flag: 1 means one or more extension headers follow
        *      the mandatory GTP header.
        *
        * S  = Sequence-number flag: 1 means the optional sequence-number field is
        *      present and meaningful.
        *
        * PN = N-PDU-number flag: 1 means the optional N-PDU-number field is present
        *      and meaningful.
        *
        * Therefore, “ESPN” is not one word. It represents the three separate flags
        * E, S, and PN.
    */
    if ((flags >> 5) != 1 || !(flags & 0x10) ||
        gtp->message_type != GTPU_G_PDU) {
        goto submit_non_gtpu;
    }
    /**
        * 1. Version = 1:
        *    The three highest flag bits contain the GTP protocol version. A value of
        *    1 identifies the GTPv1 header format that this program understands. Other
        *    versions may arrange their header fields differently, so parsing them
        *    with struct gtpv1_base would be unsafe or incorrect.
        *                 *
        * 2. Protocol Type (PT) = 1:
        *    This bit indicates that the packet uses GTP rather than the older GTP'
        *    protocol. Therefore, the remaining header can be interpreted as GTP-U.
        *
        * 3. Message Type = 255 (G-PDU):
        *    GTP-U also carries signalling messages such as Echo Request and Error
        *    Indication. A G-PDU is selected because it carries the actual tunneled
        *    user-plane payload, such as an IP packet exchanged between a UE and the
        *    data network. Only a G-PDU is therefore expected to contain the inner
        *    packet that this program later attempts to parse.
        * 
        * /*
        * (flags >> 5) != 1 checks the GTP version:
        * The version is stored in the highest three bits (bits 7–5). Shifting right
        * by five removes the lower bits and leaves the version value. If it is not 1,
        * this is not a GTPv1 packet.
        *
        * !(flags & 0x10) checks the Protocol Type (PT) flag:
        * 0x10 selects bit 4 because 0x10 = 00010000 in binary. If that bit is 1, the
        * packet is GTP; if it is 0, the packet is the older GTP' protocol. The !
        * makes the condition true when the PT bit is not set.
     */

    event->is_gtpu = 1;

    /* Increment the shared total and place its new value in this event. */
    counter_key = COUNTER_GTPU;
    counter = bpf_map_lookup_elem(&packet_counts, &counter_key);
    if (counter)
        event->gtpu_count = __sync_fetch_and_add(counter, 1) + 1;

    event->version = flags >> 5;
    event->protocol_type = (flags >> 4) & 1;
    event->flag_e = (flags >> 2) & 1;
    event->flag_s = (flags >> 1) & 1;
    event->flag_pn = flags & 1;
    event->message_type = gtp->message_type;
    event->gtp_length = bpf_ntohs(gtp->length);
    event->teid = bpf_ntohl(gtp->teid);
    /*
    * Multi-byte values in packet headers are stored in network byte order,
    * which is big-endian. The CPU may use a different byte order, so these
    * helpers convert the received values into the CPU's host byte order.
    *
    * bpf_ntohs():
    *     "network to host short"
    *     Converts a 16-bit value (short), so it is used for gtp->length.
    *
    * bpf_ntohl():
    *     "network to host long"
    *     Converts a 32-bit value (long), so it is used for gtp->teid.
    *
    * Therefore, the event stores the GTP length and TEID as ordinary numeric
    * values that the eBPF program and user-space program can interpret correctly.
    */

    /* cursor always points to the next unparsed byte after the GTP header. */
    cursor = (void *)(gtp + 1);

    /*
     * When any E/S/PN flag is set, GTP adds one common four-byte optional
     * block: sequence number (2), N-PDU number (1), next-extension type (1).
     * S and PN determine whether their corresponding values are meaningful.
     */
    if (flags & 0x07) {
        __u8 *optional = cursor;

        if ((void *)(optional + 4) > data_end)
            goto submit;

        if (event->flag_s) {
            event->sequence_number = ((__u16)optional[0] << 8) | optional[1];
            /*
            * Reconstruct the 16-bit GTP sequence number from its two individual bytes.
            *
            * optional[0] contains the most-significant byte and optional[1] contains
            * the least-significant byte because multi-byte GTP fields use network byte
            * order (most-significant byte first).
            *
            * (__u16)optional[0] converts the first byte to a 16-bit value before shifting.
            * Shifting it left by 8 moves it into the upper eight bits:
            *
            *     optional[0]                  = AAAAAAAA
            *     ((__u16)optional[0] << 8)    = AAAAAAAA 00000000
            *
            * The bitwise OR operator "|" then places optional[1] in the lower eight bits:
            *
            *     AAAAAAAA 00000000
            *   | 00000000 BBBBBBBB
            *   -------------------
            *     AAAAAAAA BBBBBBBB
            *
            * The result is the complete host-readable 16-bit sequence number.
            */
            event->sequence_present = 1;
        }
        if (event->flag_pn) {
            event->npdu_number = optional[2];
            event->npdu_present = 1;
        }

        next_extension = optional[3];
        event->first_extension_type = next_extension;
        cursor = optional + 4;
        /*
        * optional[3] is the fourth and final byte of the common optional GTP block.
        * It contains the type of the first extension header that follows. A value of
        * 0 means that no extension header follows.
        *
        * Save this value in next_extension so the extension-parsing loop knows which
        * extension type it is currently about to process. Also copy it into the event
        * so user space can report the first extension-header type, such as 0x85 for
        * the PDU Session Container.
        *
        * Finally, move cursor four bytes forward. It previously pointed to the start
        * of the optional block, so optional + 4 makes it point immediately after the
        * Sequence Number (2 bytes), N-PDU Number (1 byte), and Next Extension Header
        * Type (1 byte). If an extension exists, cursor now points to its first byte;
        * otherwise, it points to the beginning of the G-PDU payload.
        */
    }

    /*
     * GTP extension headers form a linked chain: the final byte of the current
     * extension gives the next extension's type. The first byte gives the
     * current extension's total size in four-byte units.
     *
     * The loop is deliberately bounded and unrolled because an XDP program
     * cannot follow an unlimited packet-controlled chain. Four extensions are
     * enough for this parser; if more remain, the event is submitted without
     * attempting to interpret the payload as an inner IP packet.
     */


     /*
        * Ask Clang to unroll the following fixed-size loop during compilation.
        *
        * Instead of generating a normal loop that jumps back to execute the same
        * instructions repeatedly, the compiler creates up to four separate copies
        * of the loop body—one copy for each possible iteration.
        *
        * Conceptually:
        *
        *     for (i = 0; i < 4; i++)
        *         parse_extension();
        *
        * becomes approximately:
        *
        *     parse_extension_1();
        *     parse_extension_2();
        *     parse_extension_3();
        *     parse_extension_4();
        *
        * The break conditions are preserved, so execution can still stop when
        * next_extension becomes zero. Unrolling gives the eBPF verifier an explicit
        * upper bound on the number of extension headers processed and can make its
        * safety analysis of packet-pointer accesses easier.
        *
        * It does not mean that four extension headers must exist. It means that this
        * program will parse at most four extension headers.
        */
#pragma unroll
    for (int i = 0; i < 4; i++) {
        /*
        * 'cursor' currently points to the first byte of the extension header being
        * parsed. Store it in a byte pointer so individual extension bytes can be read
        * using extension[0], extension[1], and so on.
        */
        __u8 *extension = cursor;
        __u8 *next_type_ptr;
        /*
        * This pointer will later point to the final byte of the current extension.
        * That final byte contains the type of the next extension header. Declaring
        * the pointer here does not read anything yet.
        */
        __u32 extension_bytes;
        /*
        * This variable will hold the total size of the current extension header in
        * bytes. A 32-bit type is used so the multiplication and later pointer-boundary
        * calculations have enough range.
        */

        /*
        * Stop parsing extensions if the GTP E flag is not set or the previous
        * Next Extension Header Type is zero.
        *
        * flag_e == 0 means the Next Extension Header field is not meaningful.
        * next_extension == 0 means the extension chain has ended and the cursor
        * should now be at the G-PDU payload.
        */
        if (!event->flag_e || next_extension == 0)
            break;
            /*
            * Before reading extension[0], verify that at least one byte exists between
            * 'extension' and data_end. In XDP, every packet-memory access must first be
            * proven safe to the eBPF verifier. If the byte is missing, submit the partial
            * event without continuing the parse.
            */
        if ((void *)(extension + 1) > data_end)
            goto submit;

        extension_bytes = (__u32)extension[0] * 4;
        /*
        * The first byte of a GTP-U extension header stores its length in units of
        * four octets, not directly in bytes. Convert it to __u32 and multiply it by
        * four to obtain the complete extension size in bytes.
        *
        * For example:
        *     extension[0] = 1  -> extension_bytes = 4 bytes
        *     extension[0] = 2  -> extension_bytes = 8 bytes
        */
        if (extension_bytes < 2 || extension_bytes > 256)
            goto submit;
        /*
        * Reject an unreasonable extension length before using it in pointer
        * arithmetic. A value below 2 cannot contain even the length byte and final
        * Next Extension Header Type byte. The 256-byte upper limit is a parser-defined
        * safety bound that keeps verifier reasoning and packet processing bounded;
        * it is not the general maximum assigned by the 3GPP extension-length field.
        *
        * Because the standardized length is in four-byte units, valid nonzero GTP-U
        * extension sizes produced by the calculation are normally 4, 8, 12, etc.
        */


        /*
         * Extension type 0x85 is the PDU Session Container. For the packet
         * format handled here, the lower six bits of byte 2 carry the QFI.
         * The fixed-offset bounds check helps the BPF verifier prove safety.
         */
        if (next_extension == GTP_EXT_PDU_SESSION_CONTAINER &&
            extension_bytes >= 4) {
            if ((void *)(extension + 3) > data_end)
                goto submit;
            event->qfi = extension[2] & 0x3f;
            event->qfi_present = 1;
        }
        /*
        * Parse the QFI only when the current extension-header type is 0x85, which
        * 3GPP assigns to the PDU Session Container, and its declared size is at
        * least four bytes.
        *
        * The relevant bytes are arranged as:
        *
        *     extension[0] = Extension Header Length
        *     extension[1] = PDU type and other control flags
        *     extension[2] = control bits in the upper two bits + QFI in the lower
        *                    six bits
        *     ...
        *     final byte   = Next Extension Header Type
        *
        * Before accessing extension[2], verify that the packet actually contains
        * the first three bytes. 'extension + 3' points immediately after byte 2;
        * if that position exceeds data_end, reading extension[2] would be unsafe,
        * so parsing stops and the partially completed event is submitted.
        *
        * The mask 0x3f is binary 00111111. Applying it with '&' clears the upper
        * two control bits and preserves only the lower six QFI bits:
        *
        *     extension[2]        = XXQQQQQQ
        *     0x3f                = 00111111
        *     extension[2] & 0x3f = 00QQQQQQ
        *
        * Finally, qfi_present is set to 1 so user space knows that event->qfi was
        * successfully extracted and is meaningful.
        */

        /* Prove that the complete variable-length extension is in the packet. */
        if ((void *)extension + extension_bytes > data_end)
            goto submit;

        /* Read the chain pointer stored in the extension's final byte. */
        next_type_ptr = extension + extension_bytes - 1;
        if ((void *)(next_type_ptr + 1) > data_end)
            goto submit;
        next_extension = *next_type_ptr;
        cursor = (void *)extension + extension_bytes;
        /*
        * First, verify that the complete variable-length extension header lies within
        * the received packet; otherwise, stop parsing to avoid an out-of-bounds read.
        * The final byte of every GTP-U extension header contains the type of the next
        * extension, so next_type_ptr is calculated as the extension's starting address
        * plus its total length minus one. A separate bounds check confirms that this
        * final byte is safe to read. Its value is then stored in next_extension: zero
        * means the extension chain has ended, while a nonzero value identifies the
        * extension that follows. Finally, cursor is advanced by extension_bytes so it
        * points immediately after the current extension—either at the next extension
        * header or, if the chain has ended, at the encapsulated G-PDU payload.
        */
    }

    /* A nonzero type here means the bounded loop did not finish the chain. */
    if (event->flag_e && next_extension != 0)
        goto submit;

    /*
     * After all GTP optional/extension headers, cursor reaches the G-PDU
     * payload. This parser records it only when that payload starts with a
     * complete IPv4 header; other payloads still produce a valid GTP event.
     */
    {
        struct iphdr *inner_ip = cursor;
        __u32 inner_ihl;

        if ((void *)(inner_ip + 1) > data_end)
            goto submit;
        if (inner_ip->version != 4)
            goto submit;

        inner_ihl = inner_ip->ihl * 4;
        if (inner_ihl < sizeof(*inner_ip) ||
            (void *)inner_ip + inner_ihl > data_end)
            goto submit;

        event->inner_src_ip = inner_ip->saddr;
        event->inner_dst_ip = inner_ip->daddr;
        event->inner_protocol = inner_ip->protocol;
        event->inner_ip_present = 1;
    }
    /*
    * At this point, cursor should point to the beginning of the tunneled G-PDU
    * payload. Interpret that location as an IPv4 header and first verify that the
    * packet contains at least the fixed-size struct iphdr portion. Next, check
    * that the payload actually declares IP version 4; if it is IPv6 or another
    * payload type, submit the event without inner-IPv4 information. The IHL field
    * gives the IPv4 header length in 32-bit words, so multiplying it by four
    * converts it to bytes. Verify that the calculated length is at least the
    * normal 20-byte IPv4 header and that the entire header—including any IPv4
    * options—remains within data_end. Once these checks succeed, copy the inner
    * source address, destination address, and transport protocol number into the
    * event, then set inner_ip_present to 1 so user space knows that these inner
    * fields were successfully extracted and are valid.
    */

submit:
    /* Publish the completed record so the user-space ring-buffer reader sees it. */
    bpf_ringbuf_submit(event, 0);
    /*
    * Publish the completed event to the ring buffer so the user-space program can
    * read it. The second argument is the submission-flags field. A value of 0
    * requests the normal notification behavior: the kernel decides whether the
    * user-space ring-buffer consumer needs to be notified. Other supported choices
    * include BPF_RB_NO_WAKEUP, which suppresses notification, and BPF_RB_FORCE_WAKEUP,
    * which forces notification. These flags affect notification behavior only;
    * they do not change the event data being submitted.
    */
    return XDP_PASS;

submit_non_gtpu:
    /* Record this UDP packet in the second counter, then publish its event. */
    counter_key = COUNTER_UDP_NON_GTPU;
    counter = bpf_map_lookup_elem(&packet_counts, &counter_key);
    if (counter)
        event->udp_non_gtpu_count = __sync_fetch_and_add(counter, 1) + 1;
    bpf_ringbuf_submit(event, 0);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
