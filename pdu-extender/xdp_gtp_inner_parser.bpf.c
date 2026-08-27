#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define GTPU_PORT 2152
#define GTPU_PORT_ALT 2153 /* seen in use for DU<->CU uplink F1-U/GTP-U traffic */
#define GTPU_G_PDU 255
#define GTP_EXT_PDU_SESSION_CONTAINER 0x85
#define MAX_EXTENSION_HEADERS 4

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
    /* Every extension header type actually walked, in order. Bounded to
     * MAX_EXTENSION_HEADERS to match the unrolled parsing loop below. */
    __u8 extension_count;
    __u8 extension_types[MAX_EXTENSION_HEADERS];
    __u8 pdu_type_present;
    __u8 pdu_type;
    __u8 qfi_present;
    __u8 qfi;
    __u8 inner_ip_present;
    __u8 inner_protocol;
    __u8 is_gtpu;
    __u8 pad;
    __u64 gtpu_count;
    __u64 udp_non_gtpu_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

enum counter_index {
    COUNTER_GTPU = 0,
    COUNTER_UDP_NON_GTPU = 1,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} packet_counts SEC(".maps");

/* The mandatory GTPv1-U header is always eight bytes. */
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

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return XDP_PASS;

    __builtin_memset(event, 0, sizeof(*event));
    event->outer_src_ip = outer_ip->saddr;
    event->outer_dst_ip = outer_ip->daddr;
    event->outer_src_port = bpf_ntohs(udp->source);
    event->outer_dst_port = bpf_ntohs(udp->dest);

    /*
     * Count every UDP packet. A packet is classified as GTP-U only when it
     * uses a recognized GTP-U port (2152, or 2153 as seen for some
     * DU<->CU uplink F1-U/GTP-U traffic) and has a complete, valid
     * GTPv1-U G-PDU base header.
     */
    if ((udp->source != bpf_htons(GTPU_PORT) &&
         udp->dest != bpf_htons(GTPU_PORT) &&
         udp->source != bpf_htons(GTPU_PORT_ALT) &&
         udp->dest != bpf_htons(GTPU_PORT_ALT)) ||
        (void *)(gtp + 1) > data_end) {
        goto submit_non_gtpu;
    }

    flags = gtp->flags;
    if ((flags >> 5) != 1 || !(flags & 0x10) ||
        gtp->message_type != GTPU_G_PDU) {
        goto submit_non_gtpu;
    }

    event->is_gtpu = 1;
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

    cursor = (void *)(gtp + 1);

    /* If any E/S/PN flag is set, all four optional bytes are present. */
    if (flags & 0x07) {
        __u8 *optional = cursor;

        if ((void *)(optional + 4) > data_end)
            goto submit;

        if (event->flag_s) {
            event->sequence_number = ((__u16)optional[0] << 8) | optional[1];
            event->sequence_present = 1;
        }
        if (event->flag_pn) {
            event->npdu_number = optional[2];
            event->npdu_present = 1;
        }

        next_extension = optional[3];
        event->first_extension_type = next_extension;
        cursor = optional + 4;
    }

    /*
     * Each extension begins with a length in four-byte units and ends with
     * the type of the following extension. Limit the loop for XDP safety.
     * Every extension type we successfully walk through (i.e. whose length
     * byte we could safely read) is recorded in extension_types[], up to
     * MAX_EXTENSION_HEADERS entries, so userspace can print the full chain
     * even when the inner payload isn't a parsable IP packet.
     */
#pragma unroll
    for (int i = 0; i < MAX_EXTENSION_HEADERS; i++) {
        __u8 *extension = cursor;
        __u8 *next_type_ptr;
        __u32 extension_bytes;

        if (!event->flag_e || next_extension == 0)
            break;
        if ((void *)(extension + 1) > data_end)
            goto submit;

        extension_bytes = (__u32)extension[0] * 4;
        if (extension_bytes < 2 || extension_bytes > 256)
            goto submit;

        /* Record this extension header's type now that we know its length
         * byte was safely readable. */
        if (event->extension_count < MAX_EXTENSION_HEADERS) {
            event->extension_types[event->extension_count] = next_extension;
            event->extension_count++;
        }

        /*
         * Do this fixed-offset access before variable pointer arithmetic.
         * Otherwise Clang may remove the fixed bounds check as redundant,
         * even though the BPF verifier cannot derive it from the later
         * variable-length check.
         */
        if (next_extension == GTP_EXT_PDU_SESSION_CONTAINER &&
            extension_bytes >= 4) {
            if ((void *)(extension + 3) > data_end)
                goto submit;

            /*
             * In the PDU Session Container, the upper four bits of the
             * first content octet (extension[1]) carry the PDU type:
             *   0 = DL PDU SESSION INFORMATION
             *   1 = UL PDU SESSION INFORMATION
             */
            event->pdu_type = (extension[1] >> 4) & 0x0f;
            event->pdu_type_present = 1;
            event->qfi = extension[2] & 0x3f;
            event->qfi_present = 1;
        }

        if ((void *)extension + extension_bytes > data_end)
            goto submit;

        /*
         * The last byte names the next extension. Check this calculated
         * pointer explicitly; the verifier does not infer it from the
         * earlier variable-length boundary test.
         */
        next_type_ptr = extension + extension_bytes - 1;
        if ((void *)(next_type_ptr + 1) > data_end)
            goto submit;
        next_extension = *next_type_ptr;
        cursor = (void *)extension + extension_bytes;
    }

    /* A nonzero value means more extensions remain than this bounded parser handled. */
    if (event->flag_e && next_extension != 0)
        goto submit;

    /* The G-PDU payload begins here. This version parses encapsulated IPv4.
     * If the payload is not a well-formed IPv4 header (e.g. an F1-U PDCP
     * PDU, or a truncated packet), we still submit the event: every outer
     * UDP/GTP-U field captured above (version, PT, message type, GTP
     * length, TEID, E/S/PN flags, sequence number, N-PDU number, the full
     * extension header chain, QFI, and PDU type) remains populated and is
     * reported; only inner_ip_present stays 0 to flag that the inner IP
     * header itself is unavailable/not parsable. */
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

submit:
    bpf_ringbuf_submit(event, 0);
    return XDP_PASS;

submit_non_gtpu:
    counter_key = COUNTER_UDP_NON_GTPU;
    counter = bpf_map_lookup_elem(&packet_counts, &counter_key);
    if (counter)
        event->udp_non_gtpu_count = __sync_fetch_and_add(counter, 1) + 1;
    bpf_ringbuf_submit(event, 0);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";