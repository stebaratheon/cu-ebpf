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

/* F1-U rewrite constants (see F1U_HEADER_FORMAT_INVESTIGATION.md for how
 * these were confirmed against real OAI CU-UP/DU behavior). */
#define F1U_NEW_HDR_BYTES 4        /* 3-byte PDCP (long/18-bit SN) + 1-byte SDAP */
#define MAX_INNER_MOVE_BYTES 512  /* bound for the unrolled payload-copy loops (both
                                    * directions). See comment below: this was reduced
                                    * from 1400 after two such loops in one program hit
                                    * an LLVM BPF backend limit ("Branch target out of
                                    * insn range") -- confirmed empirically to compile
                                    * cleanly at 512 with real margin below the measured
                                    * ~940-945 cliff for this file. Packets whose inner
                                    * payload exceeds this are skipped for offload (fall
                                    * through to plain XDP_PASS, unmodified) rather than
                                    * risk an unsafe or incorrect rewrite -- so this is a
                                    * real reduction in fast-path COVERAGE for large
                                    * packets (e.g. near-MTU bulk-transfer segments),
                                    * not a correctness issue. See the project README/
                                    * journal for the follow-up (BPF subprogram split)
                                    * that would restore full ~1450-byte coverage. */
#define PDCP_SN_MAX 0x3FFFF        /* 18-bit sequence number wraparound */

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
    /* Fast-path offload outcome. Shared by BOTH directions -- downlink
     * (session_map, N3 -> F1-U) and uplink (ul_session_map, F1-U -> N3)
     * -- since exactly one of the two offload blocks can ever run per
     * packet (event->is_f1u tells you which one these fields describe
     * for a given event). */
    __u8 offload_attempted;
    __u8 offload_applied;
    __u32 offload_new_teid;
    __be32 offload_new_dst_ip;   /* raw network order, same convention as outer_*_ip */
    __u16 offload_new_dst_port;  /* host order, same convention as outer_*_port */
    __u16 pad2;
    /* Debug instrumentation: the kernel's own computed values for the
     * reframing decision, reported for every attempted rewrite (even
     * ones that bail out via offload_skip/ul_offload_skip), to diagnose
     * why a rewrite may not be taking effect as expected. Shared by both
     * directions, same reasoning as offload_attempted above. */
    __s32 debug_old_removed_bytes;
    __s32 debug_move_len;
    __s32 debug_delta;
    __u32 debug_reached_rewrite; /* 1 if we got past the bail-out check */
    __u8 debug_flags_right_after_write; /* gtp->flags read back immediately
                                          * after the new flags byte is written */
    __u8 debug_flags_right_before_redirect; /* gtp->flags read back right
                                              * before bpf_redirect() returns */
    __u8 pad3[2];
    /*
     * --- Uplink (F1-U, DU -> CU) recognition fields ---
     * F1-U never carries a GTP-U extension header in either direction
     * (confirmed against real captures): the mandatory 8-byte GTP header
     * is immediately followed by a 3-byte PDCP header + 1-byte SDAP
     * header, then the inner IP packet. N3 (the other port, GTPU_PORT)
     * instead carries QFI in a GTP-U extension header (PDU Session
     * Container) and has no PDCP/SDAP at all. is_f1u records which
     * framing this packet actually used, based on which port it arrived
     * on, so the two shapes are never parsed with the wrong layout.
     */
    __u8 is_f1u;                  /* 1 if this GTP-U packet arrived on
                                    * GTPU_PORT_ALT (F1-U framing: PDCP+SDAP,
                                    * no GTP-U extension chain) */
    __u8 f1u_pdcp_sn_present;
    __u32 f1u_pdcp_sn;            /* 18-bit PDCP SN read from the PDCP header,
                                    * F1-U packets only */
    __u8 ul_map_lookup_attempted; /* 1 if we looked event->teid up in
                                    * ul_session_map (uplink F1-U packets
                                    * only). This is informational ONLY --
                                    * it never triggers a rewrite/redirect.
                                    * Uplink offload is not implemented yet. */
    __u8 ul_map_lookup_hit;
    __u8 ul_map_ready;    /* mirrors session_ctx.ready for the matched
                           * ul_session_map entry (only meaningful when
                           * ul_map_lookup_hit is set) -- the actual gate
                           * a future uplink rewrite will check before
                           * touching a packet. */
    __u8 pad4;
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

/*
 * Step-1 "pure relay" fast-path session table: ingress TEID -> where/how to
 * re-tunnel the packet. Populated (currently by hand, one entry) from
 * userspace. A production version would derive dst_mac/src_mac via
 * bpf_fib_lookup() instead of storing them statically here.
 *
 * This map is used ONLY for the downlink (N3 -> F1-U) direction. See
 * ul_session_map below for the (currently non-offloading) uplink side.
 */
struct session_ctx {
    __u32 peer_teid;       /* new TEID to write into the outer GTP header */
    __be32 dst_ip;         /* new outer destination IP, network byte order */
    __be32 src_ip;         /* new outer source IP (this CU's own address), network
                            * byte order -- without this, a rewritten packet keeps
                            * the original N3 sender's (UPF's) source IP, which a
                            * DU expecting a connected socket to the CU's known
                            * address will silently drop */
    __be16 dst_port;       /* new outer destination UDP port, network byte order */
    __u16 pad0;
    __u32 egress_ifindex;  /* interface to bpf_redirect() out of */
    __u8 dst_mac[ETH_ALEN]; /* next-hop MAC to write into the Ethernet header */
    __u8 src_mac[ETH_ALEN]; /* egress interface's own MAC */
    __u8 qfi;              /* reserved for future PDCP/QFI-aware rewriting */
    __u8 pad1[3];
    __u32 next_dl_pdcp_sn; /* per-bearer PDCP DL sequence number counter (18-bit
                            * wraparound), incremented by the kernel program on
                            * every offloaded packet for this TEID */
    __u8 ready;            /* 1 once this entry is fully populated and safe to
                            * offload from. session_map (downlink) entries are
                            * always inserted complete in one shot, so this is
                            * always 1 there. ul_session_map (uplink) entries
                            * start at 0 (placeholder, MAC/egress still zero)
                            * and flip to 1 only once userspace has also
                            * resolved the UPF's MAC -- this is the field a
                            * future uplink rewrite must check before
                            * touching a packet. */
    __u8 pad2[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct session_ctx);
} session_map SEC(".maps");

/*
 * Uplink (F1-U, DU -> CU) session table. Keyed by the UL F1-U TEID the CU
 * itself advertised to the DU (learned from the CU's own UL GTP Tunnel IE
 * in F1AP UEContextSetupRequest -- see the userspace F1AP watcher).
 *
 * Deliberately NOT used for any rewrite/redirect yet: this map's only job
 * right now is to let us confirm, via the printed HIT/MISS in the CU log,
 * that (a) the TEID the DU actually uses on inbound F1-U packets matches
 * what we learned from F1AP, and (b) userspace is populating this map
 * correctly -- before any uplink offload logic is built on top of it.
 * Reuses struct session_ctx for forward-compatibility with a future
 * uplink rewrite (peer_teid/dst_ip/dst_port would then hold the UPF's N3
 * UL tunnel endpoint); those fields are zeroed/unused placeholders today.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct session_ctx);
} ul_session_map SEC(".maps");

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
    /* Which port this arrived on tells us which framing to expect --
     * F1-U (GTPU_PORT_ALT) uses PDCP+SDAP with no extension header; N3
     * (GTPU_PORT) uses a GTP-U extension header (PDU Session Container)
     * and has no PDCP/SDAP at all. See the struct gtp_event comment. */
    event->is_f1u = (udp->source == bpf_htons(GTPU_PORT_ALT) ||
                     udp->dest == bpf_htons(GTPU_PORT_ALT));

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
     *
     * On F1-U (event->is_f1u), flag_e is always 0 in practice (F1-U never
     * carries this extension chain), so this loop simply doesn't execute
     * for F1-U packets and cursor is left sitting right after the
     * mandatory 8-byte header -- exactly where the PDCP header starts.
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

    /*
     * F1-U framing: PDCP (3 bytes) + SDAP (1 byte) sit between the
     * mandatory GTP header and the inner IP packet, with no extension
     * header. This applies to BOTH directions of F1-U (it's what this
     * program itself writes on downlink, and what the DU genuinely sends
     * on uplink) -- so read it back here whenever is_f1u is set, purely
     * for visibility (PDCP SN, QFI) and so the inner IP parse below looks
     * at the right offset instead of misreading PDCP/SDAP bytes as an IP
     * header.
     */
    if (event->is_f1u && !event->flag_e) {
        __u8 *pdcp_sdap = cursor;

        if ((void *)(pdcp_sdap + F1U_NEW_HDR_BYTES) > data_end)
            goto submit;

        event->f1u_pdcp_sn = ((__u32)(pdcp_sdap[0] & 0x3) << 16) |
                              ((__u32)pdcp_sdap[1] << 8) |
                              pdcp_sdap[2];
        event->f1u_pdcp_sn_present = 1;
        event->qfi = pdcp_sdap[3] & 0x3f;
        event->qfi_present = 1;

        cursor = pdcp_sdap + F1U_NEW_HDR_BYTES;
    }

    /* The G-PDU payload begins here. This version parses encapsulated IPv4.
     * If the payload is not a well-formed IPv4 header (e.g. a truncated
     * packet, or IPv6 -- not yet supported here), we still submit the
     * event: every outer UDP/GTP-U field captured above (version, PT,
     * message type, GTP length, TEID, E/S/PN flags, sequence number,
     * N-PDU number, the full extension header chain, QFI, PDU type, and
     * -- for F1-U -- the PDCP SN) remains populated and is reported; only
     * inner_ip_present stays 0 to flag that the inner IP header itself is
     * unavailable/not parsable. */
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
    /*
     * Step-2 fast-path offload: for GTP-U packets whose TEID has a
     * session_map entry, transform the N3-shaped packet into a correctly
     * F1-U-shaped one before redirecting it to the DU, per
     * F1U_HEADER_FORMAT_INVESTIGATION.md:
     *   - remove the GTP-U extension header (PDU Session Container) and
     *     any optional fields entirely; new GTP-U header has E=S=PN=0
     *   - insert a 3-byte PDCP header (long/18-bit SN, D/C=1 for DRB)
     *     followed by a 1-byte SDAP header (QFI only) immediately after
     *     the GTP-U mandatory header
     * This is what fixes the DU crash (Problem 10 in the README):
     * omitting the extension header keeps qfi == -1 on the DU's receive
     * path, exactly matching what its assertion requires.
     *
     * A map miss falls straight through to plain XDP_PASS, unchanged.
     *
     * This offload path is downlink-only (N3 -> F1-U): explicitly gated
     * on !event->is_f1u so an inbound uplink F1-U packet can never be
     * matched against session_map and redirected by accident.
     */
    if (event->is_gtpu && !event->is_f1u) {
        __u32 lookup_key = event->teid;
        struct session_ctx *sess = bpf_map_lookup_elem(&session_map, &lookup_key);

        event->offload_attempted = 1;

        /* Simplification: only offload when the outer IP header has no
         * options, so a full 20-byte checksum recompute is valid below. */
        if (sess && outer_ihl == sizeof(*outer_ip) &&
            (void *)(eth + 1) <= data_end &&
            (void *)(outer_ip + 1) <= data_end &&
            (void *)(udp + 1) <= data_end &&
            (void *)(gtp + 1) <= data_end) {

            /* 'cursor' already points to the start of the inner payload,
             * from the extension-header-walking loop earlier in this
             * function -- i.e. everything between the end of the
             * mandatory 8-byte GTP header and 'cursor' is the optional
             * fields + extension chain we need to remove. */
            long old_removed_bytes = (long)cursor - (long)(gtp + 1);
            long move_len = (long)data_end - (long)cursor;
            long delta = (long)F1U_NEW_HDR_BYTES - old_removed_bytes;

            event->debug_old_removed_bytes = (__s32)old_removed_bytes;
            event->debug_move_len = (__s32)move_len;
            event->debug_delta = (__s32)delta;

            if (old_removed_bytes < 0 || old_removed_bytes > 64 ||
                move_len < 0 || move_len > MAX_INNER_MOVE_BYTES ||
                delta > 0) {
                goto offload_skip;
            }

            event->debug_reached_rewrite = 1;

            {
                __u8 *old_cursor = cursor;
                __u8 *new_cursor = (__u8 *)(gtp + 1) + F1U_NEW_HDR_BYTES;
                int i;

                /* Compact the inner payload down into its new position,
                 * closing the gap left by the removed optional
                 * fields/extension header. Bounds are checked against
                 * the CURRENT (still original, larger) data_end, before
                 * bpf_xdp_adjust_tail() below shrinks it. */
#pragma unroll
                for (i = 0; i < MAX_INNER_MOVE_BYTES; i++) {
                    if (i >= move_len)
                        break;
                    if ((void *)(old_cursor + i + 1) > data_end)
                        break;
                    if ((void *)(new_cursor + i + 1) > data_end)
                        break;
                    new_cursor[i] = old_cursor[i];
                }
            }

            if (bpf_xdp_adjust_tail(ctx, (int)delta))
                goto offload_drop; /* should not happen; don't forward a
                                     * half-modified packet if it does */

            /* adjust_tail() invalidates every previously-held packet
             * pointer -- re-fetch data/data_end and every header pointer
             * fresh, with fresh bounds checks, before touching anything
             * else. (This re-check is verifier-mandatory, not merely
             * defensive; given old_removed_bytes/move_len were already
             * validated above, it is not expected to actually fail.) */
            data = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;

            eth = data;
            if ((void *)(eth + 1) > data_end)
                goto offload_drop;
            outer_ip = (void *)(eth + 1);
            if ((void *)(outer_ip + 1) > data_end)
                goto offload_drop;
            udp = (void *)outer_ip + outer_ihl;
            if ((void *)(udp + 1) > data_end)
                goto offload_drop;
            gtp = (void *)(udp + 1);
            if ((void *)(gtp + 1) > data_end)
                goto offload_drop;

            {
                __u8 *pdcp_sdap = (__u8 *)(gtp + 1);
                __u32 sn;
                __u8 qfi_to_write = event->qfi_present ? event->qfi : 0;

                if ((void *)(pdcp_sdap + F1U_NEW_HDR_BYTES) > data_end)
                    goto offload_drop;

                /* Per-bearer, wrapping (18-bit) PDCP DL sequence number.
                 * session_map values live in a BPF_MAP_TYPE_HASH, so
                 * this pointer is directly writable. Note: this BPF
                 * target's backend does not support using the *return
                 * value* of __sync_fetch_and_add() (it crashes with
                 * "Invalid usage of the XADD return value" -- an older
                 * BPF ISA limitation, not a logic bug), so the atomic
                 * add is done as a bare statement (compiles to plain
                 * XADD, universally supported) and the counter is then
                 * read back non-atomically. This means concurrent
                 * processing of the same flow's packets across multiple
                 * CPU cores could rarely produce a duplicate or skipped
                 * sequence number; acceptable for this prototype, worth
                 * revisiting if strict per-packet uniqueness matters. */
                __sync_fetch_and_add(&sess->next_dl_pdcp_sn, 1);
                sn = sess->next_dl_pdcp_sn & PDCP_SN_MAX;

                /* PDCP header (long/18-bit SN format, D/C=1 for DRB) --
                 * see F1U_HEADER_FORMAT_INVESTIGATION.md */
                pdcp_sdap[0] = 0x80 | ((sn >> 16) & 0x3);
                pdcp_sdap[1] = (sn >> 8) & 0xff;
                pdcp_sdap[2] = sn & 0xff;
                /* SDAP header: QFI only (no RQI/RDI bits set) */
                pdcp_sdap[3] = qfi_to_write & 0x3f;
            }

            /* Rewrite L2/L3/L4/GTP-U fields for the F1-U destination. */
            __builtin_memcpy(eth->h_dest, sess->dst_mac, ETH_ALEN);
            __builtin_memcpy(eth->h_source, sess->src_mac, ETH_ALEN);
            outer_ip->saddr = sess->src_ip;
            outer_ip->daddr = sess->dst_ip;
            udp->dest = sess->dst_port;

            gtp->flags = 0x30; /* version=1, PT=1, E=S=PN=0 */
            event->debug_flags_right_after_write = gtp->flags;
            gtp->message_type = GTPU_G_PDU;
            gtp->teid = bpf_htonl(sess->peer_teid);
            gtp->length = bpf_htons((__u16)(F1U_NEW_HDR_BYTES + move_len));

            outer_ip->tot_len = bpf_htons((__u16)(outer_ihl + sizeof(struct udphdr) +
                                                   sizeof(*gtp) + F1U_NEW_HDR_BYTES +
                                                   move_len));
            udp->len = bpf_htons((__u16)(sizeof(struct udphdr) + sizeof(*gtp) +
                                          F1U_NEW_HDR_BYTES + move_len));

            /* IP header has no options here, so a full recompute over its
             * fixed 20 bytes is simple and cheap. */
            outer_ip->check = 0;
            {
                __u16 *hwords = (__u16 *)outer_ip;
                __u32 csum = 0;

#pragma unroll
                for (int w = 0; w < (int)(sizeof(*outer_ip) / 2); w++)
                    csum += hwords[w];
                csum = (csum & 0xffff) + (csum >> 16);
                csum = (csum & 0xffff) + (csum >> 16);
                outer_ip->check = ~csum;
            }

            /*
             * UDP checksum: every field covered by it changed (dst IP in
             * the pseudo header, dst port, and the entire GTP-U/PDCP/SDAP
             * payload). As before, set to 0 -- explicitly legal for
             * UDP-over-IPv4 per RFC 768, and simpler than an incremental
             * update across a payload whose content has fully changed.
             */
            udp->check = 0;

            event->offload_applied = 1;
            event->offload_new_teid = sess->peer_teid;
            event->offload_new_dst_ip = sess->dst_ip;
            event->offload_new_dst_port = bpf_ntohs(sess->dst_port);
            event->debug_flags_right_before_redirect = gtp->flags;

            bpf_ringbuf_submit(event, 0);
            return bpf_redirect(sess->egress_ifindex, 0);

offload_drop:
            /* We already shrank/mutated the packet and then hit an
             * unexpected (believed-unreachable) bounds failure -- do not
             * forward a partially-rewritten packet. */
            bpf_ringbuf_submit(event, 0);
            return XDP_DROP;
        }
offload_skip:
        ;
    }

    /*
     * Uplink (F1-U -> N3) fast-path offload: for GTP-U packets whose
     * TEID has a COMPLETE (sess->ready == 1) ul_session_map entry,
     * transform the F1-U-shaped packet into a correctly N3-shaped one
     * before redirecting it to the UPF. This is the structural mirror
     * image of the downlink block above, but NOT a mirror-image
     * implementation -- see the comments inline below for exactly why.
     *
     * A map miss, or a HIT that isn't yet ready, falls straight through
     * to plain XDP_PASS, unchanged -- exactly like a downlink map miss.
     */
    if (event->is_gtpu && event->is_f1u) {
        __u32 ul_key = event->teid;
        struct session_ctx *ul_sess = bpf_map_lookup_elem(&ul_session_map, &ul_key);

        event->ul_map_lookup_attempted = 1;
        event->offload_attempted = 1;
        if (ul_sess) {
            event->ul_map_lookup_hit = 1;
            event->ul_map_ready = ul_sess->ready;
        }

        if (ul_sess && ul_sess->ready && outer_ihl == sizeof(*outer_ip) &&
            (void *)(eth + 1) <= data_end &&
            (void *)(outer_ip + 1) <= data_end &&
            (void *)(udp + 1) <= data_end &&
            (void *)(gtp + 1) <= data_end) {

            /*
             * 'cursor' was already advanced by exactly F1U_NEW_HDR_BYTES
             * (4) in the F1-U PDCP/SDAP parsing branch earlier in this
             * function -- every is_f1u packet that reaches here without
             * an extension chain (E=0, required to enter that branch)
             * has a fixed, not variable, header size to remove, unlike
             * the downlink side where the N3 extension chain's length
             * varies. old_removed_bytes is therefore expected to always
             * equal F1U_NEW_HDR_BYTES; checked explicitly below as a
             * defensive invariant rather than assumed.
             *
             * new_hdr_bytes is the N3 shape being constructed: 4 bytes
             * of optional fields (seq/npdu/next-ext-type) + 4 bytes of
             * PDU Session Container extension = 8. Net delta is
             * therefore +4 -- the packet must GROW, the opposite of the
             * downlink rewrite's shrink.
             */
            long old_removed_bytes = (long)cursor - (long)(gtp + 1);
            long move_len = (long)data_end - (long)cursor;
            long new_hdr_bytes = 4 /* optional seq/npdu/next-ext-type */
                                + 4; /* PDU Session Container extension */
            long delta = new_hdr_bytes - old_removed_bytes;

            event->debug_old_removed_bytes = (__s32)old_removed_bytes;
            event->debug_move_len = (__s32)move_len;
            event->debug_delta = (__s32)delta;

            if (old_removed_bytes != F1U_NEW_HDR_BYTES ||
                move_len < 0 || move_len > MAX_INNER_MOVE_BYTES ||
                delta <= 0 || delta > 64) {
                goto ul_offload_skip;
            }

            event->debug_reached_rewrite = 1;

            /*
             * Grow FIRST. Unlike the downlink shrink (which compacts the
             * payload into its smaller new position, THEN trims the
             * tail), there is no room to shift the payload into until
             * the tail is actually extended -- so bpf_xdp_adjust_tail()
             * must run before any data movement here, not after.
             */
            if (bpf_xdp_adjust_tail(ctx, (int)delta))
                goto ul_offload_drop; /* e.g. insufficient tailroom in the
                                        * underlying buffer -- fail safe
                                        * rather than forward a
                                        * half-grown packet */

            /* adjust_tail() invalidates every previously-held packet
             * pointer -- re-fetch fresh, same discipline as the
             * downlink path. */
            data = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;

            eth = data;
            if ((void *)(eth + 1) > data_end)
                goto ul_offload_drop;
            outer_ip = (void *)(eth + 1);
            if ((void *)(outer_ip + 1) > data_end)
                goto ul_offload_drop;
            udp = (void *)outer_ip + outer_ihl;
            if ((void *)(udp + 1) > data_end)
                goto ul_offload_drop;
            gtp = (void *)(udp + 1);
            if ((void *)(gtp + 1) > data_end)
                goto ul_offload_drop;

            {
                /*
                 * Shift the inner payload right by `delta` bytes: from
                 * its old position (right after the old 4-byte
                 * PDCP+SDAP block) to its new position (right after the
                 * new 8-byte optional+extension block). Because
                 * new_data > old_data and the regions overlap whenever
                 * move_len > delta (essentially always, since delta is
                 * fixed at 4), this MUST copy highest-offset-first --
                 * the exact opposite direction from the downlink
                 * compaction loop's forward (lowest-offset-first) copy
                 * -- or source bytes get overwritten before they're
                 * read. Bounds are checked against the fresh (grown)
                 * data_end from immediately above.
                 */
                __u8 *old_data = (__u8 *)(gtp + 1) + F1U_NEW_HDR_BYTES;
                __u8 *new_data = (__u8 *)(gtp + 1) + new_hdr_bytes;
                int i;

#pragma unroll
                for (i = 0; i < MAX_INNER_MOVE_BYTES; i++) {
                    int idx = (int)move_len - 1 - i;

                    if (idx < 0)
                        break;
                    if ((void *)(old_data + idx + 1) > data_end)
                        break;
                    if ((void *)(new_data + idx + 1) > data_end)
                        break;
                    new_data[idx] = old_data[idx];
                }
            }

            {
                __u8 *hdr = (__u8 *)(gtp + 1);
                __u8 qfi_to_write = event->qfi_present ? event->qfi : 0;

                if ((void *)(hdr + new_hdr_bytes) > data_end)
                    goto ul_offload_drop;

                /* 4-byte optional field block. seq/npdu are reserved
                 * (S=PN=0) but still must be present since E=1; next
                 * extension type = PDU Session Container. */
                hdr[0] = 0;
                hdr[1] = 0;
                hdr[2] = 0;
                hdr[3] = GTP_EXT_PDU_SESSION_CONTAINER;

                /* 4-byte PDU Session Container extension: length=1
                 * (four-byte units), PDU_TYPE=1 (UL) in the upper
                 * nibble of the first content octet, QFI (already
                 * extracted from the inbound SDAP byte) in the next,
                 * next-extension-type=0 (none). Byte layout confirmed
                 * earlier in this project against a real captured N3
                 * uplink packet. */
                hdr[4] = 1;
                hdr[5] = (__u8)(1 << 4);
                hdr[6] = qfi_to_write & 0x3f;
                hdr[7] = 0;
            }

            /* Rewrite L2/L3/L4/GTP-U fields for the N3 destination. */
            __builtin_memcpy(eth->h_dest, ul_sess->dst_mac, ETH_ALEN);
            __builtin_memcpy(eth->h_source, ul_sess->src_mac, ETH_ALEN);
            outer_ip->saddr = ul_sess->src_ip;
            outer_ip->daddr = ul_sess->dst_ip;
            udp->dest = ul_sess->dst_port;

            gtp->flags = 0x34; /* version=1, PT=1, E=1, S=0, PN=0 */
            event->debug_flags_right_after_write = gtp->flags;
            gtp->message_type = GTPU_G_PDU;
            gtp->teid = bpf_htonl(ul_sess->peer_teid);
            gtp->length = bpf_htons((__u16)(new_hdr_bytes + move_len));

            outer_ip->tot_len = bpf_htons((__u16)(outer_ihl + sizeof(struct udphdr) +
                                                   sizeof(*gtp) + new_hdr_bytes +
                                                   move_len));
            udp->len = bpf_htons((__u16)(sizeof(struct udphdr) + sizeof(*gtp) +
                                          new_hdr_bytes + move_len));

            /* IP header has no options here (checked above), so a full
             * recompute over its fixed 20 bytes is simple and cheap --
             * same as the downlink path. */
            outer_ip->check = 0;
            {
                __u16 *hwords = (__u16 *)outer_ip;
                __u32 csum = 0;

#pragma unroll
                for (int w = 0; w < (int)(sizeof(*outer_ip) / 2); w++)
                    csum += hwords[w];
                csum = (csum & 0xffff) + (csum >> 16);
                csum = (csum & 0xffff) + (csum >> 16);
                outer_ip->check = ~csum;
            }

            /* UDP checksum: every field it covers changed (dst IP, dst
             * port, and the entire GTP-U/optional/extension payload) --
             * set to 0, explicitly legal for UDP-over-IPv4 (RFC 768),
             * same reasoning as the downlink path. */
            udp->check = 0;

            event->offload_applied = 1;
            event->offload_new_teid = ul_sess->peer_teid;
            event->offload_new_dst_ip = ul_sess->dst_ip;
            event->offload_new_dst_port = bpf_ntohs(ul_sess->dst_port);
            event->debug_flags_right_before_redirect = gtp->flags;

            bpf_ringbuf_submit(event, 0);
            return bpf_redirect(ul_sess->egress_ifindex, 0);

ul_offload_drop:
            /* Already grown/mutated the packet and then hit an
             * unexpected (believed-unreachable) bounds failure -- do
             * not forward a partially-rewritten packet. */
            bpf_ringbuf_submit(event, 0);
            return XDP_DROP;
        }
ul_offload_skip:
        ;
    }

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
