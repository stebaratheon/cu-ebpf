#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define GTPU_PORT 2152
#define F1AP_PORT 38472

enum counter_key {
    USER_PLANE = 0,
    CONTROL_PLANE = 1,
};

/*
 * The standard SCTP common header is 12 bytes. Defining the small structure
 * locally avoids depending on a userspace SCTP development header.
 */
struct sctp_common_header {
    __be16 source;
    __be16 dest;
    __be32 verification_tag;
    __be32 checksum;
};

/*
 * key 0 -> F1-U/GTP-U packets (UDP port 2152)
 * key 1 -> F1-C/F1AP packets (SCTP port 38472)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} plane_counters SEC(".maps");

static __always_inline void increment_counter(__u32 key)
{
    __u64 *value = bpf_map_lookup_elem(&plane_counters, &key);

    if (value)
        __sync_fetch_and_add(value, 1);
}

SEC("xdp")
int count_user_and_control_plane(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    void *transport;
    __u32 ip_header_length;

    /* This toy parser handles Ethernet + IPv4 packets. */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /*
     * IPv4 IHL is measured in 32-bit words. Checking it allows IPv4 options
     * without assuming that every IPv4 header is exactly 20 bytes.
     */
    ip_header_length = (__u32)ip->ihl * 4;
    if (ip_header_length < sizeof(*ip))
        return XDP_PASS;

    transport = (void *)ip + ip_header_length;
    if (transport > data_end)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = transport;

        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        /*
         * F1-U uses GTP-U over UDP port 2152. Checking both directions lets
         * the same classifier work for either endpoint.
         */
        if (udp->source == bpf_htons(GTPU_PORT) ||
            udp->dest == bpf_htons(GTPU_PORT))
            increment_counter(USER_PLANE);

    } else if (ip->protocol == IPPROTO_SCTP) {
        struct sctp_common_header *sctp = transport;

        if ((void *)(sctp + 1) > data_end)
            return XDP_PASS;

        /*
         * F1-C carries F1AP over SCTP port 38472.
         */
        if (sctp->source == bpf_htons(F1AP_PORT) ||
            sctp->dest == bpf_htons(F1AP_PORT))
            increment_counter(CONTROL_PLANE);
    }

    /* Observe only: preserve the normal OAI packet-processing path. */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";