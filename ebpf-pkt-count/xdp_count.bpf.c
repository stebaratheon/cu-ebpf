#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * A shared map between kernel space and user space.
 *
 * Key 0   -> total number of packets observed
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} packet_count SEC(".maps");

SEC("xdp")
int count_packets(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 *count;

    count = bpf_map_lookup_elem(&packet_count, &key);

    if (count) {
        /*
         * Multiple CPUs might process packets simultaneously,
         * so increment the shared counter atomically.
         */
        __sync_fetch_and_add(count, 1);
    }

    /*
     * Do not drop or redirect the packet.
     * Let it continue to the normal OAI CU processing path.
     */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";