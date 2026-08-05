#include <linux/bpf.h>
// defines ebpf data structures. defines struct xdp_md, definses return values like xdp_pass, 
//xdp_drop
#include <bpf/bpf_helpers.h>
// Provides helpers macros such as SEC(), declares helper functions like bpf_map_lookup_elem

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); // creates an array map type, which is a key-value store 
    //where keys are integers and values are arbitrary data
    __uint(max_entries, 1); // only one element exists
    __type(key, __u32);
    __type(value, __u64);
} packet_count SEC(".maps");
// packet_count is a map that will be shared between kernel space and user space. It will store the 
//total number of packets observed, with key 0 mapping to the total count.
// SEC(".maps") places this object into the ELF section named "maps", which is recognized by the 
//eBPF loader to create a map in the kernel.
// when the loader loads the program, it sees this section and creates the kernel map accordingly. 
//The user space program can then access this map to read the packet count.

SEC("xdp") // this tells the loader "Attach this program to the XDP hook point"
// or, "Attach this function as an XDP program"

int count_packets(struct xdp_md *ctx)  // ctx contains metadata about the packet being processed, 
//such as the data pointer and data_end pointer, which can be used to access the packet's contents.
// it includes information like packet start, packet end, ingress interface index, and other 
//metadata. The eBPF program can use this context to make decisions about how to handle the packet.
{
    __u32 key = 0; // since the array has only one element, the key is always 0
    __u64 *count; // pointer to the value in the map corresponding to the key

    count = bpf_map_lookup_elem(&packet_count, &key);
    // give me the value stored at key 0 in the packet_count map. This function returns a pointer 
    //to the value if it exists, or NULL if it doesn't.
    if (count) {
        __sync_fetch_and_add(count, 1);
        // it is atomic because multiple CPUs might be processing packets simultaneously, and we 
        //want to avoid
    }

    return XDP_PASS;
    // this tells XDP, let the packet cpntinue to the normal processing path. We are not dropping 
    //or redirecting the packet, just counting it.
}

char LICENSE[] SEC("license") = "GPL";
// the kernel checks the license, many eBPF helper functions are available only to GPL-licensed 
//programs. This line declares that the program is licensed under the GPL, allowing it to use all available 
//helper functions.