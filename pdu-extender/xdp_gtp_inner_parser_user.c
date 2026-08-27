#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <bpf/libbpf.h>

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

static volatile sig_atomic_t stop;

static void handle_signal(int signo)
{
    (void)signo;
    stop = 1;
}

static const char *ip_protocol_name(__u8 protocol)
{
    switch (protocol) {
    case IPPROTO_ICMP: return "ICMP";
    case IPPROTO_TCP:  return "TCP";
    case IPPROTO_UDP:  return "UDP";
    default:           return "other";
    }
}

static const char *pdu_type_name(__u8 pdu_type)
{
    switch (pdu_type) {
    case 0: return "DL PDU SESSION INFORMATION";
    case 1: return "UL PDU SESSION INFORMATION";
    default: return "other/reserved";
    }
}

static int print_event(void *ctx, void *data, size_t size)
{
    const struct gtp_event *event = data;
    char outer_src[INET_ADDRSTRLEN], outer_dst[INET_ADDRSTRLEN];
    char inner_src[INET_ADDRSTRLEN], inner_dst[INET_ADDRSTRLEN];

    (void)ctx;
    if (size < sizeof(*event))
        return 0;

    inet_ntop(AF_INET, &event->outer_src_ip, outer_src, sizeof(outer_src));
    inet_ntop(AF_INET, &event->outer_dst_ip, outer_dst, sizeof(outer_dst));

    if (!event->is_gtpu) {
        printf("UDP packet without recognized GTP-U header\n");
        printf("  Outer path:       %s:%u -> %s:%u\n",
               outer_src, event->outer_src_port,
               outer_dst, event->outer_dst_port);
        printf("  UDP non-GTP count: %llu\n\n",
               (unsigned long long)event->udp_non_gtpu_count);
        return 0;
    }

    printf("GTP-U packet found (count: %llu)\n",
           (unsigned long long)event->gtpu_count);
    printf("  Outer path:       %s:%u -> %s:%u\n",
           outer_src, event->outer_src_port,
           outer_dst, event->outer_dst_port);

    /*
     * Inner IP is only readable/parsable for encapsulated IPv4 payloads.
     * When it is not (e.g. an F1-U PDCP PDU, or a truncated/otherwise
     * unsupported payload), we say so explicitly instead of silently
     * dropping the packet from view. Every other outer UDP/GTP-U field
     * below is still printed unconditionally, whether or not the inner IP
     * header parsed.
     */
    if (event->inner_ip_present) {
        inet_ntop(AF_INET, &event->inner_src_ip, inner_src, sizeof(inner_src));
        inet_ntop(AF_INET, &event->inner_dst_ip, inner_dst, sizeof(inner_dst));
        printf("  Inner path:       %s -> %s\n", inner_src, inner_dst);
        printf("  Inner protocol:   %u (%s)\n", event->inner_protocol,
               ip_protocol_name(event->inner_protocol));
    } else {
        printf("  Inner IP:         unavailable/not parsable (non-IPv4, truncated, or unsupported extension chain)\n");
    }

    printf("  Version:          %u\n", event->version);
    printf("  Protocol type:    %u (%s)\n", event->protocol_type,
           event->protocol_type ? "GTP" : "not GTP");
    printf("  Message type:     %u%s\n", event->message_type,
           event->message_type == 255 ? " (G-PDU (user data))" : "");
    printf("  GTP length:       %u bytes\n", event->gtp_length);
    printf("  TEID:             %u (0x%08x)\n", event->teid, event->teid);
    printf("  Flags:            E=%u S=%u PN=%u\n",
           event->flag_e, event->flag_s, event->flag_pn);

    if (event->sequence_present)
        printf("  Sequence number:  %u\n", event->sequence_number);
    if (event->npdu_present)
        printf("  N-PDU number:     %u\n", event->npdu_number);
    if (event->flag_e)
        printf("  First extension:  0x%02x\n", event->first_extension_type);
    if (event->extension_count > 0) {
        int count = event->extension_count;
        if (count > MAX_EXTENSION_HEADERS)
            count = MAX_EXTENSION_HEADERS;
        printf("  Extension headers (%u total):\n", event->extension_count);
        for (int i = 0; i < count; i++)
            printf("    [%d] type 0x%02x\n", i, event->extension_types[i]);
    }
    if (event->pdu_type_present)
        printf("  PDU type:         %u (%s)\n", event->pdu_type,
               pdu_type_name(event->pdu_type));
    if (event->qfi_present)
        printf("  QFI:              %u\n", event->qfi);

    putchar('\n');
    return 0;
}

int main(int argc, char **argv)
{
    const char *interface_name = argc > 1 ? argv[1] : "eth0";
    const char *object_file = "xdp_gtp_inner_parser.bpf.o";
    struct bpf_object *object = NULL;
    struct bpf_program *program;
    struct bpf_map *map;
    struct ring_buffer *ring = NULL;
    int interface_index, program_fd, error = 1;
    int attached = 0;

    interface_index = if_nametoindex(interface_name);
    if (!interface_index) {
        fprintf(stderr, "Cannot find interface %s: %s\n",
                interface_name, strerror(errno));
        return 1;
    }

    object = bpf_object__open_file(object_file, NULL);
    if (libbpf_get_error(object)) {
        fprintf(stderr, "Failed to open %s\n", object_file);
        object = NULL;
        goto cleanup;
    }

    error = bpf_object__load(object);
    if (error) {
        fprintf(stderr, "Failed to load eBPF object: %s\n", strerror(-error));
        goto cleanup;
    }

    program = bpf_object__find_program_by_name(object, "parse_gtpu");
    if (!program) {
        fprintf(stderr, "Cannot find eBPF program parse_gtpu\n");
        error = 1;
        goto cleanup;
    }
    program_fd = bpf_program__fd(program);

    error = bpf_xdp_attach(interface_index, program_fd,
                           XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST,
                           NULL);
    if (error) {
        fprintf(stderr, "Failed to attach XDP to %s: %s\n",
                interface_name, strerror(-error));
        goto cleanup;
    }
    attached = 1;

    map = bpf_object__find_map_by_name(object, "events");
    if (!map) {
        fprintf(stderr, "Cannot find events ring buffer\n");
        error = 1;
        goto cleanup;
    }

    ring = ring_buffer__new(bpf_map__fd(map), print_event, NULL, NULL);
    if (!ring) {
        fprintf(stderr, "Failed to create ring-buffer reader\n");
        error = 1;
        goto cleanup;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    printf("Parsing ingress UDP and GTP-U packets on %s; press Ctrl+C to stop.\n\n",
           interface_name);

    while (!stop) {
        error = ring_buffer__poll(ring, 250);
        if (error == -EINTR)
            continue;
        if (error < 0) {
            fprintf(stderr, "Ring-buffer polling failed: %s\n", strerror(-error));
            goto cleanup;
        }
    }
    error = 0;

cleanup:
    ring_buffer__free(ring);
    if (attached)
        bpf_xdp_detach(interface_index, XDP_FLAGS_SKB_MODE, NULL);
    bpf_object__close(object);
    return error ? 1 : 0;
}