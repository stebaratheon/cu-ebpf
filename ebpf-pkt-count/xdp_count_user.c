#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <errno.h>
#include <string.h>

#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static volatile sig_atomic_t stop = 0;

static void handle_signal(int signal_number)
{
    stop = 1;
}

int main(int argc, char **argv)
{
    const char *interface_name;
    const char *object_file = "xdp_count.bpf.o";

    struct bpf_object *object = NULL;
    struct bpf_program *program = NULL;
    struct bpf_map *map = NULL;

    int interface_index;
    int program_fd;
    int map_fd;
    int error;
    int attached = 0;

    __u32 key = 0;
    __u64 packet_total = 0;

    /*
     * The interface can be supplied on the command line.
     * If omitted, use eth0.
     */
    interface_name = argc > 1 ? argv[1] : "eth0";

    interface_index = if_nametoindex(interface_name);

    if (interface_index == 0) {
        fprintf(stderr,
                "Cannot find interface %s: %s\n",
                interface_name,
                strerror(errno));
        return 1;
    }

    /*
     * Open the compiled eBPF object file.
     */
    object = bpf_object__open_file(object_file, NULL);

    if (libbpf_get_error(object)) {
        fprintf(stderr, "Failed to open %s\n", object_file);
        object = NULL;
        return 1;
    }

    /*
     * Ask the kernel to verify and load the eBPF program and map.
     */
    error = bpf_object__load(object);

    if (error) {
        fprintf(stderr,
                "Failed to load eBPF object: %s\n",
                strerror(-error));
        goto cleanup;
    }

    program = bpf_object__find_program_by_name(
        object, "count_packets"
    );

    if (!program) {
        fprintf(stderr,
                "Cannot find eBPF program count_packets\n");
        goto cleanup;
    }

    program_fd = bpf_program__fd(program);

    if (program_fd < 0) {
        fprintf(stderr, "Cannot obtain eBPF program FD\n");
        goto cleanup;
    }

    /*
     * SKB/generic XDP mode is convenient for a container veth.
     */
    error = bpf_xdp_attach(
        interface_index,
        program_fd,
        XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST,
        NULL
    );

    if (error) {
        fprintf(stderr,
                "Failed to attach XDP to %s: %s\n",
                interface_name,
                strerror(-error));
        goto cleanup;
    }

    attached = 1;

    map = bpf_object__find_map_by_name(object, "packet_count");

    if (!map) {
        fprintf(stderr, "Cannot find packet_count map\n");
        goto cleanup;
    }

    map_fd = bpf_map__fd(map);

    if (map_fd < 0) {
        fprintf(stderr, "Cannot obtain BPF map FD\n");
        goto cleanup;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("Counting incoming packets on %s...\n",
           interface_name);
    printf("Press Ctrl+C to stop.\n\n");

    while (!stop) {
        if (bpf_map_lookup_elem(
                map_fd, &key, &packet_total) == 0) {
            printf("\rPackets seen so far: %llu",
                   (unsigned long long)packet_total);
            fflush(stdout);
        } else {
            fprintf(stderr,
                    "\nFailed to read counter: %s\n",
                    strerror(errno));
            break;
        }

        sleep(1);
    }

    printf("\nStopping...\n");

cleanup:
    /*
     * Remove our program when the reader exits.
     */
    if (attached) {
        bpf_xdp_detach(
            interface_index,
            XDP_FLAGS_SKB_MODE,
            NULL
        );
    }

    if (object)
        bpf_object__close(object);

    return 0;
}