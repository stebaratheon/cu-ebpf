#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

enum counter_key {
    USER_PLANE = 0,
    CONTROL_PLANE = 1,
};

static volatile sig_atomic_t stop;

static void handle_signal(int signal_number)
{
    (void)signal_number;
    stop = 1;
}

static int read_counter(int map_fd, __u32 key, __u64 *value)
{
    if (bpf_map_lookup_elem(map_fd, &key, value) < 0) {
        fprintf(stderr, "Failed to read counter %u: %s\n",
                key, strerror(errno));
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    const char *interface_name = argc > 1 ? argv[1] : "eth0";
    const char *object_file = "xdp_plane_count.bpf.o";
    const __u32 xdp_flags =
        XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;

    struct bpf_object *object = NULL;
    struct bpf_program *program;
    struct bpf_map *map;

    __u64 user_total = 0;
    __u64 control_total = 0;
    __u64 previous_user_total = 0;
    __u64 previous_control_total = 0;

    int interface_index;
    int program_fd;
    int map_fd;
    int error;
    int attached = 0;
    int exit_status = 1;

    interface_index = if_nametoindex(interface_name);
    if (interface_index == 0) {
        fprintf(stderr, "Cannot find interface %s: %s\n",
                interface_name, strerror(errno));
        return 1;
    }

    object = bpf_object__open_file(object_file, NULL);
    error = libbpf_get_error(object);
    if (error) {
        fprintf(stderr, "Failed to open %s: %s\n",
                object_file, strerror(-error));
        object = NULL;
        goto cleanup;
    }

    error = bpf_object__load(object);
    if (error) {
        fprintf(stderr, "Failed to load %s: %s\n",
                object_file, strerror(-error));
        goto cleanup;
    }

    program = bpf_object__find_program_by_name(
        object, "count_user_and_control_plane");
    if (!program) {
        fprintf(stderr, "Cannot find the XDP program\n");
        goto cleanup;
    }

    program_fd = bpf_program__fd(program);
    if (program_fd < 0) {
        fprintf(stderr, "Cannot obtain the XDP program file descriptor\n");
        goto cleanup;
    }

    error = bpf_xdp_attach(interface_index, program_fd, xdp_flags, NULL);
    if (error) {
        fprintf(stderr, "Failed to attach XDP to %s: %s\n",
                interface_name, strerror(-error));
        goto cleanup;
    }
    attached = 1;

    map = bpf_object__find_map_by_name(object, "plane_counters");
    if (!map) {
        fprintf(stderr, "Cannot find the plane_counters map\n");
        goto cleanup;
    }

    map_fd = bpf_map__fd(map);
    if (map_fd < 0) {
        fprintf(stderr, "Cannot obtain the BPF map file descriptor\n");
        goto cleanup;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("Watching %s for:\n", interface_name);
    printf("  User plane:    GTP-U over UDP port 2152\n");
    printf("  Control plane: F1AP over SCTP port 38472\n");
    printf("Press Ctrl+C to stop.\n\n");

    exit_status = 0;

    while (!stop) {
        if (read_counter(map_fd, USER_PLANE, &user_total) < 0 ||
            read_counter(map_fd, CONTROL_PLANE, &control_total) < 0) {
            exit_status = 1;
            break;
        }

        /*
         * Print one notification per polling interval, rather than one line
         * per packet. Printing for every packet would be very expensive.
         */
        if (user_total > previous_user_total) {
            printf("User plane packet found (+%llu)\n",
                   (unsigned long long)
                   (user_total - previous_user_total));
        }

        if (control_total > previous_control_total) {
            printf("Control plane packet found (+%llu)\n",
                   (unsigned long long)
                   (control_total - previous_control_total));
        }

        printf("Totals: user plane = %llu, control plane = %llu\n\n",
               (unsigned long long)user_total,
               (unsigned long long)control_total);
        fflush(stdout);

        previous_user_total = user_total;
        previous_control_total = control_total;
        sleep(1);
    }

    printf("Stopping...\n");

cleanup:
    if (attached) {
        error = bpf_xdp_detach(
            interface_index, XDP_FLAGS_SKB_MODE, NULL);
        if (error) {
            fprintf(stderr, "Warning: failed to detach XDP from %s: %s\n",
                    interface_name, strerror(-error));
            exit_status = 1;
        }
    }

    if (object)
        bpf_object__close(object);

    return exit_status;
}