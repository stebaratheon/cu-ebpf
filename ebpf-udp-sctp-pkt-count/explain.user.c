#include <stdio.h>
// Provides standard input/output functions such as printf() and fprintf().

#include <stdlib.h>
// Provides general-purpose C utilities and constants such as EXIT_SUCCESS
// and EXIT_FAILURE.

#include <unistd.h>
// Provides POSIX functions such as sleep().

#include <signal.h>
// Provides signal handling. We use it to detect Ctrl+C, which sends SIGINT,
// so that the program can detach the XDP program before exiting.

#include <net/if.h>
// Provides if_nametoindex(), which converts an interface name such as "eth0"
// into the numeric interface index used by the kernel.

#include <errno.h>
// Declares errno. Many system and libbpf operations set errno to indicate
// why an operation failed.

#include <string.h>
// Provides strerror(), which converts an error number into a readable message.

#include <linux/if_link.h>
// Defines XDP attachment flags such as XDP_FLAGS_SKB_MODE and
// XDP_FLAGS_UPDATE_IF_NOEXIST.

#include <bpf/bpf.h>
// Provides user-space functions for interacting with BPF maps, such as
// bpf_map_lookup_elem().

#include <bpf/libbpf.h>
// Provides libbpf's object-loading and program-management functions, such as
// bpf_object__open_file(), bpf_object__load(), and bpf_xdp_attach().


enum counter_key {
    USER_PLANE = 0,
    CONTROL_PLANE = 1,
};
// These values must match the keys used by the kernel-space program.
//
// plane_counter[0] stores the number of GTP-U user-plane packets.
// plane_counter[1] stores the number of F1AP control-plane packets.


static volatile sig_atomic_t stop = 0;
// This is a global flag that tells the main loop when to stop.
//
// static means this variable is visible only inside this C source file.
//
// volatile tells the compiler that the value may change unexpectedly, such as
// when the signal handler runs. Therefore, the compiler must read its current
// value each time instead of assuming that it remains unchanged.
//
// sig_atomic_t is an integer type that can be read or written safely by a
// signal handler. Initially, stop is 0, so the main loop continues running.


static void handle_signal(int signal_number)
// is this function name fixed? yes, it is fixed. The operating system calls this function when the process receives one of the signals registered below, such as SIGINT from pressing Ctrl+C.
// The operating system calls this function when the process receives one of
// the signals registered below, such as SIGINT from pressing Ctrl+C.
//
// A signal handler should perform only very small and safe operations. Here it
// only changes the stop flag. The normal program flow performs the cleanup.
{
    (void)signal_number;
    // The handler must accept the signal number because that is the function
    // signature expected by signal(). We do not need its value, so this cast
    // explicitly marks it as unused and avoids a compiler warning.

    stop = 1;
    // The next time the main loop checks stop, it will terminate.
}


int main(int argc, char **argv)
// argc is the number of command-line arguments.
//
// argv is an array of strings containing those arguments. For example:
//
//   ./xdp_count_user eth0
//
// gives:
//
//   argv[0] = "./xdp_count_user"
//   argv[1] = "eth0"
//   argc    = 2
{
    const char *interface_name;
    // This pointer will refer to the name of the interface, such as "eth0".
    // const means this program will not modify the characters in that string.

    const char *object_file = "xdp_count.bpf.o";
    // This is the compiled kernel-space eBPF object file.
    //
    // Clang creates this file from xdp_count.bpf.c. It contains the compiled
    // eBPF instructions, map definition, program name, and license section.

    struct bpf_object *object = NULL;
    // struct bpf_object is a libbpf structure representing the complete
    // opened eBPF ELF object file.
    //
    // It may contain one or more eBPF programs and maps. We use a pointer
    // because libbpf creates and manages the actual structure internally.

    struct bpf_program *program = NULL;
    // Represents one eBPF program found inside the object file. In this case,
    // it will represent count_user_and_control_plane.

    struct bpf_map *map = NULL;
    // Represents the plane_counter map found inside the object file.

    int interface_index;
    // The kernel identifies network interfaces using integer indexes rather
    // than names. For example, eth0 might have interface index 2.

    int program_fd;
    // fd means file descriptor.
    //
    // Linux represents many kernel resources using small integers called file
    // descriptors. program_fd is the handle through which libbpf refers to the
    // eBPF program loaded into the kernel.

    int map_fd;
    // The file descriptor representing the BPF map in the kernel.
    // It is passed to bpf_map_lookup_elem() when reading map values.

    int error;
    // Stores return values from libbpf functions. A value of 0 generally
    // indicates success, while a negative value indicates an error.

    int attached = 0;
    // Records whether this process successfully attached the XDP program.
    // Cleanup should detach it only if attachment actually succeeded.

    int exit_status = EXIT_FAILURE;
    // Assume the program failed unless it reaches normal completion.

    __u32 user_key = USER_PLANE;
    __u32 control_key = CONTROL_PLANE;
    // These are the two 32-bit keys used to read entries 0 and 1 from the map.
    // Their type matches __type(key, __u32) in the kernel-space map definition.

    __u64 user_total = 0;
    __u64 control_total = 0;
    // These variables receive the 64-bit counter values read from the map.
    // Their type matches __type(value, __u64) in the kernel-space program.


    /*
     * If an interface name was supplied, use argv[1]. Otherwise, use eth0.
     *
     * The conditional expression:
     *
     *     condition ? value_if_true : value_if_false
     *
     * is a shorter form of an if/else assignment.
     */
    interface_name = argc > 1 ? argv[1] : "eth0";


    interface_index = if_nametoindex(interface_name);
    // Ask the operating system for the numeric index corresponding to the
    // interface name. XDP attachment requires this index rather than "eth0".

    if (interface_index == 0) {
        // if_nametoindex() returns 0 if the interface does not exist or another
        // error occurs.

        fprintf(stderr,
                "Cannot find interface %s: %s\n",
                interface_name,
                strerror(errno));
        // fprintf() prints formatted text to a selected stream.
        //
        // stderr is the standard error stream. It is normally used for error
        // messages, while printf() writes to the standard output stream.
        //
        // strerror(errno) converts the current error number into text such as
        // "No such device".

        return EXIT_FAILURE;
    }


    object = bpf_object__open_file(object_file, NULL);
    // Open and inspect the compiled ELF object file.
    //
    // This does not yet load the program into the kernel. It lets libbpf read
    // the file and discover its programs, maps, and other ELF sections.
    //
    // The second argument could point to a structure containing advanced
    // loading options. NULL means to use libbpf's default options.

    if (libbpf_get_error(object)) {
        // Some libbpf functions return an error encoded inside a pointer rather
        // than simply returning NULL. libbpf_get_error() checks whether this
        // pointer represents such an error.

        fprintf(stderr, "Failed to open %s\n", object_file);

        object = NULL;
        // Do not pass an error-encoded pointer to bpf_object__close() later.

        goto cleanup;
        // Jump to the cleanup label near the end of main(). This keeps all
        // resource-release operations in one place instead of duplicating
        // cleanup code after every possible error.
    }


    error = bpf_object__load(object);
    // Ask the kernel to create the BPF maps, verify the eBPF instructions,
    // and load the program into the kernel.
    //
    // The eBPF verifier checks properties such as:
    //
    //   - packet accesses stay within data and data_end;
    //   - pointers are used safely;
    //   - the program cannot execute unrestricted loops;
    //   - helper functions are called correctly.
    //
    // Loading does not attach the program to eth0 yet.

    if (error) {
        // libbpf normally returns 0 on success and a negative errno value on
        // failure. For example, -EPERM means permission was denied.

        fprintf(stderr,
                "Failed to load eBPF object: %s\n",
                strerror(-error));
        // Because error is negative, -error converts it into the positive
        // error number expected by strerror().

        goto cleanup;
    }


    program = bpf_object__find_program_by_name(
        object, "count_user_and_control_plane"
    );
    // Search the loaded object for the eBPF function whose C function name is
    // count_user_and_control_plane.
    //
    // This is the function marked SEC("xdp") in the kernel-space program.

    if (!program) {
        // A NULL pointer means libbpf could not find a program with that name.

        fprintf(stderr,
                "Cannot find eBPF program "
                "count_user_and_control_plane\n");
        goto cleanup;
    }


    program_fd = bpf_program__fd(program);
    // Obtain the file descriptor for the program now loaded in the kernel.

    if (program_fd < 0) {
        fprintf(stderr, "Cannot obtain eBPF program FD\n");
        goto cleanup;
    }


    error = bpf_xdp_attach(
        interface_index,
        program_fd,
        XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST,
        NULL
    );
    // Attach the loaded program to the XDP receive hook of the selected
    // interface.
    //
    // XDP_FLAGS_SKB_MODE requests generic, or SKB, XDP mode. In this mode the
    // kernel runs XDP after constructing the basic socket-buffer representation
    // of the packet. Generic mode is useful for container veth interfaces,
    // whose drivers may not support native driver-level XDP.
    // So kernel  makes a basic socket-buffer representation of the packet and then 
    // runs XDP on that representation. "Run XDP" means the kernel executes the
    // eBPF program on the packet.

    // What is generic XDP mode? Generic XDP mode, also known as SKB mode, is a 
    // mode of operation for eBPF programs that allows them to be executed on 
    // packets after they have been processed by the kernel's network stack.
    // In this mode, the kernel creates a socket buffer (SKB) representation of
    // the packet, which includes metadata and pointers to the actual packet data.
    // The eBPF program can then access and manipulate this SKB representation,
    // allowing for more complex packet processing and analysis. Generic XDP mode
    // is useful for scenarios where native driver-level XDP is not supported or 
    // when additional processing is required after the packet has been handled by 
    // the network stack.
    // But I thought program at XDP hook operates before the packet traverses the
    // kernel's network stack. How can it run after the packet has been processed
    // by the kernel's network stack? Answer: In native XDP mode, the eBPF program
    // runs before the packet traverses the kernel's network stack. However, in
    // generic (SKB) XDP mode, the eBPF program runs after the packet has been
    //  processed by the kernel's network stack. This is because, in generic mode,
    // the kernel creates a socket buffer (SKB) representation of the packet after
    // it has been processed by the network stack. The eBPF program can then 
    // access and manipulate this SKB representation, allowing for more complex
    // packet processing and analysis.
    // So what is the benefit of fast packet processing in native XDP mode if the packet is dropped after processing by the kernel's network stack? Answer: The benefit of fast packet processing in native XDP mode is that it allows for early packet filtering and decision-making before the packet traverses the kernel's network stack. This can help reduce the load on the network stack and improve overall system performance, especially in high-throughput scenarios. By dropping unwanted packets early in the processing pipeline, native XDP mode can help conserve system resources and improve the efficiency of packet handling. In contrast, generic (SKB) XDP mode allows for more complex packet processing and analysis after the packet has been processed by the network stack, but it may introduce additional overhead and latency compared to native XDP mode.
    // what if i want to run the program in native XDP mode? Answer: To run the program in native XDP mode, you can change the attachment flags in the bpf_xdp_attach() function call. Instead of using XDP_FLAGS_SKB_MODE, you can use XDP_FLAGS_DRV_MODE. This flag requests native driver-level XDP mode, which allows the eBPF program to run before the packet traverses the kernel's network stack. However, keep in mind that not all network drivers support native XDP mode, so you should check your specific driver documentation to ensure compatibility.
    // for native mode Do i must have a NIC that supports XDP? Answer: Yes, to run eBPF programs in native XDP mode, you must have a network interface card (NIC) that supports XDP. Native XDP mode relies on the capabilities of the NIC driver to execute eBPF programs at the driver level, before the packet traverses the kernel's network stack. Not all NICs and their corresponding drivers support native XDP mode, so it's essential to check your specific NIC's documentation to determine if it is compatible with native XDP. If your NIC does not support native XDP, you can still use generic (SKB) XDP mode, which operates after the packet has been processed by the kernel's network stack.
    // so dor docker container the native mode is not supported? Answer: In many cases, native XDP mode may not be supported in Docker containers, especially if the underlying network interface does not support it or if the container is using a virtualized network interface (such as a veth pair) that does not have native XDP capabilities. In such scenarios, you can still use generic (SKB) XDP mode, which operates after the packet has been processed by the kernel's network stack. Generic XDP mode is more widely supported and can be used in containerized environments where native XDP is not available. However, if your container is running on a host with a NIC that supports native XDP and the container has direct access to that NIC, it may be possible to use native XDP mode, but this is less common in typical container deployments.
    // so is generic xdp mode still faster than normal packet processing? Answer: Yes, generic (SKB) XDP mode can still provide performance benefits compared to normal packet processing, even though it operates after the packet has been processed by the kernel's network stack. While it may not be as fast as native XDP mode, generic XDP mode allows for early packet filtering and decision-making within the eBPF program, which can help reduce the load on the network stack and improve overall system performance. By allowing for more complex packet processing and analysis, generic XDP mode can still offer advantages over traditional packet processing methods, especially in scenarios where specific packet handling or filtering is required.
    // so in generic xdp mode we can do more complex packet processing and analysis than in native xdp mode? Answer: Not necessarily. Both native and generic XDP modes allow for complex packet processing and analysis using eBPF programs. The main difference between the two modes is the point at which the eBPF program is executed in the packet processing pipeline. In native XDP mode, the program runs before the packet traverses the kernel's network stack, while in generic (SKB) XDP mode, it runs after the packet has been processed by the network stack.
    // so is generic xdp mode still before user-space application processing? Answer: Yes, generic (SKB) XDP mode still operates before user-space application processing. In both native and generic XDP modes, the eBPF program is executed in the kernel space, allowing for packet filtering and decision-making before the packet reaches user-space applications. The main difference between the two modes is the point at which the eBPF program is executed in relation to the kernel's network stack, but both modes still provide an opportunity to process packets before they are handed off to user-space applications. 
    // so if i want to attach that program to TC hook, what should i do? Answer: To attach an eBPF program to the Traffic Control (TC) hook instead of XDP, you would need to use the `bpf_tc_attach()` function provided by libbpf. This function allows you to attach an eBPF program to a specific TC hook point, such as ingress or egress. You would also need to ensure that your eBPF program is compatible with the TC hook and that you have the necessary permissions to attach it. Additionally, you may need to modify your program's logic to work with the TC context and data structures. Keep in mind that attaching to TC may have different performance characteristics compared to XDP, so you should evaluate your specific use case and requirements before making this change.
    // So what is the difference between XDP and TC? Answer: XDP (eXpress Data Path) and TC (Traffic Control) are both mechanisms for processing network packets in the Linux kernel, but they operate at different points in the packet processing pipeline and have different use cases.
    // XDP operates at a very low level, directly at the network driver level, allowing for high-performance packet processing and filtering before the packet traverses the kernel's network stack. It is designed for scenarios where low latency and high throughput are critical, such as DDoS mitigation, load balancing, and packet filtering. XDP programs are typically written in eBPF and can be attached to network interfaces to process incoming packets.
    // TC, on the other hand, operates at a higher level in the kernel's networking stack, specifically within the Traffic Control subsystem. TC is primarily used for shaping, scheduling, and policing network traffic. It allows for more complex traffic management policies, such as rate limiting, prioritization, and queuing. TC programs can also be written in eBPF, but they are generally used for different purposes than XDP programs. While TC can also perform packet filtering and processing, it is not as low-level or high-performance as XDP, making it more suitable for traffic management and control rather than ultra-low-latency packet processing.
    // In summary, XDP is focused on high-performance packet processing at the driver level, while TC is focused on traffic management and control within the kernel's networking stack. The choice between XDP and TC depends on the specific requirements of your application, such as performance, latency, and traffic management needs.
    // so is xdp generic mode is equal to attaching the program to  sk_skb hook? Answer: Yes, in generic (SKB) XDP mode, the eBPF program is executed after the packet has been processed by the kernel's network stack, which is similar to attaching the program to the `sk_skb` hook. In this mode, the kernel creates a socket buffer (SKB) representation of the packet, and the eBPF program can access and manipulate this SKB representation. This allows for more complex packet processing and analysis compared to native XDP mode, which operates at the driver level before the packet traverses the network stack. However, it's important to note that while generic XDP mode provides similar functionality to attaching to the `sk_skb` hook, it is still part of the XDP framework and may have different performance characteristics and limitations compared to traditional TC or `sk_skb` hooks.

    
    // What is socket-buffer representation? A socket buffer is a data structure 
    // used in the Linux kernel to represent network packets. It contains metadata
    // about the packet, such as its length, protocol type, and pointers to the
    // actual data. The socket buffer allows the kernel to manage and manipulate
    // packets as they traverse the network stack.
    //
    // XDP_FLAGS_UPDATE_IF_NOEXIST means attach only if another XDP program is
    // not already attached. This prevents the program from silently replacing
    // an existing XDP program.
    //
    // The final NULL means no additional attachment options are supplied.

    if (error) {
        fprintf(stderr,
                "Failed to attach XDP to %s: %s\n",
                interface_name,
                strerror(-error));
        goto cleanup;
    }

    attached = 1;
    // Remember that attachment succeeded so cleanup knows it must detach.


    map = bpf_object__find_map_by_name(object, "plane_counter");
    // Search the eBPF object for the map named plane_counter.
    //
    // The name must exactly match the variable name used in the kernel-space
    // map definition.

    if (!map) {
        fprintf(stderr, "Cannot find plane_counter map\n");
        goto cleanup;
    }


    map_fd = bpf_map__fd(map);
    // Obtain the file descriptor of the map created in the kernel.

    if (map_fd < 0) {
        fprintf(stderr, "Cannot obtain BPF map FD\n");
        goto cleanup;
    }


    signal(SIGINT, handle_signal);
    // SIGINT is normally sent when the user presses Ctrl+C.

    signal(SIGTERM, handle_signal);
    // SIGTERM is a request from another process or command to terminate.
    //
    // For either signal, call handle_signal() instead of immediately ending
    // the process. This gives the main function a chance to detach XDP.


    printf("Counting F1 user-plane and control-plane packets on %s...\n",
           interface_name);
    printf("Press Ctrl+C to stop.\n\n");


    while (!stop) {
        // Repeat until handle_signal() changes stop from 0 to 1.

        if (bpf_map_lookup_elem(
                map_fd, &user_key, &user_total) != 0) {
            // Copy the map value at key USER_PLANE into user_total.
            //
            // Unlike the kernel-side bpf_map_lookup_elem() helper, the
            // user-space version does not return a pointer to the map value.
            // It copies the value into the memory whose address is supplied
            // as the third argument.
            //
            // The arguments mean:
            //
            //   map_fd      -> which kernel map to read
            //   &user_key   -> address of the key
            //   &user_total -> address where the value should be copied

            fprintf(stderr,
                    "\nFailed to read user-plane counter: %s\n",
                    strerror(errno));
            goto cleanup;
        }


        if (bpf_map_lookup_elem(
                map_fd, &control_key, &control_total) != 0) {
            // Read entry CONTROL_PLANE from the same map and copy its value
            // into control_total.

            fprintf(stderr,
                    "\nFailed to read control-plane counter: %s\n",
                    strerror(errno));
            goto cleanup;
        }


        printf("\rUser-plane packets: %-12llu  "
               "Control-plane packets: %-12llu",
               (unsigned long long)user_total,
               (unsigned long long)control_total);
        // \r moves the cursor to the beginning of the current terminal line.
        // This lets each update overwrite the previous values instead of
        // printing a new line every second.
        //
        // %llu prints an unsigned long long integer. The explicit casts ensure
        // that the argument type matches the format specifier.
        //
        // %-12llu reserves 12 character positions and left-aligns the number,
        // helping overwrite any digits left from an earlier, larger value.

        fflush(stdout);
        // printf() output may remain temporarily in a user-space output buffer.
        // fflush(stdout) forces it to appear immediately on the terminal.

        sleep(1);
        // Pause for one second before reading and displaying the counters again.
        // Packets continue to be counted in kernel space during this pause.
    }


    printf("\nStopping...\n");
    exit_status = EXIT_SUCCESS;
    // Reaching here means the loop ended normally after a signal.


cleanup:
    /*
     * This label is reached both during normal termination and after errors.
     * Resources are released in reverse order: detach the program first, then
     * close the object that owns the program and map descriptors.
     */

    if (attached) {
        error = bpf_xdp_detach(
            interface_index,
            XDP_FLAGS_SKB_MODE,
            NULL
        );
        // Remove the XDP program from the interface.
        //
        // The mode flag must match the mode used during attachment. Since the
        // program was attached in SKB mode, it is detached in SKB mode too.

        if (error) {
            fprintf(stderr,
                    "Warning: failed to detach XDP from %s: %s\n",
                    interface_name,
                    strerror(-error));

            exit_status = EXIT_FAILURE;
        }
    }


    if (object) {
        bpf_object__close(object);
        // Release libbpf's user-space representation of the object and close
        // the associated program and map file descriptors.
        //
        // This does not need to delete the map separately because the map is
        // owned through this loaded object and has not been pinned in bpffs.
    }


    return exit_status;
    // Return 0 to the shell on success and a nonzero value on failure.
}