# Toy XDP Packet Counter for the OAI CU Container

This example attaches a small XDP/eBPF program to `eth0` inside the
`rfsim5g-oai-cu` container. The kernel-space program counts packets arriving on
the interface and returns `XDP_PASS`, so packets continue through the normal OAI
processing path. A user-space C program loads and attaches the eBPF program,
reads its BPF map once per second, and prints the running packet count.

> **Current scope:** this toy version counts **all ingress packets** on `eth0`,
> including GTP-U, SCTP/F1AP, ARP, and background traffic. It does not yet count
> only GTP-U packets.

## Step 0: Configure the CU container

Add these capabilities to the CU service in the Docker Compose file:

```yaml
services:
  oai-cu:
    cap_add:
      - NET_ADMIN
      - BPF
      - PERFMON
      - SYS_RESOURCE
```

Why they are needed:

- `NET_ADMIN` allows the user-space loader to attach and detach the XDP program
  on `eth0`.
- `BPF` allows privileged eBPF operations, including loading programs and
  creating BPF maps.
- `PERFMON` permits performance-monitoring operations used by the BPF
  subsystem on newer kernels.
- `SYS_RESOURCE` allows the process to adjust resource limits required for
  locked BPF memory on some kernel/libbpf versions.

On older Linux kernels, the separate `BPF` and `PERFMON` capabilities may not
be sufficient. Such systems may require `SYS_ADMIN`, although it should not be
added unless the load fails and the host kernel genuinely requires it.

Recreate the CU container so the capability changes take effect. Run this from
the host, using the CU **Compose service name**:

```bash
sudo docker compose up -d --force-recreate oai-cu
```

If the container becomes stuck and cannot be stopped normally, find its host
process and terminate it as a last resort:

```bash
sudo docker inspect --format '{{.State.Pid}}' rfsim5g-oai-cu
sudo kill -9 <process_id>
```

Then recreate the container:

```bash
sudo docker compose up -d --force-recreate oai-cu
```

## Step 1: Install the dependencies

Enter the running CU container:

```bash
sudo docker exec -it rfsim5g-oai-cu /bin/bash
```

Inside the container, install the compiler, headers, libraries, and optional
text editor:

```bash
apt-get update
apt-get install -y nano clang gcc libbpf-dev libelf-dev zlib1g-dev
```

## Step 2: Add the kernel- and user-space source files

### Option A: Create the files inside the container

Inside the CU container:

```bash
nano /opt/oai-gnb/xdp_count.bpf.c
nano /opt/oai-gnb/xdp_count_user.c
```

Paste the corresponding source code into each file. In Nano, save and exit
with:

```text
Ctrl+O → Enter → Ctrl+X
```

Because the container shell normally runs as `root`, `sudo` is not required
inside the container.

### Option B: Copy existing files from the host

From the host directory containing `xdp_count.bpf.c` and
`xdp_count_user.c`, run:

```bash
sudo docker cp ./xdp_count.bpf.c \
  rfsim5g-oai-cu:/opt/oai-gnb/xdp_count.bpf.c

sudo docker cp ./xdp_count_user.c \
  rfsim5g-oai-cu:/opt/oai-gnb/xdp_count_user.c
```

Files copied or created inside the container survive a normal stop/start, but
they disappear if the container is deleted and recreated. Keep the original
source files on the host.

## Step 3: Compile and run

Enter the CU container if necessary:

```bash
sudo docker exec -it rfsim5g-oai-cu /bin/bash
```

Move to the source directory:

```bash
cd /opt/oai-gnb
```

Compile the kernel-space eBPF program:

```bash
clang -O2 -g -target bpf \
  -D__TARGET_ARCH_x86 \
  -I/usr/include/x86_64-linux-gnu \
  -c xdp_count.bpf.c \
  -o xdp_count.bpf.o
```

Compile the user-space loader:

```bash
gcc -O2 -g xdp_count_user.c \
  -o xdp_count_user \
  -lbpf -lelf -lz
```

Run the loader and attach the program to `eth0`:

```bash
./xdp_count_user eth0
```

The process remains active and prints the total once per second:

```text
Counting incoming packets on eth0...
Press Ctrl+C to stop.

Packets seen so far: 4832
```

Leave this terminal running while generating traffic. Press `Ctrl+C` to stop
the program; the user-space loader will detach the XDP program before exiting.

## Step 4: Generate test traffic

Open separate terminals for the external data network and the NR UE.

Start the `iperf3` server in `oai-ext-dn`:

```bash
iperf3 -s -B 192.168.72.135
```

Start the client in the NR-UE container, binding it to the UE tunnel address:

```bash
iperf3 -c 192.168.72.135 -B 12.1.1.3 -t 20
```

The test path is:

```text
NR UE → DU → CU eth0/XDP → CU-UP → UPF → external data network
                packet counter ↑
```

The counter may increase before and after the `iperf3` test because this first
version counts every packet entering `eth0`. A later version can parse
Ethernet, IPv4, UDP, and count only GTP-U traffic using UDP port `2152`.

## Troubleshooting

### `Operation not permitted` while loading or attaching

Confirm that the container was **recreated**, rather than merely restarted,
after adding the capabilities:

```bash
sudo docker inspect rfsim5g-oai-cu \
  --format '{{json .HostConfig.CapAdd}}'
```

Also confirm that `NET_ADMIN`, `BPF`, `PERFMON`, and `SYS_RESOURCE` appear in
the output.

### `Cannot find interface eth0`

List the interfaces inside the CU container:

```bash
ip link show
```

Then supply the correct interface name:

```bash
./xdp_count_user <interface_name>
```

### A program is already attached

The loader intentionally uses `XDP_FLAGS_UPDATE_IF_NOEXIST`; it will not replace
an existing XDP program. Inspect the interface:

```bash
ip -details link show dev eth0
```

Stop the process that owns the existing program or detach it deliberately
before rerunning this example.
