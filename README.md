# cu-ebpf

CU fast path acceleration using eBPF.

## Step 1: Run the containers

1. Clone the repo from here: https://github.com/openairinterface/openairinterface5g/tree/develop
2. Navigate to the directory containing the CU-DU split configuration. Inside the `openairinterface5g` repo, run:
   ```
   cd ci-scripts/yaml_files/5g_f1_rfsimulator
   ```
3. In the `oai-cu` container specification, add these capabilities and security options (or just replace the `docker-compose.yaml` file there with the one from this repo):
   ```yaml
   cap_add:
     - SYS_NICE
     - NET_ADMIN
     - NET_RAW
     - SETUID
     - SETGID
     - CHOWN
     - DAC_OVERRIDE
   security_opt:
     - apparmor:unconfined
   ```
4. Run the core network functions (use `docker compose` instead of `docker-compose` if you hit a Docker version mismatch):
   ```
   docker-compose up -d mysql oai-amf oai-smf oai-upf oai-ext-dn
   ```
   Wait until all the containers are up and healthy — check with:
   ```
   docker-compose ps -a
   ```
5. Run the gNB (CU and DU) and the UE:
   ```
   docker-compose up -d oai-cu   # after this, jump to Step 2 below, then come back here
   docker-compose up -d oai-du-pci0
   docker-compose up -d oai-nr-ue
   ```
   Verify the CU (gNB) is connected to the AMF:
   ```
   docker logs rfsim5g-oai-amf
   ```
   ```
   [AMF] [amf_app] [info ] |----------------------------------------------------gNBs' information-------------------------------------------|
   [AMF] [amf_app] [info ] |    Index    |      Status      |       Global ID       |       gNB Name       |               PLMN             |
   [AMF] [amf_app] [info ] |      1      |    Connected     |         0x0       |         gnb-rfsim        |            208, 99             |
   [AMF] [amf_app] [info ] |----------------------------------------------------------------------------------------------------------------|
   ```
6. Confirm the UE is connected:
   ```
   docker exec -it rfsim5g-oai-nr-ue /bin/bash
   ifconfig
   ```
   ```
   eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
           inet 192.168.71.150  netmask 255.255.255.192  broadcast 192.168.71.191
           ether 02:42:c0:a8:47:89  txqueuelen 0  (Ethernet)
           RX packets 224259  bytes 5821372018 (5.8 GB)
           RX errors 0  dropped 0  overruns 0  frame 0
           TX packets 235916  bytes 7848786376 (7.8 GB)
           TX errors 0  dropped 0  overruns 0  carrier 0  collisions 0

   lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
           inet 127.0.0.1  netmask 255.0.0.0
           loop  txqueuelen 1000  (Local Loopback)
           RX packets 0  bytes 0 (0.0 B)
           RX errors 0  dropped 0  overruns 0  frame 0
           TX packets 0  bytes 0 (0.0 B)
           TX errors 0  dropped 0  overruns 0  carrier 0  collisions 0

   oaitun_ue1: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
           inet 12.1.1.2  netmask 255.255.255.0  destination 12.1.1.2
           unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
           RX packets 0  bytes 0 (0.0 B)
           RX errors 0  dropped 0  overruns 0  frame 0
           TX packets 0  bytes 0 (0.0 B)
           TX errors 0  dropped 0  overruns 0  carrier 0  collisions 0
   ```
7. The final setup:

   | Node | Container | Docker IP | Tunnel IP | Notes |
   |------|-----------|-----------|-----------|-------|
   | UE | `rfsim5g-oai-nr-ue` | 192.168.71.181 | 12.1.1.2 | Frequency: 3619200000, connected to DU0 |
   | DU | `rfsim5g-oai-du-pci0` | — | — | rfsimulator serveraddr: 192.168.71.171 |
   | CU | `rfsim5g-oai-cu` | — | — | rfsimulator serveraddr: 192.168.71.150 |
   | ext-dn | `rfsim5g-oai-ext-dn` | — | — | rfsimulator serveraddr: 192.168.72.135 |

## Step 2: Start capturing before the UE connects

In a separate terminal:

1. Enter the CU container:
   ```
   docker exec -it rfsim5g-oai-cu /bin/bash
   ```
2. Check whether `tcpdump` is installed:
   ```
   which tcpdump
   ```
   If it isn't, install it:
   ```
   apt-get update && apt-get install -y tcpdump
   ```
3. Copy `tcpdump` to `/opt/container-packet-capture` (to avoid conflicts with the host's `tcpdump`), then start capturing packets to a PCAP file:
   ```
   cp "$(command -v tcpdump)" /opt/container-packet-capture
   /opt/container-packet-capture -i eth0 -nn -s 0 -w /tmp/traffic.pcap
   ```
   Or, to filter on the relevant ports only:
   ```
   /opt/container-packet-capture -i eth0 -nn -s 0 -w /tmp/traffic.pcap 'udp port 2152 or sctp port 38472'
   ```

## Step 3: Start user-plane traffic between the UE and ext-dn

1. Start the server inside `ext-dn`:
   ```
   docker exec -it rfsim5g-oai-ext-dn /bin/bash
   iperf3 -s -B 192.168.72.135
   ```
2. Start the client inside the UE and send traffic:
   ```
   iperf3 -c 192.168.72.135 -B 12.1.1.3 -t 20
   ```

## Step 4: Copy the pcap from the container to the host and inspect it

1. In the CU container (from Step 2, in the separate terminal), stop the capture with `Ctrl+C`.
2. On the host, copy the pcap file out of the container:
   ```
   docker cp rfsim5g-oai-cu:/tmp/traffic.pcap .
   ```
3. Inspect the capture:
   ```
   wireshark traffic.pcap
   ```
