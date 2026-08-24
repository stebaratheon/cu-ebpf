# Troubleshooting: OAI UE `oaitun_ue1` Interface Is Not Created

## Issue

The OAI NR UE container starts successfully, but the expected UE tunnel interface is not created.

Running the following command inside the UE container:

```bash
ip addr
```

or:

```bash
ifconfig
```

shows only:

```text
eth0
lo
```

The expected interface is missing:

```text
oaitun_ue1
```

The UE log repeatedly reports:

```text
[MAC] W [UE 0] RAR reception failed
```

---

## Why `oaitun_ue1` Is Missing

OAI does not create `oaitun_ue1` immediately when the UE container starts.

The interface is created only after the UE completes the following procedures:

1. Synchronization with the DU
2. PRACH transmission
3. Random access
4. RRC connection establishment
5. NAS registration
6. PDU session establishment
7. Assignment of the UE IP address

The complete sequence is approximately:

```text
UE synchronization
        ↓
PRACH Msg1
        ↓
RAR Msg2
        ↓
Msg3 and Msg4
        ↓
RRC connection
        ↓
NAS registration
        ↓
PDU session establishment
        ↓
oaitun_ue1 is created
```

Therefore, a missing `oaitun_ue1` usually means that one of the earlier procedures failed.

---

## Important Note About the AMF Status

The AMF showed that the gNB was connected:

```text
Status: Connected
gNB Name: cu-rfsim
```

However, this only confirms the connection between the CU and AMF over NGAP.

It does **not** confirm that:

- The UE completed random access
- The UE established an RRC connection
- The UE registered with the core network
- A PDU session was established

Therefore, the gNB can appear as connected in the AMF while `oaitun_ue1` is still missing.

---

## UE-Side Error

The UE log showed repeated PRACH transmissions followed by RAR failures:

```text
[NR_MAC] I PRACH scheduler: Selected RO Frame 925, Slot 19
[PHY] I PRACH [UE 0] ... preambleIndex = 2
[MAC] W [UE 0] RAR reception failed
```

This means:

1. The UE selected a PRACH occasion.
2. The UE transmitted the PRACH preamble, also called Msg1.
3. The UE waited for the Random Access Response, also called Msg2.
4. The UE did not receive Msg2 within the allowed time.

The problem therefore occurred during the random-access procedure, before RRC connection establishment and UE registration.

---

## Debugging the Problem

### 1. Check the UE log

```bash
docker logs rfsim5g-oai-nr-ue --tail 300
```

To filter the important messages:

```bash
docker logs rfsim5g-oai-nr-ue 2>&1 | \
grep -Ei "sync|PRACH|RAR|RRC|registration|PDU session|oaitun|failed|error"
```

The relevant UE error was:

```text
[MAC] W [UE 0] RAR reception failed
```

This indicates that the UE sent Msg1 but did not receive Msg2.

---

### 2. Check Whether the DU Received PRACH

Run:

```bash
docker logs rfsim5g-oai-du-pci0 2>&1 | \
grep -Ei "PRACH|preamble|RA-RNTI|TC-RNTI|random access|RACH|Msg2"
```

The DU log showed:

```text
[NR_PHY] A [RAPROC] 671.19 Initiating RA procedure with preamble 31, energy 56.4 dB
[NR_MAC] A 671.19 UE RA-RNTI 0113 TC-RNTI 7240: initiating RA procedure
[NR_MAC] W exceeded RA window: preamble at 671.19 now 672.10 (diff 11), ra_ResponseWindow 4/10 slots
[NR_MAC] E sfn: 672.10 UE RA-RNTI 0113 TC-RNTI 7240: exceeded RA window, cannot schedule Msg2
```

These messages prove that:

- The RF simulator connection was working.
- The UE successfully transmitted the PRACH preamble.
- The DU successfully detected the preamble.
- The DU created the random-access context.
- The failure happened while the DU attempted to schedule Msg2.

---

## Root Cause

The DU received the PRACH preamble at:

```text
Frame 671, Slot 19
```

The DU attempted to schedule Msg2 at:

```text
Frame 672, Slot 10
```

The elapsed time was therefore:

```text
11 slots
```

However, the configured Random Access Response window allowed only:

```text
10 slots
```

This is explicitly shown in the DU log:

```text
exceeded RA window: preamble at 671.19 now 672.10 (diff 11),
ra_ResponseWindow 4/10 slots
```

Because the DU was one slot outside the permitted response window, it refused to schedule Msg2:

```text
exceeded RA window, cannot schedule Msg2
```

The resulting failure sequence was:

```text
UE sends PRACH Msg1
        ↓
DU successfully detects Msg1
        ↓
DU attempts to schedule Msg2 after 11 slots
        ↓
Configured RAR window permits only 10 slots
        ↓
DU refuses to schedule Msg2
        ↓
UE reports "RAR reception failed"
        ↓
Random access does not complete
        ↓
No RRC connection
        ↓
No UE registration
        ↓
No PDU session
        ↓
No oaitun_ue1 interface
```

---

## Understanding `ra_ResponseWindow`

`ra_ResponseWindow` is an enumerated configuration value.

The number assigned to it is **not** the direct number of slots.

| Configuration value | Actual response window |
|---:|---:|
| `0` | 1 slot |
| `1` | 2 slots |
| `2` | 4 slots |
| `3` | 8 slots |
| `4` | 10 slots |
| `5` | 20 slots |
| `6` | 40 slots |
| `7` | 80 slots |

For example:

```text
ra_ResponseWindow = 4;
```

means:

```text
10-slot RAR response window
```

This was also confirmed by the OAI DU log:

```text
ra_ResponseWindow 4/10 slots
```

---

## Fix

The DU configuration file used in this setup was:

```text
../../conf_files/gnb-du.sa.band78.106prb.rfsim.conf
```

Search for `ra_ResponseWindow`:

```bash
grep -n "ra_ResponseWindow" \
../../conf_files/gnb-du.sa.band78.106prb.rfsim.conf
```

The original configuration was:

```text
ra_ResponseWindow = 4;
```

Change it to:

```text
ra_ResponseWindow = 5;
```

The final change is:

```diff
- ra_ResponseWindow = 4;
+ ra_ResponseWindow = 5;
```

This increases the actual Random Access Response window:

```text
10 slots → 20 slots
```

The DU can then schedule Msg2 after the observed 11-slot delay without exceeding the response window.

---

## Restart the UE and DU

In this RF simulator setup, the UE operates as the RFsim server:

```text
--rfsimulator.[0].serveraddr server
```

DU0 connects to the UE at:

```text
--rfsimulator.[0].serveraddr 192.168.71.181
```

Therefore, the appropriate startup order is:

```text
CU → NR UE → DU
```

After changing the DU configuration, restart the UE first:

```bash
docker restart rfsim5g-oai-nr-ue
```

Wait briefly:

```bash
sleep 3
```

Then restart DU0:

```bash
docker restart rfsim5g-oai-du-pci0
```

Alternatively, combine the commands:

```bash
docker restart rfsim5g-oai-nr-ue
sleep 3
docker restart rfsim5g-oai-du-pci0
```

---

## Verify the Fix

### 1. Check the DU log

```bash
docker logs -f rfsim5g-oai-du-pci0
```

The DU should now proceed beyond Msg2 scheduling.

Depending on the OAI version, successful messages may include:

```text
Msg2
Msg3
CBRA procedure succeeded
Adding new UE context
```

The following error should no longer repeat:

```text
exceeded RA window, cannot schedule Msg2
```

---

### 2. Check the UE log

```bash
docker logs rfsim5g-oai-nr-ue 2>&1 | \
grep -Ei "RAR|Msg3|RRC|Registration|PDU Session|oaitun"
```

The UE should proceed through:

```text
RAR reception
RRC connection
Registration
PDU session establishment
```

---

### 3. Check the UE Tunnel Interface

```bash
docker exec rfsim5g-oai-nr-ue ip addr show
```

The interface should now appear:

```text
oaitun_ue1
```

It should also have the IP address assigned by the 5G Core, for example:

```text
oaitun_ue1:
    inet 12.1.1.2/24
```

The exact IP address depends on the UPF and SMF configuration.

---

### 4. Test User-Plane Connectivity

For example:

```bash
docker exec -it rfsim5g-oai-nr-ue \
ping -I oaitun_ue1 -c 4 192.168.72.135
```

Here, `192.168.72.135` is the external data-network container in this deployment.

---

## Why This Was Not a TUN Permission Problem

The UE service already had the required capability:

```yaml
cap_add:
  - NET_ADMIN
  - NET_RAW
  - SYS_NICE
```

It also had access to the host TUN device:

```yaml
devices:
  - /dev/net/tun:/dev/net/tun
```

The device can be checked inside the UE container with:

```bash
docker exec rfsim5g-oai-nr-ue ls -l /dev/net/tun
```

In this case, the TUN configuration was correct.

The interface was missing because the UE never reached PDU-session establishment. OAI therefore had no UE data-plane interface to create yet.

---

## General Debugging Guide

The following table can be used when `oaitun_ue1` is missing.

| Last successful event | Likely problem area |
|---|---|
| No UE synchronization | RFsim connection, center frequency, bandwidth or numerology |
| UE sends PRACH but DU does not detect it | RFsim path or UE/DU PHY mismatch |
| DU detects PRACH but cannot schedule Msg2 | RAR window or DU scheduler timing |
| Random access succeeds but RRC fails | CU/DU F1 or RRC configuration |
| RRC succeeds but registration fails | AMF, PLMN, IMSI, authentication or subscriber database |
| Registration succeeds but PDU session fails | SMF, UPF, DNN or S-NSSAI configuration |
| PDU session succeeds but tunnel is absent | `/dev/net/tun`, `NET_ADMIN` or UE interface configuration |

---

## Configuration-Version Warning

The Compose file uses development images:

```yaml
image: oaisoftwarealliance/oai-gnb:develop
image: oaisoftwarealliance/oai-nr-ue:develop
```

The local configuration files may come from a different OAI commit than the running `develop` images.

This can cause configuration or timing assumptions to differ between:

- The OAI binary inside the container
- The local DU configuration
- The local UE configuration

Record the local OAI commit:

```bash
git rev-parse HEAD
```

Check the gNB image information:

```bash
docker image inspect oaisoftwarealliance/oai-gnb:develop \
  --format 'ID={{.Id}} Created={{.Created}}'
```

Check the UE image information:

```bash
docker image inspect oaisoftwarealliance/oai-nr-ue:develop \
  --format 'ID={{.Id}} Created={{.Created}}'
```

When possible, use container images and configuration files from compatible OAI revisions.

---

## Final Result

The working configuration change was:

```diff
- ra_ResponseWindow = 4;
+ ra_ResponseWindow = 5;
```

Before the change:

```text
Msg2 scheduling delay = 11 slots
Allowed RAR window    = 10 slots
Result                = Msg2 rejected
```

After the change:

```text
Msg2 scheduling delay = 11 slots
Allowed RAR window    = 20 slots
Result                = Msg2 scheduled successfully
```

After increasing the response window, random access completed successfully and OAI created the `oaitun_ue1` interface.