#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <net/if.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define MAX_EXTENSION_HEADERS 4

/* Mirrors the kernel-side struct session_ctx exactly (same field order and
 * types), since this is the raw layout written into the BPF hash map. Used
 * for BOTH session_map (downlink) and ul_session_map (uplink, info-only). */
struct session_ctx {
    __u32 peer_teid;
    __u32 dst_ip;
    __u32 src_ip;
    __u16 dst_port;
    __u16 pad0;
    __u32 egress_ifindex;
    __u8 dst_mac[ETH_ALEN];
    __u8 src_mac[ETH_ALEN];
    __u8 qfi;
    __u8 pad1[3];
    __u32 next_dl_pdcp_sn; /* mirrors kernel-side struct exactly; zero-initialized
                            * via memset() before population, incremented only by
                            * the kernel program */
};

/* Mirrors the kernel-side struct gtp_event exactly (same field order and
 * types) -- this is the raw layout read out of the ring buffer. */
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
    __u8 offload_attempted;
    __u8 offload_applied;
    __u32 offload_new_teid;
    __u32 offload_new_dst_ip;
    __u16 offload_new_dst_port;
    __u16 pad2;
    __s32 debug_old_removed_bytes;
    __s32 debug_move_len;
    __s32 debug_delta;
    __u32 debug_reached_rewrite;
    __u8 debug_flags_right_after_write;
    __u8 debug_flags_right_before_redirect;
    __u8 pad3[2];
    __u8 is_f1u;
    __u8 f1u_pdcp_sn_present;
    __u32 f1u_pdcp_sn;
    __u8 ul_map_lookup_attempted;
    __u8 ul_map_lookup_hit;
    __u8 pad4[2];
    __u64 gtpu_count;
    __u64 udp_non_gtpu_count;
};

/* --- Static config: only genuine topology facts remain hardcoded (IP
 * addresses of known peers, capture/egress interface names). MAC
 * addresses are now resolved dynamically at startup -- see
 * resolve_mac_addresses() -- instead of being hardcoded. TEID/IP tunnel
 * pairing is learned dynamically via the F1AP watcher below. */
#define GTPU_STANDARD_PORT      2152        /* N3 (UPF<->CU) port in this setup */
#define F1U_PORT                2153        /* F1-U (DU<->CU) port observed in this setup --
                                              * NOT signaled by F1AP; must match your environment */
#define OFFLOAD_EGRESS_IFACE    "eth0"              /* egress interface toward the DU */
#define DU_IP                   "192.168.71.171"
#define F1AP_CAPTURE_IFACE      "eth0"               /* interface F1AP/SCTP is visible on */

static volatile sig_atomic_t stop;

/* --- Globals shared between the main (ring-buffer) thread and the
 * background F1AP-watcher thread. Guarded by f1u_lock. --- */
static pthread_mutex_t f1u_lock = PTHREAD_MUTEX_INITIALIZER;
static int f1u_dl_known;         /* 1 once we've learned a DL F1-U tunnel endpoint */
static __u32 f1u_dl_teid;        /* host byte order */
static __u32 f1u_dl_ip;          /* network byte order (raw, from inet_pton) */

/* 1 once we've learned the CU's own UL F1-U tunnel endpoint, i.e. the TEID
 * the CU advertised to the DU (via F1AP UEContextSetupRequest) for the DU
 * to use when sending uplink F1-U traffic to this CU. This is the TEID we
 * expect to see on inbound F1-U packets from the DU. */
static int f1u_ul_known;
static __u32 f1u_ul_teid;        /* host byte order */

/* Resolved once at startup, read-only afterwards. */
static int g_session_map_fd = -1;
static int g_ul_session_map_fd = -1;
static __u32 g_egress_ifindex;
static __u8 g_du_mac[ETH_ALEN];   /* DU's MAC, via ARP lookup on DU_IP -- used as dst_mac */
static __u8 g_own_mac[ETH_ALEN];  /* CU's own eth0 MAC, via ioctl -- used as src_mac */
static __u32 g_own_ip;            /* CU's own eth0 IPv4 address, network byte order --
                                    * via ioctl -- used as the rewritten outer source IP */
static pthread_mutex_t g_du_mac_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_du_mac_valid; /* 0 until a real (non-stale) DU MAC has been confirmed */

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

static int parse_mac(const char *str, __u8 mac[ETH_ALEN])
{
    unsigned int b[ETH_ALEN];
    int i;

    if (sscanf(str, "%x:%x:%x:%x:%x:%x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != ETH_ALEN)
        return -1;
    for (i = 0; i < ETH_ALEN; i++)
        mac[i] = (__u8)b[i];
    return 0;
}

/* CU's own interface MAC -- SIOCGIFHWADDR ioctl, not ARP (ARP has no
 * entry for the host's own address). */
static int get_own_iface_mac(const char *iface, __u8 mac[ETH_ALEN])
{
    struct ifreq ifr;
    int fd, ret;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ret = ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    if (ret < 0)
        return -1;

    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    return 0;
}

/* CU's own interface IPv4 address -- SIOCGIFADDR ioctl. This becomes the
 * rewritten outer source IP for offloaded F1-U packets (see session_ctx's
 * src_ip field): an offloaded packet arrives here as N3 traffic (source =
 * the UPF's IP), and if that source IP is left as-is, the DU's F1-U socket
 * -- typically connected to the CU's known address -- will silently drop
 * every rewritten packet on arrival even though it looks fine on the wire.
 * This same address is also how we recognize the CU's own UL F1-U tunnel
 * endpoint in the F1AP watcher below. */
static int get_own_iface_ip(const char *iface, __u32 *ip)
{
    struct ifreq ifr;
    struct sockaddr_in *addr;
    int fd, ret;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ret = ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    if (ret < 0)
        return -1;

    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    *ip = addr->sin_addr.s_addr;
    return 0;
}

/*
 * Sends a single empty UDP datagram toward `ip_str`. This isn't meant to
 * be received by anything -- it just gives the kernel a reason to issue
 * an ARP request for that IP if it hasn't already resolved it, so the
 * subsequent /proc/net/arp read below has an entry to find.
 */
static void force_arp_resolve(const char *ip_str)
{
    struct sockaddr_in addr;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9); /* discard port; no reply expected or needed */
    inet_pton(AF_INET, ip_str, &addr.sin_addr);
    sendto(fd, "", 0, 0, (struct sockaddr *)&addr, sizeof(addr));
    close(fd);
}

/*
 * Deletes any existing neighbor-table entry for `ip_str` so the next
 * force_arp_resolve() actually triggers a fresh ARP exchange instead of
 * silently reusing a stale (possibly wrong) cached MAC -- which is
 * exactly what happens when a Docker container is restarted and reuses
 * the same static IP with a new MAC. Failure is expected/harmless when
 * there was no entry to delete.
 */
static void flush_arp_entry(const char *ip_str)
{
    char cmd[256];

    snprintf(cmd, sizeof(cmd), "ip neigh del %s dev %s >/dev/null 2>&1",
             ip_str, OFFLOAD_EGRESS_IFACE);
    if (system(cmd) == -1) {
        /* Non-fatal: expected when there's nothing to delete, or the
         * shell itself couldn't be spawned. Either way, the caller's
         * subsequent force_arp_resolve()/lookup will simply reflect
         * whatever the ARP table already has. */
    }
}

/* Reads /proc/net/arp looking for `ip_str`, filling in its resolved MAC.
 * Returns 0 on success, -1 if no (complete) entry is found. */
static int lookup_mac_by_ip(const char *ip_str, __u8 mac[ETH_ALEN])
{
    FILE *fp;
    char line[256];
    int found = -1;

    fp = fopen("/proc/net/arp", "r");
    if (!fp)
        return -1;

    if (!fgets(line, sizeof(line), fp)) { /* skip header line */
        fclose(fp);
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        char ip[64], hwtype[16], flags[16], hwaddr[32], mask[16], dev[32];

        if (sscanf(line, "%63s %15s %15s %31s %15s %31s",
                   ip, hwtype, flags, hwaddr, mask, dev) == 6 &&
            strcmp(ip, ip_str) == 0 &&
            strcmp(hwaddr, "00:00:00:00:00:00") != 0) {
            if (parse_mac(hwaddr, mac) == 0)
                found = 0;
            break;
        }
    }

    fclose(fp);
    return found;
}

/* One-time setup: resolve our own MAC (fatal if this fails -- something
 * is very wrong with the interface), and attempt a first DU MAC probe
 * (non-fatal; the DU may simply not be up yet). The periodic refresh
 * thread below takes over from here. */
static int init_own_mac(void)
{
    char own_ip_str[INET_ADDRSTRLEN];

    if (get_own_iface_mac(OFFLOAD_EGRESS_IFACE, g_own_mac) != 0) {
        fprintf(stderr, "Failed to read own MAC on %s: %s\n",
                OFFLOAD_EGRESS_IFACE, strerror(errno));
        return -1;
    }
    printf("Own MAC on %s: %02x:%02x:%02x:%02x:%02x:%02x\n",
           OFFLOAD_EGRESS_IFACE,
           g_own_mac[0], g_own_mac[1], g_own_mac[2], g_own_mac[3], g_own_mac[4], g_own_mac[5]);

    if (get_own_iface_ip(OFFLOAD_EGRESS_IFACE, &g_own_ip) != 0) {
        fprintf(stderr, "Failed to read own IP on %s: %s\n",
                OFFLOAD_EGRESS_IFACE, strerror(errno));
        return -1;
    }
    inet_ntop(AF_INET, &g_own_ip, own_ip_str, sizeof(own_ip_str));
    printf("Own IP on %s: %s\n", OFFLOAD_EGRESS_IFACE, own_ip_str);
    return 0;
}

#define DU_MAC_REFRESH_INTERVAL_SEC 3

/*
 * Background thread: periodically flushes any cached ARP entry for the
 * DU and re-probes it, so that (a) the DU coming up after this program
 * starts is picked up automatically, and (b) a DU container restarting
 * with a new MAC on the same IP is detected rather than silently reusing
 * a stale cached entry. Only logs and updates g_du_mac when the resolved
 * value actually changes.
 */
static void *du_mac_refresh_thread(void *arg)
{
    __u8 candidate[ETH_ALEN];
    __u8 last_logged[ETH_ALEN];
    int have_last_logged = 0;

    (void)arg;

    while (!stop) {
        flush_arp_entry(DU_IP);
        force_arp_resolve(DU_IP);
        usleep(300000); /* give the ARP exchange a moment to complete */

        if (lookup_mac_by_ip(DU_IP, candidate) == 0) {
            int changed = !have_last_logged ||
                          memcmp(candidate, last_logged, ETH_ALEN) != 0;

            pthread_mutex_lock(&g_du_mac_lock);
            memcpy(g_du_mac, candidate, ETH_ALEN);
            g_du_mac_valid = 1;
            pthread_mutex_unlock(&g_du_mac_lock);

            if (changed) {
                printf("DU MAC (%s) resolved/updated: %02x:%02x:%02x:%02x:%02x:%02x\n",
                       DU_IP, candidate[0], candidate[1], candidate[2],
                       candidate[3], candidate[4], candidate[5]);
                memcpy(last_logged, candidate, ETH_ALEN);
                have_last_logged = 1;
            }
        }
        /* No entry found: DU is presumably still down. Keep whatever was
         * last known valid (if any) rather than flapping offload on/off
         * on a momentary ARP miss; just try again next cycle. */

        sleep(DU_MAC_REFRESH_INTERVAL_SEC);
    }
    return NULL;
}

/*
 * One-time (per TEID) population of ul_session_map, so the kernel program
 * can report HIT/MISS for inbound uplink F1-U packets and we can visually
 * confirm the learned UL TEID matches real DU traffic -- before any
 * uplink offload/rewrite logic exists.
 *
 * Every field except the map key itself is a placeholder for now: we
 * don't yet know the UPF's N3 address or the TEID the UPF expects for
 * this bearer's uplink (that requires correlating PFCP/NGAP signaling,
 * which this program does not capture), so peer_teid/dst_ip/dst_port/
 * egress_ifindex/dst_mac/src_mac all stay zero. Only the *presence* of
 * this entry, and the kernel program's ability to find it by TEID,
 * matters for this step.
 */
static void maybe_populate_ul_session_map(__u32 ul_teid)
{
    struct session_ctx placeholder;
    struct session_ctx existing;

    if (g_ul_session_map_fd < 0)
        return;

    /* Already registered -- don't touch it again (same lookup-before-
     * insert discipline as the downlink side, even though nothing
     * currently increments a counter inside this placeholder). */
    if (bpf_map_lookup_elem(g_ul_session_map_fd, &ul_teid, &existing) == 0)
        return;

    memset(&placeholder, 0, sizeof(placeholder));

    if (bpf_map_update_elem(g_ul_session_map_fd, &ul_teid, &placeholder, BPF_NOEXIST) == 0)
        printf("  [auto-learned] ul_session_map: UL F1-U TEID 0x%08x registered "
               "(info-only, no offload yet)\n", ul_teid);
    else if (errno != EEXIST)
        fprintf(stderr, "  [auto-learned] ul_session_map update failed: %s\n",
                strerror(errno));
    /* EEXIST just means another thread/call raced us and inserted it
     * first -- benign, nothing to do. */
}

/*
 * Confirmed via `tshark -T json` on a real UEContextSetupResponse:
 *   f1ap.gTP_TEID: "77:51:2b:d5"                      (colon-separated hex octets)
 *   f1ap.transportLayerAddressIPv4: "192.168.71.171"  (plain dotted-decimal)
 * We extract these directly by field name via `tshark -T fields`, which
 * is far more reliable than scanning JSON/ek text for substrings.
 */
static __u32 parse_colon_hex_teid(const char *s)
{
    __u32 val = 0;

    for (; *s; s++) {
        int nibble;

        if (*s == ':')
            continue;
        if (*s >= '0' && *s <= '9')
            nibble = *s - '0';
        else if (*s >= 'a' && *s <= 'f')
            nibble = *s - 'a' + 10;
        else if (*s >= 'A' && *s <= 'F')
            nibble = *s - 'A' + 10;
        else
            break; /* stop at whitespace/newline/anything unexpected */

        val = (val << 4) | (__u32)nibble;
    }
    return val;
}

/*
 * Background thread: runs tshark filtered specifically to F1AP messages
 * that carry a GTP tunnel endpoint (f1ap.procedureCode==5 is
 * id-UEContextSetup; requiring f1ap.gTP_TEID to be present selects both
 * UEContextSetupRequest, which carries the CU's own UL tunnel info, and
 * UEContextSetupResponse, which carries the DU's DL tunnel info).
 * Extracts the TEID and IP directly by field name -- no text-scraping --
 * then routes each one by which address it belongs to:
 *   - matches DU_IP            -> DL F1-U tunnel endpoint (existing path)
 *   - matches our own eth0 IP  -> UL F1-U tunnel endpoint (new: this is
 *                                 the TEID the DU will use when sending us
 *                                 uplink traffic)
 *   - matches neither          -> unexpected topology; logged, ignored
 *
 * Simplification: tracks only the single most recently announced DL/UL
 * F1-U tunnel endpoint each (fine for a one-UE/one-bearer testbed).
 * Handling multiple concurrent bearers/DRBs needs correlating F1AP
 * messages to specific UEs/PDU sessions, which this does not attempt yet.
 */
static void *f1ap_watcher_thread(void *arg)
{
    char cmd[512];
    char line[512];
    char own_ip_str[INET_ADDRSTRLEN];
    FILE *fp;
    int seen_first_packet = 0;

    (void)arg;

    inet_ntop(AF_INET, &g_own_ip, own_ip_str, sizeof(own_ip_str));

    snprintf(cmd, sizeof(cmd),
             "tshark -i %s -f \"sctp\" "
             "-Y \"f1ap.procedureCode==5 && f1ap.gTP_TEID\" "
             "-T fields -e f1ap.gTP_TEID -e f1ap.transportLayerAddressIPv4 "
             "-E separator=/t -E occurrence=f -l 2>/dev/null",
             F1AP_CAPTURE_IFACE);

    fp = popen(cmd, "r");
    if (!fp) {
        fprintf(stderr, "F1AP watcher: failed to start tshark: %s\n", strerror(errno));
        return NULL;
    }

    printf("F1AP watcher started (%s)\n", cmd);
    printf("F1AP watcher: waiting for first matching packet to confirm capture is live...\n");

    while (!stop && fgets(line, sizeof(line), fp)) {
        char *tab, *newline;
        char teid_field[64];
        char ip_field[64];
        __u32 teid_val;
        struct in_addr addr;

        if (!seen_first_packet) {
            printf("F1AP watcher: capture is live (first matching packet seen) -- "
                   "safe to bring up DU/UE from here on\n");
            seen_first_packet = 1;
        }

        newline = strchr(line, '\n');
        if (newline)
            *newline = '\0';

        tab = strchr(line, '\t');
        if (!tab || tab == line) {
            /* No TEID field on this line (shouldn't happen given the
             * display filter, but be defensive) or line is otherwise
             * malformed -- skip it. */
            continue;
        }

        {
            size_t teid_len = (size_t)(tab - line);
            if (teid_len >= sizeof(teid_field))
                teid_len = sizeof(teid_field) - 1;
            memcpy(teid_field, line, teid_len);
            teid_field[teid_len] = '\0';
        }
        snprintf(ip_field, sizeof(ip_field), "%s", tab + 1);

        if (ip_field[0] == '\0') {
            fprintf(stderr,
                    "F1AP watcher: TEID field '%s' present but no IP on the same "
                    "line -- ignoring\n", teid_field);
            continue;
        }

        teid_val = parse_colon_hex_teid(teid_field);
        if (teid_val == 0) {
            fprintf(stderr, "F1AP watcher: parsed TEID as 0 from '%s' -- ignoring\n", teid_field);
            continue;
        }

        if (inet_pton(AF_INET, ip_field, &addr) != 1) {
            fprintf(stderr, "F1AP watcher: could not parse IP '%s' -- ignoring\n", ip_field);
            continue;
        }

        if (strcmp(ip_field, DU_IP) == 0) {
            /* DL F1-U tunnel endpoint: the DU's own address, from
             * UEContextSetupResponse. Existing behavior, unchanged. */
            pthread_mutex_lock(&f1u_lock);
            f1u_dl_teid = teid_val;
            f1u_dl_ip = addr.s_addr;
            f1u_dl_known = 1;
            pthread_mutex_unlock(&f1u_lock);

            printf("F1AP watcher: learned DL F1-U TEID 0x%08x @ %s\n", teid_val, ip_field);
        } else if (strcmp(ip_field, own_ip_str) == 0) {
            /* UL F1-U tunnel endpoint: this CU's own address, from
             * UEContextSetupRequest -- the TEID the CU advertised for the
             * DU to send uplink F1-U traffic to. Register it in
             * ul_session_map (info-only; see maybe_populate_ul_session_map). */
            pthread_mutex_lock(&f1u_lock);
            f1u_ul_teid = teid_val;
            f1u_ul_known = 1;
            pthread_mutex_unlock(&f1u_lock);

            printf("F1AP watcher: learned UL F1-U TEID 0x%08x @ %s (this CU's own address)\n",
                   teid_val, ip_field);
            maybe_populate_ul_session_map(teid_val);
        } else {
            /* Neither the DU's address nor our own -- unexpected given
             * this testbed's topology. Log and move on rather than
             * guessing which direction this belongs to. */
            printf("F1AP watcher: ignoring TEID 0x%08x @ %s (neither the DU's address "
                   "(%s) nor our own (%s) -- unexpected topology)\n",
                   teid_val, ip_field, DU_IP, own_ip_str);
        }
    }

    pclose(fp);
    return NULL;
}

/*
 * Called from the main thread for every N3-looking downlink GTP-U event
 * (is_gtpu && inner_ip_present && !is_f1u -- i.e. genuinely arrived on
 * the N3 port, not the F1-U one). If we've learned a DL F1-U tunnel
 * endpoint and this N3 TEID isn't mapped yet, populate session_map so the
 * BPF program starts fast-pathing this flow.
 *
 * IMPORTANT: if this TEID is ALREADY mapped, we must not touch it again.
 * The kernel program owns and increments session_ctx.next_dl_pdcp_sn for
 * every offloaded packet on this flow; if we re-populate the entry from
 * scratch (memset-zeroed) on every packet, we clobber that counter back
 * toward 0 continuously, so the DU never sees a monotonically increasing
 * PDCP DL sequence number and silently drops/reorders-out everything
 * past the first packet or two -- exactly the "connection accepted but
 * zero throughput" symptom this fixes.
 */
static void maybe_learn_and_populate(const struct gtp_event *event)
{
    struct session_ctx sess;
    struct session_ctx existing;
    __u32 key;
    __u8 du_mac[ETH_ALEN];

    key = event->teid;

    /* Already mapped -- leave it alone so next_dl_pdcp_sn (owned by the
     * kernel program from here on) is never reset. */
    if (bpf_map_lookup_elem(g_session_map_fd, &key, &existing) == 0)
        return;

    pthread_mutex_lock(&f1u_lock);
    if (!f1u_dl_known) {
        pthread_mutex_unlock(&f1u_lock);
        return;
    }

    memset(&sess, 0, sizeof(sess));
    sess.peer_teid = f1u_dl_teid;
    sess.dst_ip = f1u_dl_ip;
    sess.src_ip = g_own_ip;
    pthread_mutex_unlock(&f1u_lock);

    pthread_mutex_lock(&g_du_mac_lock);
    if (!g_du_mac_valid) {
        pthread_mutex_unlock(&g_du_mac_lock);
        return; /* DU not resolved yet (e.g. not up) -- try again next packet */
    }
    memcpy(du_mac, g_du_mac, ETH_ALEN);
    pthread_mutex_unlock(&g_du_mac_lock);

    sess.dst_port = htons(F1U_PORT);
    sess.egress_ifindex = g_egress_ifindex;
    memcpy(sess.dst_mac, du_mac, ETH_ALEN);
    memcpy(sess.src_mac, g_own_mac, ETH_ALEN);
    /* next_dl_pdcp_sn stays 0 here -- this is the one-time initial
     * population; the kernel program takes over incrementing it from
     * this point on. */

    if (bpf_map_update_elem(g_session_map_fd, &key, &sess, BPF_NOEXIST) == 0) {
        char dst[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &sess.dst_ip, dst, sizeof(dst));
        printf("  [auto-learned] session_map: N3 TEID 0x%08x -> F1-U TEID 0x%08x @ %s:%u\n",
               event->teid, sess.peer_teid, dst, F1U_PORT);
    } else if (errno != EEXIST) {
        fprintf(stderr, "  [auto-learned] session_map update failed: %s\n", strerror(errno));
    }
    /* EEXIST here just means another thread/event raced us and inserted
     * it first -- benign, nothing to do. */
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
    printf("  Framing:          %s\n",
           event->is_f1u ? "F1-U (PDCP+SDAP, no GTP extension)"
                         : "N3 (GTP-U extension for QFI)");

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
    if (event->f1u_pdcp_sn_present)
        printf("  PDCP SN (F1-U):   %u\n", event->f1u_pdcp_sn);
    if (event->qfi_present)
        printf("  QFI:              %u\n", event->qfi);

    if (event->offload_attempted) {
        if (event->offload_applied) {
            char new_dst[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, &event->offload_new_dst_ip, new_dst, sizeof(new_dst));
            printf("  Fast-path offload: HIT -> new TEID %u (0x%08x), redirected to %s:%u\n",
                   event->offload_new_teid, event->offload_new_teid,
                   new_dst, event->offload_new_dst_port);
        } else {
            printf("  Fast-path offload: miss (no session_map entry for this TEID, or unsupported IP options)\n");
        }
        printf("  [debug] old_removed_bytes=%d move_len=%d delta=%d reached_rewrite=%u\n",
               event->debug_old_removed_bytes, event->debug_move_len,
               event->debug_delta, event->debug_reached_rewrite);
        if (event->offload_applied)
            printf("  [debug] gtp->flags read back: right_after_write=0x%02x right_before_redirect=0x%02x\n",
                   event->debug_flags_right_after_write,
                   event->debug_flags_right_before_redirect);
    }

    if (event->ul_map_lookup_attempted)
        printf("  UL session map:   %s (TEID 0x%08x) -- info only, no offload applied yet\n",
               event->ul_map_lookup_hit ? "HIT" : "MISS", event->teid);

    /* DL auto-learn only applies to genuine N3-side packets. Guard with
     * !is_f1u explicitly: now that F1-U packets can also come back with
     * inner_ip_present == 1 (PDCP+SDAP parsing fixed above), without this
     * guard an uplink packet would incorrectly attempt to populate the
     * DOWNLINK session_map keyed by an uplink TEID. */
    if (event->is_gtpu && event->inner_ip_present && !event->is_f1u)
        maybe_learn_and_populate(event);

    putchar('\n');
    return 0;
}

int main(int argc, char **argv)
{
    const char *interface_name = argc > 1 ? argv[1] : "eth0";
    const char *object_file = "xdp_gtp_inner_parser.bpf.o";
    struct bpf_object *object = NULL;
    struct bpf_program *program;
    struct bpf_map *events_map, *session_map, *ul_session_map;
    struct ring_buffer *ring = NULL;
    pthread_t f1ap_thread;
    pthread_t du_mac_thread;
    int interface_index, program_fd, error = 1;
    int attached = 0;
    __u32 attached_mode = 0;

    interface_index = if_nametoindex(interface_name);
    if (!interface_index) {
        fprintf(stderr, "Cannot find interface %s: %s\n",
                interface_name, strerror(errno));
        return 1;
    }

    g_egress_ifindex = if_nametoindex(OFFLOAD_EGRESS_IFACE);
    if (!g_egress_ifindex) {
        fprintf(stderr, "Cannot find egress interface %s: %s\n",
                OFFLOAD_EGRESS_IFACE, strerror(errno));
        return 1;
    }

    if (init_own_mac() != 0) {
        fprintf(stderr, "Failed to determine own MAC address\n");
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

    session_map = bpf_object__find_map_by_name(object, "session_map");
    if (!session_map) {
        fprintf(stderr, "Cannot find session_map\n");
        error = 1;
        goto cleanup;
    }
    g_session_map_fd = bpf_map__fd(session_map);

    ul_session_map = bpf_object__find_map_by_name(object, "ul_session_map");
    if (!ul_session_map) {
        fprintf(stderr, "Cannot find ul_session_map\n");
        error = 1;
        goto cleanup;
    }
    g_ul_session_map_fd = bpf_map__fd(ul_session_map);

    /* Force a clean slate: if a previous run's XDP program is still
     * attached (e.g. from an unclean exit), XDP_FLAGS_UPDATE_IF_NOEXIST
     * below would otherwise silently keep running that OLD program
     * instead of loading this newly built one -- explicitly detach first
     * so a rebuild always actually takes effect. Try both modes since
     * either could have been attached previously. */
    bpf_xdp_detach(interface_index, XDP_FLAGS_DRV_MODE, NULL);
    bpf_xdp_detach(interface_index, XDP_FLAGS_SKB_MODE, NULL);

    /*
     * Try native (driver) mode first. Modern veth drivers support native
     * XDP specifically for container-to-container redirect scenarios
     * like this one, and it's a more mature code path for
     * bpf_xdp_adjust_tail()+bpf_redirect() than generic/SKB mode. Fall
     * back to generic mode if the driver doesn't support it.
     *
     * TEMPORARY DIAGNOSTIC: set FORCE_SKB_MODE=1 in the environment to
     * skip straight to generic/SKB mode, to check whether a specific
     * observed bug (the on-wire gtp->flags byte reverting to its
     * pre-rewrite value despite the BPF program provably writing and
     * retaining the correct value right up to bpf_redirect()) is
     * specific to native-mode XDP redirect on this veth/kernel. Remove
     * once that's resolved. */
    if (getenv("FORCE_SKB_MODE")) {
        error = 1; /* skip the native attempt below entirely */
    } else {
        error = bpf_xdp_attach(interface_index, program_fd,
                               XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST,
                               NULL);
    }
    if (error) {
        if (getenv("FORCE_SKB_MODE"))
            fprintf(stderr, "FORCE_SKB_MODE set; skipping native attach.\n");
        else
            fprintf(stderr, "Native (driver-mode) XDP attach failed (%s); "
                    "falling back to generic/SKB mode.\n", strerror(-error));
        error = bpf_xdp_attach(interface_index, program_fd,
                               XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST,
                               NULL);
        if (!error) {
            printf("Attached in generic (SKB) mode.\n");
            attached_mode = XDP_FLAGS_SKB_MODE;
        }
    } else {
        printf("Attached in native (driver) mode.\n");
        attached_mode = XDP_FLAGS_DRV_MODE;
    }
    if (error) {
        fprintf(stderr, "Failed to attach XDP to %s: %s\n",
                interface_name, strerror(-error));
        goto cleanup;
    }
    attached = 1;

    events_map = bpf_object__find_map_by_name(object, "events");
    if (!events_map) {
        fprintf(stderr, "Cannot find events ring buffer\n");
        error = 1;
        goto cleanup;
    }

    ring = ring_buffer__new(bpf_map__fd(events_map), print_event, NULL, NULL);
    if (!ring) {
        fprintf(stderr, "Failed to create ring-buffer reader\n");
        error = 1;
        goto cleanup;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    if (pthread_create(&du_mac_thread, NULL, du_mac_refresh_thread, NULL) != 0) {
        fprintf(stderr, "Failed to start DU MAC refresh thread: %s\n", strerror(errno));
        error = 1;
        goto cleanup;
    }

    if (pthread_create(&f1ap_thread, NULL, f1ap_watcher_thread, NULL) != 0) {
        fprintf(stderr, "Failed to start F1AP watcher thread: %s\n", strerror(errno));
        error = 1;
        goto cleanup;
    }

    /* TEMPORARY DIAGNOSTIC: SEED_SESSION=<n3_teid_hex>:<f1u_teid_hex> seeds
     * session_map directly with an already-known real bearer mapping,
     * bypassing the F1AP watcher -- useful when the bearer was already
     * established before this process started (no fresh F1AP
     * UEContextSetupResponse to observe). Remove once no longer needed. */
    {
        const char *seed = getenv("SEED_SESSION");

        if (seed) {
            unsigned int n3_teid = 0, f1u_teid = 0;

            if (sscanf(seed, "%x:%x", &n3_teid, &f1u_teid) == 2) {
                struct session_ctx sess;
                int waited;

                for (waited = 0; waited < 50 && !g_du_mac_valid; waited++)
                    usleep(100000);

                if (g_du_mac_valid) {
                    memset(&sess, 0, sizeof(sess));
                    sess.peer_teid = f1u_teid;
                    inet_pton(AF_INET, DU_IP, &sess.dst_ip);
                    sess.src_ip = g_own_ip;
                    sess.dst_port = htons(F1U_PORT);
                    sess.egress_ifindex = g_egress_ifindex;
                    pthread_mutex_lock(&g_du_mac_lock);
                    memcpy(sess.dst_mac, g_du_mac, ETH_ALEN);
                    pthread_mutex_unlock(&g_du_mac_lock);
                    memcpy(sess.src_mac, g_own_mac, ETH_ALEN);
                    sess.qfi = 1;
                    if (bpf_map_update_elem(g_session_map_fd, &n3_teid, &sess, BPF_ANY) == 0)
                        printf("SEED_SESSION: seeded N3 TEID 0x%08x -> F1-U TEID 0x%08x\n",
                               n3_teid, f1u_teid);
                    else
                        fprintf(stderr, "SEED_SESSION: bpf_map_update_elem failed: %s\n",
                                strerror(errno));
                } else {
                    fprintf(stderr, "SEED_SESSION: DU MAC never resolved, skipping seed\n");
                }
            } else {
                fprintf(stderr, "SEED_SESSION: expected <n3_teid_hex>:<f1u_teid_hex>\n");
            }
        }
    }

    printf("Parsing ingress UDP and GTP-U packets on %s; press Ctrl+C to stop.\n\n",
           interface_name);

    while (!stop) {
        error = ring_buffer__poll(ring, 250);
        if (error == -EINTR)
            continue;
        if (error < 0) {
            fprintf(stderr, "Ring-buffer polling failed: %s\n", strerror(-error));
            break;
        }
    }
    error = 0;

    pthread_join(f1ap_thread, NULL);
    pthread_join(du_mac_thread, NULL);

cleanup:
    ring_buffer__free(ring);
    if (attached)
        bpf_xdp_detach(interface_index, attached_mode, NULL);
    bpf_object__close(object);
    return error ? 1 : 0;
}
