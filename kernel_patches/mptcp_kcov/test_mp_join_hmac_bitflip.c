// SPDX-License-Identifier: Apache-2.0
//
// test_mp_join_hmac_bitflip.c -- v02 C1 smoke test for the
// NFQUEUE-rewrite mutation mechanism.  Drives the same MP_CAPABLE +
// MP_JOIN flow as test_mp_join_normal.c but intercepts the client's
// MP_JOIN ACK on egress and flips one bit in the 20-byte HMAC field
// before the kernel forwards the packet to itself (loopback).  The
// server's subflow_hmac_valid then rejects the ACK with the gate
// kcov_for_bpf v06/0001 + mptcp_kcov 0002 were specifically authored
// to instrument.
//
// What this exercises (mirrors design doc Section 11.bis):
//
//   1-5: same as test_mp_join_normal.c -- pm_type=1, mptcp_pm genl
//        + event subscription, MP_CAPABLE on 127.0.0.1, 1-byte
//        fully_established primer.
//   6:   iptables -I OUTPUT -p tcp -j NFQUEUE --queue-num 0
//        (note: the rule catches ALL TCP egress, not just MPTCP --
//        callback filters by TCP-option kind + MP_JOIN subtype +
//        option length.  Simpler than crafting an iptables matcher
//        for MPTCP option kind 30 which not every iptables
//        installation supports.)
//   7:   nfq_open + bind to queue 0 + set copy mode (whole packet)
//   8:   spawn a worker thread that select()s on the netlink fd and
//        dispatches via nfq_handle_packet.
//   9:   issue MPTCP_PM_CMD_SUBFLOW_CREATE (drives MP_JOIN).
//   10:  worker callback identifies the MP_JOIN ACK (kind=30,
//        len=24, subtype=1, no SYN/FIN/RST, ACK set), flips bit 0 of
//        the first HMAC byte (option offset 4), recomputes the TCP
//        checksum, NF_ACCEPTs the rewritten payload.
//   11:  wait up to 2s for mptcpi_subflows on the server msk to
//        change.  In the success case (bad HMAC -> server rejects)
//        it stays at 0; if it goes to 1, our mutation did not reach
//        the server (maybe wrong packet, maybe iptables rule didn't
//        match, maybe checksum was wrong and kernel dropped silently
//        before delivery).
//   12:  re-snapshot MIB.  Expected delta:
//          MPJoinSynRx           +1  (client SYN reached server ok)
//          MPJoinAckRx            0  (bad ACK rejected before counted)
//          MPJoinAckHMacFailure  +1  (HMAC gate fired)
//
// Build:
//   gcc -O2 -Wall -o test_mp_join_hmac_bitflip test_mp_join_hmac_bitflip.c
//       -lnetfilter_queue -lnfnetlink -lpthread
//   (one line; broken here for readability)
//
// Run (as root, in the patched VM, from any dir):
//   ./test_mp_join_hmac_bitflip
//
// Exit codes:
//   0  pass: HMAC mutation fired AND failure counter incremented
//      AND no subflow on the server side
//   1  fail: prerequisite syscall failed (socket, netlink, iptables,
//      nfqueue setup)
//   2  fail: kernel did not accept SUBFLOW_CREATE
//   3  fail: NFQUEUE callback never saw an MP_JOIN ACK to mutate
//      (within the 2s timeout)
//   4  fail: MIB counters didn't match the expected mutation pattern
//   5  fail: subflow somehow established despite bit-flipped HMAC
//      (would indicate a real kernel bug -- HMAC validation skipped)
//
// Author: Shardul Bankar.  Co-developed-by: Claude Opus 4.7 (1M context).

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

#include <linux/genetlink.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>

#ifndef SOL_MPTCP
#define SOL_MPTCP		284
#endif
#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP		262
#endif
#ifndef MPTCP_INFO
#define MPTCP_INFO		1
#endif

#define NFQUEUE_NUM		0

/* Subset of struct mptcp_info we need.  Match include/uapi/linux/mptcp.h
 * at the kernel base (commit 232989ca65248); fields beyond mptcpi_csum_enabled
 * are irrelevant for this test. */
struct mptcp_info_short {
	uint8_t  mptcpi_subflows;
	uint8_t  mptcpi_add_addr_signal;
	uint8_t  mptcpi_add_addr_accepted;
	uint8_t  mptcpi_subflows_max;
	uint8_t  mptcpi_add_addr_signal_max;
	uint8_t  mptcpi_add_addr_accepted_max;
	uint8_t  _pad[2];
	uint32_t mptcpi_flags;
	uint32_t mptcpi_token;
	uint64_t mptcpi_write_seq;
	uint64_t mptcpi_snd_una;
	uint64_t mptcpi_rcv_nxt;
	uint8_t  mptcpi_local_addr_used;
	uint8_t  mptcpi_local_addr_max;
	uint8_t  mptcpi_csum_enabled;
} __attribute__((packed));

/* mptcp_pm genl enums + values (mirror kernel uapi at commit base). */
enum {
	MPTCP_PM_ATTR_UNSPEC_TEST,
	MPTCP_PM_ATTR_ADDR,
	MPTCP_PM_ATTR_RCV_ADD_ADDRS,
	MPTCP_PM_ATTR_SUBFLOWS,
	MPTCP_PM_ATTR_TOKEN,
	MPTCP_PM_ATTR_LOC_ID,
	MPTCP_PM_ATTR_ADDR_REMOTE,
};
enum {
	MPTCP_PM_ADDR_ATTR_UNSPEC_TEST,
	MPTCP_PM_ADDR_ATTR_FAMILY,
	MPTCP_PM_ADDR_ATTR_ID,
	MPTCP_PM_ADDR_ATTR_ADDR4,
	MPTCP_PM_ADDR_ATTR_ADDR6,
	MPTCP_PM_ADDR_ATTR_PORT,
	MPTCP_PM_ADDR_ATTR_FLAGS,
	MPTCP_PM_ADDR_ATTR_IF_IDX,
};
#define MPTCP_PM_CMD_SUBFLOW_CREATE_VAL  10
#define MPTCP_PM_VER_VAL                 1

/* ----- NFQUEUE callback shared state ------------------------------ */

/* Set by the NFQUEUE callback when it successfully intercepted and
 * mutated an MP_JOIN ACK.  Main thread polls. */
static atomic_int g_mutation_fired = 0;

/* Diagnostics counters. */
static atomic_int g_packets_seen = 0;
static atomic_int g_mp_join_acks_seen = 0;

/* Worker-thread plumbing. */
static atomic_int g_nfq_stop = 0;
static struct nfq_handle *g_nfq_h = NULL;
static struct nfq_q_handle *g_nfq_qh = NULL;

/* iptables rule cleanup: best-effort -D on exit. */
static int g_iptables_inserted = 0;

/* Walk TCP options looking for an MP_JOIN ACK option (kind=30,
 * len=24, subtype=1).  Returns pointer to the kind byte if found,
 * else NULL. */
static uint8_t *find_mp_join_ack(uint8_t *tcp_seg, int tcp_hlen)
{
	int optlen = tcp_hlen - (int)sizeof(struct tcphdr);
	uint8_t *opts = tcp_seg + sizeof(struct tcphdr);
	int i = 0;
	while (i < optlen) {
		uint8_t kind = opts[i];
		if (kind == 0)
			break;	/* end of options */
		if (kind == 1) {
			i++;	/* NOP */
			continue;
		}
		if (i + 1 >= optlen)
			break;
		uint8_t len = opts[i + 1];
		if (len < 2 || i + len > optlen)
			break;
		if (kind == 30 && len == 24) {
			uint8_t subtype = (opts[i + 2] >> 4) & 0xf;
			if (subtype == 1)
				return &opts[i];
		}
		i += len;
	}
	return NULL;
}

/* ----- NFQUEUE callback ------------------------------------------- */

static int brf_nfq_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
			struct nfq_data *nfa, void *data)
{
	(void)nfmsg;
	(void)data;

	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
	uint32_t id = ph ? ntohl(ph->packet_id) : 0;

	unsigned char *payload;
	int payload_len = nfq_get_payload(nfa, &payload);
	if (payload_len < 0)
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	atomic_fetch_add(&g_packets_seen, 1);

	if (payload_len < (int)(sizeof(struct iphdr) + sizeof(struct tcphdr)))
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	struct iphdr *ip = (struct iphdr *)payload;
	if (ip->protocol != IPPROTO_TCP)
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	int ip_hlen = ip->ihl * 4;
	if (payload_len < ip_hlen + (int)sizeof(struct tcphdr))
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	struct tcphdr *tcp = (struct tcphdr *)(payload + ip_hlen);
	int tcp_hlen = tcp->doff * 4;
	if (payload_len < ip_hlen + tcp_hlen)
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	/* MP_JOIN ACK is a pure ACK -- no SYN/FIN/RST. */
	if (!tcp->ack || tcp->syn || tcp->fin || tcp->rst)
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	uint8_t *opt = find_mp_join_ack((uint8_t *)tcp, tcp_hlen);
	if (!opt)
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	atomic_fetch_add(&g_mp_join_acks_seen, 1);

	if (atomic_load(&g_mutation_fired)) {
		/* Already mutated one -- pass subsequent MP_JOIN ACKs
		 * through unchanged so we don't loop on retransmits. */
		fprintf(stderr,
			"NFQUEUE: additional MP_JOIN ACK passed through unchanged\n");
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}

	/* MP_JOIN ACK option layout (RFC 8684 Section 3.2):
	 *   byte 0:  Kind = 30
	 *   byte 1:  Length = 24
	 *   byte 2:  Subtype (high 4 bits) = 1, reserved (low 4 bits)
	 *   byte 3:  Reserved
	 *   bytes 4-23: HMAC (160 bits)
	 * Flip bit 0 of HMAC byte 0 (option offset 4). */
	uint8_t before = opt[4];
	opt[4] ^= 0x01;
	fprintf(stderr,
		"NFQUEUE: MP_JOIN ACK intercepted -- HMAC[0]=0x%02x -> 0x%02x\n",
		before, opt[4]);

	/* Recompute TCP checksum using libnetfilter_queue's canonical helper.
	 * A hand-rolled csum_tcpudp was tried first but produced wrong values
	 * on loopback (the original outgoing packet carries a CHECKSUM_PARTIAL
	 * pseudo-header sum rather than a full csum, which a naive recompute
	 * mishandles).  libnfq's helper handles this correctly. */
	nfq_tcp_compute_checksum_ipv4(tcp, ip);

	atomic_store(&g_mutation_fired, 1);
	return nfq_set_verdict(qh, id, NF_ACCEPT, payload_len, payload);
}

/* ----- NFQUEUE worker thread -------------------------------------- */

static void *nfq_worker(void *arg)
{
	(void)arg;
	int fd = nfq_fd(g_nfq_h);
	char buf[65536] __attribute__((aligned(8)));

	while (!atomic_load(&g_nfq_stop)) {
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };

		int r = select(fd + 1, &rfds, NULL, NULL, &tv);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "nfq select: %s\n", strerror(errno));
			break;
		}
		if (r == 0)
			continue;
		if (!FD_ISSET(fd, &rfds))
			continue;

		int n = recv(fd, buf, sizeof(buf), 0);
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			fprintf(stderr, "nfq recv: %s\n", strerror(errno));
			break;
		}
		nfq_handle_packet(g_nfq_h, buf, n);
	}
	return NULL;
}

/* ----- iptables wrapper ------------------------------------------- */

static int run_iptables(const char *op, int queue_num)
{
	char cmd[256];
	snprintf(cmd, sizeof(cmd),
		 "iptables %s OUTPUT -p tcp -j NFQUEUE --queue-num %d "
		 "--queue-bypass 2>/dev/null",
		 op, queue_num);
	int rc = system(cmd);
	if (rc != 0)
		fprintf(stderr, "FAIL: %s (rc=%d)\n", cmd, rc);
	return rc;
}

static void teardown_iptables(void)
{
	if (g_iptables_inserted) {
		run_iptables("-D", NFQUEUE_NUM);
		g_iptables_inserted = 0;
	}
}

/* ----- write_sysctl / resolve_mptcp_pm_family / genl_subflow_create
 *       /read_mib_counter: copied verbatim from test_mp_join_normal.c.
 *       When we accumulate more tests we should refactor into a shared
 *       header (e.g. test_mp_join_common.h).  Not worth the refactor
 *       at two tests. */

static bool write_sysctl(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return false;
	}
	int len = strlen(val);
	if (write(fd, val, len) != len) {
		fprintf(stderr, "write %s: %s\n", path, strerror(errno));
		close(fd);
		return false;
	}
	close(fd);
	return true;
}

/* CTRL_CMD_GETFAMILY to look up the mptcp_pm family id and the
 * mptcp_pm_events multicast group id. */
static int resolve_mptcp_pm_family(int sock, uint16_t *family_id,
				   uint32_t *event_grp_id)
{
	struct {
		struct nlmsghdr  nh;
		struct genlmsghdr gh;
		char attrs[256];
	} __attribute__((packed)) req = { 0 };

	req.nh.nlmsg_len = NLMSG_SPACE(sizeof(req.gh) + 64);
	req.nh.nlmsg_type = GENL_ID_CTRL;
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_seq = 1;
	req.gh.cmd = CTRL_CMD_GETFAMILY;
	req.gh.version = 1;

	const char *name = "mptcp_pm";
	struct nlattr *na = (struct nlattr *)req.attrs;
	na->nla_type = CTRL_ATTR_FAMILY_NAME;
	na->nla_len = NLA_HDRLEN + strlen(name) + 1;
	strcpy((char *)na + NLA_HDRLEN, name);
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.gh)) + NLA_ALIGN(na->nla_len);

	if (send(sock, &req, req.nh.nlmsg_len, 0) < 0) {
		perror("send CTRL_CMD_GETFAMILY");
		return -1;
	}

	char resp[8192];
	int n = recv(sock, resp, sizeof(resp), 0);
	if (n < 0) {
		perror("recv CTRL_CMD_GETFAMILY");
		return -1;
	}

	struct nlmsghdr *nh = (struct nlmsghdr *)resp;
	if (nh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *ne = NLMSG_DATA(nh);
		fprintf(stderr, "CTRL_CMD_GETFAMILY netlink error: %d\n", ne->error);
		return -1;
	}

	struct genlmsghdr *gh = NLMSG_DATA(nh);
	int attrlen = nh->nlmsg_len - NLMSG_LENGTH(sizeof(*gh));
	struct nlattr *attr = (struct nlattr *)((char *)gh + NLMSG_ALIGN(sizeof(*gh)));

	while (attrlen > 0) {
		if (attr->nla_type == CTRL_ATTR_FAMILY_ID) {
			*family_id = *(uint16_t *)((char *)attr + NLA_HDRLEN);
		} else if (attr->nla_type == CTRL_ATTR_MCAST_GROUPS) {
			struct nlattr *grp = (struct nlattr *)((char *)attr + NLA_HDRLEN);
			int glen = attr->nla_len - NLA_HDRLEN;
			while (glen > 0) {
				struct nlattr *sub = (struct nlattr *)((char *)grp + NLA_HDRLEN);
				int slen = grp->nla_len - NLA_HDRLEN;
				const char *gname = NULL;
				uint32_t gid = 0;
				while (slen > 0) {
					if (sub->nla_type == CTRL_ATTR_MCAST_GRP_NAME)
						gname = (const char *)((char *)sub + NLA_HDRLEN);
					else if (sub->nla_type == CTRL_ATTR_MCAST_GRP_ID)
						gid = *(uint32_t *)((char *)sub + NLA_HDRLEN);
					int sa = NLA_ALIGN(sub->nla_len);
					sub = (struct nlattr *)((char *)sub + sa);
					slen -= sa;
				}
				if (gname && strcmp(gname, "mptcp_pm_events") == 0) {
					*event_grp_id = gid;
				}
				int ga = NLA_ALIGN(grp->nla_len);
				grp = (struct nlattr *)((char *)grp + ga);
				glen -= ga;
			}
		}
		int aa = NLA_ALIGN(attr->nla_len);
		attr = (struct nlattr *)((char *)attr + aa);
		attrlen -= aa;
	}

	if (*family_id == 0) {
		fprintf(stderr, "mptcp_pm family not found\n");
		return -1;
	}
	return 0;
}

/* MPTCP_PM_CMD_SUBFLOW_CREATE: local <-> remote (IPv4 only here). */
static int genl_subflow_create(int sock, uint16_t family_id,
			       uint32_t token, uint8_t local_id,
			       uint32_t local_addr_be, uint16_t local_port_h,
			       uint32_t remote_addr_be, uint16_t remote_port_h)
{
	struct {
		struct nlmsghdr nh;
		struct genlmsghdr gh;
		char body[512];
	} __attribute__((packed)) req = { 0 };

	req.nh.nlmsg_type  = family_id;
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_seq   = 2;
	req.gh.cmd     = MPTCP_PM_CMD_SUBFLOW_CREATE_VAL;
	req.gh.version = MPTCP_PM_VER_VAL;

	char *p = req.body;

	/* MPTCP_PM_ATTR_TOKEN (u32) */
	{
		struct nlattr *a = (struct nlattr *)p;
		a->nla_type = MPTCP_PM_ATTR_TOKEN;
		a->nla_len = NLA_HDRLEN + sizeof(uint32_t);
		*(uint32_t *)((char *)a + NLA_HDRLEN) = token;
		p += NLA_ALIGN(a->nla_len);
	}

	/* MPTCP_PM_ATTR_ADDR (nested -- local) */
	{
		struct nlattr *outer = (struct nlattr *)p;
		outer->nla_type = MPTCP_PM_ATTR_ADDR | NLA_F_NESTED;
		char *q = (char *)outer + NLA_HDRLEN;

		struct nlattr *a;
		a = (struct nlattr *)q;
		a->nla_type = MPTCP_PM_ADDR_ATTR_FAMILY;
		a->nla_len = NLA_HDRLEN + sizeof(uint16_t);
		*(uint16_t *)((char *)a + NLA_HDRLEN) = AF_INET;
		q += NLA_ALIGN(a->nla_len);

		a = (struct nlattr *)q;
		a->nla_type = MPTCP_PM_ADDR_ATTR_ID;
		a->nla_len = NLA_HDRLEN + sizeof(uint8_t);
		*(uint8_t *)((char *)a + NLA_HDRLEN) = local_id;
		q += NLA_ALIGN(a->nla_len);

		a = (struct nlattr *)q;
		a->nla_type = MPTCP_PM_ADDR_ATTR_ADDR4;
		a->nla_len = NLA_HDRLEN + sizeof(uint32_t);
		*(uint32_t *)((char *)a + NLA_HDRLEN) = local_addr_be;
		q += NLA_ALIGN(a->nla_len);

		if (local_port_h != 0) {
			a = (struct nlattr *)q;
			a->nla_type = MPTCP_PM_ADDR_ATTR_PORT;
			a->nla_len = NLA_HDRLEN + sizeof(uint16_t);
			*(uint16_t *)((char *)a + NLA_HDRLEN) = local_port_h;
			q += NLA_ALIGN(a->nla_len);
		}

		outer->nla_len = (uint16_t)(q - (char *)outer);
		p = q;
	}

	/* MPTCP_PM_ATTR_ADDR_REMOTE (nested -- remote) */
	{
		struct nlattr *outer = (struct nlattr *)p;
		outer->nla_type = MPTCP_PM_ATTR_ADDR_REMOTE | NLA_F_NESTED;
		char *q = (char *)outer + NLA_HDRLEN;

		struct nlattr *a;
		a = (struct nlattr *)q;
		a->nla_type = MPTCP_PM_ADDR_ATTR_FAMILY;
		a->nla_len = NLA_HDRLEN + sizeof(uint16_t);
		*(uint16_t *)((char *)a + NLA_HDRLEN) = AF_INET;
		q += NLA_ALIGN(a->nla_len);

		a = (struct nlattr *)q;
		a->nla_type = MPTCP_PM_ADDR_ATTR_ADDR4;
		a->nla_len = NLA_HDRLEN + sizeof(uint32_t);
		*(uint32_t *)((char *)a + NLA_HDRLEN) = remote_addr_be;
		q += NLA_ALIGN(a->nla_len);

		a = (struct nlattr *)q;
		a->nla_type = MPTCP_PM_ADDR_ATTR_PORT;
		a->nla_len = NLA_HDRLEN + sizeof(uint16_t);
		*(uint16_t *)((char *)a + NLA_HDRLEN) = remote_port_h;
		q += NLA_ALIGN(a->nla_len);

		outer->nla_len = (uint16_t)(q - (char *)outer);
		p = q;
	}

	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.gh)) +
			   (uint32_t)(p - req.body);

	if (send(sock, &req, req.nh.nlmsg_len, 0) < 0) {
		perror("send SUBFLOW_CREATE");
		return -1;
	}

	char resp[8192];
	int n = recv(sock, resp, sizeof(resp), 0);
	if (n < 0) {
		perror("recv SUBFLOW_CREATE ack");
		return -1;
	}
	struct nlmsghdr *nh = (struct nlmsghdr *)resp;
	if (nh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *ne = NLMSG_DATA(nh);
		if (ne->error != 0) {
			fprintf(stderr,
				"SUBFLOW_CREATE failed: errno=%d (%s)\n",
				-ne->error, strerror(-ne->error));
			return -1;
		}
	}
	return 0;
}

static long read_mib_counter_verbose(const char *name, int verbose)
{
	FILE *f = fopen("/proc/net/netstat", "r");
	if (!f) {
		if (verbose)
			fprintf(stderr, "MIB: open /proc/net/netstat: %s\n",
				strerror(errno));
		return -1;
	}
	char header[16384], values[16384];
	long val = -1;
	int found_mptcpext = 0;
	while (fgets(header, sizeof(header), f)) {
		if (strncmp(header, "MPTcpExt:", 9) != 0)
			continue;
		found_mptcpext = 1;
		if (!fgets(values, sizeof(values), f))
			break;

		char *hp = header + 9;
		char *vp = values + 9;
		while (*hp == ' ' || *hp == '\t') hp++;
		while (*vp == ' ' || *vp == '\t') vp++;
		char *hsave = NULL, *vsave = NULL;
		char *htok = strtok_r(hp, " \t\n", &hsave);
		char *vtok = strtok_r(vp, " \t\n", &vsave);
		while (htok && vtok) {
			if (strcmp(htok, name) == 0) {
				val = strtol(vtok, NULL, 10);
				break;
			}
			htok = strtok_r(NULL, " \t\n", &hsave);
			vtok = strtok_r(NULL, " \t\n", &vsave);
		}
		break;
	}
	if (!found_mptcpext && verbose)
		fprintf(stderr,
			"MIB: no MPTcpExt: line in /proc/net/netstat\n");
	fclose(f);
	return val;
}

static long read_mib_counter(const char *name)
{
	return read_mib_counter_verbose(name, 0);
}

/* ----- main ------------------------------------------------------- */

int main(void)
{
	struct sockaddr_in addr = { .sin_family = AF_INET };
	struct sockaddr_nl nlsa = { .nl_family = AF_NETLINK };
	socklen_t alen = sizeof(addr);
	int server = -1, client = -1, accepted = -1;
	int nl_send = -1, nl_event = -1;
	uint16_t family_id = 0;
	uint32_t event_grp_id = 0;
	pthread_t worker_thread;
	int worker_started = 0;
	int rc = 1;
	int one = 1;

	/* Best-effort iptables teardown on any exit path. */
	atexit(teardown_iptables);

	/* 1. Userspace PM mode netns-wide. */
	if (!write_sysctl("/proc/sys/net/mptcp/pm_type", "1")) {
		fprintf(stderr,
			"FAIL: cannot set pm_type=1 (need root + CONFIG_MPTCP)\n");
		goto out;
	}
	printf("PASS: net.mptcp.pm_type = 1 (userspace PM enabled)\n");

	/* 2. Genl socket: resolve family + event group. */
	nl_send = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (nl_send < 0) {
		perror("socket(genl send)");
		goto out;
	}
	if (bind(nl_send, (struct sockaddr *)&nlsa, sizeof(nlsa)) < 0) {
		perror("bind(genl send)");
		goto out;
	}
	if (resolve_mptcp_pm_family(nl_send, &family_id, &event_grp_id) < 0)
		goto out;
	printf("PASS: mptcp_pm family resolved: id=%u, events grp=%u\n",
	       family_id, event_grp_id);

	/* 3. Subscribe to events.  Makes mptcp_userspace_pm_active(msk) true. */
	nl_event = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (nl_event < 0) {
		perror("socket(genl event)");
		goto out;
	}
	if (bind(nl_event, (struct sockaddr *)&nlsa, sizeof(nlsa)) < 0) {
		perror("bind(genl event)");
		goto out;
	}
	if (setsockopt(nl_event, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
		       &event_grp_id, sizeof(event_grp_id)) < 0) {
		perror("NETLINK_ADD_MEMBERSHIP mptcp_pm_events");
		goto out;
	}
	printf("PASS: subscribed to mptcp_pm_events\n");

	/* 4. Server side. */
	server = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (server < 0) { perror("socket(server)"); goto out; }
	setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	addr.sin_port = 0;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind server"); goto out;
	}
	if (getsockname(server, (struct sockaddr *)&addr, &alen) < 0) {
		perror("getsockname"); goto out;
	}
	if (listen(server, 1) < 0) { perror("listen"); goto out; }
	uint16_t server_port_h = ntohs(addr.sin_port);
	printf("server: bound 127.0.0.1:%u\n", server_port_h);

	/* 5. Client side: drive MP_CAPABLE. */
	client = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (client < 0) { perror("socket(client)"); goto out; }
	if (connect(client, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect"); goto out;
	}
	accepted = accept(server, NULL, NULL);
	if (accepted < 0) { perror("accept"); goto out; }
	printf("PASS: MP_CAPABLE handshake completed\n");

	/* 5.5. 1-byte primer for client-side fully_established. */
	{
		char b = 'x';
		if (send(client, &b, 1, 0) != 1) { perror("prime send c->s"); goto out; }
		if (recv(accepted, &b, 1, MSG_WAITALL) != 1) { perror("prime recv on server"); goto out; }
		if (send(accepted, &b, 1, 0) != 1) { perror("prime send s->c"); goto out; }
		if (recv(client, &b, 1, MSG_WAITALL) != 1) { perror("prime recv on client"); goto out; }
		printf("PASS: 1-byte round-trip primed fully_established\n");
	}

	/* 6. Read token. */
	struct mptcp_info_short info;
	socklen_t ilen = sizeof(info);
	memset(&info, 0, sizeof(info));
	if (getsockopt(client, SOL_MPTCP, MPTCP_INFO, &info, &ilen) < 0) {
		perror("getsockopt(MPTCP_INFO) client"); goto out;
	}
	uint32_t token = info.mptcpi_token;
	printf("client token: 0x%08x\n", token);

	/* 7. NFQUEUE setup: open library, bind queue, set copy mode. */
	g_nfq_h = nfq_open();
	if (!g_nfq_h) {
		perror("nfq_open");
		goto out;
	}
	/* nfq_unbind_pf / nfq_bind_pf are deprecated on modern kernels --
	 * they return EINVAL because the kernel handles protocol-family
	 * binding implicitly via nfq_create_queue.  Older examples (and
	 * the libnetfilter_queue man page from ~2010) show them being
	 * called; do not.  Verified: skipping them works on 6.x kernels;
	 * calling nfq_bind_pf(AF_INET) on 7.x fails with EINVAL. */
	g_nfq_qh = nfq_create_queue(g_nfq_h, NFQUEUE_NUM, &brf_nfq_callback, NULL);
	if (!g_nfq_qh) {
		perror("nfq_create_queue");
		goto out;
	}
	if (nfq_set_mode(g_nfq_qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		perror("nfq_set_mode");
		goto out;
	}
	printf("PASS: NFQUEUE bound to queue %d\n", NFQUEUE_NUM);

	/* 8. iptables rule -- queue all OUTPUT TCP for inspection.  Bypass
	 *    flag means: if our worker is not running, pass packets through
	 *    instead of dropping (defensive). */
	if (run_iptables("-I", NFQUEUE_NUM) != 0) {
		fprintf(stderr,
			"FAIL: iptables rule insert.  Is iptables installed?  Try: apt install iptables\n");
		goto out;
	}
	g_iptables_inserted = 1;
	printf("PASS: iptables rule added (OUTPUT -p tcp -j NFQUEUE)\n");

	/* 9. Start worker thread to handle queued packets. */
	if (pthread_create(&worker_thread, NULL, nfq_worker, NULL) != 0) {
		perror("pthread_create nfq_worker");
		goto out;
	}
	worker_started = 1;

	/* 10. Snapshot MIB counters. */
	long syn_rx_before  = read_mib_counter_verbose("MPJoinSynRx", 1);
	long ack_rx_before  = read_mib_counter("MPJoinAckRx");
	long ack_fail_before = read_mib_counter("MPJoinAckHMacFailure");
	printf("MIB before: MPJoinSynRx=%ld MPJoinAckRx=%ld MPJoinAckHMacFailure=%ld\n",
	       syn_rx_before, ack_rx_before, ack_fail_before);

	/* 11. Initiate MP_JOIN. */
	if (genl_subflow_create(nl_send, family_id, token, 1,
				htonl(0x7f000002), 0,
				htonl(0x7f000001), server_port_h) < 0) {
		rc = 2;
		goto out;
	}
	printf("PASS: SUBFLOW_CREATE acked by kernel\n");

	/* 12. Wait for our NFQUEUE callback to fire (intercept + mutate). */
	int waited_ms = 0;
	while (waited_ms < 2000 && !atomic_load(&g_mutation_fired)) {
		usleep(50000);
		waited_ms += 50;
	}
	if (!atomic_load(&g_mutation_fired)) {
		fprintf(stderr,
			"FAIL: NFQUEUE saw %d packets (%d MP_JOIN ACKs) but never intercepted -- "
			"check iptables / queue setup\n",
			atomic_load(&g_packets_seen),
			atomic_load(&g_mp_join_acks_seen));
		rc = 3;
		goto out;
	}
	printf("PASS: NFQUEUE intercepted MP_JOIN ACK (saw %d packets total, "
	       "%d MP_JOIN ACKs)\n",
	       atomic_load(&g_packets_seen),
	       atomic_load(&g_mp_join_acks_seen));

	/* 13. Verify subflow did NOT establish on the server side.
	 *     If it did, our mutation was wrong / the kernel didn't check
	 *     HMAC / we mutated the wrong byte. */
	usleep(500000);
	memset(&info, 0, sizeof(info));
	ilen = sizeof(info);
	if (getsockopt(accepted, SOL_MPTCP, MPTCP_INFO, &info, &ilen) == 0) {
		if (info.mptcpi_subflows >= 1) {
			fprintf(stderr,
				"FAIL: server msk mptcpi_subflows=%u "
				"(expected 0; kernel did not reject the bad HMAC?)\n",
				info.mptcpi_subflows);
			rc = 5;
			goto out;
		}
	}
	printf("PASS: server msk mptcpi_subflows stayed 0 (HMAC mutation rejected)\n");

	/* 14. Re-snapshot MIB and verify the failure counter moved. */
	long syn_rx_after   = read_mib_counter("MPJoinSynRx");
	long ack_rx_after   = read_mib_counter("MPJoinAckRx");
	long ack_fail_after = read_mib_counter("MPJoinAckHMacFailure");
	printf("MIB after:  MPJoinSynRx=%ld MPJoinAckRx=%ld MPJoinAckHMacFailure=%ld\n",
	       syn_rx_after, ack_rx_after, ack_fail_after);

	long syn_delta  = syn_rx_after  - syn_rx_before;
	long ack_delta  = ack_rx_after  - ack_rx_before;
	long fail_delta = ack_fail_after - ack_fail_before;

	int verdict = 0;
	if (syn_delta != 1) {
		fprintf(stderr,
			"FAIL: MPJoinSynRx delta=%ld, expected 1\n", syn_delta);
		verdict = 1;
	}
	if (ack_delta != 0) {
		fprintf(stderr,
			"FAIL: MPJoinAckRx delta=%ld, expected 0 "
			"(bad ACK should be rejected before count)\n", ack_delta);
		verdict = 1;
	}
	if (fail_delta != 1) {
		fprintf(stderr,
			"FAIL: MPJoinAckHMacFailure delta=%ld, expected 1\n",
			fail_delta);
		verdict = 1;
	}
	if (verdict) {
		rc = 4;
		goto out;
	}
	printf("PASS: MIB delta matches: MPJoinSynRx +1, MPJoinAckRx +0, "
	       "MPJoinAckHMacFailure +1\n");

	rc = 0;

out:
	/* Stop the worker thread first so it stops touching nfq state. */
	if (worker_started) {
		atomic_store(&g_nfq_stop, 1);
		pthread_join(worker_thread, NULL);
	}
	if (g_nfq_qh) nfq_destroy_queue(g_nfq_qh);
	if (g_nfq_h)  nfq_close(g_nfq_h);
	/* atexit removes the iptables rule */
	if (accepted >= 0) close(accepted);
	if (client   >= 0) close(client);
	if (server   >= 0) close(server);
	if (nl_event >= 0) close(nl_event);
	if (nl_send  >= 0) close(nl_send);

	if (rc == 0)
		printf("\nresult: PASS "
		       "(NFQUEUE-rewrite of MP_JOIN ACK HMAC trips the gate end-to-end)\n");
	else
		fprintf(stderr,
			"\nresult: FAIL (rc=%d) -- see messages above\n", rc);
	return rc;
}
