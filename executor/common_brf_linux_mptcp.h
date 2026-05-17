// SPDX-License-Identifier: Apache-2.0
//
// MPTCP MP_JOIN harness -- pseudo-syscall implementations (v0 skeleton).
//
// Companion design doc: .claude/designs/mptcp_join_harness_design.md
// Companion syzlang   : sys/linux/socket_mptcp_crypto.txt
//
// v0 status (2026-05-15): all five pseudo-syscalls return -1 with a
// debug() log line.  Compiles and links; lets syz-sysgen wire up the
// dispatch table.  Real implementations land incrementally per the
// implementation order in the design doc Section 12.
//
// The persistent two-netns + veth pair is set up the first time
// syz_mptcp_pair_init runs (lazy init), not at executor start.  See
// the netns_initialized flag in the pool below.

#ifndef BRF_COMMON_LINUX_MPTCP_H
#define BRF_COMMON_LINUX_MPTCP_H

#define MPTCP_PAIR_POOL_SIZE         16
#define MPTCP_MAX_SUBFLOWS_PER_PAIR  8

// ---------- Flag enum values ----------
// Must mirror sys/linux/socket_mptcp_crypto.txt.const exactly.
#define MPTCP_INIT_CSUM_ON           1
#define MPTCP_INIT_CSUM_OFF          2
#define MPTCP_INIT_DENY_JOIN_ID0     4

#define MPTCP_NONCE_NORMAL           0
#define MPTCP_NONCE_ZERO             1
#define MPTCP_NONCE_FLIP_HIGH        2
#define MPTCP_NONCE_FLIP_LOW         3
#define MPTCP_NONCE_REPLAY           4

#define MPTCP_HMAC_NORMAL            0
#define MPTCP_HMAC_ZERO              1
#define MPTCP_HMAC_BIT_FLIP          2
#define MPTCP_HMAC_TRUNCATE          3
#define MPTCP_HMAC_SWAP              4

#define MPTCP_MAP_NORMAL             0
#define MPTCP_MAP_STALE_SEQ          1
#define MPTCP_MAP_OFF_BY_ONE         2
#define MPTCP_MAP_INFINITE           3
#define MPTCP_MAP_HOLE               4

#define MPTCP_CTL_FAIL               0
#define MPTCP_CTL_FASTCLOSE          1
#define MPTCP_CTL_RST                2

// ---------- MPTCP uapi fallbacks ----------
// Older distro headers won't have these; match the patched kernel.
#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP               262
#endif
#ifndef SOL_MPTCP
#define SOL_MPTCP                   284
#endif
#ifndef MPTCP_INFO
#define MPTCP_INFO                  1
#endif
#ifndef MPTCP_KCOV_HANDLE
#define MPTCP_KCOV_HANDLE           5
#endif
#ifndef MPTCP_DEBUG_KEYS
#define MPTCP_DEBUG_KEYS            6
struct mptcp_debug_keys {
	uint64_t local_key;
	uint64_t remote_key;
};
#endif

// MPTCP_PM_ADDR_FLAG_* are defined in <linux/mptcp.h> which we deliberately
// don't include (see comment on struct brf_mptcp_info_short for why).  Mirror
// the bit values explicitly; these are uapi and won't change without breaking
// existing userspace.
#ifndef MPTCP_PM_ADDR_FLAG_SIGNAL
#define MPTCP_PM_ADDR_FLAG_SIGNAL	(1U << 0)
#define MPTCP_PM_ADDR_FLAG_SUBFLOW	(1U << 1)
#define MPTCP_PM_ADDR_FLAG_BACKUP	(1U << 2)
#define MPTCP_PM_ADDR_FLAG_FULLMESH	(1U << 3)
#define MPTCP_PM_ADDR_FLAG_IMPLICIT	(1U << 4)
#endif

// Pull in mptcp_pm.h for MPTCP_PM_CMD_SUBFLOW_CREATE + attr enums.  Distro
// headers usually carry this since iproute2 ships against it; the fallback
// below mirrors include/uapi/linux/mptcp_pm.h at the kernel base commit
// 232989ca65248 in case the host headers lag.
// NFQUEUE infrastructure for v02 wire-level mutation (HMAC_BIT_FLIP etc.
// in syz_mptcp_join_subflow).  Standard Linux uapi; available on Debian
// trixie and any kernel built with CONFIG_NETFILTER_NETLINK_QUEUE.
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>

#if __has_include(<linux/mptcp_pm.h>)
#include <linux/mptcp_pm.h>
#else
#define MPTCP_PM_NAME	"mptcp_pm"
#define MPTCP_PM_VER	1
enum {
	MPTCP_PM_ATTR_UNSPEC_FB,
	MPTCP_PM_ATTR_ADDR,
	MPTCP_PM_ATTR_RCV_ADD_ADDRS,
	MPTCP_PM_ATTR_SUBFLOWS,
	MPTCP_PM_ATTR_TOKEN,
	MPTCP_PM_ATTR_LOC_ID,
	MPTCP_PM_ATTR_ADDR_REMOTE,
};
enum {
	MPTCP_PM_ADDR_ATTR_UNSPEC_FB,
	MPTCP_PM_ADDR_ATTR_FAMILY,
	MPTCP_PM_ADDR_ATTR_ID,
	MPTCP_PM_ADDR_ATTR_ADDR4,
	MPTCP_PM_ADDR_ATTR_ADDR6,
	MPTCP_PM_ADDR_ATTR_PORT,
	MPTCP_PM_ADDR_ATTR_FLAGS,
	MPTCP_PM_ADDR_ATTR_IF_IDX,
};
enum {
	MPTCP_PM_CMD_UNSPEC_FB,
	MPTCP_PM_CMD_ADD_ADDR,
	MPTCP_PM_CMD_DEL_ADDR,
	MPTCP_PM_CMD_GET_ADDR,
	MPTCP_PM_CMD_FLUSH_ADDRS,
	MPTCP_PM_CMD_SET_LIMITS,
	MPTCP_PM_CMD_GET_LIMITS,
	MPTCP_PM_CMD_SET_FLAGS,
	MPTCP_PM_CMD_ANNOUNCE,
	MPTCP_PM_CMD_REMOVE,
	MPTCP_PM_CMD_SUBFLOW_CREATE,
	MPTCP_PM_CMD_SUBFLOW_DESTROY,
};
#endif

// ---------- NFQUEUE raw-netlink plumbing (v02 C2a) ----------
//
// We open NETLINK_NETFILTER, bind queue 0, set NFQNL_COPY_PACKET mode,
// and install an iptables OUTPUT rule.  The worker thread + mutation
// callback come in C2b; this file's C2a just stands up the
// infrastructure so brf_mptcp_ensure_nfq_setup() returning 0 means
// the queue is live and packets are buffered for us.
//
// libnetfilter_queue is intentionally avoided here to keep
// syz-executor's link surface clean.  The smoke test at
// kernel_patches/mptcp_kcov/test_mp_join_hmac_bitflip.c uses libnfq
// since it's a standalone program.  ~150 LOC of raw netlink + the
// ported checksum helper (next commit) buys us no new build dep.

#define BRF_NFQ_QUEUE_NUM 0

static int brf_nfq_fd = -1;
static int brf_nfq_setup_done = 0;
static int brf_nfq_iptables_inserted = 0;

/* Pending-mutation state, set by syz_mptcp_join_subflow before
 * SUBFLOW_CREATE and consumed by the worker thread when the next
 * MP_JOIN ACK appears on egress.  Use GCC __atomic builtins rather
 * than <stdatomic.h> because the executor compiles as C++ where
 * atomic_int has different semantics; __atomic_* works in both. */
static volatile int brf_nfq_pending_hmac_mut = 0;  /* MPTCP_HMAC_NORMAL */
static volatile int brf_nfq_mut_fired        = 0;
static volatile int brf_nfq_worker_stop      = 0;
static pthread_t    brf_nfq_worker_thread;
static int          brf_nfq_worker_started   = 0;

#define BRF_ATOMIC_LOAD(p)     __atomic_load_n((p), __ATOMIC_SEQ_CST)
#define BRF_ATOMIC_STORE(p, v) __atomic_store_n((p), (v), __ATOMIC_SEQ_CST)

/* ---- Ported from libnetfilter_queue's checksum.c.  Verified
 * equivalent to nfq_tcp_compute_checksum_ipv4 (which we use in the
 * standalone smoke test).  A hand-rolled tcp_csum_ipv4 was tried first
 * and was off by 0x01f6 -- almost certainly a packed-struct alignment
 * subtlety I couldn't reproduce in isolation.  This implementation
 * accesses fields via half-word integer shifts (no packed struct +
 * 16-bit alias), which sidesteps it. */
static uint16_t brf_nfq_csum_fold(uint32_t sum)
{
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return (uint16_t)(~sum);
}

static uint32_t brf_nfq_pseudoheader_tcpudp_v4(const struct iphdr *iph)
{
	uint16_t udptcp_len = ntohs(iph->tot_len) - (iph->ihl * 4);
	uint32_t sum = 0;
	sum += (iph->saddr >> 16) & 0xFFFF;
	sum += iph->saddr & 0xFFFF;
	sum += (iph->daddr >> 16) & 0xFFFF;
	sum += iph->daddr & 0xFFFF;
	sum += htons(iph->protocol);
	sum += htons(udptcp_len);
	return sum;
}

static uint16_t brf_nfq_csum_buf(uint32_t sum, const uint16_t *buf, int size)
{
	while (size > 1) {
		sum += *buf++;
		size -= 2;
	}
	if (size)
		sum += *(const uint8_t *)buf;
	return brf_nfq_csum_fold(sum);
}

static void brf_nfq_tcp_compute_checksum_ipv4(struct tcphdr *tcph,
					      const struct iphdr *iph)
{
	uint16_t iph_len = iph->ihl * 4;
	uint16_t udptcp_len = ntohs(iph->tot_len) - iph_len;
	uint32_t sum = brf_nfq_pseudoheader_tcpudp_v4(iph);

	tcph->check = 0;
	tcph->check = brf_nfq_csum_buf(sum,
				       (const uint16_t *)tcph,
				       udptcp_len);
}

static void brf_nfq_cleanup(void)
{
	if (brf_nfq_worker_started) {
		BRF_ATOMIC_STORE(&brf_nfq_worker_stop, 1);
		/* Close the fd to unblock the worker's recv(); join, then
		 * proceed with the rest of cleanup. */
		if (brf_nfq_fd >= 0) {
			shutdown(brf_nfq_fd, SHUT_RDWR);
		}
		pthread_join(brf_nfq_worker_thread, NULL);
		brf_nfq_worker_started = 0;
	}
	if (brf_nfq_iptables_inserted) {
		int rc = system("iptables -D OUTPUT -p tcp -j NFQUEUE "
				"--queue-num 0 2>/dev/null");
		(void)rc;
		brf_nfq_iptables_inserted = 0;
	}
	if (brf_nfq_fd >= 0) {
		close(brf_nfq_fd);
		brf_nfq_fd = -1;
	}
}

/* Send one NFQUEUE netlink message and wait for the NLMSG_ERROR ack.
 * msg_type is e.g. ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG).
 * res_id is the queue number (in host order; we htons() it here).
 * attr_payload (if non-NULL) is appended after the nfgenmsg as raw
 * netlink-attribute bytes the caller has already laid out. */
static int brf_nfq_send_msg(int fd, uint16_t msg_type, uint16_t res_id,
			    const void *attr_payload, uint16_t attr_payload_len)
{
	char buf[256];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct nfgenmsg *nfg = (struct nfgenmsg *)NLMSG_DATA(nlh);
	char ack_buf[256];
	ssize_t n;

	if (NLMSG_LENGTH(sizeof(*nfg)) + attr_payload_len > sizeof(buf))
		return -1;
	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*nfg));
	nlh->nlmsg_type = msg_type;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = (uint32_t)time(NULL);
	nlh->nlmsg_pid = 0;
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(res_id);
	if (attr_payload && attr_payload_len > 0) {
		memcpy((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len),
		       attr_payload, attr_payload_len);
		nlh->nlmsg_len += attr_payload_len;
	}

	if (send(fd, buf, nlh->nlmsg_len, 0) < 0)
		return -1;

	n = recv(fd, ack_buf, sizeof(ack_buf), 0);
	if (n < 0)
		return -1;
	struct nlmsghdr *ack_nlh = (struct nlmsghdr *)ack_buf;
	if (ack_nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(ack_nlh);
		if (err->error != 0) {
			errno = -err->error;
			return -1;
		}
	}
	return 0;
}

/* NFQNL_CFG_CMD_{BIND,UNBIND,PF_BIND,PF_UNBIND} for a given queue. */
static int brf_nfq_send_config_cmd(int fd, uint16_t queue_num,
				   uint8_t cmd, uint16_t pf)
{
	struct {
		struct nlattr nla;
		struct nfqnl_msg_config_cmd cfg;
	} __attribute__((packed)) payload;

	payload.nla.nla_len = sizeof(payload);
	payload.nla.nla_type = NFQA_CFG_CMD;
	payload.cfg.command = cmd;
	payload.cfg._pad = 0;
	payload.cfg.pf = htons(pf);
	return brf_nfq_send_msg(fd,
		(NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG,
		queue_num, &payload, sizeof(payload));
}

/* NFQA_CFG_PARAMS -- copy mode + range. */
static int brf_nfq_send_config_params(int fd, uint16_t queue_num,
				      uint8_t copy_mode, uint32_t copy_range)
{
	struct {
		struct nlattr nla;
		struct nfqnl_msg_config_params params;
	} __attribute__((packed)) payload;

	payload.nla.nla_len = sizeof(payload);
	payload.nla.nla_type = NFQA_CFG_PARAMS;
	payload.params.copy_mode = copy_mode;
	payload.params.copy_range = htonl(copy_range);
	return brf_nfq_send_msg(fd,
		(NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG,
		queue_num, &payload, sizeof(payload));
}

/* Send NFQNL_MSG_VERDICT.  If payload != NULL, the packet is rewritten
 * with the modified bytes; otherwise the kernel uses the original. */
static int brf_nfq_send_verdict(int fd, uint16_t queue_num,
				uint32_t packet_id, uint32_t verdict,
				const uint8_t *payload, uint16_t payload_len)
{
	char buf[65536 + 256];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct nfgenmsg *nfg = (struct nfgenmsg *)NLMSG_DATA(nlh);
	struct {
		struct nlattr nla;
		struct nfqnl_msg_verdict_hdr vh;
	} __attribute__((packed)) vhdr;
	char *cursor;

	if (NLMSG_LENGTH(sizeof(*nfg)) + sizeof(vhdr) + NLA_HDRLEN +
	    payload_len > sizeof(buf))
		return -1;

	memset(buf, 0, NLMSG_LENGTH(sizeof(*nfg)));
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*nfg));
	nlh->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 0;
	nlh->nlmsg_pid = 0;
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(queue_num);

	vhdr.nla.nla_len = sizeof(vhdr);
	vhdr.nla.nla_type = NFQA_VERDICT_HDR;
	vhdr.vh.verdict = htonl(verdict);
	vhdr.vh.id = htonl(packet_id);
	cursor = (char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len);
	memcpy(cursor, &vhdr, sizeof(vhdr));
	nlh->nlmsg_len += sizeof(vhdr);

	if (payload && payload_len > 0) {
		struct nlattr pl_attr;
		pl_attr.nla_len = NLA_HDRLEN + payload_len;
		pl_attr.nla_type = NFQA_PAYLOAD;
		cursor = (char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len);
		memcpy(cursor, &pl_attr, sizeof(pl_attr));
		memcpy(cursor + NLA_HDRLEN, payload, payload_len);
		nlh->nlmsg_len += NLA_HDRLEN + payload_len;
	}

	return (int)send(fd, buf, nlh->nlmsg_len, 0);
}

/* Walk TCP options.  Returns pointer to the MP_JOIN ACK option's kind
 * byte (kind=30, len=24, subtype=1) within tcp_seg, or NULL. */
static uint8_t *brf_nfq_find_mp_join_ack(uint8_t *tcp_seg, int tcp_hlen)
{
	int optlen = tcp_hlen - (int)sizeof(struct tcphdr);
	uint8_t *opts = tcp_seg + sizeof(struct tcphdr);
	int i = 0;
	while (i < optlen) {
		uint8_t kind = opts[i];
		if (kind == 0)		/* End-of-options */
			break;
		if (kind == 1) {	/* NOP */
			i++;
			continue;
		}
		if (i + 1 >= optlen)
			break;
		uint8_t len = opts[i + 1];
		if (len < 2 || i + len > optlen)
			break;
		/* MP_JOIN ACK: kind=30, len=24, subtype (high nibble of byte 2) = 1 */
		if (kind == 30 && len == 24 &&
		    (opts[i + 2] >> 4) == 1)
			return &opts[i];
		i += len;
	}
	return NULL;
}

/* Apply HMAC mutation to MP_JOIN ACK option bytes.  Option offset 4
 * starts the 20-byte HMAC field. */
static void brf_nfq_apply_hmac_mut(uint8_t *opt, int mut_type)
{
	switch (mut_type) {
	case MPTCP_HMAC_BIT_FLIP:
		opt[4] ^= 0x01;
		break;
	case MPTCP_HMAC_ZERO:
		memset(&opt[4], 0, 20);
		break;
	/* HMAC_TRUNCATE / HMAC_SWAP land in a later commit -- they
	 * change the option length which requires resizing the TCP
	 * header, more involved than a same-size byte rewrite. */
	default:
		break;
	}
}

/* NLA walking helpers (libnetlink-style; not in distro linux/netlink.h). */
#define BRF_NLA_OK(nla, rem) \
	((rem) >= (int)sizeof(struct nlattr) && \
	 (nla)->nla_len >= sizeof(struct nlattr) && \
	 (int)(nla)->nla_len <= (rem))
#define BRF_NLA_NEXT(nla, rem) \
	((rem) -= NLA_ALIGN((nla)->nla_len), \
	 (struct nlattr *)((char *)(nla) + NLA_ALIGN((nla)->nla_len)))
#define BRF_NLA_DATA(nla) ((void *)((char *)(nla) + NLA_HDRLEN))

/* Worker thread.  Reads NFQUEUE packets, applies the pending HMAC
 * mutation (if any) to the first matching MP_JOIN ACK, and forwards
 * everything else unchanged with NF_ACCEPT. */
static void *brf_nfq_worker_loop(void *arg)
{
	(void)arg;
	char buf[65536];

	while (!BRF_ATOMIC_LOAD(&brf_nfq_worker_stop)) {
		ssize_t n = recv(brf_nfq_fd, buf, sizeof(buf), 0);
		if (n < 0) {
			if (errno == EINTR) continue;
			break;
		}

		struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
		if (!NLMSG_OK(nlh, (size_t)n))
			continue;
		if ((nlh->nlmsg_type >> 8) != NFNL_SUBSYS_QUEUE ||
		    (nlh->nlmsg_type & 0xff) != NFQNL_MSG_PACKET)
			continue;

		struct nfgenmsg *nfg = (struct nfgenmsg *)NLMSG_DATA(nlh);
		uint16_t queue_num = ntohs(nfg->res_id);

		/* Walk attrs to find PACKET_HDR and PAYLOAD. */
		struct nlattr *attr = (struct nlattr *)
			((char *)nfg + NLMSG_ALIGN(sizeof(*nfg)));
		int attr_len = nlh->nlmsg_len - NLMSG_HDRLEN -
			NLMSG_ALIGN(sizeof(*nfg));

		uint32_t packet_id = 0;
		uint8_t *payload = NULL;
		int payload_len = 0;
		while (BRF_NLA_OK(attr, attr_len)) {
			if (attr->nla_type == NFQA_PACKET_HDR) {
				struct nfqnl_msg_packet_hdr *ph =
					(struct nfqnl_msg_packet_hdr *)
					BRF_NLA_DATA(attr);
				packet_id = ntohl(ph->packet_id);
			} else if (attr->nla_type == NFQA_PAYLOAD) {
				payload = (uint8_t *)BRF_NLA_DATA(attr);
				payload_len = attr->nla_len - NLA_HDRLEN;
			}
			attr = BRF_NLA_NEXT(attr, attr_len);
		}

		/* Default verdict: pass through unchanged. */
		int mut_to_apply = 0;
		uint8_t *opt = NULL;

		if (payload && payload_len >=
		    (int)(sizeof(struct iphdr) + sizeof(struct tcphdr))) {
			struct iphdr *ip = (struct iphdr *)payload;
			int ip_hlen = ip->ihl * 4;
			if (ip->protocol == IPPROTO_TCP &&
			    payload_len >= ip_hlen + (int)sizeof(struct tcphdr)) {
				struct tcphdr *tcp = (struct tcphdr *)
					(payload + ip_hlen);
				int tcp_hlen = tcp->doff * 4;
				if (payload_len >= ip_hlen + tcp_hlen &&
				    tcp->ack && !tcp->syn && !tcp->fin &&
				    !tcp->rst) {
					opt = brf_nfq_find_mp_join_ack(
						(uint8_t *)tcp, tcp_hlen);
					if (opt && !BRF_ATOMIC_LOAD(
						&brf_nfq_mut_fired)) {
						mut_to_apply = BRF_ATOMIC_LOAD(
						    &brf_nfq_pending_hmac_mut);
					}
				}
				if (mut_to_apply != 0 &&
				    mut_to_apply != MPTCP_HMAC_NORMAL) {
					brf_nfq_apply_hmac_mut(opt,
							       mut_to_apply);
					brf_nfq_tcp_compute_checksum_ipv4(
						tcp, ip);
					BRF_ATOMIC_STORE(&brf_nfq_mut_fired, 1);
					debug("nfq_worker: applied "
					      "hmac_mut=%d to MP_JOIN ACK\n",
					      mut_to_apply);
					brf_nfq_send_verdict(brf_nfq_fd,
						queue_num, packet_id,
						NF_ACCEPT, payload,
						(uint16_t)payload_len);
					continue;
				}
			}
		}

		brf_nfq_send_verdict(brf_nfq_fd, queue_num, packet_id,
				     NF_ACCEPT, NULL, 0);
	}
	return NULL;
}

/* Idempotent setup.  Called lazily from syz_mptcp_join_subflow when a
 * mutation mode is requested.  Returns 0 on success; on failure leaves
 * the static state cleaned up so a retry can run.
 *
 * Marked unused for C2a: the call site lands in C2c when the mutation
 * branch in syz_mptcp_join_subflow stops returning -1.  The attribute
 * is a no-op once the function is referenced. */
static int brf_mptcp_ensure_nfq_setup(void) __attribute__((unused));
static int brf_mptcp_ensure_nfq_setup(void)
{
	struct sockaddr_nl sa;

	if (brf_nfq_setup_done)
		return 0;

	brf_nfq_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
	if (brf_nfq_fd < 0) {
		debug("nfq_setup: socket(NETLINK_NETFILTER): %s\n",
		      strerror(errno));
		return -1;
	}
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(brf_nfq_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		debug("nfq_setup: bind: %s\n", strerror(errno));
		goto fail;
	}

	/* PF_BIND/PF_UNBIND are no-ops on modern kernels but cheap to
	 * send; failures here are non-fatal (kernel returns EOPNOTSUPP or
	 * just acks with 0). */
	(void)brf_nfq_send_config_cmd(brf_nfq_fd, 0,
				      NFQNL_CFG_CMD_PF_UNBIND, AF_INET);
	(void)brf_nfq_send_config_cmd(brf_nfq_fd, 0,
				      NFQNL_CFG_CMD_PF_BIND, AF_INET);

	if (brf_nfq_send_config_cmd(brf_nfq_fd, BRF_NFQ_QUEUE_NUM,
				    NFQNL_CFG_CMD_BIND, AF_UNSPEC) < 0) {
		debug("nfq_setup: CMD_BIND queue %d: %s\n",
		      BRF_NFQ_QUEUE_NUM, strerror(errno));
		goto fail;
	}
	if (brf_nfq_send_config_params(brf_nfq_fd, BRF_NFQ_QUEUE_NUM,
				       NFQNL_COPY_PACKET, 0xffff) < 0) {
		debug("nfq_setup: COPY_PACKET mode: %s\n", strerror(errno));
		goto fail;
	}

	/* iptables rule -- catches ALL egress TCP; callback (C2b) filters
	 * by TCP-option kind + MP_JOIN subtype + option length. */
	if (system("iptables -I OUTPUT -p tcp -j NFQUEUE --queue-num 0") != 0) {
		debug("nfq_setup: iptables -I OUTPUT failed "
		      "(need CAP_NET_ADMIN?)\n");
		goto fail;
	}
	brf_nfq_iptables_inserted = 1;
	atexit(brf_nfq_cleanup);

	/* Spawn the worker thread (C2b).  Once running, packets arriving
	 * on the queue are forwarded with NF_ACCEPT and the first MP_JOIN
	 * ACK matching a pending mutation gets rewritten in-flight. */
	if (pthread_create(&brf_nfq_worker_thread, NULL,
			   brf_nfq_worker_loop, NULL) != 0) {
		debug("nfq_setup: pthread_create worker: %s\n",
		      strerror(errno));
		goto fail;
	}
	brf_nfq_worker_started = 1;

	brf_nfq_setup_done = 1;
	debug("nfq_setup: queue=%d fd=%d iptables+worker online\n",
	      BRF_NFQ_QUEUE_NUM, brf_nfq_fd);
	return 0;

fail:
	if (brf_nfq_fd >= 0) {
		close(brf_nfq_fd);
		brf_nfq_fd = -1;
	}
	return -1;
}

// Subset of struct mptcp_info we need (mptcpi_token + mptcpi_csum_enabled).
// We declare our own packed view to avoid pulling in linux/mptcp.h with a
// definition that may have grown additional trailing fields upstream.
struct brf_mptcp_info_short {
	uint8_t  mptcpi_subflows;
	uint8_t  mptcpi_add_addr_signal;
	uint8_t  mptcpi_add_addr_accepted;
	uint8_t  mptcpi_subflows_max;
	uint8_t  mptcpi_add_addr_signal_max;
	uint8_t  mptcpi_add_addr_accepted_max;
	uint8_t  _pad_csum_align[2];
	uint32_t mptcpi_flags;
	uint32_t mptcpi_token;
	uint64_t mptcpi_write_seq;
	uint64_t mptcpi_snd_una;
	uint64_t mptcpi_rcv_nxt;
	uint8_t  mptcpi_local_addr_used;
	uint8_t  mptcpi_local_addr_max;
	uint8_t  mptcpi_csum_enabled;
	/* rest of the struct is irrelevant for v01 */
} __attribute__((packed));

// ---------- Internal state ----------

struct brf_mptcp_subflow_state {
	uint32_t local_nonce;
	uint32_t remote_nonce;
	uint8_t  expected_thmac[8];   // server's truncated HMAC in SYN-ACK
	uint8_t  expected_hmac[20];   // client's full HMAC in ACK
	int      tcp_subflow_fd;
	bool     established;
};

struct brf_mptcp_pair_state {
	bool     in_use;

	// Endpoint sockets (set up in syz_mptcp_pair_init).
	int      server_listen_fd;
	int      server_msk_fd;
	int      client_msk_fd;

	// Server's bound port in network byte order.  Captured at pair_init
	// time so MP_JOIN's MPTCP_PM_CMD_SUBFLOW_CREATE knows where to point
	// the new subflow without having to call getsockname() again.
	uint16_t server_listen_port;

	// MP_CAPABLE-captured cryptographic material.  See
	// net/mptcp/crypto.c (mptcp_crypto_key_sha / _hmac_sha) for the
	// derivation rules these fields must respect.
	uint64_t local_key;            // client (our) MPTCP key
	uint64_t remote_key;           // server (peer) MPTCP key
	uint32_t token;                // upper 32 bits of SHA-256(BE remote_key)
	uint64_t idsn_local;           // bytes [24..31] of SHA-256(BE local_key)
	uint64_t idsn_remote;
	bool     csum_enabled;
	bool     deny_join_id0;

	// Per-subflow state, indexed [0..subflow_count).
	struct brf_mptcp_subflow_state subflows[MPTCP_MAX_SUBFLOWS_PER_PAIR];
	int      subflow_count;

	// Diagnostics surfaced to the fuzzer harness via syscall
	// return values; the kernel's reset reason is captured via
	// MIB counter deltas inside syz_mptcp_join_subflow.
	int      last_kernel_errno;
	uint32_t last_mib_rst_reason;
};

// Out-param struct for syz_mptcp_pair_init.  Field order + sizes
// MUST match the syzlang `mptcp_pair_state_t` in
// sys/linux/socket_mptcp_crypto.txt.
struct brf_mptcp_pair_state_out {
	int32_t  server_fd;
	int32_t  client_fd;
	int64_t  local_key;
	int64_t  remote_key;
	int32_t  token;
	int8_t   csum_enabled;
} __attribute__((packed));

static struct brf_mptcp_pair_state brf_mptcp_pair_pool[MPTCP_PAIR_POOL_SIZE];

// Reserved for a future v0N when netns isolation gets enabled.  v01
// does everything on loopback in the calling task's network namespace.
static bool brf_mptcp_netns_initialized __attribute__((unused)) = false;

// ---------- Pseudo-syscall implementations (v0 skeletons) ----------

/* Forward declaration: defined alongside syz_mptcp_join_subflow below.  Needed
 * here because syz_mptcp_pair_init must flip net.mptcp.pm_type=1 BEFORE
 * creating any msk (the pm_type is captured at msk-construction time). */
#if SYZ_EXECUTOR || __NR_syz_mptcp_join_subflow
static int brf_mptcp_ensure_executor_setup(void);
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_pair_init
/*
 * Create an MP_CAPABLE-established pair on loopback, capture the
 * cryptographic state (both keys + the derived token) via the patched
 * MPTCP_DEBUG_KEYS / MPTCP_INFO sockopts, and return a pool index that
 * subsequent pseudo-syscalls can reference via the mptcp_pair resource
 * type.
 *
 * v01 scope (matches design doc Section 5.1 after the 2026-05-15
 * simplification): no netns / veth / AF_PACKET; both sockets live on
 * 127.0.0.1 with ephemeral ports.  Wire-level injection is reserved
 * for the mutation paths in syz_mptcp_join_subflow / drive_traffic.
 *
 * Caveats:
 *  - The server_addr / client_addr inputs from syzlang are ignored in
 *    v01 (both endpoints bind to 127.0.0.1); future versions can
 *    honour them when netns or multi-address modes are introduced.
 *  - init_flags is parsed but only inspected for documentation; the
 *    MPTCP csum-mode flag is observed via getsockopt(MPTCP_INFO) after
 *    the handshake completes rather than forced via setsockopt.
 */
static long syz_mptcp_pair_init(volatile long a0, volatile long a1,
				volatile long a2, volatile long a3)
{
	struct brf_mptcp_pair_state_out *out =
		(struct brf_mptcp_pair_state_out *)a3;
	struct brf_mptcp_pair_state *pair;
	struct sockaddr_in srv_addr;
	struct mptcp_debug_keys keys;
	struct brf_mptcp_info_short info;
	socklen_t alen, klen, ilen;
	int slot, one = 1;

	(void)a0;	/* server_addr (sockaddr_storage)  -- ignored in v01 */
	(void)a1;	/* client_addr (sockaddr_storage)  -- ignored in v01 */
	(void)a2;	/* init_flags                      -- ignored in v01 */

	/* 0. Flip the netns to userspace PM mode BEFORE creating any msk:
	 *    msk->pm.pm_type is captured at sock-creation time
	 *    (mptcp_pm_data_reset). Without this, syz_mptcp_join_subflow's
	 *    MPTCP_PM_CMD_SUBFLOW_CREATE later returns "userspace PM not
	 *    selected".  ensure_executor_setup() is idempotent across calls
	 *    and across pseudo-syscalls. */
#if SYZ_EXECUTOR || __NR_syz_mptcp_join_subflow
	if (brf_mptcp_ensure_executor_setup() < 0)
		return -1;
#endif

	/* 1. Allocate a free pool slot. */
	for (slot = 0; slot < MPTCP_PAIR_POOL_SIZE; slot++)
		if (!brf_mptcp_pair_pool[slot].in_use)
			break;
	if (slot == MPTCP_PAIR_POOL_SIZE) {
		debug("syz_mptcp_pair_init: pool exhausted (size=%d)\n",
		      MPTCP_PAIR_POOL_SIZE);
		return -1;
	}
	pair = &brf_mptcp_pair_pool[slot];
	memset(pair, 0, sizeof(*pair));
	pair->in_use = true;
	pair->server_listen_fd = -1;
	pair->server_msk_fd = -1;
	pair->client_msk_fd = -1;
	/* memset() left tcp_subflow_fd == 0 across the pool which would later
	 * make pair_close() call close(0) (stdin); fix to -1 here. */
	for (int s = 0; s < MPTCP_MAX_SUBFLOWS_PER_PAIR; s++)
		pair->subflows[s].tcp_subflow_fd = -1;

	/* 2. Server socket: bind to ephemeral on 127.0.0.1, listen. */
	pair->server_listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (pair->server_listen_fd < 0) {
		debug("syz_mptcp_pair_init: server socket: %s\n",
		      strerror(errno));
		goto fail;
	}
	setsockopt(pair->server_listen_fd, SOL_SOCKET, SO_REUSEADDR,
		   &one, sizeof(one));

	memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = 0;	/* let the kernel pick */
	srv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(pair->server_listen_fd, (struct sockaddr *)&srv_addr,
		 sizeof(srv_addr)) < 0) {
		debug("syz_mptcp_pair_init: bind: %s\n", strerror(errno));
		goto fail;
	}
	alen = sizeof(srv_addr);
	if (getsockname(pair->server_listen_fd,
			(struct sockaddr *)&srv_addr, &alen) < 0) {
		debug("syz_mptcp_pair_init: getsockname: %s\n",
		      strerror(errno));
		goto fail;
	}
	pair->server_listen_port = srv_addr.sin_port;
	if (listen(pair->server_listen_fd, 1) < 0) {
		debug("syz_mptcp_pair_init: listen: %s\n", strerror(errno));
		goto fail;
	}

	/* 3. Client socket: drive MP_CAPABLE via connect(). */
	pair->client_msk_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (pair->client_msk_fd < 0) {
		debug("syz_mptcp_pair_init: client socket: %s\n",
		      strerror(errno));
		goto fail;
	}
	if (connect(pair->client_msk_fd, (struct sockaddr *)&srv_addr,
		    sizeof(srv_addr)) < 0) {
		debug("syz_mptcp_pair_init: connect: %s\n", strerror(errno));
		goto fail;
	}
	pair->server_msk_fd = accept(pair->server_listen_fd, NULL, NULL);
	if (pair->server_msk_fd < 0) {
		debug("syz_mptcp_pair_init: accept: %s\n", strerror(errno));
		goto fail;
	}

	/* 3.5. Drive a 1-byte round-trip to force the client-side
	 *      msk->fully_established transition.  After bare connect() +
	 *      accept(), the SERVER msk is fully_established (set in
	 *      mptcp_sock_create_accept on third-ACK reception) but the
	 *      CLIENT msk is not -- check_fully_established (net/mptcp/
	 *      options.c) only flips the client's flag when an inbound DSS
	 *      packet with use_ack arrives.  Without this, the subsequent
	 *      MPTCP_PM_CMD_SUBFLOW_CREATE from syz_mptcp_join_subflow gets
	 *      -ENOTCONN at __mptcp_subflow_connect (net/mptcp/subflow.c).
	 *      The round-trip is intentionally bidirectional so both sides
	 *      end up fully_established irrespective of which path the
	 *      kernel takes to detect the transition. */
	{
		char b = 'x';
		ssize_t n;
		n = send(pair->client_msk_fd, &b, 1, 0);
		if (n != 1) {
			debug("syz_mptcp_pair_init: prime send c->s: %s\n",
			      strerror(errno));
			goto fail;
		}
		n = recv(pair->server_msk_fd, &b, 1, MSG_WAITALL);
		if (n != 1) {
			debug("syz_mptcp_pair_init: prime recv on s: %s\n",
			      strerror(errno));
			goto fail;
		}
		n = send(pair->server_msk_fd, &b, 1, 0);
		if (n != 1) {
			debug("syz_mptcp_pair_init: prime send s->c: %s\n",
			      strerror(errno));
			goto fail;
		}
		n = recv(pair->client_msk_fd, &b, 1, MSG_WAITALL);
		if (n != 1) {
			debug("syz_mptcp_pair_init: prime recv on c: %s\n",
			      strerror(errno));
			goto fail;
		}
	}

	/* 4. Capture both MPTCP keys from the client side via the new
	 *    CONFIG_KCOV-gated MPTCP_DEBUG_KEYS getsockopt.  Local =
	 *    initiator (us); remote = responder (server).  These are
	 *    the values mptcp_crypto_hmac_sha would feed to HMAC for
	 *    subsequent MP_JOIN authentication. */
	memset(&keys, 0, sizeof(keys));
	klen = sizeof(keys);
	if (getsockopt(pair->client_msk_fd, SOL_MPTCP, MPTCP_DEBUG_KEYS,
		       &keys, &klen) < 0) {
		debug("syz_mptcp_pair_init: MPTCP_DEBUG_KEYS: %s\n",
		      strerror(errno));
		goto fail;
	}
	pair->local_key = keys.local_key;
	pair->remote_key = keys.remote_key;

	/* 5. Capture token + csum_enabled via MPTCP_INFO.  The token is
	 *    upper-32-bits SHA-256(BE remote_key) computed by the kernel
	 *    in mptcp_crypto_key_sha and stored in msk->token; reading
	 *    it back is cheaper than recomputing and guaranteed to
	 *    match whatever the kernel will check against. */
	memset(&info, 0, sizeof(info));
	ilen = sizeof(info);
	if (getsockopt(pair->client_msk_fd, SOL_MPTCP, MPTCP_INFO,
		       &info, &ilen) < 0) {
		debug("syz_mptcp_pair_init: MPTCP_INFO: %s\n",
		      strerror(errno));
		goto fail;
	}
	pair->token = info.mptcpi_token;
	pair->csum_enabled = info.mptcpi_csum_enabled;

	/* 6. Populate the syzlang out-param. */
	if (out) {
		out->server_fd = pair->server_listen_fd;
		out->client_fd = pair->client_msk_fd;
		out->local_key = (int64_t)pair->local_key;
		out->remote_key = (int64_t)pair->remote_key;
		out->token = (int32_t)pair->token;
		out->csum_enabled = (int8_t)pair->csum_enabled;
	}

	debug("syz_mptcp_pair_init: pair %d established, port %d, "
	      "token=0x%08x, csum=%d\n",
	      slot, ntohs(srv_addr.sin_port), pair->token,
	      pair->csum_enabled);
	return slot;

fail:
	if (pair->server_msk_fd    >= 0) close(pair->server_msk_fd);
	if (pair->client_msk_fd    >= 0) close(pair->client_msk_fd);
	if (pair->server_listen_fd >= 0) close(pair->server_listen_fd);
	memset(pair, 0, sizeof(*pair));
	return -1;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_join_subflow

/*
 * NORMAL-mode MP_JOIN implementation (v01).  Design doc Section 5.2.
 *
 * Mechanism: switch the netns to userspace MPTCP path-manager mode and use
 * MPTCP_PM_CMD_SUBFLOW_CREATE to explicitly initiate each MP_JOIN.  The
 * kernel-PM alternative (configure an endpoint with the `subflow` flag and
 * let the PM auto-fire) only triggers during MP_CAPABLE -> ESTABLISHED, which
 * has already happened by the time join_subflow is called -- wrong shape for
 * a stateful pseudo-syscall.
 *
 * The server's acceptance gate (mptcp_can_accept_new_subflow,
 * net/mptcp/subflow.c) in userspace-PM mode requires a multicast listener on
 * the mptcp_pm_events group: just binding a netlink socket and subscribing is
 * enough; we never need to read the events.
 *
 * v01 deliberate omissions (per task brief Pick-up-here block):
 *   - No nonce/thmac capture.  Kernel drives crypto end-to-end in NORMAL
 *     mode; capture only becomes load-bearing once mutation modes land.
 *   - No mutation paths.  Calls with nonce_mut/hmac_mut != NORMAL return -1.
 *   - No explicit `ip addr add 127.0.0.2/8 dev lo`.  Linux treats all of
 *     127/8 as local on lo via the auto-installed connected route, so
 *     kernel_bind() inside __mptcp_subflow_connect accepts 127.0.0.2 as a
 *     source address without explicit assignment.  Revisit if VM smoke
 *     surfaces EADDRNOTAVAIL.
 */

/* One-time-per-process state.  Lazy-initialised on first syz_mptcp_pair_init
 * (so MP_CAPABLE msks inherit the userspace PM type) or first
 * syz_mptcp_join_subflow (so direct re-entry from a repro still works). */
static int      brf_mptcp_setup_done = 0;
static int      brf_mptcp_genl_sock = -1;
static int      brf_mptcp_event_sock = -1;
static uint16_t brf_mptcp_pm_family_id = 0;

/* Parse a CTRL_CMD_GETFAMILY reply for both the family id and the id of the
 * "mptcp_pm_events" multicast group.  common_linux.h's
 * netlink_query_family_id only returns family id; we need both, hence a
 * dedicated implementation. */
static int brf_mptcp_resolve_pm_family(int sock,
				       uint16_t *family_id_out,
				       uint32_t *event_grp_id_out)
{
	char buf[1024];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct genlmsghdr *ghdr;
	struct nlattr *attr;
	const char fname[] = "mptcp_pm";
	const size_t fname_sz = sizeof(fname);
	ssize_t n;
	uint16_t fid = 0;
	uint32_t egid = 0;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = GENL_ID_CTRL;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq   = 1;
	nlh->nlmsg_pid   = 0;
	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	ghdr->cmd     = CTRL_CMD_GETFAMILY;
	ghdr->version = 1;
	attr = (struct nlattr *)((char *)NLMSG_DATA(nlh) +
				 NLMSG_ALIGN(sizeof(*ghdr)));
	attr->nla_type = CTRL_ATTR_FAMILY_NAME;
	attr->nla_len  = NLA_HDRLEN + fname_sz;
	memcpy((char *)attr + NLA_HDRLEN, fname, fname_sz);
	nlh->nlmsg_len = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ghdr)) +
			 NLA_ALIGN(attr->nla_len);

	if (send(sock, buf, nlh->nlmsg_len, 0) < 0) {
		debug("mptcp_setup: send GETFAMILY: %s\n", strerror(errno));
		return -1;
	}
	n = recv(sock, buf, sizeof(buf), 0);
	if (n < 0) {
		debug("mptcp_setup: recv GETFAMILY: %s\n", strerror(errno));
		return -1;
	}

	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *ne = (struct nlmsgerr *)NLMSG_DATA(nlh);
		debug("mptcp_setup: GETFAMILY err=%d (%s)\n",
		      ne->error, strerror(-ne->error));
		errno = -ne->error;
		return -1;
	}
	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	attr = (struct nlattr *)((char *)NLMSG_DATA(nlh) +
				 NLMSG_ALIGN(sizeof(*ghdr)));
	ssize_t left = nlh->nlmsg_len - NLMSG_HDRLEN -
		       NLMSG_ALIGN(sizeof(*ghdr));

	while (left >= (ssize_t)NLA_HDRLEN &&
	       attr->nla_len >= NLA_HDRLEN &&
	       (ssize_t)NLA_ALIGN(attr->nla_len) <= left) {
		switch (attr->nla_type & NLA_TYPE_MASK) {
		case CTRL_ATTR_FAMILY_ID:
			if (attr->nla_len >= NLA_HDRLEN + sizeof(uint16_t))
				fid = *(uint16_t *)((char *)attr + NLA_HDRLEN);
			break;
		case CTRL_ATTR_MCAST_GROUPS: {
			/* nested array of unnamed nested attributes, each
			 * holding {CTRL_ATTR_MCAST_GRP_NAME,
			 *          CTRL_ATTR_MCAST_GRP_ID} */
			char *gpos = (char *)attr + NLA_HDRLEN;
			char *gend = (char *)attr + attr->nla_len;
			while (gpos + NLA_HDRLEN <= gend) {
				struct nlattr *grp = (struct nlattr *)gpos;
				if (grp->nla_len < NLA_HDRLEN ||
				    gpos + grp->nla_len > gend)
					break;
				char *ipos = (char *)grp + NLA_HDRLEN;
				char *iend = (char *)grp + grp->nla_len;
				const char *gname = NULL;
				uint32_t gid = 0;
				while (ipos + NLA_HDRLEN <= iend) {
					struct nlattr *inner =
						(struct nlattr *)ipos;
					if (inner->nla_len < NLA_HDRLEN ||
					    ipos + inner->nla_len > iend)
						break;
					if ((inner->nla_type & NLA_TYPE_MASK) ==
					    CTRL_ATTR_MCAST_GRP_NAME)
						gname = (const char *)inner +
							NLA_HDRLEN;
					else if ((inner->nla_type & NLA_TYPE_MASK) ==
						 CTRL_ATTR_MCAST_GRP_ID &&
						 inner->nla_len >=
							 NLA_HDRLEN +
								 sizeof(uint32_t))
						gid = *(uint32_t *)((char *)inner +
								    NLA_HDRLEN);
					ipos += NLA_ALIGN(inner->nla_len);
				}
				if (gname && strcmp(gname,
						    "mptcp_pm_events") == 0)
					egid = gid;
				gpos += NLA_ALIGN(grp->nla_len);
			}
			break;
		}
		}
		left -= NLA_ALIGN(attr->nla_len);
		attr = (struct nlattr *)((char *)attr +
					 NLA_ALIGN(attr->nla_len));
	}
	if (fid == 0 || egid == 0) {
		debug("mptcp_setup: GETFAMILY parse incomplete: "
		      "fid=%u egid=%u\n", fid, egid);
		errno = ENOENT;
		return -1;
	}
	*family_id_out    = fid;
	*event_grp_id_out = egid;
	return 0;
}

/* Idempotent.  Sets net.mptcp.pm_type=1, opens a genl socket for sending PM
 * commands, opens a second genl socket subscribed to mptcp_pm_events so the
 * server-side acceptance gate (mptcp_userspace_pm_active) returns true.
 * Stashes state in the brf_mptcp_* statics above. */
static int brf_mptcp_ensure_executor_setup(void)
{
	struct sockaddr_nl sa;
	uint32_t event_grp_id = 0;

	if (brf_mptcp_setup_done)
		return 0;

	if (!write_file("/proc/sys/net/mptcp/pm_type", "1")) {
		debug("mptcp_setup: write pm_type=1 failed: %s\n",
		      strerror(errno));
		return -1;
	}

	brf_mptcp_genl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (brf_mptcp_genl_sock < 0) {
		debug("mptcp_setup: socket(genl): %s\n", strerror(errno));
		return -1;
	}
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(brf_mptcp_genl_sock, (struct sockaddr *)&sa,
		 sizeof(sa)) < 0) {
		debug("mptcp_setup: bind(genl): %s\n", strerror(errno));
		goto fail;
	}

	if (brf_mptcp_resolve_pm_family(brf_mptcp_genl_sock,
					&brf_mptcp_pm_family_id,
					&event_grp_id) < 0)
		goto fail;

	brf_mptcp_event_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (brf_mptcp_event_sock < 0) {
		debug("mptcp_setup: socket(event): %s\n", strerror(errno));
		goto fail;
	}
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(brf_mptcp_event_sock, (struct sockaddr *)&sa,
		 sizeof(sa)) < 0) {
		debug("mptcp_setup: bind(event): %s\n", strerror(errno));
		goto fail;
	}
	if (setsockopt(brf_mptcp_event_sock, SOL_NETLINK,
		       NETLINK_ADD_MEMBERSHIP, &event_grp_id,
		       sizeof(event_grp_id)) < 0) {
		debug("mptcp_setup: NETLINK_ADD_MEMBERSHIP "
		      "mptcp_pm_events: %s\n", strerror(errno));
		goto fail;
	}

	brf_mptcp_setup_done = 1;
	debug("mptcp_setup: pm_type=1, family_id=%u event_grp_id=%u, "
	      "listener active\n", brf_mptcp_pm_family_id, event_grp_id);
	return 0;

fail:
	if (brf_mptcp_event_sock >= 0) {
		close(brf_mptcp_event_sock);
		brf_mptcp_event_sock = -1;
	}
	if (brf_mptcp_genl_sock >= 0) {
		close(brf_mptcp_genl_sock);
		brf_mptcp_genl_sock = -1;
	}
	return -1;
}

/* Send one MPTCP_PM_CMD_SUBFLOW_CREATE and wait for its NLMSG_ERROR ack.
 *
 * Byte-order gotcha (kernel uapi quirk):
 *   - Addresses (MPTCP_PM_ADDR_ATTR_ADDR4) are network-byte-order in the
 *     attribute; the kernel reads them raw via nla_get_in_addr.
 *   - Ports (MPTCP_PM_ADDR_ATTR_PORT) are HOST-byte-order in the attribute;
 *     the kernel applies htons() on the way in (net/mptcp/pm_netlink.c:86,
 *     `addr->port = htons(nla_get_u16(...))`).
 *   Passing the port in network order makes the kernel byteswap a second
 *   time and aim the MP_JOIN SYN at a wrong port -- looks like a silent
 *   failure with no debug, no SS entry, no MIB increment.
 */
static int brf_mptcp_genl_subflow_create(uint32_t token, uint8_t addr_id,
					 uint32_t addr_flags,
					 uint32_t local_addr_be,
					 uint16_t local_port_h,
					 uint32_t remote_addr_be,
					 uint16_t remote_port_h)
{
	char buf[256];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct genlmsghdr *ghdr;
	struct nlattr *attr, *nest;
	char *p;
	ssize_t n;
#define BRF_PUT_ATTR(typ, src, sz) do {				\
		attr = (struct nlattr *)p;			\
		attr->nla_type = (typ);				\
		attr->nla_len  = NLA_HDRLEN + (sz);		\
		memcpy((char *)attr + NLA_HDRLEN, (src), (sz));	\
		p += NLA_ALIGN(attr->nla_len);			\
	} while (0)

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = brf_mptcp_pm_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = 2;
	nlh->nlmsg_pid   = 0;
	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	ghdr->cmd     = MPTCP_PM_CMD_SUBFLOW_CREATE;
	ghdr->version = MPTCP_PM_VER;

	p = (char *)NLMSG_DATA(nlh) + NLMSG_ALIGN(sizeof(*ghdr));

	BRF_PUT_ATTR(MPTCP_PM_ATTR_TOKEN, &token, sizeof(token));

	/* MPTCP_PM_ATTR_ADDR: nested local-address entry.  FLAGS is
	 * optional in the kernel parser; only included when non-zero
	 * to keep the SUBFLOW_CREATE call shape identical for the
	 * NORMAL/backup=0 path. */
	{
		uint16_t fam_v = AF_INET;
		nest = (struct nlattr *)p;
		nest->nla_type = MPTCP_PM_ATTR_ADDR | NLA_F_NESTED;
		p += NLA_HDRLEN;
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_FAMILY, &fam_v,
			     sizeof(fam_v));
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_ID, &addr_id,
			     sizeof(addr_id));
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_ADDR4, &local_addr_be,
			     sizeof(local_addr_be));
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_PORT, &local_port_h,
			     sizeof(local_port_h));
		if (addr_flags)
			BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_FLAGS, &addr_flags,
				     sizeof(addr_flags));
		nest->nla_len = p - (char *)nest;
	}

	/* MPTCP_PM_ATTR_ADDR_REMOTE: nested remote-address entry. */
	{
		uint16_t fam_v = AF_INET;
		nest = (struct nlattr *)p;
		nest->nla_type = MPTCP_PM_ATTR_ADDR_REMOTE | NLA_F_NESTED;
		p += NLA_HDRLEN;
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_FAMILY, &fam_v,
			     sizeof(fam_v));
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_ADDR4, &remote_addr_be,
			     sizeof(remote_addr_be));
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_PORT, &remote_port_h,
			     sizeof(remote_port_h));
		nest->nla_len = p - (char *)nest;
	}

	nlh->nlmsg_len = p - buf;

	if (send(brf_mptcp_genl_sock, buf, nlh->nlmsg_len, 0) < 0) {
		debug("subflow_create: send: %s\n", strerror(errno));
		return -1;
	}

	n = recv(brf_mptcp_genl_sock, buf, sizeof(buf), 0);
	if (n < 0) {
		debug("subflow_create: recv: %s\n", strerror(errno));
		return -1;
	}
	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type != NLMSG_ERROR) {
		debug("subflow_create: unexpected ack type %u\n",
		      nlh->nlmsg_type);
		errno = EPROTO;
		return -1;
	}
	{
		struct nlmsgerr *ne = (struct nlmsgerr *)NLMSG_DATA(nlh);
		if (ne->error) {
			debug("subflow_create: kernel err=%d (%s)\n",
			      ne->error, strerror(-ne->error));
			errno = -ne->error;
			return -1;
		}
	}
	return 0;
#undef BRF_PUT_ATTR
}

static long syz_mptcp_join_subflow(volatile long a0, volatile long a1,
				   volatile long a2, volatile long a3,
				   volatile long a4)
{
	struct brf_mptcp_pair_state *pair;
	long slot = a0;
	uint8_t addr_id   = (uint8_t)a1;
	uint8_t backup    = (uint8_t)a2;	/* syzlang clamps to [0:1] */
	uint8_t nonce_mut = (uint8_t)a3;
	uint8_t hmac_mut  = (uint8_t)a4;
	int sub_slot;
	int retries;
	const uint32_t local_addr_be  = htonl(0x7f000002);
	const uint32_t remote_addr_be = htonl(0x7f000001);

	/* v01: only NORMAL mode.  Mutation enum values are part of the
	 * syzlang surface so the corpus generator emits them, but the
	 * executor C side rejects them rather than half-implementing. */
	if (nonce_mut != MPTCP_NONCE_NORMAL ||
	    hmac_mut  != MPTCP_HMAC_NORMAL) {
		debug("syz_mptcp_join_subflow: mutation modes not "
		      "implemented in v01 (nonce_mut=%u hmac_mut=%u)\n",
		      nonce_mut, hmac_mut);
		return -1;
	}

	if (brf_mptcp_ensure_executor_setup() < 0)
		return -1;

	if (slot < 0 || slot >= MPTCP_PAIR_POOL_SIZE) {
		debug("syz_mptcp_join_subflow: slot %ld out of range\n", slot);
		return -1;
	}
	pair = &brf_mptcp_pair_pool[slot];
	if (!pair->in_use) {
		debug("syz_mptcp_join_subflow: slot %ld not in use\n", slot);
		return -1;
	}
	if (pair->subflow_count >= MPTCP_MAX_SUBFLOWS_PER_PAIR) {
		debug("syz_mptcp_join_subflow: pair %ld subflow pool full "
		      "(%d/%d)\n", slot, pair->subflow_count,
		      MPTCP_MAX_SUBFLOWS_PER_PAIR);
		return -1;
	}
	sub_slot = pair->subflow_count;

	/* The kernel rejects MPTCP address id 0 ("invalid addr id" in
	 * mptcp_userspace_pm_append_new_local_addr).  syzlang's addr_id
	 * is signed int8, so we coerce zero to 1; non-zero values pass
	 * through. */
	if (addr_id == 0)
		addr_id = 1;

	/* server_listen_port is stored in NBO (sin_port form); the genl
	 * port attribute wants host-byte order -- see byte-order comment
	 * on brf_mptcp_genl_subflow_create.
	 *
	 * addr_flags: SUBFLOW is set unconditionally by the kernel handler
	 * (mptcp_pm_nl_subflow_create_doit, pm_userspace.c).  SIGNAL is
	 * rejected by the same handler.  BACKUP is the only flag we set
	 * here, when the syzlang backup parameter is 1 -- this puts the
	 * new subflow on the backup-priority code path
	 * (mptcp_subflow_set_active / MP_PRIO handling). */
	uint32_t addr_flags = backup ? MPTCP_PM_ADDR_FLAG_BACKUP : 0;
	if (brf_mptcp_genl_subflow_create(pair->token, addr_id, addr_flags,
					  local_addr_be,  0,
					  remote_addr_be,
					  ntohs(pair->server_listen_port)) < 0)
		return -1;

	/* SUBFLOW_CREATE returns after __mptcp_subflow_connect() initiated
	 * the SYN; the server-side msk's pm.extra_subflows then increments
	 * as soon as the kernel's MPTCP option parser accepts the incoming
	 * MP_JOIN (mptcp_pm_allow_new_subflow path).  Poll MPTCP_INFO until
	 * the count goes up, with a ~1s ceiling -- a loopback handshake
	 * should complete in well under a millisecond. */
	for (retries = 0; retries < 20; retries++) {
		struct brf_mptcp_info_short info;
		socklen_t ilen = sizeof(info);
		memset(&info, 0, sizeof(info));
		if (getsockopt(pair->server_msk_fd, SOL_MPTCP, MPTCP_INFO,
			       &info, &ilen) == 0 &&
		    info.mptcpi_subflows >= 1) {
			pair->subflows[sub_slot].established = true;
			pair->subflow_count++;
			debug("syz_mptcp_join_subflow: pair=%ld subflow=%d "
			      "established (server mptcpi_subflows=%u, "
			      "polls=%d)\n", slot, sub_slot,
			      info.mptcpi_subflows, retries + 1);
			return 0;
		}
		usleep(50000);	/* 50 ms */
	}
	debug("syz_mptcp_join_subflow: pair=%ld subflow=%d not established "
	      "within ~1s\n", slot, sub_slot);
	return -1;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_drive_traffic
static long syz_mptcp_drive_traffic(volatile long a0, volatile long a1,
				    volatile long a2, volatile long a3,
				    volatile long a4)
{
	// a0: pair, a1: subflow_id, a2: data ptr, a3: len, a4: map_mut
	debug("syz_mptcp_drive_traffic: not implemented (v0 skeleton)\n");
	return -1;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_send_control
static long syz_mptcp_send_control(volatile long a0, volatile long a1,
				   volatile long a2)
{
	// a0: pair, a1: subflow_id, a2: suboption
	debug("syz_mptcp_send_control: not implemented (v0 skeleton)\n");
	return -1;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_pair_close
static long syz_mptcp_pair_close(volatile long a0)
{
	long slot = a0;
	struct brf_mptcp_pair_state *pair;
	int i;

	if (slot < 0 || slot >= MPTCP_PAIR_POOL_SIZE) {
		debug("syz_mptcp_pair_close: slot %ld out of range\n", slot);
		return -1;
	}
	pair = &brf_mptcp_pair_pool[slot];
	if (!pair->in_use) {
		debug("syz_mptcp_pair_close: slot %ld not in use\n", slot);
		return -1;
	}

	for (i = 0; i < pair->subflow_count && i < MPTCP_MAX_SUBFLOWS_PER_PAIR;
	     i++) {
		if (pair->subflows[i].tcp_subflow_fd >= 0)
			close(pair->subflows[i].tcp_subflow_fd);
	}
	if (pair->server_msk_fd    >= 0) close(pair->server_msk_fd);
	if (pair->client_msk_fd    >= 0) close(pair->client_msk_fd);
	if (pair->server_listen_fd >= 0) close(pair->server_listen_fd);
	memset(pair, 0, sizeof(*pair));
	return 0;
}
#endif

#endif // BRF_COMMON_LINUX_MPTCP_H
