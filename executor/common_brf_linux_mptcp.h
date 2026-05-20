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

#define MPTCP_PAIR_POOL_SIZE         64
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
static volatile int brf_nfq_pending_hmac_mut  = 0;  /* MPTCP_HMAC_NORMAL */
static volatile int brf_nfq_pending_nonce_mut = 0;  /* MPTCP_NONCE_NORMAL */
static volatile int brf_nfq_pending_map_mut   = 0;  /* MPTCP_MAP_NORMAL */
/* v05 multi-pair: per-mutation-type fired flag so concurrent calls of
 * different kinds (e.g., pair A's hmac_mut + pair B's map_mut) each
 * fire independently instead of racing on a single mut_fired.  Worker
 * checks the relevant flag per option type.  brf_nfq_mut_fired remains
 * as a legacy any-mutation-fired indicator for poll loops that just
 * want "did anything happen". */
static volatile int brf_nfq_mut_fired_hmac    = 0;
static volatile int brf_nfq_mut_fired_nonce   = 0;
static volatile int brf_nfq_mut_fired_map     = 0;
static volatile int brf_nfq_mut_fired         = 0;  /* OR of the three */
static volatile int brf_nfq_worker_stop       = 0;
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
	/* Static (BSS) instead of stack -- syz-executor uses
	 * -Wframe-larger-than=16384 and only the worker thread calls
	 * this so single-instance reuse is safe. */
	static char buf[65536 + 256];
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

/* Walk TCP options.  Returns pointer to the MP_JOIN option's kind byte
 * if it matches kind=30, subtype=1, AND the caller-specified expected
 * length.  Use expected_len=24 for MP_JOIN ACK, 12 for MP_JOIN SYN. */
static uint8_t *brf_nfq_find_mp_join_option(uint8_t *tcp_seg, int tcp_hlen,
					    uint8_t expected_len)
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
		/* MP_JOIN: kind=30, subtype (high nibble of byte 2) = 1.
		 * Length distinguishes SYN(12) / SYN-ACK(16) / ACK(24). */
		if (kind == 30 && len == expected_len &&
		    (opts[i + 2] >> 4) == 1)
			return &opts[i];
		i += len;
	}
	return NULL;
}

/* Backwards-compat alias; callers pre-C3 expected MP_JOIN ACK. */
static inline uint8_t *brf_nfq_find_mp_join_ack(uint8_t *tcp_seg, int tcp_hlen)
{
	return brf_nfq_find_mp_join_option(tcp_seg, tcp_hlen, 24);
}

/* Find MP_JOIN SYN option (kind=30, len=12, subtype=1).  Nonce is at
 * option offset 8 (4 bytes); token is at option offset 4 (4 bytes). */
static inline uint8_t *brf_nfq_find_mp_join_syn(uint8_t *tcp_seg, int tcp_hlen)
{
	return brf_nfq_find_mp_join_option(tcp_seg, tcp_hlen, 12);
}

/* Find DSS option (kind=30, subtype=2).  Variable length depending on
 * flags m/M/a/A in option byte 3:
 *   - A=1: includes a DSN_ACK (4 bytes if a=0, 8 bytes if a=1)
 *   - M=1: includes a mapping (4-byte DSN if m=0 / 8-byte DSN if m=1,
 *          + 4-byte subflow seq + 2-byte length + optional 2-byte csum)
 * For mutation we don't need to fully parse, just locate the option. */
static uint8_t *brf_nfq_find_dss_option(uint8_t *tcp_seg, int tcp_hlen)
{
	int optlen = tcp_hlen - (int)sizeof(struct tcphdr);
	uint8_t *opts = tcp_seg + sizeof(struct tcphdr);
	int i = 0;
	while (i < optlen) {
		uint8_t kind = opts[i];
		if (kind == 0)
			break;
		if (kind == 1) {
			i++;
			continue;
		}
		if (i + 1 >= optlen)
			break;
		uint8_t len = opts[i + 1];
		if (len < 2 || i + len > optlen)
			break;
		/* DSS: kind=30, subtype=2 in high nibble of byte 2 */
		if (kind == 30 && len >= 4 &&
		    (opts[i + 2] >> 4) == 2)
			return &opts[i];
		i += len;
	}
	return NULL;
}

/* Apply DSS mutation.  DSS option layout (RFC 8684 Section 3.3) is
 * variable -- depends on flag bits in opt[3] (m, M, a, A).  Rather
 * than parse the variant, mutate at offsets that are present in the
 * common variants; depending on actual flags this hits either the
 * DSN_ACK or the DSN mapping or the subflow_seq field.  All variants
 * exercise the parser in net/mptcp/options.c either way. */
static void brf_nfq_apply_map_mut(uint8_t *opt, int mut_type)
{
	uint8_t opt_len = opt[1];

	switch (mut_type) {
	case MPTCP_MAP_STALE_SEQ:
		/* Subtract 0x1000 from the first 32-bit field after the
		 * option header.  Hits DSN_ACK if A=1, else DSN. */
		if (opt_len >= 8) {
			uint32_t v;
			memcpy(&v, opt + 4, 4);
			v = htonl(ntohl(v) - 0x1000);
			memcpy(opt + 4, &v, 4);
		}
		break;
	case MPTCP_MAP_OFF_BY_ONE:
		/* Add 1 to the first 32-bit field.  Subtle: trips
		 * out-of-order / sequence-boundary code. */
		if (opt_len >= 8) {
			uint32_t v;
			memcpy(&v, opt + 4, 4);
			v = htonl(ntohl(v) + 1);
			memcpy(opt + 4, &v, 4);
		}
		break;
	case MPTCP_MAP_INFINITE:
		/* Set M=1 in opt[3] (mapping present flag).  If the packet
		 * didn't have a mapping before, this confuses the parser
		 * into expecting one. */
		opt[3] |= 0x40;
		break;
	case MPTCP_MAP_HOLE:
		/* Mutate subflow_seq (usually at offset 8 when both M=1
		 * and a=0,A=1 -- common case).  Subtract 0x100 to create
		 * an apparent sequence gap. */
		if (opt_len >= 12) {
			uint32_t v;
			memcpy(&v, opt + 8, 4);
			v = htonl(ntohl(v) - 0x100);
			memcpy(opt + 8, &v, 4);
		}
		break;
	default:
		break;
	}
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
	case MPTCP_HMAC_TRUNCATE: {
		/* Shorten the option from 24 bytes to 12, pad the rest of
		 * the original option slot with TCPOPT_NOP (kind=1, single
		 * byte each) so total TCP option length stays unchanged --
		 * required for TCP header layout consistency.
		 *
		 * Effect on parser: the truncated MP_JOIN ACK looks like
		 * an MP_JOIN SYN by length (12 = SYN length) but still
		 * carries subtype=1, with the HMAC bytes gone.  Server's
		 * check_fully_established path hits length-mismatch and
		 * subtype-vs-length validation code that the fixed-length
		 * mutations never reach.  Bug-fertile because the
		 * length/subtype invariants are checked in multiple
		 * places. */
		opt[1] = 12;
		for (int i = 12; i < 24; i++)
			opt[i] = 1;	/* TCPOPT_NOP */
		break;
	}
	case MPTCP_HMAC_SWAP: {
		/* Swap the two halves of the 20-byte HMAC.  Same length,
		 * so no TCP option resizing.  HMAC validation fails for
		 * the same reason as BIT_FLIP, but the byte pattern is
		 * structurally different (two contiguous valid-looking
		 * 8-byte runs swapped) -- exercises any kernel code that
		 * looks at the HMAC bytes beyond just "compare full
		 * digest".  Note: HMAC is 20 bytes so the two halves are
		 * unequal; swap [4..13] with [14..23] = 10-byte swap. */
		uint8_t tmp[10];
		memcpy(tmp, &opt[4], 10);
		memcpy(&opt[4], &opt[14], 10);
		memcpy(&opt[14], tmp, 10);
		break;
	}
	default:
		break;
	}
}

/* Rotating prior-nonce buffer for MPTCP_NONCE_REPLAY (v05.2).
 * Initialized to a sentinel; each REPLAY mutation overwrites the
 * outgoing SYN's nonce with this saved value AND saves the original
 * nonce as the next round's replay target.  Effect: each REPLAY
 * cycle injects a stale nonce + carries forward the current one.
 * Tests the kernel's nonce-uniqueness assumptions across MP_JOIN
 * attempts on the same token (mptcp_token_join_request and
 * subflow_token_join_request paths). */
static uint8_t brf_nfq_replay_nonce[4] = {0xde, 0xad, 0xbe, 0xef};

/* Apply nonce mutation to MP_JOIN SYN option bytes.  Option layout:
 *   byte 0:  Kind = 30
 *   byte 1:  Length = 12
 *   byte 2:  Subtype (high 4) = 1, addr_id flags (low 4)
 *   byte 3:  Address ID
 *   bytes 4-7:  Receiver's Token (4 bytes)
 *   bytes 8-11: Sender's Random Nonce (4 bytes)  <-- our target
 *
 * The server's HMAC is computed over (server_key, client_key,
 * server_nonce, client_nonce).  Mutating the client nonce makes the
 * client's HMAC computation diverge from what server expects -- the
 * SYN-ACK's truncated HMAC won't match and the CLIENT side rejects
 * via subflow_thmac_valid (different gate than HMAC_BIT_FLIP, which
 * targets the server's ACK validation). */
static void brf_nfq_apply_nonce_mut(uint8_t *opt, int mut_type)
{
	switch (mut_type) {
	case MPTCP_NONCE_ZERO:
		memset(&opt[8], 0, 4);
		break;
	case MPTCP_NONCE_FLIP_HIGH:
		opt[8] ^= 0x80;
		break;
	case MPTCP_NONCE_FLIP_LOW:
		opt[11] ^= 0x01;
		break;
	case MPTCP_NONCE_REPLAY: {
		/* Swap the SYN's current nonce with the saved one --
		 * inject the saved nonce, then save the (just-replaced)
		 * current nonce as the next REPLAY target.  Creates a
		 * carry-forward chain across calls. */
		uint8_t tmp[4];
		memcpy(tmp, &opt[8], 4);
		memcpy(&opt[8], brf_nfq_replay_nonce, 4);
		memcpy(brf_nfq_replay_nonce, tmp, 4);
		break;
	}
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
	/* Static (BSS) instead of stack -- see comment in
	 * brf_nfq_send_verdict.  This function is the sole producer of
	 * its own buffer and the only worker thread. */
	static char buf[65536];

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

		/* Default: pass through unchanged.  Otherwise dispatch on
		 * which MP_JOIN variant the packet carries and which
		 * mutation kind is currently pending. */
		int  applied_mut = 0;
		const char *applied_what = NULL;
		struct iphdr  *ip  = NULL;
		struct tcphdr *tcp = NULL;

		if (payload && payload_len >=
		    (int)(sizeof(struct iphdr) + sizeof(struct tcphdr))) {
			ip = (struct iphdr *)payload;
			int ip_hlen = ip->ihl * 4;
			if (ip->protocol == IPPROTO_TCP &&
			    payload_len >= ip_hlen + (int)sizeof(struct tcphdr)) {
				tcp = (struct tcphdr *)(payload + ip_hlen);
				int tcp_hlen = tcp->doff * 4;
				if (payload_len >= ip_hlen + tcp_hlen) {
					/* v05 multi-pair: each mutation kind
					 * has its own fired flag, so a pending
					 * HMAC mutation doesn't get blocked by
					 * a prior map_mut firing.  Each branch
					 * checks its own type. */
					/* MP_JOIN ACK egress (hmac). */
					if (tcp->ack && !tcp->syn &&
					    !tcp->fin && !tcp->rst &&
					    !BRF_ATOMIC_LOAD(&brf_nfq_mut_fired_hmac)) {
						uint8_t *opt = brf_nfq_find_mp_join_ack(
							(uint8_t *)tcp, tcp_hlen);
						int hmac_mut = BRF_ATOMIC_LOAD(
						    &brf_nfq_pending_hmac_mut);
						if (opt && hmac_mut != MPTCP_HMAC_NORMAL) {
							brf_nfq_apply_hmac_mut(
								opt, hmac_mut);
							applied_mut = hmac_mut;
							applied_what = "MP_JOIN ACK hmac";
							BRF_ATOMIC_STORE(
								&brf_nfq_mut_fired_hmac, 1);
						}
					}
					/* DSS egress (map). */
					if (!applied_mut &&
					    tcp->ack && !tcp->syn &&
					    !tcp->fin && !tcp->rst &&
					    !BRF_ATOMIC_LOAD(&brf_nfq_mut_fired_map)) {
						uint8_t *opt = brf_nfq_find_dss_option(
							(uint8_t *)tcp, tcp_hlen);
						int map_mut = BRF_ATOMIC_LOAD(
						    &brf_nfq_pending_map_mut);
						if (opt && map_mut != MPTCP_MAP_NORMAL) {
							brf_nfq_apply_map_mut(
								opt, map_mut);
							applied_mut = map_mut;
							applied_what = "DSS map";
							BRF_ATOMIC_STORE(
								&brf_nfq_mut_fired_map, 1);
						}
					}
					/* MP_JOIN SYN egress (nonce). */
					else if (tcp->syn && !tcp->ack &&
						 !tcp->fin && !tcp->rst &&
						 !BRF_ATOMIC_LOAD(&brf_nfq_mut_fired_nonce)) {
						uint8_t *opt = brf_nfq_find_mp_join_syn(
							(uint8_t *)tcp, tcp_hlen);
						int nonce_mut = BRF_ATOMIC_LOAD(
						    &brf_nfq_pending_nonce_mut);
						if (opt && nonce_mut != MPTCP_NONCE_NORMAL) {
							brf_nfq_apply_nonce_mut(
								opt, nonce_mut);
							applied_mut = nonce_mut;
							applied_what = "MP_JOIN SYN nonce";
							BRF_ATOMIC_STORE(
								&brf_nfq_mut_fired_nonce, 1);
						}
					}
				}
			}
		}

		if (applied_mut != 0) {
			brf_nfq_tcp_compute_checksum_ipv4(tcp, ip);
			/* legacy mut_fired = OR of types; consumers that
			 * just want "did anything fire" still work. */
			BRF_ATOMIC_STORE(&brf_nfq_mut_fired, 1);
			debug("nfq_worker: applied %s mut=%d\n",
			      applied_what, applied_mut);
			brf_nfq_send_verdict(brf_nfq_fd, queue_num, packet_id,
					     NF_ACCEPT, payload,
					     (uint16_t)payload_len);
			continue;
		}

		brf_nfq_send_verdict(brf_nfq_fd, queue_num, packet_id,
				     NF_ACCEPT, NULL, 0);
	}
	return NULL;
}

/* Idempotent setup.  Called lazily from syz_mptcp_join_subflow when a
 * mutation mode is requested.  Returns 0 on success; on failure leaves
 * the static state cleaned up so a retry can run. */
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

/* MPTCP_PM_CMD_ANNOUNCE: tell the kernel to announce an additional
 * address via the ADD_ADDR option in the next outgoing packet on the
 * given token's connection.  Used by the v05.3 pseudo-syscall
 * syz_mptcp_pm_announce to exercise the path manager's add-addr
 * emit + peer-side mptcp_pm_add_addr_received parse paths -- entirely
 * unreached by the v02/v04 corpus, where we only do SUBFLOW_CREATE.
 *
 * Same byte-order quirk as subflow_create: port is host-order in the
 * attribute (kernel htons() on the way in). */
static int brf_mptcp_genl_announce(uint32_t token, uint8_t addr_id,
				   uint32_t addr_be, uint16_t port_h,
				   uint32_t addr_flags)
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
	nlh->nlmsg_seq   = 3;
	nlh->nlmsg_pid   = 0;
	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	ghdr->cmd     = MPTCP_PM_CMD_ANNOUNCE;
	ghdr->version = MPTCP_PM_VER;

	p = (char *)NLMSG_DATA(nlh) + NLMSG_ALIGN(sizeof(*ghdr));

	BRF_PUT_ATTR(MPTCP_PM_ATTR_TOKEN, &token, sizeof(token));

	{
		uint16_t fam_v = AF_INET;
		nest = (struct nlattr *)p;
		nest->nla_type = MPTCP_PM_ATTR_ADDR | NLA_F_NESTED;
		p += NLA_HDRLEN;
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_FAMILY, &fam_v, sizeof(fam_v));
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_ID, &addr_id, sizeof(addr_id));
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_ADDR4, &addr_be,
			     sizeof(addr_be));
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_PORT, &port_h, sizeof(port_h));
		if (addr_flags)
			BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_FLAGS, &addr_flags,
				     sizeof(addr_flags));
		nest->nla_len = p - (char *)nest;
	}

	nlh->nlmsg_len = p - buf;

	if (send(brf_mptcp_genl_sock, buf, nlh->nlmsg_len, 0) < 0) {
		debug("pm_announce: send: %s\n", strerror(errno));
		return -1;
	}
	n = recv(brf_mptcp_genl_sock, buf, sizeof(buf), 0);
	if (n < 0) {
		debug("pm_announce: recv: %s\n", strerror(errno));
		return -1;
	}
	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type != NLMSG_ERROR) {
		debug("pm_announce: unexpected ack type %u\n", nlh->nlmsg_type);
		errno = EPROTO;
		return -1;
	}
	{
		struct nlmsgerr *ne = (struct nlmsgerr *)NLMSG_DATA(nlh);
		if (ne->error) {
			debug("pm_announce: kernel err=%d (%s)\n",
			      ne->error, strerror(-ne->error));
			errno = -ne->error;
			return -1;
		}
	}
	return 0;
#undef BRF_PUT_ATTR
}

/* MPTCP_PM_CMD_REMOVE: tell the kernel to remove an address that was
 * previously tracked by the userspace path manager.  Used by the
 * v05.4 pseudo-syscall syz_mptcp_pm_remove to exercise the inverse
 * cleanup path of pm_announce -- the same anno_list /
 * userspace_pm_local_addr_list lifecycle code whose ADD side
 * produced the kmemleak race fixed upstream as
 * "mptcp: pm: fix memory leak from alloc-during-teardown race".
 *
 * Required attributes: TOKEN, LOC_ID (the addr_id).  No nested ADDR
 * attribute -- the kernel looks up by id alone.  addr_id == 0 takes
 * a separate kernel path (mptcp_userspace_pm_remove_id_zero_address)
 * that the fuzzer should reach via natural enum exploration; we do
 * NOT coerce 0 to 1 the way pm_announce does, because for REMOVE
 * the kernel accepts id == 0 as a meaningful value.
 */
static int brf_mptcp_genl_remove(uint32_t token, uint8_t addr_id)
{
	char buf[128];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct genlmsghdr *ghdr;
	struct nlattr *attr;
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
	nlh->nlmsg_seq   = 4;
	nlh->nlmsg_pid   = 0;
	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	ghdr->cmd     = MPTCP_PM_CMD_REMOVE;
	ghdr->version = MPTCP_PM_VER;

	p = (char *)NLMSG_DATA(nlh) + NLMSG_ALIGN(sizeof(*ghdr));

	BRF_PUT_ATTR(MPTCP_PM_ATTR_TOKEN, &token, sizeof(token));
	BRF_PUT_ATTR(MPTCP_PM_ATTR_LOC_ID, &addr_id, sizeof(addr_id));

	nlh->nlmsg_len = p - buf;

	if (send(brf_mptcp_genl_sock, buf, nlh->nlmsg_len, 0) < 0) {
		debug("pm_remove: send: %s\n", strerror(errno));
		return -1;
	}
	n = recv(brf_mptcp_genl_sock, buf, sizeof(buf), 0);
	if (n < 0) {
		debug("pm_remove: recv: %s\n", strerror(errno));
		return -1;
	}
	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type != NLMSG_ERROR) {
		debug("pm_remove: unexpected ack type %u\n", nlh->nlmsg_type);
		errno = EPROTO;
		return -1;
	}
	{
		struct nlmsgerr *ne = (struct nlmsgerr *)NLMSG_DATA(nlh);
		if (ne->error) {
			debug("pm_remove: kernel err=%d (%s)\n",
			      ne->error, strerror(-ne->error));
			errno = -ne->error;
			return -1;
		}
	}
	return 0;
#undef BRF_PUT_ATTR
}

/* MPTCP_PM_CMD_SUBFLOW_DESTROY: tell the kernel to tear down the
 * subflow matching (local addr+port, remote addr+port) on the msk
 * identified by token.  Same payload shape as SUBFLOW_CREATE
 * (nested ADDR + nested ADDR_REMOTE, both with family + addr4 +
 * port).  Used by v05.5 pseudo-syscall syz_mptcp_pm_subflow_destroy
 * to exercise the subflow-teardown path -- a different code area
 * from pm_remove's addr-list teardown.
 *
 * Kernel side: mptcp_pm_nl_subflow_destroy_doit ->
 * (subflow lookup by tuple) -> mptcp_close_ssk -> subflow cleanup.
 */
static int brf_mptcp_genl_subflow_destroy(uint32_t token, uint8_t addr_id,
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
	nlh->nlmsg_seq   = 5;
	nlh->nlmsg_pid   = 0;
	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	ghdr->cmd     = MPTCP_PM_CMD_SUBFLOW_DESTROY;
	ghdr->version = MPTCP_PM_VER;

	p = (char *)NLMSG_DATA(nlh) + NLMSG_ALIGN(sizeof(*ghdr));

	BRF_PUT_ATTR(MPTCP_PM_ATTR_TOKEN, &token, sizeof(token));

	{
		uint16_t fam_v = AF_INET;
		nest = (struct nlattr *)p;
		nest->nla_type = MPTCP_PM_ATTR_ADDR | NLA_F_NESTED;
		p += NLA_HDRLEN;
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_FAMILY, &fam_v, sizeof(fam_v));
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_ID, &addr_id, sizeof(addr_id));
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_ADDR4, &local_addr_be,
			     sizeof(local_addr_be));
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_PORT, &local_port_h,
			     sizeof(local_port_h));
		nest->nla_len = p - (char *)nest;
	}
	{
		uint16_t fam_v = AF_INET;
		nest = (struct nlattr *)p;
		nest->nla_type = MPTCP_PM_ATTR_ADDR_REMOTE | NLA_F_NESTED;
		p += NLA_HDRLEN;
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_FAMILY, &fam_v, sizeof(fam_v));
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_ADDR4, &remote_addr_be,
			     sizeof(remote_addr_be));
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_PORT, &remote_port_h,
			     sizeof(remote_port_h));
		nest->nla_len = p - (char *)nest;
	}

	nlh->nlmsg_len = p - buf;

	if (send(brf_mptcp_genl_sock, buf, nlh->nlmsg_len, 0) < 0) {
		debug("pm_subflow_destroy: send: %s\n", strerror(errno));
		return -1;
	}
	n = recv(brf_mptcp_genl_sock, buf, sizeof(buf), 0);
	if (n < 0) {
		debug("pm_subflow_destroy: recv: %s\n", strerror(errno));
		return -1;
	}
	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type != NLMSG_ERROR) {
		debug("pm_subflow_destroy: unexpected ack type %u\n",
		      nlh->nlmsg_type);
		errno = EPROTO;
		return -1;
	}
	{
		struct nlmsgerr *ne = (struct nlmsgerr *)NLMSG_DATA(nlh);
		if (ne->error) {
			debug("pm_subflow_destroy: kernel err=%d (%s)\n",
			      ne->error, strerror(-ne->error));
			errno = -ne->error;
			return -1;
		}
	}
	return 0;
#undef BRF_PUT_ATTR
}

/* MPTCP_PM_CMD_SET_FLAGS: change flags (BACKUP / SIGNAL / SUBFLOW /
 * FULLMESH / IMPLICIT) on an address entry.  Used by the v06.1
 * pseudo-syscall syz_mptcp_pm_set_flags.  The kernel routes through
 * mptcp_pm_set_flags which dispatches to pm_userspace or pm_kernel
 * based on pm_type; in our pm_type=1 setup the userspace branch
 * fires, including MP_PRIO emission on backup-flag transitions.
 *
 * Attrs: TOKEN + nested ADDR with (FAMILY, ID, ADDR4, PORT, FLAGS).
 * Local addr fixed at 127.0.0.2 (matches join_subflow's address).
 */
static int brf_mptcp_genl_set_flags(uint32_t token, uint8_t addr_id,
				    uint32_t addr_flags, uint16_t port_h)
{
	char buf[256];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct genlmsghdr *ghdr;
	struct nlattr *attr, *nest;
	char *p;
	ssize_t n;
	uint32_t local_addr_be = htonl(0x7f000002);
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
	nlh->nlmsg_seq   = 6;
	nlh->nlmsg_pid   = 0;
	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	ghdr->cmd     = MPTCP_PM_CMD_SET_FLAGS;
	ghdr->version = MPTCP_PM_VER;

	p = (char *)NLMSG_DATA(nlh) + NLMSG_ALIGN(sizeof(*ghdr));

	BRF_PUT_ATTR(MPTCP_PM_ATTR_TOKEN, &token, sizeof(token));

	{
		uint16_t fam_v = AF_INET;
		nest = (struct nlattr *)p;
		nest->nla_type = MPTCP_PM_ATTR_ADDR | NLA_F_NESTED;
		p += NLA_HDRLEN;
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_FAMILY, &fam_v, sizeof(fam_v));
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_ID, &addr_id, sizeof(addr_id));
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_ADDR4, &local_addr_be,
			     sizeof(local_addr_be));
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_PORT, &port_h, sizeof(port_h));
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_FLAGS, &addr_flags,
			     sizeof(addr_flags));
		nest->nla_len = p - (char *)nest;
	}

	nlh->nlmsg_len = p - buf;

	if (send(brf_mptcp_genl_sock, buf, nlh->nlmsg_len, 0) < 0) {
		debug("pm_set_flags: send: %s\n", strerror(errno));
		return -1;
	}
	n = recv(brf_mptcp_genl_sock, buf, sizeof(buf), 0);
	if (n < 0) {
		debug("pm_set_flags: recv: %s\n", strerror(errno));
		return -1;
	}
	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type != NLMSG_ERROR) {
		debug("pm_set_flags: unexpected ack type %u\n", nlh->nlmsg_type);
		errno = EPROTO;
		return -1;
	}
	{
		struct nlmsgerr *ne = (struct nlmsgerr *)NLMSG_DATA(nlh);
		if (ne->error) {
			debug("pm_set_flags: kernel err=%d (%s)\n",
			      ne->error, strerror(-ne->error));
			errno = -ne->error;
			return -1;
		}
	}
	return 0;
#undef BRF_PUT_ATTR
}

/* MPTCP_PM_CMD_ADD_ADDR (kernel PM): register a netns-scoped address
 * in pernet->local_addr_list.  No TOKEN -- operates per-netns, not
 * per-msk.  Used by the v06.2 pseudo-syscall
 * syz_mptcp_pm_kernel_add_addr to exercise the kernel-PM address-
 * table code surface (pm_kernel.c) which is entirely separate from
 * the userspace-PM address tracking the v05.x pseudo-syscalls touch.
 *
 * Attrs: nested ADDR with (FAMILY, ID, ADDR4, PORT, optional FLAGS).
 */
static int brf_mptcp_genl_kernel_add_addr(uint8_t addr_id,
					  uint32_t addr_be, uint16_t port_h,
					  uint32_t addr_flags)
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
	nlh->nlmsg_seq   = 7;
	nlh->nlmsg_pid   = 0;
	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	ghdr->cmd     = MPTCP_PM_CMD_ADD_ADDR;
	ghdr->version = MPTCP_PM_VER;

	p = (char *)NLMSG_DATA(nlh) + NLMSG_ALIGN(sizeof(*ghdr));

	{
		uint16_t fam_v = AF_INET;
		nest = (struct nlattr *)p;
		nest->nla_type = MPTCP_PM_ATTR_ADDR | NLA_F_NESTED;
		p += NLA_HDRLEN;
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_FAMILY, &fam_v, sizeof(fam_v));
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_ID, &addr_id, sizeof(addr_id));
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_ADDR4, &addr_be,
			     sizeof(addr_be));
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_PORT, &port_h, sizeof(port_h));
		if (addr_flags)
			BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_FLAGS, &addr_flags,
				     sizeof(addr_flags));
		nest->nla_len = p - (char *)nest;
	}

	nlh->nlmsg_len = p - buf;

	if (send(brf_mptcp_genl_sock, buf, nlh->nlmsg_len, 0) < 0) {
		debug("pm_kernel_add_addr: send: %s\n", strerror(errno));
		return -1;
	}
	n = recv(brf_mptcp_genl_sock, buf, sizeof(buf), 0);
	if (n < 0) {
		debug("pm_kernel_add_addr: recv: %s\n", strerror(errno));
		return -1;
	}
	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type != NLMSG_ERROR) {
		debug("pm_kernel_add_addr: unexpected ack type %u\n",
		      nlh->nlmsg_type);
		errno = EPROTO;
		return -1;
	}
	{
		struct nlmsgerr *ne = (struct nlmsgerr *)NLMSG_DATA(nlh);
		if (ne->error) {
			debug("pm_kernel_add_addr: kernel err=%d (%s)\n",
			      ne->error, strerror(-ne->error));
			errno = -ne->error;
			return -1;
		}
	}
	return 0;
#undef BRF_PUT_ATTR
}

/* MPTCP_PM_CMD_DEL_ADDR (kernel PM): remove an address from
 * pernet->local_addr_list.  Companion to brf_mptcp_genl_kernel_add_addr.
 * Used by the v06.3 pseudo-syscall syz_mptcp_pm_kernel_del_addr.
 *
 * Attrs: nested ADDR with (FAMILY, ID).  No TOKEN.
 */
static int brf_mptcp_genl_kernel_del_addr(uint8_t addr_id)
{
	char buf[128];
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
	nlh->nlmsg_seq   = 8;
	nlh->nlmsg_pid   = 0;
	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	ghdr->cmd     = MPTCP_PM_CMD_DEL_ADDR;
	ghdr->version = MPTCP_PM_VER;

	p = (char *)NLMSG_DATA(nlh) + NLMSG_ALIGN(sizeof(*ghdr));

	{
		uint16_t fam_v = AF_INET;
		nest = (struct nlattr *)p;
		nest->nla_type = MPTCP_PM_ATTR_ADDR | NLA_F_NESTED;
		p += NLA_HDRLEN;
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_FAMILY, &fam_v, sizeof(fam_v));
		BRF_PUT_ATTR(MPTCP_PM_ADDR_ATTR_ID, &addr_id, sizeof(addr_id));
		nest->nla_len = p - (char *)nest;
	}

	nlh->nlmsg_len = p - buf;

	if (send(brf_mptcp_genl_sock, buf, nlh->nlmsg_len, 0) < 0) {
		debug("pm_kernel_del_addr: send: %s\n", strerror(errno));
		return -1;
	}
	n = recv(brf_mptcp_genl_sock, buf, sizeof(buf), 0);
	if (n < 0) {
		debug("pm_kernel_del_addr: recv: %s\n", strerror(errno));
		return -1;
	}
	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type != NLMSG_ERROR) {
		debug("pm_kernel_del_addr: unexpected ack type %u\n",
		      nlh->nlmsg_type);
		errno = EPROTO;
		return -1;
	}
	{
		struct nlmsgerr *ne = (struct nlmsgerr *)NLMSG_DATA(nlh);
		if (ne->error) {
			debug("pm_kernel_del_addr: kernel err=%d (%s)\n",
			      ne->error, strerror(-ne->error));
			errno = -ne->error;
			return -1;
		}
	}
	return 0;
#undef BRF_PUT_ATTR
}

/* MPTCP_PM_CMD_FLUSH_ADDRS (kernel PM): bulk-clear
 * pernet->local_addr_list.  Used by the v06.4 pseudo-syscall
 * syz_mptcp_pm_kernel_flush_addrs.  Exercises the same
 * splice-then-iterate teardown shape as mptcp_pm_destroy on the
 * userspace side.  No attrs required.
 */
static int brf_mptcp_genl_kernel_flush_addrs(void)
{
	char buf[64];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct genlmsghdr *ghdr;
	ssize_t n;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = brf_mptcp_pm_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = 9;
	nlh->nlmsg_pid   = 0;
	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	ghdr->cmd     = MPTCP_PM_CMD_FLUSH_ADDRS;
	ghdr->version = MPTCP_PM_VER;

	nlh->nlmsg_len = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ghdr));

	if (send(brf_mptcp_genl_sock, buf, nlh->nlmsg_len, 0) < 0) {
		debug("pm_kernel_flush_addrs: send: %s\n", strerror(errno));
		return -1;
	}
	n = recv(brf_mptcp_genl_sock, buf, sizeof(buf), 0);
	if (n < 0) {
		debug("pm_kernel_flush_addrs: recv: %s\n", strerror(errno));
		return -1;
	}
	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type != NLMSG_ERROR) {
		debug("pm_kernel_flush_addrs: unexpected ack type %u\n",
		      nlh->nlmsg_type);
		errno = EPROTO;
		return -1;
	}
	{
		struct nlmsgerr *ne = (struct nlmsgerr *)NLMSG_DATA(nlh);
		if (ne->error) {
			debug("pm_kernel_flush_addrs: kernel err=%d (%s)\n",
			      ne->error, strerror(-ne->error));
			errno = -ne->error;
			return -1;
		}
	}
	return 0;
}

/* MPTCP_PM_CMD_SET_LIMITS (kernel PM): set per-netns limits on
 * accepted ADD_ADDRs and on extra subflows.  Attrs: RCV_ADD_ADDRS
 * (u32) + SUBFLOWS (u32).  Used by v06.5 syz_mptcp_pm_set_limits.
 */
static int brf_mptcp_genl_set_limits(uint32_t rcv_add_addrs,
				     uint32_t subflows)
{
	char buf[128];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct genlmsghdr *ghdr;
	struct nlattr *attr;
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
	nlh->nlmsg_seq   = 10;
	nlh->nlmsg_pid   = 0;
	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	ghdr->cmd     = MPTCP_PM_CMD_SET_LIMITS;
	ghdr->version = MPTCP_PM_VER;

	p = (char *)NLMSG_DATA(nlh) + NLMSG_ALIGN(sizeof(*ghdr));
	BRF_PUT_ATTR(MPTCP_PM_ATTR_RCV_ADD_ADDRS, &rcv_add_addrs,
		     sizeof(rcv_add_addrs));
	BRF_PUT_ATTR(MPTCP_PM_ATTR_SUBFLOWS, &subflows, sizeof(subflows));

	nlh->nlmsg_len = p - buf;

	if (send(brf_mptcp_genl_sock, buf, nlh->nlmsg_len, 0) < 0) {
		debug("pm_set_limits: send: %s\n", strerror(errno));
		return -1;
	}
	n = recv(brf_mptcp_genl_sock, buf, sizeof(buf), 0);
	if (n < 0) {
		debug("pm_set_limits: recv: %s\n", strerror(errno));
		return -1;
	}
	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type != NLMSG_ERROR) {
		debug("pm_set_limits: unexpected ack type %u\n",
		      nlh->nlmsg_type);
		errno = EPROTO;
		return -1;
	}
	{
		struct nlmsgerr *ne = (struct nlmsgerr *)NLMSG_DATA(nlh);
		if (ne->error) {
			debug("pm_set_limits: kernel err=%d (%s)\n",
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

	/* Mutation mode dispatch (v02 C2 + C3):
	 *   - hmac_mut  != NORMAL: rewrite MP_JOIN ACK's HMAC field.
	 *     Server's subflow_hmac_valid gate catches it.
	 *   - nonce_mut != NORMAL: rewrite MP_JOIN SYN's client nonce.
	 *     The server-side HMAC computation diverges from what the
	 *     client expects in the SYN-ACK; client's subflow_thmac_valid
	 *     gate catches it (different gate, different rejection path).
	 *   - Both set: nonce_mut fires first (SYN egress precedes ACK
	 *     egress), mut_fired latches at 1, ACK passes through
	 *     unmodified.  Acceptable behavior for fuzzer coverage.
	 *
	 * Whether the subflow ends up rejected (expected) or not, this
	 * pseudo-syscall returns 0 -- the value to the fuzzer is the
	 * kcov coverage from the attempted handshake, not a binary
	 * success bit. */
	if (brf_mptcp_ensure_executor_setup() < 0)
		return -1;

	if (hmac_mut != MPTCP_HMAC_NORMAL ||
	    nonce_mut != MPTCP_NONCE_NORMAL) {
		if (brf_mptcp_ensure_nfq_setup() < 0)
			return -1;
		/* v05 multi-pair: reset only the per-type fired flags we
		 * care about so a concurrent drive_traffic's pending
		 * map_mut isn't disturbed.  Legacy mut_fired still gets
		 * reset for poll-loop backwards compat. */
		BRF_ATOMIC_STORE(&brf_nfq_mut_fired, 0);
		if (hmac_mut != MPTCP_HMAC_NORMAL)
			BRF_ATOMIC_STORE(&brf_nfq_mut_fired_hmac, 0);
		if (nonce_mut != MPTCP_NONCE_NORMAL)
			BRF_ATOMIC_STORE(&brf_nfq_mut_fired_nonce, 0);
		BRF_ATOMIC_STORE(&brf_nfq_pending_hmac_mut, hmac_mut);
		BRF_ATOMIC_STORE(&brf_nfq_pending_nonce_mut, nonce_mut);
	}

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
	 * should complete in well under a millisecond.
	 *
	 * Mutation modes (hmac_mut or nonce_mut != NORMAL) flip the
	 * success condition: we expect the subflow to NOT establish
	 * because the worker mutated either the MP_JOIN SYN (nonce) or
	 * ACK (hmac) and a kernel gate rejected it.  Return 0 either way
	 * (subflow joined OR mutation observed) since the kcov coverage
	 * from the handshake is what the fuzzer consumes.  Subflow
	 * bookkeeping (subflow_count++) only on actual establishment. */
	int is_mutation = (hmac_mut != MPTCP_HMAC_NORMAL) ||
			  (nonce_mut != MPTCP_NONCE_NORMAL);
	for (retries = 0; retries < 20; retries++) {
		struct brf_mptcp_info_short info;
		socklen_t ilen = sizeof(info);
		memset(&info, 0, sizeof(info));
		if (getsockopt(pair->server_msk_fd, SOL_MPTCP, MPTCP_INFO,
			       &info, &ilen) == 0) {
			if (info.mptcpi_subflows >= 1) {
				pair->subflows[sub_slot].established = true;
				pair->subflow_count++;
				debug("syz_mptcp_join_subflow: pair=%ld subflow=%d "
				      "established (server mptcpi_subflows=%u, "
				      "polls=%d, hmac_mut=%u, nonce_mut=%u)\n",
				      slot, sub_slot, info.mptcpi_subflows,
				      retries + 1, hmac_mut, nonce_mut);
				if (is_mutation) {
					BRF_ATOMIC_STORE(
						&brf_nfq_pending_hmac_mut, 0);
					BRF_ATOMIC_STORE(
						&brf_nfq_pending_nonce_mut, 0);
				}
				return 0;
			}
			if (is_mutation &&
			    BRF_ATOMIC_LOAD(&brf_nfq_mut_fired)) {
				debug("syz_mptcp_join_subflow: pair=%ld "
				      "hmac_mut=%u nonce_mut=%u applied; "
				      "subflow rejected as expected "
				      "(polls=%d)\n", slot, hmac_mut,
				      nonce_mut, retries + 1);
				BRF_ATOMIC_STORE(
					&brf_nfq_pending_hmac_mut, 0);
				BRF_ATOMIC_STORE(
					&brf_nfq_pending_nonce_mut, 0);
				return 0;
			}
		}
		usleep(50000);	/* 50 ms */
	}
	if (is_mutation) {
		debug("syz_mptcp_join_subflow: pair=%ld hmac_mut=%u "
		      "nonce_mut=%u no resolution in 1s (mut_fired=%d) -- "
		      "returning 0 anyway since kcov coverage from attempted "
		      "handshake is the useful signal\n", slot, hmac_mut,
		      nonce_mut, BRF_ATOMIC_LOAD(&brf_nfq_mut_fired));
		BRF_ATOMIC_STORE(&brf_nfq_pending_hmac_mut, 0);
		BRF_ATOMIC_STORE(&brf_nfq_pending_nonce_mut, 0);
		return 0;
	}
	debug("syz_mptcp_join_subflow: pair=%ld subflow=%d not established "
	      "within ~1s\n", slot, sub_slot);
	return -1;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_drive_traffic
/*
 * v04 C1: send `data_len` bytes through an established MP_CAPABLE pair's
 * client->server direction, exercising the MPTCP-level data path
 * (mptcp_sendmsg, mptcp_established_options_dss emit, server's
 * mptcp_incoming_options DSS parse, mptcp_subflow_data_available etc).
 *
 * subflow_id is informational in v04 C1 -- writes go through client_msk_fd
 * which lets the kernel's mptcp_subflow_get_send scheduler pick.  A future
 * iteration can write directly on pair->subflows[subflow_id].tcp_subflow_fd
 * for per-subflow steering, at the cost of bypassing the MPTCP layer.
 *
 * map_mut != NORMAL is routed through the NFQUEUE worker shared with v02
 * (HMAC/nonce).  Worker rewrites the DSS option bytes of the first egress
 * data ACK that carries one.  Mutation kinds: STALE_SEQ / OFF_BY_ONE
 * (modify the first 32-bit field after option header, which is DSN_ACK
 * or DSN depending on flags), INFINITE (set M=1 flag), HOLE (mutate
 * subflow_seq).  Exercises mptcp_incoming_options DSS parsing edge
 * cases.
 *
 * Bounded send (4096 bytes max) + best-effort drain on server side so a
 * pathological prog can't wedge the pair's TX buffer for the rest of the
 * fuzz iteration.  Errors are non-fatal -- the syscall returns the bytes
 * actually sent (or 0 if nothing went through); fuzzer cares about
 * kcov coverage from the attempted send, not a success bit.
 */
static long syz_mptcp_drive_traffic(volatile long a0, volatile long a1,
				    volatile long a2, volatile long a3,
				    volatile long a4)
{
	struct brf_mptcp_pair_state *pair;
	long slot = a0;
	const void *data = (const void *)a2;
	size_t data_len = (size_t)a3;
	uint8_t map_mut = (uint8_t)a4;
	char drain_buf[4096];
	ssize_t sent, drained, total_drained = 0;

	(void)a1;	/* subflow_id -- informational in v04 C1 */

	/* v04 C2: route map_mut through the NFQUEUE worker shared with
	 * v02 (HMAC/nonce).  Worker rewrites the DSS option bytes of the
	 * first egress data ACK that carries one.
	 *
	 * v05 multi-pair: only reset the map per-type fired flag so a
	 * concurrent join_subflow's pending hmac/nonce isn't disturbed. */
	if (map_mut != MPTCP_MAP_NORMAL) {
		if (brf_mptcp_ensure_nfq_setup() < 0)
			return -1;
		BRF_ATOMIC_STORE(&brf_nfq_mut_fired, 0);
		BRF_ATOMIC_STORE(&brf_nfq_mut_fired_map, 0);
		BRF_ATOMIC_STORE(&brf_nfq_pending_map_mut, map_mut);
	}

	if (slot < 0 || slot >= MPTCP_PAIR_POOL_SIZE) {
		debug("syz_mptcp_drive_traffic: slot %ld out of range\n", slot);
		return -1;
	}
	pair = &brf_mptcp_pair_pool[slot];
	if (!pair->in_use) {
		debug("syz_mptcp_drive_traffic: slot %ld not in use\n", slot);
		return -1;
	}
	if (pair->client_msk_fd < 0 || pair->server_msk_fd < 0) {
		debug("syz_mptcp_drive_traffic: slot %ld fds not set "
		      "(client=%d server=%d)\n", slot,
		      pair->client_msk_fd, pair->server_msk_fd);
		return -1;
	}

	/* Cap the send size -- syzkaller will mutate data_len wildly and we
	 * don't want a 16MB send wedging the pair. */
	if (data_len > sizeof(drain_buf))
		data_len = sizeof(drain_buf);

	sent = send(pair->client_msk_fd, data, data_len,
		    MSG_DONTWAIT | MSG_NOSIGNAL);
	if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
		debug("syz_mptcp_drive_traffic: send: %s\n", strerror(errno));

	/* Drain server side -- bounded so we don't loop forever on a chatty
	 * peer.  Without this, the pair's RX buffer fills and subsequent
	 * sends start EAGAIN-ing.  Max 8 iterations = up to 32KB drained. */
	for (int i = 0; i < 8; i++) {
		drained = recv(pair->server_msk_fd, drain_buf,
			       sizeof(drain_buf),
			       MSG_DONTWAIT | MSG_NOSIGNAL);
		if (drained <= 0)
			break;
		total_drained += drained;
	}

	debug("syz_mptcp_drive_traffic: slot=%ld sent=%zd drained=%zd "
	      "data_len=%zu map_mut=%u mut_fired=%d\n",
	      slot, sent, total_drained, data_len, map_mut,
	      BRF_ATOMIC_LOAD(&brf_nfq_mut_fired));
	/* Clear pending mutation so the next prog's drive_traffic without
	 * map_mut doesn't accidentally mutate a stale packet. */
	if (map_mut != MPTCP_MAP_NORMAL)
		BRF_ATOMIC_STORE(&brf_nfq_pending_map_mut, 0);
	return sent >= 0 ? sent : 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_send_control
/*
 * v04 C3: emit an MPTCP control event by closing the chosen socket with
 * the mechanism that triggers the requested kind of control packet.
 * The kernel does all the wire-side work -- we just pick which fd to
 * close and how.
 *
 *   suboption == MPTCP_CTL_RST       -> SO_LINGER timeout=0 + close()
 *                                       => RST on wire (kernel adds
 *                                          MP_RST option if subflow is
 *                                          still in MPTCP state).
 *                                          Exercises subflow_reset,
 *                                          mptcp_subflow_drop_ctx,
 *                                          mptcp_pm_subflow_check_next.
 *   suboption == MPTCP_CTL_FASTCLOSE -> shutdown(SHUT_RDWR) + close()
 *                                       => graceful close, MPTCP emits
 *                                          MP_FASTCLOSE if there's
 *                                          unacked data or in specific
 *                                          state.  Exercises
 *                                          mptcp_do_fastclose,
 *                                          __mptcp_destroy_sock cleanup
 *                                          path, mptcp_close_wake_up.
 *   suboption == MPTCP_CTL_FAIL      -> close() only
 *                                       => normal FIN exchange.
 *                                          Exercises mptcp_shutdown,
 *                                          mptcp_check_send_data_fin,
 *                                          mptcp_close_ssk.
 *
 * subflow_id selects which fd to close:
 *   subflow_id <= 0 or out of range  -> client_msk_fd (whole MPTCP
 *                                       connection from client side)
 *   subflow_id in [0, subflow_count) -> that subflow's tcp_subflow_fd
 *                                       (tears down just the subflow,
 *                                        leaving the main connection)
 *
 * After close, the corresponding fd in pair state is set to -1 so the
 * subsequent pair_close() doesn't double-close.  These close paths are
 * historically the most bug-fertile area of MPTCP (every recent CVE
 * has touched mptcp_close / __mptcp_destroy_sock / mptcp_do_fastclose).
 */
static long syz_mptcp_send_control(volatile long a0, volatile long a1,
				   volatile long a2)
{
	struct brf_mptcp_pair_state *pair;
	long slot = a0;
	int subflow_id = (int)a1;
	uint8_t suboption = (uint8_t)a2;
	int fd = -1;
	struct linger ling;
	const char *target_name;

	if (slot < 0 || slot >= MPTCP_PAIR_POOL_SIZE) {
		debug("syz_mptcp_send_control: slot %ld out of range\n", slot);
		return -1;
	}
	pair = &brf_mptcp_pair_pool[slot];
	if (!pair->in_use) {
		debug("syz_mptcp_send_control: slot %ld not in use\n", slot);
		return -1;
	}

	if (subflow_id <= 0 || subflow_id >= pair->subflow_count) {
		fd = pair->client_msk_fd;
		target_name = "client_msk";
	} else {
		fd = pair->subflows[subflow_id].tcp_subflow_fd;
		target_name = "subflow_tcp";
	}

	if (fd < 0) {
		debug("syz_mptcp_send_control: slot=%ld subflow_id=%d "
		      "target=%s already closed\n",
		      slot, subflow_id, target_name);
		return -1;
	}

	switch (suboption) {
	case MPTCP_CTL_RST:
		ling.l_onoff = 1;
		ling.l_linger = 0;
		setsockopt(fd, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
		close(fd);
		break;
	case MPTCP_CTL_FASTCLOSE:
		shutdown(fd, SHUT_RDWR);
		close(fd);
		break;
	case MPTCP_CTL_FAIL:
		close(fd);
		break;
	default:
		debug("syz_mptcp_send_control: unknown suboption=%u\n",
		      suboption);
		return -1;
	}

	/* Mark fd closed so pair_close / drive_traffic don't operate on
	 * a recycled fd. */
	if (subflow_id <= 0 || subflow_id >= pair->subflow_count) {
		pair->client_msk_fd = -1;
	} else {
		pair->subflows[subflow_id].tcp_subflow_fd = -1;
		pair->subflows[subflow_id].established = false;
	}

	debug("syz_mptcp_send_control: slot=%ld subflow_id=%d target=%s "
	      "suboption=%u closed\n",
	      slot, subflow_id, target_name, suboption);
	return 0;
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

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_announce
/*
 * v05.3: tell the kernel to announce an additional address via the
 * MPTCP ADD_ADDR option.  Exercises:
 *   - mptcp_pm_nl_announce_doit (kernel-side genl handler)
 *   - mptcp_pm_alloc_anno_list / mptcp_pm_add_addr_signal (emit path)
 *   - peer-side mptcp_pm_add_addr_received (parse path)
 *   - mptcp_pm_announce_addr / mptcp_pm_addr_send_ack (echo path)
 *
 * The path-manager add-addr code surface is entirely unreached by
 * the v02/v04/v05 corpus (which only does SUBFLOW_CREATE).  Add-addr
 * paths have been the source of several recent MPTCP CVEs.
 *
 * addr_be / port_h are caller-provided so the fuzzer can probe with
 * legitimate-looking and degenerate values.  addr_id collisions with
 * the join_subflow addr_ids are intentionally allowed -- the kernel's
 * id collision handling is itself a code path worth exercising.
 *
 * MPTCP_PM_ADDR_FLAG_SIGNAL is set unconditionally so the address is
 * actually emitted on wire (without SIGNAL, the kernel just stores
 * it without announcing).
 */
static long syz_mptcp_pm_announce(volatile long a0, volatile long a1,
				  volatile long a2, volatile long a3)
{
	struct brf_mptcp_pair_state *pair;
	long slot = a0;
	uint8_t addr_id = (uint8_t)a1;
	uint32_t addr_be = (uint32_t)a2;	/* caller picks; NBO assumed */
	uint16_t port_h  = (uint16_t)a3;	/* host byte order per quirk */

	if (slot < 0 || slot >= MPTCP_PAIR_POOL_SIZE) {
		debug("syz_mptcp_pm_announce: slot %ld out of range\n", slot);
		return -1;
	}
	pair = &brf_mptcp_pair_pool[slot];
	if (!pair->in_use) {
		debug("syz_mptcp_pm_announce: slot %ld not in use\n", slot);
		return -1;
	}
	if (brf_mptcp_ensure_executor_setup() < 0)
		return -1;

	/* addr_id == 0 is rejected by the kernel; coerce to 1 (same
	 * defensive coercion as syz_mptcp_join_subflow). */
	if (addr_id == 0)
		addr_id = 1;

	if (brf_mptcp_genl_announce(pair->token, addr_id, addr_be, port_h,
				    MPTCP_PM_ADDR_FLAG_SIGNAL) < 0) {
		debug("syz_mptcp_pm_announce: slot=%ld addr_id=%u failed\n",
		      slot, addr_id);
		return -1;
	}

	debug("syz_mptcp_pm_announce: slot=%ld addr_id=%u "
	      "addr=0x%08x port=%u announced\n",
	      slot, addr_id, ntohl(addr_be), port_h);
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_remove
/*
 * v05.4: tell the kernel to remove an address that was previously
 * tracked by the userspace path manager.  Sibling of pm_announce
 * (v05.3); exercises the inverse cleanup path:
 *   - mptcp_pm_nl_remove_doit (kernel-side genl handler)
 *   - mptcp_pm_remove_addr_entry (entry teardown)
 *   - mptcp_remove_anno_list_by_saddr (anno_list cleanup)
 *   - mptcp_pm_del_add_timer (add-timer cancellation)
 *   - mptcp_userspace_pm_remove_id_zero_address (addr_id == 0 path)
 *
 * Production hypothesis (per the memory at
 * project_harness_viability_assessment):  fuzzing the same
 * anno_list / userspace_pm_local_addr_list lifecycle code from the
 * REMOVE side, after the ADD side produced the kmemleak race we
 * just fixed, has a high probability of surfacing a related bug.
 * This pseudo-syscall is the cheapest possible test of that
 * hypothesis -- if v05.4 doesn't produce a finding within a week
 * of fuzzer time, the model needs revisiting.
 *
 * addr_id is passed straight through; the kernel routes
 * addr_id == 0 to a separate handler
 * (mptcp_userspace_pm_remove_id_zero_address) which is itself a
 * code surface the fuzzer should reach.  Unlike pm_announce we do
 * NOT coerce 0 to 1.
 */
static long syz_mptcp_pm_remove(volatile long a0, volatile long a1)
{
	struct brf_mptcp_pair_state *pair;
	long slot = a0;
	uint8_t addr_id = (uint8_t)a1;

	if (slot < 0 || slot >= MPTCP_PAIR_POOL_SIZE) {
		debug("syz_mptcp_pm_remove: slot %ld out of range\n", slot);
		return -1;
	}
	pair = &brf_mptcp_pair_pool[slot];
	if (!pair->in_use) {
		debug("syz_mptcp_pm_remove: slot %ld not in use\n", slot);
		return -1;
	}
	if (brf_mptcp_ensure_executor_setup() < 0)
		return -1;

	if (brf_mptcp_genl_remove(pair->token, addr_id) < 0) {
		debug("syz_mptcp_pm_remove: slot=%ld addr_id=%u failed\n",
		      slot, addr_id);
		return -1;
	}

	debug("syz_mptcp_pm_remove: slot=%ld addr_id=%u removed\n",
	      slot, addr_id);
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_subflow_destroy
/*
 * v05.5: tell the kernel to tear down a specific subflow on this
 * msk, identified by (local addr+port, remote addr+port).  Sibling
 * of v01's join_subflow (SUBFLOW_CREATE); exercises the subflow
 * teardown path which is a different code area from pm_remove's
 * addr-list teardown.
 *
 * Local addr is fixed at 127.0.0.2 (matches what join_subflow
 * uses); remote addr is fixed at 127.0.0.1.  Ports are passed
 * through from the syscall args -- fuzzer mutations occasionally
 * happen to match a real subflow's tuple (exercises the
 * mptcp_close_ssk success path) and mostly don't (exercises the
 * tuple-lookup failure path in mptcp_pm_nl_subflow_destroy_doit).
 * Both surfaces are interesting; we deliberately do not try to
 * cleverly select port=server_port to bias toward matching.
 */
static long syz_mptcp_pm_subflow_destroy(volatile long a0, volatile long a1,
					 volatile long a2, volatile long a3)
{
	struct brf_mptcp_pair_state *pair;
	long slot = a0;
	uint8_t addr_id = (uint8_t)a1;
	uint16_t local_port_h  = (uint16_t)a2;
	uint16_t remote_port_h = (uint16_t)a3;

	if (slot < 0 || slot >= MPTCP_PAIR_POOL_SIZE) {
		debug("syz_mptcp_pm_subflow_destroy: slot %ld out of range\n",
		      slot);
		return -1;
	}
	pair = &brf_mptcp_pair_pool[slot];
	if (!pair->in_use) {
		debug("syz_mptcp_pm_subflow_destroy: slot %ld not in use\n",
		      slot);
		return -1;
	}
	if (brf_mptcp_ensure_executor_setup() < 0)
		return -1;

	if (brf_mptcp_genl_subflow_destroy(pair->token, addr_id,
					   htonl(0x7f000002), local_port_h,
					   htonl(0x7f000001), remote_port_h) < 0) {
		debug("syz_mptcp_pm_subflow_destroy: slot=%ld addr_id=%u "
		      "lport=%u rport=%u failed\n",
		      slot, addr_id, local_port_h, remote_port_h);
		return -1;
	}

	debug("syz_mptcp_pm_subflow_destroy: slot=%ld addr_id=%u "
	      "lport=%u rport=%u destroyed\n",
	      slot, addr_id, local_port_h, remote_port_h);
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_set_flags
/*
 * v06.1: change flags on an address entry via MPTCP_PM_CMD_SET_FLAGS.
 * Routes through mptcp_pm_set_flags -> pm_userspace branch (since
 * pm_type=1 in our setup), exercising the MP_PRIO emission path on
 * backup-flag transitions and the userspace-PM flag-update logic.
 *
 * addr_flags is passed through; the fuzzer picks bit combinations
 * from the MPTCP_PM_ADDR_FLAG_* space (SIGNAL=1, SUBFLOW=2,
 * BACKUP=4, FULLMESH=8, IMPLICIT=16).  Most interesting transition
 * is toggling BACKUP on an existing announced address -- emits
 * MP_PRIO on the wire.
 */
static long syz_mptcp_pm_set_flags(volatile long a0, volatile long a1,
				   volatile long a2, volatile long a3)
{
	struct brf_mptcp_pair_state *pair;
	long slot = a0;
	uint8_t addr_id = (uint8_t)a1;
	uint32_t addr_flags = (uint32_t)a2;
	uint16_t port_h = (uint16_t)a3;

	if (slot < 0 || slot >= MPTCP_PAIR_POOL_SIZE) {
		debug("syz_mptcp_pm_set_flags: slot %ld out of range\n", slot);
		return -1;
	}
	pair = &brf_mptcp_pair_pool[slot];
	if (!pair->in_use) {
		debug("syz_mptcp_pm_set_flags: slot %ld not in use\n", slot);
		return -1;
	}
	if (brf_mptcp_ensure_executor_setup() < 0)
		return -1;

	if (brf_mptcp_genl_set_flags(pair->token, addr_id, addr_flags,
				     port_h) < 0) {
		debug("syz_mptcp_pm_set_flags: slot=%ld id=%u flags=0x%x "
		      "port=%u failed\n",
		      slot, addr_id, addr_flags, port_h);
		return -1;
	}

	debug("syz_mptcp_pm_set_flags: slot=%ld id=%u flags=0x%x "
	      "port=%u set\n", slot, addr_id, addr_flags, port_h);
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_kernel_add_addr
/*
 * v06.2: register a netns-scoped address in the kernel PM's
 * pernet->local_addr_list via MPTCP_PM_CMD_ADD_ADDR.  Exercises
 * pm_kernel.c surface (id-allocation bitmap, pernet locking,
 * address-entry kmalloc) that the v05.x pseudo-syscalls do not
 * touch.  Per-netns (no msk / pair argument).
 */
static long syz_mptcp_pm_kernel_add_addr(volatile long a0, volatile long a1,
					 volatile long a2, volatile long a3)
{
	uint8_t addr_id = (uint8_t)a0;
	uint32_t addr_be = (uint32_t)a1;
	uint16_t port_h = (uint16_t)a2;
	uint32_t addr_flags = (uint32_t)a3;

	if (brf_mptcp_ensure_executor_setup() < 0)
		return -1;

	if (brf_mptcp_genl_kernel_add_addr(addr_id, addr_be, port_h,
					   addr_flags) < 0) {
		debug("syz_mptcp_pm_kernel_add_addr: id=%u addr=0x%08x "
		      "port=%u flags=0x%x failed\n",
		      addr_id, ntohl(addr_be), port_h, addr_flags);
		return -1;
	}

	debug("syz_mptcp_pm_kernel_add_addr: id=%u addr=0x%08x port=%u "
	      "flags=0x%x added\n",
	      addr_id, ntohl(addr_be), port_h, addr_flags);
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_kernel_del_addr
/*
 * v06.3: remove an address from the kernel PM's
 * pernet->local_addr_list via MPTCP_PM_CMD_DEL_ADDR.  Companion to
 * v06.2 add_addr.  Exercises kernel-PM teardown machinery (id
 * lookup, list_del, kfree_rcu) structurally similar to the
 * userspace-PM teardown whose alloc side produced the kmemleak
 * race -- hypothesis is a related class of race may exist on the
 * kernel-PM side.
 */
static long syz_mptcp_pm_kernel_del_addr(volatile long a0)
{
	uint8_t addr_id = (uint8_t)a0;

	if (brf_mptcp_ensure_executor_setup() < 0)
		return -1;

	if (brf_mptcp_genl_kernel_del_addr(addr_id) < 0) {
		debug("syz_mptcp_pm_kernel_del_addr: id=%u failed\n",
		      addr_id);
		return -1;
	}

	debug("syz_mptcp_pm_kernel_del_addr: id=%u deleted\n", addr_id);
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_kernel_flush_addrs
/*
 * v06.4: bulk-clear pernet->local_addr_list via
 * MPTCP_PM_CMD_FLUSH_ADDRS.  Exercises the splice-then-iterate
 * teardown shape -- same structural pattern as the userspace-side
 * mptcp_pm_destroy code whose alloc-during-teardown race was just
 * fixed.  Worth fuzzing concurrently with v06.2 add_addr and v06.3
 * del_addr for the bulk-vs-incremental race surface.
 *
 * No args -- the command is bare.
 */
static long syz_mptcp_pm_kernel_flush_addrs(void)
{
	if (brf_mptcp_ensure_executor_setup() < 0)
		return -1;

	if (brf_mptcp_genl_kernel_flush_addrs() < 0) {
		debug("syz_mptcp_pm_kernel_flush_addrs: failed\n");
		return -1;
	}

	debug("syz_mptcp_pm_kernel_flush_addrs: addrs flushed\n");
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_set_limits
/*
 * v06.5: set the kernel PM's per-netns limit_add_addr_accepted and
 * limit_extra_subflows.  Exercises mptcp_pm_nl_set_limits_doit and
 * the downstream readers that consult these values when accepting
 * remote ADD_ADDRs / additional subflows.
 */
static long syz_mptcp_pm_set_limits(volatile long a0, volatile long a1)
{
	uint32_t rcv_add_addrs = (uint32_t)a0;
	uint32_t subflows = (uint32_t)a1;

	if (brf_mptcp_ensure_executor_setup() < 0)
		return -1;
	if (brf_mptcp_genl_set_limits(rcv_add_addrs, subflows) < 0) {
		debug("syz_mptcp_pm_set_limits: rcv=%u sf=%u failed\n",
		      rcv_add_addrs, subflows);
		return -1;
	}
	debug("syz_mptcp_pm_set_limits: rcv=%u sf=%u set\n",
	      rcv_add_addrs, subflows);
	return 0;
}
#endif

#endif // BRF_COMMON_LINUX_MPTCP_H
