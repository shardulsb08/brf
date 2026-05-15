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
static long syz_mptcp_join_subflow(volatile long a0, volatile long a1,
				   volatile long a2, volatile long a3,
				   volatile long a4)
{
	// a0: pair (pool index)
	// a1: addr_id
	// a2: backup (0/1)
	// a3: nonce_mut
	// a4: hmac_mut
	//
	// v0 skeleton.  Real implementation: design doc Section 5.2.
	// Sketch:
	//   1. Look up pool slot; allocate a subflow slot.
	//   2. Generate local_nonce; apply nonce_mut to the wire copy.
	//   3. Craft MP_JOIN SYN bytes; inject via AF_PACKET.
	//   4. Wait for SYN-ACK; extract remote_nonce + server thmac.
	//   5. Verify server thmac equals first 8 bytes of
	//        HMAC-SHA256(K = remote_key||local_key BE,
	//                    M = remote_nonce||local_nonce BE).
	//      Discrepancy is logged (kernel-emitted thmac is whatever
	//      the kernel emitted; verification is for our own sanity).
	//   6. Compute our ACK HMAC:
	//        HMAC-SHA256(K = local_key||remote_key BE,
	//                    M = local_nonce||remote_nonce BE)
	//      Apply hmac_mut to the wire copy.
	//   7. Inject MP_JOIN ACK with the (possibly mutated) HMAC.
	debug("syz_mptcp_join_subflow: not implemented (v0 skeleton)\n");
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
