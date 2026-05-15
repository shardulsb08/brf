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

// Marked __attribute__((unused)) for the v0 skeleton because the stub
// pseudo-syscalls return -1 without touching state.  Remove the
// attribute once real implementations land (per design doc Section 12).
static struct brf_mptcp_pair_state brf_mptcp_pair_pool[MPTCP_PAIR_POOL_SIZE] __attribute__((unused));
static bool brf_mptcp_netns_initialized __attribute__((unused)) = false;

// ---------- Pseudo-syscall implementations (v0 skeletons) ----------

#if SYZ_EXECUTOR || __NR_syz_mptcp_pair_init
static long syz_mptcp_pair_init(volatile long a0, volatile long a1,
				volatile long a2, volatile long a3)
{
	// a0: ptr to server_addr (sockaddr_storage)
	// a1: ptr to client_addr (sockaddr_storage)
	// a2: flags (mptcp_init_flags)
	// a3: ptr to out_state (struct brf_mptcp_pair_state_out)
	//
	// v0 skeleton.  Real implementation: design doc Section 5.1.
	// Sketch:
	//   1. Lazy netns init: if !brf_mptcp_netns_initialized, set up
	//      two netns connected by a veth pair, mark initialized.
	//   2. Allocate a pool slot.
	//   3. socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP) for server +
	//      client; bind / listen / connect inside the netns pair.
	//   4. AF_PACKET wire peek on the veth to extract local_key
	//      (client's MP_CAPABLE SYN) and remote_key (server's
	//      MP_CAPABLE SYN-ACK).
	//   5. Compute token = upper-32-bits SHA-256(BE remote_key) and
	//      IDSNs per net/mptcp/crypto.c:mptcp_crypto_key_sha.
	//   6. Populate the pool slot and the out-param.
	//   7. Return pool slot index as the mptcp_pair resource value.
	debug("syz_mptcp_pair_init: not implemented (v0 skeleton)\n");
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
	// a0: pair (pool index)
	debug("syz_mptcp_pair_close: not implemented (v0 skeleton)\n");
	return -1;
}
#endif

#endif // BRF_COMMON_LINUX_MPTCP_H
