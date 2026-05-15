# MPTCP MP_JOIN harness design

**Read this when:** designing, implementing, debugging, or extending
the MPTCP MP_JOIN fuzz harness in this BRF tree.  When designing a
sibling harness for QUIC handshake or NET_HANDSHAKE / tlshd, read
this first as the worked example, then specialise.

**Companion documents:**
- `.claude/designs/brf_architecture.md` (Section 7 is the recipe this
  doc instantiates).
- `.claude/tasks/netdev_0x1a_protocol_fuzzing/CLAUDE.md` (task brief,
  scope and constraints).
- `.claude/tasks/netdev_0x1a_protocol_fuzzing/context_reference.md`
  (strategic context, citation discipline).

**Status:** v0 draft, 2026-05-15.  No code written yet.  This doc
fixes the design before implementation so the harness lands in
idiomatic BRF shape on first try.

## 1. Goal

Build a BRF-style pseudo-syscall harness for the MPTCP MP_JOIN
handshake (RFC 8684 Section 3.2) that satisfies the cryptographic
gates which currently block any stateless Syzkaller fuzzer from
reaching MP_JOIN-validation code paths.

**The load-bearing claim:** with this harness, a fuzzer can produce
syntactically valid MP_JOIN suboptions (correct token, correct HMAC
over correct nonces and keys) **and** controlled, semantically
meaningful mutations of those suboptions -- so HMAC-validation, DSS
mapping, and subflow-state code paths receive real coverage that
the upstream Syzkaller stack cannot deliver.

Why this specific flow first:

- Deepest existing MPTCP expertise (Shardul's HMAC-A / HMAC-B
  fixes upstream).
- Clearest single cryptographic gate (HMAC over four pieces of
  captured state); proving the harness here generalises.
- Active maintainer team (matttbe, Mat Martineau, Geliang Tang,
  Paolo Abeni) and syzbot integration -- any bug found has a
  direct upstream path.

## 2. The cryptographic gates this harness must clear

Recap from the gate map (agent research, 2026-05-15) -- these are
the gates where a random fuzzer fails:

| Gate                                  | Probability of stateless pass | What is needed                                                |
|---------------------------------------|-------------------------------|---------------------------------------------------------------|
| MP_JOIN token lookup                  | 0%                           | Live `msk->token` registered by a prior MP_CAPABLE exchange    |
| MP_JOIN HMAC validation (server side) | < 2^-64 per attempt          | HMAC-SHA256(local_key||remote_key, local_nonce||remote_nonce)  |
| MP_JOIN HMAC validation (client side) | < 2^-160 per attempt         | Full 20-byte HMAC over the same inputs                         |
| MP_DSS mapping validity / csum        | ~1:2^32 if csum enabled      | Negotiated csum mode + valid CRC-32C over payload              |
| Subflow accept readiness              | ~50% (depends on msk state)  | `msk` fully established and PM accepts subflows                |

The harness's job is to **make each of these probabilities
controllable** -- 100% in normal mode (proves we reach past the
gate), and a *defined* probability in mutation mode (proves the
mutation reaches the kernel parser).

## 3. Pseudo-syscall family

Five pseudo-syscalls (subject to refinement after first build).
All declared in a new file `sys/linux/socket_mptcp_crypto.txt`,
implemented in a new header `executor/common_brf_linux_mptcp.h`.

### 3.1 Resource and state types (syzlang)

```
resource mptcp_pair[intptr]

mptcp_init_flags = MPTCP_INIT_CSUM_ON, MPTCP_INIT_CSUM_OFF,
                   MPTCP_INIT_DENY_JOIN_ID0
mptcp_nonce_mut  = MPTCP_NONCE_NORMAL, MPTCP_NONCE_ZERO,
                   MPTCP_NONCE_FLIP_HIGH, MPTCP_NONCE_FLIP_LOW,
                   MPTCP_NONCE_REPLAY
mptcp_hmac_mut   = MPTCP_HMAC_NORMAL, MPTCP_HMAC_ZERO,
                   MPTCP_HMAC_BIT_FLIP, MPTCP_HMAC_TRUNCATE,
                   MPTCP_HMAC_SWAP
mptcp_map_mut    = MPTCP_MAP_NORMAL, MPTCP_MAP_STALE_SEQ,
                   MPTCP_MAP_OFF_BY_ONE, MPTCP_MAP_INFINITE,
                   MPTCP_MAP_HOLE
mptcp_control_subopt = MPTCP_CTL_FAIL, MPTCP_CTL_FASTCLOSE,
                       MPTCP_CTL_RST

mptcp_pair_state {
    /* Out-param populated by syz_mptcp_pair_init.  Visible to
     * the fuzzer descriptor evaluator so subsequent syscalls
     * can resource-reference fields if needed.  Most consumers
     * only need the opaque mptcp_pair handle. */
    server_fd        int32
    client_fd        int32
    local_key        int64
    remote_key       int64
    token            int32
    csum_enabled     int8
}
```

### 3.2 The five syscalls (syzlang)

```
# Create server + client pair, complete MP_CAPABLE, capture
# all cryptographic state.  Returns an opaque pair handle.
syz_mptcp_pair_init(
    server_addr ptr[in, sockaddr_storage],
    client_addr ptr[in, sockaddr_storage],
    flags       flags[mptcp_init_flags, int32],
    out_state   ptr[out, mptcp_pair_state]
) mptcp_pair

# Initiate MP_JOIN from a new client-side subflow.  In NORMAL
# mode, all crypto material is correct and the join succeeds.
# In mutation modes, the executor mutates exactly the named
# field, leaving everything else valid -- so kernel parser
# failures are attributable.
syz_mptcp_join_subflow(
    pair      mptcp_pair,
    addr_id   int8,
    backup    bool8,
    nonce_mut flags[mptcp_nonce_mut, int8],
    hmac_mut  flags[mptcp_hmac_mut, int8]
)

# Send data through an established subflow, optionally with a
# mutated DSS mapping.
syz_mptcp_drive_traffic(
    pair       mptcp_pair,
    subflow_id int32,
    data       ptr[in, array[int8]],
    data_len   bytesize[data, int32],
    map_mut    flags[mptcp_map_mut, int8]
)

# Inject a control suboption (MP_FAIL, MP_FASTCLOSE, MP_RST)
# at a specific point in the connection.  Tests recovery paths.
syz_mptcp_send_control(
    pair       mptcp_pair,
    subflow_id int32,
    suboption  flags[mptcp_control_subopt, int8]
)

# Closeout.  Frees state slot, closes file descriptors.
syz_mptcp_pair_close(pair mptcp_pair)
```

## 4. The state-carrier struct (C)

`executor/common_brf_linux_mptcp.h`:

```c
#define MPTCP_PAIR_POOL_SIZE     16
#define MPTCP_MAX_SUBFLOWS_PER_PAIR 8

struct mptcp_subflow_state {
    uint32_t local_nonce;            /* generated locally for this subflow */
    uint32_t remote_nonce;           /* extracted from peer's SYN-ACK     */
    uint8_t  expected_thmac[8];      /* truncated HMAC; what server sends */
    uint8_t  expected_hmac[20];      /* full HMAC; what client sends      */
    int      tcp_subflow_fd;         /* the joined TCP subflow            */
    bool     established;            /* MP_JOIN ACK received and accepted */
};

struct mptcp_pair_state_c {
    bool     in_use;

    /* Endpoint sockets */
    int      server_listen_fd;       /* IPPROTO_MPTCP listening socket    */
    int      server_msk_fd;          /* accepted msk after MP_CAPABLE     */
    int      client_msk_fd;          /* client side msk                   */

    /* MP_CAPABLE-captured cryptographic state.
     * Per RFC 8684 Section 3.1, both keys are exchanged during
     * MP_CAPABLE.  The token is SHA-256(remote_key) truncated
     * to 32 bits.  IDSN is the bottom 64 bits of SHA-256(remote_key).
     */
    uint64_t local_key;
    uint64_t remote_key;
    uint32_t token;
    uint64_t idsn_local;
    uint64_t idsn_remote;
    bool     csum_enabled;
    bool     deny_join_id0;

    /* Per-subflow state. */
    struct mptcp_subflow_state subflows[MPTCP_MAX_SUBFLOWS_PER_PAIR];
    int      subflow_count;

    /* Diagnostics. */
    int      last_kernel_errno;
    uint32_t last_mib_rst_reason;
};

static struct mptcp_pair_state_c mptcp_pair_pool[MPTCP_PAIR_POOL_SIZE];
```

The struct lives in static executor memory (same pattern as BRF's
`bpf_object_list`).  The `mptcp_pair` syzlang resource is the index
into this pool; the out-param `mptcp_pair_state` (syzlang) is a
projection of the C struct's user-visible fields.

## 5. The derivation pipeline

For each pseudo-syscall, what the **executor** must compute and what
the **kernel** sees:

### 5.1 syz_mptcp_pair_init

Steps in C:

```
 1. Allocate a free slot in mptcp_pair_pool; mark in_use.
 2. socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP) for server; bind;
    listen.  Use ephemeral port if server_addr->port == 0.
 3. socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP) for client.  Set
    setsockopt(SOL_MPTCP, MPTCP_INFO_xxx) as needed for csum mode.
 4. connect() client to server.  Wait for ESTABLISHED.
 5. Capture local_key and remote_key.  Two paths:
    (a) getsockopt(SOL_MPTCP, MPTCP_INFO) -- kernel exposes the
        local mptcp_info structure with msk_key (since v5.16) and
        peer key.  Cleanest.
    (b) Raw socket peek on the loopback PACKET interface during
        connect() to extract the MP_CAPABLE option bytes directly.
        Used as fallback or for cross-verification.
 6. Compute token = upper 32 bits of SHA-256(remote_key).
 7. Compute idsn_local = lower 64 bits of SHA-256(local_key);
    idsn_remote = lower 64 bits of SHA-256(remote_key).
 8. Populate out-param mptcp_pair_state.
 9. Return the pool slot index (cast as mptcp_pair resource).
```

Notes:

- Step 5 may have a chicken-and-egg problem: `MPTCP_INFO`'s key
  field may be gated by `CAP_NET_ADMIN`.  Verify against the
  current kernel in the dev_env VM; if gated, fall back to (b).
- Step 6's truncation direction is "upper 32 bits" per RFC 8684
  Section 3.2.  Verify against `net/mptcp/crypto.c
  mptcp_crypto_key_sha()` (Linux uses upper bits).

### 5.2 syz_mptcp_join_subflow

Steps in C:

```
 1. Look up pair from the resource handle.
 2. Allocate a free subflow slot in pair->subflows[].
 3. Generate local_nonce = 32 bits from /dev/urandom.
 4. Craft the MP_JOIN SYN option bytes:
      type=30, len=12, subtype=1<<4|backup<<0, addr_id, token,
      local_nonce
    Apply nonce_mut to local_nonce in this buffer if mut != NORMAL.
 5. Inject the TCP SYN with this option onto loopback.  Two paths:
    (a) Use AF_PACKET + raw ethernet frame craft.
    (b) Use a TUN device that the harness owns.
    See Section 6 for the choice.
 6. Wait for SYN-ACK on the same path.  Extract remote_nonce and
    server's truncated HMAC (thmac, 8 bytes).
 7. Verify thmac matches our expectation:
      expected_thmac = first 8 bytes of HMAC-SHA256(
        key  = remote_key || local_key,
        msg  = remote_nonce || local_nonce
      )
    Note key/nonce ordering: peer-first for the responder's HMAC.
 8. Compute our HMAC for the ACK:
      hmac = HMAC-SHA256(
        key  = local_key || remote_key,
        msg  = local_nonce || remote_nonce
      )
    Apply hmac_mut to this 20-byte buffer if mut != NORMAL.
 9. Craft and inject the MP_JOIN ACK with hmac.
10. If the kernel accepts (no RST received within timeout),
    populate pair->subflows[i].established = true.
11. Return 0 on success, negative on kernel-side failure (the
    fuzzer then has a coverage signal indicating which gate
    failed).
```

The HMAC ordering, key ordering, and length-truncation details
come from RFC 8684 Section 3.2 and `net/mptcp/crypto.c
mptcp_crypto_hmac_sha()` -- verify against kernel code, not
RFC alone, since Linux conventions on byte order can differ.

### 5.3 syz_mptcp_drive_traffic

Steps in C:

```
 1. Look up pair + subflow.
 2. write(pair->subflows[subflow_id].tcp_subflow_fd, data, len);
    OR craft a TCP segment with payload + DSS option.
 3. If map_mut == NORMAL, kernel emits a correct DSS option.
 4. If map_mut != NORMAL, intercept the outgoing packet, rewrite
    the DSS bytes per the mutation, and re-emit.  Mutations:
      STALE_SEQ -- data_seq from N RTTs ago
      OFF_BY_ONE -- data_seq off by 1
      INFINITE   -- data_len = 0 (RFC: infinite mapping marker)
      HOLE       -- data_seq leaves a gap
 5. Return.  Coverage of get_mapping_status / validate_mapping
    in net/mptcp/subflow.c shows whether the kernel reached
    deep mapping validation.
```

### 5.4 syz_mptcp_send_control and syz_mptcp_pair_close

Straightforward.  `send_control` crafts a single MPTCP option
suboption with the requested type and sends it.  `pair_close`
closes all fds and clears the pool slot.

## 6. Injection mechanism choice

Three options, with tradeoffs:

| Option                       | Pros                                       | Cons                                          |
|------------------------------|--------------------------------------------|-----------------------------------------------|
| (a) Real sockets on `lo`     | Kernel does TCP for us; minimal setup     | Cannot mutate options -- kernel emits its own |
| (b) AF_PACKET raw inject     | Full byte control; can mutate freely      | Must implement TCP state machine in executor |
| (c) Hybrid: real client side, AF_PACKET peer | Real kernel side for "our" endpoint; raw inject for "peer" packets | Most complex; needs careful path isolation    |

**Recommendation: (c) hybrid.**

Rationale: the *kernel under test* is what we want to fuzz.  In
option (c), the kernel runs its real MPTCP parser on the bytes we
inject via AF_PACKET; our side uses real sockets so we don't have
to implement TCP retransmits, ACK handling, etc.

Concretely:

- The *server* endpoint is a real `IPPROTO_MPTCP` listening socket
  on the loopback.  Kernel-under-test runs the parser.
- The *client* endpoint pretends to be a remote peer, crafted via
  AF_PACKET.  The harness emits SYN+MP_CAPABLE, ACK, SYN+MP_JOIN
  with mutated bytes, etc.
- Use a dedicated netns or a non-loopback dummy interface so we
  don't fight the kernel's own loopback TCP behaviour for the
  injected packets.

If (c) proves too complex for v1, fall back to (a) for the
honest-handshake path and capture-only operation (no mutations);
that proves the state-carrier works and exposes some bugs but
loses the mutation surface.

## 6.bis Kernel base for this harness

The kernel base is a tracking branch, not a frozen tag.  See
`.claude/designs/kernel_base_management.md` for the full workflow
(why tracking-not-pinning, update procedure, patch application,
reproducibility-footer convention for bug reports).

Specifically for MPTCP work:

- Local branch: `mptcp_brf_fuzz_base` in the kernel tree at
  `/mnt/work_4gb/Dev/mpiric_kernel_dev_env/open/src/kernel/linux/`.
- Upstream source: `mptcp/export` (riches surface; net-next based).
  Bug findings get routed at report time (Fixes -> mptcp/export-net;
  feature -> mptcp/export).
- Current snapshot (2026-05-15): `export/20260515T083717`.
- Update cadence: weekly between campaigns; freeze during a
  campaign; bump before any publishable run.

## 7. Kernel-side kcov instrumentation

Per `brf_architecture.md` Section 7 Step 6, reuse patch 0001 from
the kcov-for-BRF v06 set verbatim, then author an analogue of
patch 0002 for MPTCP.

### 7.1 Where to add the handle

Two reasonable choices for the per-flow struct:

- `struct mptcp_sock` (net/mptcp/protocol.h): per-msk handle.
  Coverage instrumentation wraps msk-level entry points
  (mptcp_sendmsg, mptcp_recvmsg, the PM doits).
- `struct mptcp_subflow_context` (same file): per-subflow handle.
  Wraps subflow-level entry points (subflow_data_ready,
  get_mapping_status, the MPTCP option parser hooks).

**Recommendation: both, separately wired.**  The msk handle
captures msk-level state machine.  The subflow handle captures
the gates that actually reject bad MP_JOIN bytes.  For our
purposes the subflow handle is the more important one because
the validity gates fire there.

### 7.2 Entry points to wrap

For v1, instrument at the option-parser dispatcher and the
HMAC-validation sites:

```
net/mptcp/options.c:359   mptcp_get_options          (option dispatch)
net/mptcp/options.c:35     mptcp_parse_option         (per-subtype)
net/mptcp/subflow.c:85     subflow_token_join_request (token lookup)
net/mptcp/subflow.c:753    subflow_hmac_valid          (server-side HMAC)
net/mptcp/subflow.c:414    subflow_thmac_valid         (client-side HMAC)
net/mptcp/subflow.c:1109   get_mapping_status          (DSS mapping)
net/mptcp/subflow.c:915    mptcp_can_accept_new_subflow
net/mptcp/pm.c:*           mptcp_pm_*                  (PM events)
```

Wrap each in `kcov_remote_start_prealloc(handle, area, size)` /
`kcov_remote_stop_prealloc()` calls keyed on the appropriate
struct's handle field.

### 7.3 How userspace gets the handle into the kernel

For BPF, BRF passes the handle via `bpf_attr.kcov_remote_handle`
(patch 0002).  For MPTCP, the equivalent is a setsockopt or a
netlink call.  Options:

- New `setsockopt(SOL_MPTCP, MPTCP_KCOV_HANDLE, &handle)`.
  Cleanest, but requires a new sockopt code.
- Repurpose an existing debug sockopt under `#ifdef CONFIG_KCOV`.
  Cheaper to land.
- Userspace netlink op via `mptcp_pm_genl_family`.  Heavy.

**Recommendation: new setsockopt under CONFIG_KCOV.**  Mirrors
how BPF does it and isolates the change cleanly.

### 7.4 Patch series structure

Following the BRF v06 pattern:

```
0001-kcov: applied verbatim from BRF v06 (already exists).
0002-mptcp: adds kcov_remote_handle / area / size to
            mptcp_sock + mptcp_subflow_context; wraps the
            entry points listed in 7.2; defines the new
            setsockopt.
0003-mptcp: (optional) expose handle via MPTCP_INFO getsockopt.
```

Drafts of 0002 / 0003 will live as patches in this BRF tree
under (TBD path, possibly `kernel_patches/mptcp_kcov/`) when
they are written, in a sibling tree to where the existing
v06 lives.

## 8. v1 mutation set (what to actually fuzz first)

Keep the mutation surface tight at v1.  All controlled by the
mutation-flag enums in Section 3.

| Field             | Mutations                                         | Tests which gate                          |
|-------------------|---------------------------------------------------|-------------------------------------------|
| local_nonce       | ZERO, FLIP_HIGH, FLIP_LOW, REPLAY                | server-side HMAC validation               |
| client HMAC       | ZERO, BIT_FLIP, TRUNCATE, SWAP                   | server's `subflow_hmac_valid`             |
| addr_id           | 0 (reserved), out-of-range, not-advertised        | `subflow_chk_local_id`, PM validation     |
| DSS mapping       | STALE_SEQ, OFF_BY_ONE, INFINITE, HOLE             | `get_mapping_status`, `validate_mapping`  |
| Control suboption | MP_FAIL mid-stream, MP_FASTCLOSE mid-stream, MP_RST at unexpected times | recovery / fallback paths    |

Out of scope for v1 (worth at v2 if time permits):

- Concurrent MP_JOIN races (issue #621 territory; requires
  multi-thread injection).
- Subflow ADD_ADDR / RM_ADDR / MP_PRIO mutations.
- IPv6 (start IPv4-only; widen once IPv4 path is solid).
- Cross-namespace MPTCP (the "EMPTCP" paths Shardul's
  HMAC-A/B work touched).

## 9. First-runs success criteria

**Harness-validity criteria** (must pass before claiming the
harness works):

1. **Normal-mode coverage:**  Running 100 inputs with all
   mutation flags set to NORMAL, kcov shows entry into
   `subflow_hmac_valid` (server side) AND `subflow_thmac_valid`
   (client side) AND `mptcp_can_accept_new_subflow` returning
   true.  Counter `MPTCP_MIB_JOINACKMAC` increments.
2. **Mutation reachability:**  Running 100 inputs with each
   mutation enum value at least once, the relevant counter
   increments AND the corresponding RST reason fires when
   expected.  Specifically:
   - HMAC mutations -> `MPTCP_RST_EPROHIBIT` increments.
   - Token unknown (e.g., closing a pair mid-test) ->
     `MPTCP_MIB_JOINNOTOKEN` increments.
3. **Coverage growth:**  Over a 5-minute run, new basic blocks
   in `net/mptcp/subflow.c` and `net/mptcp/options.c` are
   discovered.  Plateau within 5 minutes is OK; zero growth
   indicates a stuck harness.

**Bug-finding criteria** (the talk's actual deliverable):

1. KASAN report on any MPTCP code path.
2. WARN_ON / lockdep splat in `net/mptcp/`.
3. Hung-task or softlockup attributable to MPTCP.
4. Unexpected RST reason (logic bug rather than parser
   rejection).
5. Memory leak (kmemleak hit) in mptcp/subflow lifetime.

Any one of these, with a deterministic reproducer, is a
publishable finding.  Per the project memory
`feedback_netdev_framing_provisional.md`, bug findings are
load-bearing for the talk -- the harness's value as
infrastructure is incomplete without them.

## 10. What can go wrong (anti-scope and risks)

- **MPTCP info getsockopt may not expose keys.**  If it doesn't,
  fall back to raw-socket capture during connect().  Test in the
  dev_env VM before committing to one path.
- **AF_PACKET raw inject on loopback may race with kernel's own
  TCP.**  Use a dummy netdev or netns to isolate, or run in a
  fresh netns per pair.
- **HMAC byte ordering subtleties.**  RFC 8684 vs Linux's
  implementation: cross-reference `net/mptcp/crypto.c` directly
  rather than trusting the RFC paraphrase here.
- **MPTCP version negotiation.**  RFC 8684 added a version field;
  earlier kernels handled it slightly differently.  Pin to the
  dev_env kernel version and document.
- **Synchronous-handshake timeouts.**  If the harness's injected
  packets are too slow (or too fast), the kernel may reset or
  ignore.  Use the same timing the kernel itself uses (TCP
  retransmit defaults) as the starting point.

## 11. Open questions to settle before implementation

1. **Pair-init key capture path:** (a) MPTCP_INFO getsockopt vs
   (b) raw-socket peek.  Settle in first dev_env experiment.
2. **netns vs loopback isolation.**  Per-pair fresh netns is
   cleanest but adds setup latency.  Loopback with careful
   port allocation is faster.  Benchmark in the dev_env.
3. **Kcov-handle plumbing path.**  setsockopt vs other.  See 7.3.
4. **Coverage instrumentation granularity:** msk-level vs
   subflow-level vs both.  Recommendation: both, but if patch
   complexity is an issue, start subflow-only since the gates
   we care about fire there.

## 12. Implementation order (when work starts)

1. Write the syzlang descriptions (Section 3) and run syz-sysgen
   to verify they parse without errors.  Sanity check.
2. Skeleton `executor/common_brf_linux_mptcp.h` with empty
   implementations and the static pool defined.  Compiles.
3. Implement `syz_mptcp_pair_init` end-to-end with no mutations
   -- prove key capture works.
4. Author the kernel-side kcov patches (0002-mptcp, 0003-mptcp)
   off the BRF v06 0001 patch as base.
5. Boot the dev_env VM with the patched kernel.  Verify kcov
   handle plumbing end-to-end on a sample MPTCP connection.
6. Implement `syz_mptcp_join_subflow` in NORMAL mode only.
   Verify HMAC validation gate is reached and passes.
7. Add mutation modes one enum value at a time.  Verify each
   mutation produces the expected kernel signal (RST reason,
   counter increment, coverage delta).
8. Implement `syz_mptcp_drive_traffic` and `syz_mptcp_send_control`.
9. Wire the new pseudo-syscalls into BRF's generator (Section 7.4
   of `brf_architecture.md`).  Start with the simpler "extend
   GenPrologue" option (a); refactor to "sibling fuzzer" (b) if
   it turns out to be needed.
10. First fuzz run.  Measure success criteria from Section 9.

Time-box each step.  If step N takes longer than 2x the planned
time, surface the blocker rather than grinding.

## 13. Cross-references

- `.claude/designs/brf_architecture.md` -- the architecture this
  doc instantiates.
- `.claude/tasks/netdev_0x1a_protocol_fuzzing/CLAUDE.md` -- task
  brief.
- Project memory `reference_kcov_brf_patches.md` -- pointer to
  the v06 patches.
- Project memory `feedback_netdev_framing_provisional.md` --
  bug-finding-is-load-bearing constraint.
- Global memory `feedback_frame_by_impact.md` -- framing posture.
- `net/mptcp/` in the kernel tree under
  `/mnt/work_4gb/Dev/mpiric_kernel_dev_env/open/src/kernel/linux/`
  -- the code under test.  Key files: protocol.c, subflow.c,
  options.c, pm.c, crypto.c, token.c, mib.c.
- RFC 8684 "TCP Extensions for Multipath Operation with Multiple
  Addresses" -- the protocol spec; cite as ground truth, but
  cross-reference Linux's implementation in `net/mptcp/crypto.c`
  for byte-ordering details.
