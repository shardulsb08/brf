# MPTCP runtime coverage for the MP_JOIN harness

**Status:** patches 0001-0003 added 2026-05-15; patches 0004-0005
added 2026-05-21; patches 0006-0007 added 2026-05-22.  Patches were authored as real commits on the kernel
tree's `mptcp_brf_fuzz_base` branch, then exported with `git
format-patch` -- they should apply cleanly against the same base
(`mptcp/export`).  If the upstream base has moved, `git am --3way`
typically resolves any context drift.

**Iterations** live in BRF git history, not in version-suffixed
subdirectories.  When patches need revision, replace them in this
directory in a new BRF commit; `git log -p kernel_patches/mptcp_kcov/`
recovers the history.  The "v01"/"v02" labels you may see in body
text below are informal iteration markers, not directory names.

**Companion documents:**
- `.claude/designs/brf_architecture.md` Section 7 Step 6 -- general
  kcov-instrumentation pattern.
- `.claude/designs/mptcp_join_harness_design.md` Section 7 -- the
  per-MPTCP instrumentation plan and granularity decision
  (subflow-level, with msk-level handle as user-facing knob).
- `.claude/designs/kernel_base_management.md` -- where this patch
  series fits in the build flow (apply after fast-forwarding
  `mptcp_brf_fuzz_base` to upstream `mptcp/export`).
- Prior art: `bpf_kcov/` (eBPF analogue; patch 0001 there
  is the prereq for this series and is reused verbatim).

## What this series adds

Seven patches:

1. **`MPTCP_KCOV_HANDLE` setsockopt + per-msk scratch area +
   kcov_owner ownership marker**, CONFIG_KCOV-gated.  User sets a
   kcov remote handle on a `struct mptcp_sock` via the new
   sockopt; the handler vmalloc()s a 64 KB scratch buffer used by
   kcov_remote_start_prealloc.  v01 puts the buffer on the msk
   (shared across subflows).  Accepted msks inherit the pointer
   via sk_clone_lock()'s memcpy, so a `kcov_owner` field marks
   the allocating msk; only that msk vfree()s on destroy.

2. **Coverage-collection wrappers** around three MPTCP subflow
   validity gates:
     - `subflow_token_join_request` (token lookup, post-success)
     - `subflow_hmac_valid`         (server-side full HMAC)
     - `subflow_thmac_valid`        (client-side truncated HMAC)
   Wrappers are `BRF_MPTCP_KCOV_START(msk)` / `_STOP(msk)` macros
   defined in `net/mptcp/protocol.h`; the macros snapshot the
   handle once into a local to avoid racing with setsockopt
   between start and stop, and reduce to a single branch when
   the handle is zero.

3. **`MPTCP_DEBUG_KEYS` getsockopt** that returns
   `struct mptcp_debug_keys` (local_key, remote_key) from the msk,
   CONFIG_KCOV-gated.  Lets the BRF protocol-flow harness in this
   tree obtain the MP_CAPABLE-captured cryptographic state
   without parsing TCP-option bytes from the wire via AF_PACKET.
   Required by `syz_mptcp_pair_init` in
   `executor/common_brf_linux_mptcp.h`.

4. **Coverage-collection wrapper around the incoming-option
   parser.**  `mptcp_parse_option` (the per-suboption parse
   dispatch) is reached only via `mptcp_get_options`, whose sole
   caller in `options.c` is `mptcp_incoming_options` -- which
   already has the parent `msk` in scope.  Wrapping the
   `mptcp_get_options()` call there with `BRF_MPTCP_KCOV_START` /
   `_STOP` gives the parser an active kcov region without the
   signature refactor patch 2 cited when it deferred this.
   Covers ADD_ADDR / RM_ADDR / MP_PRIO / MP_FAIL / MP_RST / DSS
   option parsing, which runs in softirq.  Added 2026-05-21.

5. **kcov softirq-context guard.**  The `BRF_MPTCP_KCOV_*` macros
   call `kcov_remote_start()`, which WARNs (`kernel/kcov.c`) when
   called in process context from a task that already has kcov
   enabled.  The wrapped MPTCP RX paths -- the option parser and
   the MP_JOIN gates -- run not only in softirq but also in
   process context: `release_sock()` drains the socket backlog
   inline inside whatever syscall held the lock.  A fuzz run hit
   the WARNING via `mptcp_incoming_options` on the `sendto` ->
   `release_sock` path.  patch 5 guards the macros with
   `in_serving_softirq()` so the remote section is taken only in
   real softirq context (in process context the task's own
   per-task kcov already records the code -- no coverage lost).
   Added 2026-05-21.

6. **kcov scratch-area use-after-free fix.**  A fuzz run oopsed in
   `kcov_remote_start_prealloc` writing into a `vfree()`'d area.
   Patch 1's per-msk area had three lifetime holes: accepted msks
   memcpy-inherited the area pointer via `sk_clone_lock()` and
   could outlive the owner; the area was freed synchronously,
   racing in-flight softirq option parsing; and
   `BRF_MPTCP_KCOV_START` read the area pointer twice.  patch 6
   clears the inherited kcov fields in `mptcp_sk_clone_init()`
   (every area is now single-owner), frees via `kvfree_rcu()`
   (allocating with `kvmalloc()` to match) so an in-flight
   softirq's RCU grace period elapses before the free, and
   snapshots the area pointer once in the macro.  Added 2026-05-22.

7. **kcov-field initialisation in `__mptcp_init_sock()`.**  A fuzz
   run hit `WARNING: kernel/kcov.c:971` 24x via
   `mptcp_incoming_options` -- the handle-validity `WARN_ON` in
   `kcov_remote_start_prealloc` (`!kcov_check_handle()`).  The
   register dump showed a garbage handle (`d3bfc2c05b95c3c2`):
   uninitialised slab memory.  The kcov fields patch 1 added to
   `struct mptcp_sock` are written only by
   `setsockopt(MPTCP_KCOV_HANDLE)` and were never initialised at
   socket creation.  `mptcp_prot` uses `SLAB_TYPESAFE_BY_RCU`, so
   `sk_prot_alloc()` strips `__GFP_ZERO` and a recycled
   `mptcp_sock` keeps stale bytes; an msk that never sets a handle
   (a plain fuzzer socket, or a listener the harness leaves unset)
   exposes garbage to `BRF_MPTCP_KCOV_START`.  patch 6 cleared
   only the clone-inherited fields; this is the same family --
   the remaining new-socket hole.  patch 7 zeroes the four fields
   in `__mptcp_init_sock()`, the single init path for every msk
   (it also subsumes patch 6's clone-path clearing, reduced here
   to a comment).  This is the handle-validity WARN at
   `kcov.c:971`, distinct from the `in_task()`/kcov-enabled WARN
   at `kcov.c:983` that patch 5's `in_serving_softirq()` guard
   addresses.  Added 2026-05-22.

## Prerequisites

Apply **before** this series:

```
brf/kernel_patches/bpf_kcov/0001-kcov-bpf-Add-support-for-preallocated-coverage-area.patch
```

That patch (subsystem-agnostic) adds `kcov_remote_start_prealloc()`
and `kcov_remote_stop_prealloc()` to `kernel/kcov.c`; this series
depends on those symbols.  See `kernel_patches/bpf_kcov/
README.md` in this BRF tree for the prereq details.

## Apply order (entirely local to this BRF tree)

```bash
cd /mnt/work_4gb/Dev/mpiric_kernel_dev_env/open/src/kernel/linux
git checkout mptcp_brf_fuzz_base
git fetch mptcp && git reset --hard mptcp/export

# Path-agnostic shorthand for the BRF kernel-patches root.
BRF=/mnt/work_4gb/Dev/mpiric_kernel_dev_env/open/src/fuzzing/brf

# 1. Subsystem-agnostic kcov prereq.
git am < $BRF/kernel_patches/bpf_kcov/0001-kcov-bpf-Add-support-for-preallocated-coverage-area.patch

# 2. This series.
git am < $BRF/kernel_patches/mptcp_kcov/0001-mptcp-add-kcov_remote_handle-fields-and-MPTCP_KCOV_H.patch
git am < $BRF/kernel_patches/mptcp_kcov/0002-mptcp-instrument-MP_JOIN-validity-gates-with-kcov.patch
git am < $BRF/kernel_patches/mptcp_kcov/0003-mptcp-add-MPTCP_DEBUG_KEYS-getsockopt-for-test-harne.patch
git am < $BRF/kernel_patches/mptcp_kcov/0004-mptcp-extend-kcov-instrumentation-to-the-option-pars.patch
git am < $BRF/kernel_patches/mptcp_kcov/0005-mptcp-restrict-BRF-kcov-instrumentation-to-softirq-c.patch
git am < $BRF/kernel_patches/mptcp_kcov/0006-mptcp-fix-use-after-free-of-the-BRF-kcov-scratch-are.patch
git am < $BRF/kernel_patches/mptcp_kcov/0007-mptcp-initialize-BRF-kcov-fields-in-__mptcp_init_soc.patch
```

If a patch fails to apply (e.g. after the upstream base moves),
use `git am --3way` for 3-way merge.

## Still deferred

- **`net/mptcp/subflow.c get_mapping_status` instrumentation.**
  ~10 early-return paths in the function; a clean wrap needs a
  rename-and-wrap refactor (move body to `__get_mapping_status`,
  add thin outer wrapper).  Doable in v02 once the harness is
  exercising the DSS path enough to motivate it.
- **Per-subflow scratch area.**  v01 shares the area at msk
  scope, accepting cross-subflow CPU race.  v02 may promote to
  per-subflow or per-CPU if the race surfaces.
- **uapi exposure via getsockopt.**  Userspace sets the handle
  so it already knows it; getter not needed for v01.

## Verification (when first booted)

In the VM after boot, a minimal C program should:

1. Open kcov fd (`/sys/kernel/debug/kcov`), `ioctl(KCOV_INIT_TRACE,
   N)`, `mmap(N * sizeof(unsigned long))`.
2. `ioctl(KCOV_REMOTE_ENABLE, &kcov_remote_arg)` with the chosen
   handle.
3. Open an `IPPROTO_MPTCP` socket, `setsockopt(SOL_MPTCP,
   MPTCP_KCOV_HANDLE, &handle)`.
4. Complete an MP_CAPABLE handshake.
5. Trigger an MP_JOIN (a successful one).
6. Read the kcov buffer; expect non-zero PC values that map to
   `subflow_token_join_request` / `subflow_hmac_valid` /
   `subflow_thmac_valid` symbols.
7. Trigger an MP_JOIN with a bad HMAC; coverage should still
   land in `subflow_hmac_valid` and the reset path.
