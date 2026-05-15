# MPTCP runtime coverage for the MP_JOIN harness -- patch series v01

**Status:** v01 first draft (2026-05-15).  Not yet applied or
booted; expect minor context fixups on first `git am` against
`mptcp/export` (tag `export/20260515T083717` or later).

**Companion documents:**
- `.claude/designs/brf_architecture.md` Section 7 Step 6 -- general
  kcov-instrumentation pattern.
- `.claude/designs/mptcp_join_harness_design.md` Section 7 -- the
  per-MPTCP instrumentation plan and granularity decision
  (subflow-level, with msk-level handle as user-facing knob).
- `.claude/designs/kernel_base_management.md` -- where this patch
  series fits in the build flow (apply after fast-forwarding
  `mptcp_brf_fuzz_base` to upstream `mptcp/export`).
- Prior art: `kcov_for_bpf/v06/` (eBPF analogue; patch 0001 there
  is the prereq for this series and is reused verbatim).

## What this series adds

Three independent layers, two patches:

1. **`MPTCP_KCOV_HANDLE` setsockopt at SOL_MPTCP level**, gated by
   `CONFIG_KCOV`.  User sets a kcov remote handle on a `struct
   mptcp_sock`; subflows created subsequently inherit it.
2. **Per-subflow kcov scratch area** owned by
   `struct mptcp_subflow_context`, allocated at subflow ULP init
   time when the parent msk has a non-zero handle, freed at ULP
   release time.
3. **Coverage-collection wrappers** around the MPTCP validity
   gates that screen out random fuzz input:
     - `mptcp_get_options`  / `mptcp_parse_option`
     - `subflow_token_join_request`  (token lookup)
     - `subflow_hmac_valid`  (server-side HMAC)
     - `subflow_thmac_valid`  (client-side HMAC)
     - `get_mapping_status`  (DSS mapping)
     - `mptcp_can_accept_new_subflow`

## Prerequisites

Apply **before** this series:

```
brf/kernel_patches/kcov_for_bpf/v06/0001-kcov-bpf-Add-support-for-preallocated-coverage-area.patch
```

That patch (subsystem-agnostic) adds `kcov_remote_start_prealloc()`
and `kcov_remote_stop_prealloc()` to `kernel/kcov.c`; this series
depends on those symbols.

## Apply order

```bash
cd /mnt/work_4gb/Dev/mpiric_kernel_dev_env/open/src/kernel/linux
git checkout mptcp_brf_fuzz_base
git reset --hard mptcp/export

# Subsystem-agnostic prereq from BRF's earlier work.
git am < /mnt/work_4gb/Tools/003_kernel_testing/prana_kernel_testing/container_kernel_workspace/kernel_patches/ebpf/brf/kcov_for_bpf/v06/0001-kcov-bpf-Add-support-for-preallocated-coverage-area.patch

# This series.
PATCH_DIR=/mnt/work_4gb/Dev/mpiric_kernel_dev_env/open/src/fuzzing/brf/kernel_patches/mptcp_kcov/v01
git am < $PATCH_DIR/0001-mptcp-add-kcov-remote-handle-fields-and-sockopt.patch
git am < $PATCH_DIR/0002-mptcp-instrument-validity-gates-with-kcov.patch
```

If a patch fails to apply (line-number drift from upstream
churn), use `git am --3way` for 3-way merge, or `git apply
--reject` to drop `.rej` files for manual fixup.

## What is NOT in v01

- **No uapi exposure via `MPTCP_INFO` getsockopt.**  v06's
  patch 0003 (BPF analogue) exposed the handle for userspace
  visibility.  For our harness the userspace SETS the handle so
  it already knows it; getter not needed for v01.  Add later if
  needed.
- **No msk-level instrumentation wrappers.**  Per design doc
  Section 7.1 + open-question Q4 settlement (2026-05-15), we
  start subflow-only.  The validity gates we want to fuzz fire
  at subflow level.  Add msk-level later if `mptcp_sendmsg` /
  `mptcp_recvmsg` paths turn out to need coverage we can't get
  via subflow instrumentation.
- **No per-subflow setsockopt for setting the handle.**  Handle
  inheritance from msk to subflows is automatic at subflow
  creation; explicit per-subflow setting would require a
  separate setsockopt path on the TCP subflow socket which is
  more invasive.  v01 keeps inheritance-only.

## Verification (when first booted)

In the VM after boot:

```bash
# 1. Confirm CONFIG_KCOV is enabled and our new sockopt is
#    visible.
cat /sys/kernel/debug/kcov-something          # TODO: which kcov
                                              # debug path

# 2. Write a minimal C program that:
#    - opens IPPROTO_MPTCP socket
#    - opens kcov fd, ioctl KCOV_INIT_TRACE, mmap
#    - setsockopt(SOL_MPTCP, MPTCP_KCOV_HANDLE, &handle)
#    - completes an MP_CAPABLE exchange
#    - reads coverage buffer
#    Expect non-zero PC values in the buffer covering net/mptcp/.

# 3. Then trigger an MP_JOIN with bad HMAC; confirm the
#    subflow_hmac_valid -> RST path appears in coverage.
```

## TODOs flagged inline in the patches

Where the patches are uncertain about exact upstream line context
or surrounding logic, a `/* TODO(v01): ... */` comment marks the
spot.  These need first-apply review.
