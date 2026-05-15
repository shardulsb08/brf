# kcov runtime coverage wiring for eBPF (and the kcov core prereq)

**Origin:** Shardul Bankar, Sep 2025.  Co-developed with Cursor,
ChatGPT, and Gemini.  Authored to enable BRF's runtime coverage
feedback for eBPF program execution (per the BRF paper -- ACM
PACMSE 1(FSE) Art. 52, arXiv:2305.08782 -- which requires
kernel-side modifications for the kcov_remote interface to be
safe in non-sleepable contexts).

**Status (2026-05-15):** sixth iteration since first authored;
believed working but not 100% verified against current upstream
tips.  Patch 0001 is the subsystem-agnostic prerequisite for any
BRF-style protocol harness in this tree (MPTCP, future QUIC,
future tlshd).

**Iteration history** lives in BRF git, not in version-suffixed
directories.  When a patch needs revision, replace it in this
directory in a new BRF commit; the previous version is recoverable
via `git log -p kernel_patches/bpf_kcov/`.  The original
pre-import iteration snapshots (v01..v06) are preserved in the
Mpiric tools tree at `/mnt/work_4gb/Tools/003_kernel_testing/
prana_kernel_testing/container_kernel_workspace/kernel_patches/
ebpf/brf/kcov_for_bpf/` as a historical reference.

## Patches

| Patch | Subsystem            | Reusable for protocol harnesses?                          |
|-------|----------------------|-----------------------------------------------------------|
| 0001  | `kernel/kcov.c`      | **YES**, verbatim.  Subsystem-agnostic.                  |
| 0002  | BPF runtime          | PATTERN reusable.  Re-derive for each new subsystem.     |
| 0003  | BPF UAPI exposure    | Only if userspace needs handle visibility (often no).    |

### 0001-kcov-bpf-Add-support-for-preallocated-coverage-area.patch

Adds `kcov_remote_start_prealloc(handle, area, size)` and
`kcov_remote_stop_prealloc()` to `kernel/kcov.c` +
`include/linux/kcov.h`.  The existing `kcov_remote_start()` uses
`vmalloc()` which can sleep; the prealloc variants take a
caller-owned area, making them safe in interrupt and other
non-sleepable contexts.

This patch is **load-bearing** for every other `<subsystem>_kcov/`
patch series in this `kernel_patches/` tree.  Apply it first.

### 0002-bpf-Add-BRF-coverage-collection-support-via-kcov-rem.patch

eBPF-specific wiring.  Adds `kcov_remote_handle`,
`kcov_coverage_area`, `kcov_area_size` to `struct bpf_prog`;
wraps `__bpf_prog_run()` in the prealloc start/stop calls;
extends `union bpf_attr` and libbpf's `bpf_prog_load_opts` to
pass the handle from userspace.  The same pattern (add fields +
wrap entry point + extend uapi) is re-derived per-subsystem in
the other `<subsystem>_kcov/` directories.

### 0003-bpf-Support-getting-kcov_remote_handle-using-bpf_pro.patch

eBPF UAPI exposure.  Adds `kcov_remote_handle` to
`struct bpf_prog_info` so userspace can confirm coverage is
enabled on a loaded program.  Optional; only needed if the
harness wants to verify coverage from the userspace side.

## Apply order (within the BRF tree)

```bash
cd /mnt/work_4gb/Dev/mpiric_kernel_dev_env/open/src/kernel/linux
git checkout mptcp_brf_fuzz_base
git fetch mptcp && git reset --hard mptcp/export

BRF=/mnt/work_4gb/Dev/mpiric_kernel_dev_env/open/src/fuzzing/brf

# 1. Subsystem-agnostic kcov prereq (required by every harness below).
git am < $BRF/kernel_patches/bpf_kcov/0001-kcov-bpf-Add-support-for-preallocated-coverage-area.patch

# 2. Optional: eBPF runtime coverage (only if reviving BRF for eBPF).
# git am < $BRF/kernel_patches/bpf_kcov/0002-bpf-Add-BRF-coverage-collection-support-via-kcov-rem.patch
# git am < $BRF/kernel_patches/bpf_kcov/0003-bpf-Support-getting-kcov_remote_handle-using-bpf_pro.patch

# 3. Subsystem-specific patches for whatever harness is being built.
# Example: MPTCP MP_JOIN harness:
# git am < $BRF/kernel_patches/mptcp_kcov/0001-*.patch
# git am < $BRF/kernel_patches/mptcp_kcov/0002-*.patch
```

## Bumping the patches

When an upstream change breaks application (kcov core refactor,
function rename) or when fuzz findings drive new kcov primitives:

1. Re-author the patch in the kernel tree (apply old, edit, commit
   with the same `Signed-off-by`), or amend the existing commit.
2. Regenerate with `git format-patch --base=<base>`.
3. Replace the patch file in this directory.
4. Commit the BRF tree.  The old version is now in BRF git
   history.

The "vNN" labels you may see in older Mpiric tooling
(`prana_kernel_testing/.../v01..v06/`) are NOT used inside this
BRF tree.

## See also

- `.claude/designs/brf_architecture.md` Section 7 Step 6 -- how
  these patches fit into the overall BRF architecture and the
  recipe for per-subsystem analogues.
- `.claude/designs/kernel_base_management.md` -- the build
  workflow that applies these patches.
- Project memory `reference_kcov_brf_patches.md` (in the BRF
  project memory tier) -- the original Mpiric tools-tree pointer +
  pre-import iteration history.
