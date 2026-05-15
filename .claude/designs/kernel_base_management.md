# Kernel-base management for protocol-flow fuzzing

**Read this when:** picking a kernel base for any harness in this tree,
updating the base periodically, applying our kernel-side patches,
recording reproducible references for bug reports, or designing a
new sibling harness (QUIC, tlshd, future protocols) and need to know
where its kernel base comes from.

**Companion documents:** `.claude/designs/brf_architecture.md`,
`.claude/designs/mptcp_join_harness_design.md`.

## The model

```
                    UPSTREAM SOURCES
   ----------------------------------------------------
   mptcp/export        (mptcp_net-next.git)   MPTCP work
   mptcp/export-net    (mptcp_net-next.git)   MPTCP Fixes
   lxin/net-next       (lxin/quic)            in-kernel QUIC
   origin/master       (torvalds/linux)       mainline reference
                              |
                              | fetch + fast-forward
                              v
                    LOCAL TRACKING BRANCHES
   ----------------------------------------------------
   mptcp_brf_fuzz_base   <- mirrors mptcp/export
   quic_brf_fuzz_base    <- mirrors lxin's QUIC tip (when QUIC harness starts)
   tlshd_brf_fuzz_base   <- mirrors net-next or stable (when tlshd harness starts)
                              |
                              | apply our patches
                              v
                    BUILT KERNEL FOR FUZZING
   ----------------------------------------------------
   ${base} + brf/kernel_patches/<harness>_kcov/*.patch
```

Three principles:

1. **The tracking branch is a pure mirror.** No local commits.  When
   upstream moves, we fast-forward (or hard-reset, since there's
   nothing local to preserve).
2. **Our kernel-side patches live in the BRF repo**, not in the
   kernel tree.  They are applied at build time, exactly like
   `bpf_kcov`.  This means the kernel tree stays
   "upstream-clean" -- useful for diffing against upstream and for
   reproducing bugs against the unmodified base.
3. **Reproducibility = upstream snapshot + our patch version.**
   Every bug report and every published artifact records both.

## Tracking branches in this repo

| Branch (local in kernel tree)  | Upstream source            | Used by                                |
|--------------------------------|----------------------------|----------------------------------------|
| `mptcp_brf_fuzz_base`          | `mptcp/export`             | MPTCP MP_JOIN harness (active)         |
| `quic_brf_fuzz_base`           | `lxin/master` (lxin/quic)  | in-kernel QUIC harness (future)        |
| `tlshd_brf_fuzz_base`          | TBD (probably `next/master`) | NET_HANDSHAKE / tlshd harness (future) |

Created today (2026-05-15): `mptcp_brf_fuzz_base` from tag
`export/20260515T083717`.

## Update procedure (do this periodically)

```
cd /mnt/work_4gb/Dev/mpiric_kernel_dev_env/open/src/kernel/linux

# 1. Fetch latest upstream
git fetch mptcp                     # for MPTCP work
git fetch lxin                      # for QUIC work
git fetch origin                    # for mainline reference

# 2. Switch to the tracking branch and fast-forward
git checkout mptcp_brf_fuzz_base
git reset --hard mptcp/export       # safe: no local commits

# 3. Record the snapshot reference (for any bug report or campaign)
git describe --tags                 # closest upstream tag, e.g.
                                    #   export/20260515T083717

# 4. Rebuild the kernel for the dev_env VM
#    (this step is build-system-specific; the relevant scripts are
#    in /mnt/work_4gb/Dev/mpiric_kernel_dev_env/)
```

**Cadence:**

- During active fuzz campaigns: do not update unless something
  upstream specifically affects what's being fuzzed.  Coverage data
  and bug reproducibility require a stable base.
- Between campaigns: weekly update is reasonable.  More often if a
  maintainer announces a relevant fix has landed.
- Before a publishable run (paper, talk demo, lore submission):
  update to the latest export, then freeze for the run.
- After a long absence (>1 month): update before doing anything
  else; the upstream-vs-our-tree drift can break our patches.

## Applying our patches

Our kernel-side patch series live in the BRF repo, one directory
per `<subsystem>_kcov` series.  Files are flat inside each
directory (no version subdirs); iterations live in BRF git
history, and the "current" patches are always whatever is in the
directory at the BRF commit being used.

```
brf/kernel_patches/
    bpf_kcov/              # eBPF runtime coverage (subsystem-agnostic 0001 + BPF wiring)
    mptcp_kcov/            # MPTCP runtime coverage (current; MP_JOIN harness)
    quic_kcov/             # in-kernel QUIC runtime coverage (future)
    handshake_kcov/        # NET_HANDSHAKE runtime coverage (future)
```

Apply order: first the subsystem-agnostic kcov prereq
(`bpf_kcov/0001-...`), then the per-subsystem-specific patches.

A small shell helper (TBD path) should automate this so a single
command sets up a buildable kernel:

```sh
# Sketch only -- not yet written
./brf/scripts/setup_kernel_for_harness.sh \
    --base   mptcp/export \
    --harness mptcp_kcov
```

For now, do it manually:

```sh
cd /mnt/work_4gb/Dev/mpiric_kernel_dev_env/open/src/kernel/linux
git checkout mptcp_brf_fuzz_base
git reset --hard mptcp/export

# All patches now live inside the BRF repo (self-contained dev flow).
BRF=/mnt/work_4gb/Dev/mpiric_kernel_dev_env/open/src/fuzzing/brf

# 1. Subsystem-agnostic kcov prereq.
git am < $BRF/kernel_patches/bpf_kcov/0001-kcov-bpf-Add-support-for-preallocated-coverage-area.patch

# 2. Subsystem-specific patches for whatever harness is being built.
git am < $BRF/kernel_patches/mptcp_kcov/0001-mptcp-add-kcov_remote_handle-fields-and-MPTCP_KCOV_H.patch
git am < $BRF/kernel_patches/mptcp_kcov/0002-mptcp-instrument-MP_JOIN-validity-gates-with-kcov.patch
```

(Patches are 3-way mergeable in `git am`, so most upstream churn
won't break application.)

## Recording reproducibility (for bug reports)

When a harness produces a finding worth reporting upstream, capture:

1. **Upstream snapshot:**
   ```
   git -C /mnt/work_4gb/Dev/mpiric_kernel_dev_env/open/src/kernel/linux \
       describe --tags    # e.g., export/20260515T083717
   git -C ...              log --oneline -1  # exact commit hash
   ```
2. **BRF tree commit covering the patches:** `git -C brf log
   --oneline -1 -- kernel_patches/mptcp_kcov/` (or whichever
   harness).  This is the canonical version identifier; iteration
   history lives in BRF git, not in a directory name.
3. **BRF tree commit covering the harness binary:** `git -C brf
   log --oneline -1` -- so the userspace harness is reproducible
   too.

A standard footer for any bug report or commit message:

```
Reproduced on:
  mptcp_net-next.git mptcp/export  @ export/20260515T083717
  brf protocol_flow_fuzzing_harness @ <commit>
  kernel patches: brf/kernel_patches/mptcp_kcov/
```

This footer is what maintainers need to confirm the bug on their
own trees.

## Branch hygiene

- Never commit on a `*_brf_fuzz_base` branch.  If a change is needed,
  it lives as a patch series in `brf/kernel_patches/`, not as a
  local commit on the tracking branch.
- If a tracking branch accidentally accumulates local commits
  (e.g., from a stray `git commit -am`), surface immediately and
  decide: cherry-pick into a patch series or discard.
- Untracked files in the kernel tree (`.cfg` files, scratch scripts,
  patch dumps) are fine; they don't interfere with branch hygiene.

## Why not pin to one tag forever

A frozen base seems reproducible but in practice loses value fast:

- Bug-finding stalls as the kernel evolves and new bugs land
  upstream.
- "We tested against version X" claims age out within weeks.
- Maintainers need bugs reproducible on *current* trees to act on
  them; an old-base reproducer is less actionable.

The right tradeoff: keep moving, but snapshot the moving point at
each report.  Dated tags from upstream make this trivial.
