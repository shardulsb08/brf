# 001 — `mptcp_pm_destroy()` alloc-during-teardown race

## Summary

Concurrent userspace PM `ANNOUNCE` genl handler can race with
`mptcp_pm_destroy()` on the same msk and orphan
`struct mptcp_pm_add_entry` (192 B) on `anno_list` and / or
`struct mptcp_pm_addr_entry` (64 B) on
`userspace_pm_local_addr_list`.  Kmemleak surfaces both.

## Subsystem

`net/mptcp/` — userspace path manager + protocol teardown path.

## Discovered

**Date:** 2026-05-18.

**How:** syz-manager run on the
`2026_05_15_190810_brf_mptcp_v01` kernel build using the
Mpiric MPTCP protocol-flow harness extension on BRF
(`shardulsb08/brf`, branch `protocol_flow_fuzzing_harness`).
Within minutes of starting, multiple kmemleak crashes
appeared with backtraces rooted at
`mptcp_pm_alloc_anno_list+...` from
`mptcp_pm_nl_announce_doit+...`.  Sustained leak rate at the
baseline workload was ~0.34 reports/minute.

## Anatomy

`mptcp_pm_destroy()` drains `msk->pm.anno_list` via
`list_splice_init()` under `msk->pm.lock`, releases the lock,
then for the userspace PM also drains
`msk->pm.userspace_pm_local_addr_list` under the same lock.
Between the two splices, `pm.lock` is released.

A concurrent userspace-PM genl `ANNOUNCE` on the same msk holds
a sock reference via `mptcp_token_get_sock()` and, inside
`mptcp_pm_nl_announce_doit()`, calls
`mptcp_userspace_pm_append_new_local_addr()` and
`mptcp_pm_alloc_anno_list()`.  Both briefly take `pm.lock` to
`list_add` to their respective lists.

Because the genl handler holds a sock reference,
`mptcp_pm_destroy()` may run on the same msk via
`mptcp_disconnect()` — which invokes `mptcp_destroy_common()`
without dropping the sock refcount — before the handler
completes.  If the `pm.lock` acquisitions interleave such that
destroy's splice runs first, the subsequent alloc paths
`list_add` to a head pointing to itself.  Nothing else iterates
that list for this msk, and the entry leaks.

The race window is microseconds wide but with `procs: 6`
syzkaller workload it fires reliably (10 instances of the
"alloc on TCP_CLOSE" probe across the corpus we instrumented;
6 produced orphaned entries that kmemleak later flagged).

## Reproduction

- **Standalone single-process:**
  `kernel_patches/mptcp_kcov/test_mp_pm_announce_leak.c`.
  Stability wrapper `run_stability.sh` (50 iterations clean)
  confirms the harness side is deterministic.  Does **not**
  reproduce the leak in isolation — the race requires
  concurrent destroy load.
- **Fuzzer:** any syz-manager run on this kernel with the
  MPTCP userspace PM enabled (`net.mptcp.pm_type=1`) and
  concurrent `ANNOUNCE` / `close()` patterns in the corpus.
  Config used: `shared/mpiric/027_netdev_0x1a_proposal/work/brf_protocol_fuzz_setup/syz_manager/mptcp_v01_first_kmemleak_debug.cfg`.

## Diagnosis and fix

Mechanism confirmed via a two-phase validation:

1. **Diagnostic build** — flag set on destroy, checked under
   `pm.lock` in both alloc paths, but allocation continues
   (just logs `RACE CAUGHT`).  65-minute run produced
   22 kmemleak reports at the baseline ~0.34/min rate.
2. **Fix build** — same flag, but alloc paths return false /
   `-EINVAL` when flag is observed set.  29-minute run produced
   zero kmemleak reports against an expected ~10 at baseline
   (Poisson P(0) ≈ 4.5×10⁻⁵).  Multi-hour runs subsequently
   stayed at zero.

Fix shape: a `bool destroying` field in `struct mptcp_pm_data`,
set by `mptcp_pm_destroy()` via `WRITE_ONCE` before its
`pm.lock`-held splice; checked under `pm.lock` by
`mptcp_pm_alloc_anno_list()` and
`mptcp_userspace_pm_append_new_local_addr()` via `READ_ONCE`.
Either ordering of `pm.lock` acquisition is correct under this
flag: alloc-wins-first → entry sits on the list, destroy's
splice frees it normally; destroy-wins-first → subsequent alloc
sees the flag and refuses.

3 files, 17 insertions, no deletions.

## Upstream

- **Patch:**
  [`0001-mptcp-pm-fix-memory-leak-from-alloc-during-teardown-.patch`](./0001-mptcp-pm-fix-memory-leak-from-alloc-during-teardown-.patch)
- **Branch:** `mptcp_brf_upstream_fixes` (in the linux clone),
  forked from `mptcp/export-net`; tip `0774d3dde5d74`.
- **Commit subject:** `[PATCH net] mptcp: pm: fix memory leak
  from alloc-during-teardown race`.
- **Status:** sent to mptcp@ on 2026-05-20.  Awaiting review.
- **Lore link:** _(add once available)_.
- **Cc:** maintainer list resolved via
  `scripts/get_maintainer.pl net/mptcp/pm.c net/mptcp/pm_userspace.c`
  before send.

## Lessons (reusable)

- **Don't trust your first probe condition; verify empirically.**
  The initial WARN_ONCE on "non-empty anno_list at
  `pm_data_init`" turned out to fire on every fresh slab
  allocation (CONFIG_INIT_ON_ALLOC=n means slab returns raw
  memory whose `list_head` bytes look "non-empty" via
  `list_empty()`'s self-reference check).  31 reports filed
  before realising the probe itself was the false-positive
  source.
- **syzkaller treats kernel `WARN()` as a crash and resets the
  VM.**  This starves kmemleak's ~30-second min-age scan
  window.  Use `pr_warn` instead of `WARN_ONCE` for
  fuzzer-build instrumentation if you need the VM to stay
  alive long enough for kmemleak to fire.
- **dmesg ring buffer + serial-console bandwidth jointly bound
  how much pre-leak history you can capture.**  At ~17 KB/s
  console bandwidth on the syzkaller VM, ~125 BRF probe lines
  per second saturated.  Tighten probe volume (demote to
  `pr_debug`, gate destroy logs on `pm.add_addr_signaled > 0`)
  to fit the channel.
- **Two-phase fix validation is cheap and decisive.**  Build
  the same flag twice: once where the probe fires but the
  allocation continues (proves the condition fires at the same
  rate as the leak); once where the flag actually bails the
  alloc (proves the fix prevents the leak).  Comparative leak
  rates close out both questions in one rebuild each.
- **Hex-dump-derived msk addresses survive `%p` hashing.**  A
  kmemleak hex dump shows the leaked entry's `list_head` next
  / prev pointers as raw addresses; subtract the
  `offsetof(struct mptcp_sock, pm.anno_list)` to recover the
  msk's raw address.  Useful when `%p` hashing in dmesg
  prevents direct correlation between alloc-time logs and
  kmemleak-time reports.

## Files in this finding

- `README.md` — this writeup.
- `0001-mptcp-pm-fix-memory-leak-from-alloc-during-teardown-.patch`
  — the upstream patch (same content as
  `shared/mpiric/027_netdev_0x1a_proposal/work/brf_protocol_fuzz_setup/upstream_submission/`).
