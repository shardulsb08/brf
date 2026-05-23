# 002 — `__mptcp_push_pending()` close-path divide-by-zero in `tcp_tso_segs`

## Summary

A divide-by-zero in `tcp_tso_segs()` is reachable when
`__mptcp_close_ssk()` calls the unconditional
`__mptcp_push_pending(sk, 0)` at the end of the close path
while the just-closed subflow is in a state where
`__tcp_can_send()` returns false (FIN_WAIT1/2, CLOSING,
LAST_ACK).  `info->mss_now` stays 0 from the stack-init, never
gets assigned, and the trailing `mptcp_push_release()` feeds 0
into the TSO divide.

## Subsystem

`net/mptcp/` — `__mptcp_push_pending` /
`__subflow_push_pending` output path, reached via the kernel-PM
admin `MPTCP_PM_CMD_FLUSH_ADDRS` netlink command.

## Discovered

**Date:** 2026-05-23.

**How:** Mpiric MPTCP protocol-flow harness extension on BRF
(`shardulsb08/brf`, branch `protocol_flow_fuzzing_harness`),
syz-manager run on the
`2026_05_19_005753_brf_mptcp_v01_first_kmemleak_debug` kernel
build (`mptcp_brf_fuzz_base` tip `c2e28d808c9b`, BRF kcov
patches 0001-0007) with the verifier-accept instrumentation v2
landed.  The `syz_mptcp_pm_kernel_flush_addrs` pseudo-syscall
(gap 10 of the 2026-05-21 coverage audit, kernel-PM path)
reached the bug on the first qualifying iteration.

Crash dir:
`workdir_v01/crashes/53781e140c84d967e99e3fcb01db97d121313078/`
— `description: divide error in tcp_tso_segs`.

## Anatomy

`__mptcp_push_pending()` stack-allocates
`struct mptcp_sendmsg_info` zero-initialised except for
`.flags`.  `info->mss_now` and `->size_goal` are set inside
`mptcp_sendmsg_frag()` at its `tcp_send_mss()` call — but
`mptcp_sendmsg_frag()` returns `-EAGAIN` **before** reaching
that assignment when `__tcp_can_send(ssk)` returns false (i.e.,
the ssk is in any state other than `TCP_ESTABLISHED` /
`TCP_CLOSE_WAIT`).

For an ssk that `__mptcp_close_ssk()` has just transitioned to
FIN_WAIT1/2 / CLOSING / LAST_ACK, `__subflow_push_pending()`
propagates the early return back to `__mptcp_push_pending()`
without ever setting `info->mss_now`.  If every scheduled
subflow takes this path the trailing

```c
if (ssk)
    mptcp_push_release(ssk, &info);
```

in `__mptcp_push_pending()` feeds `info.mss_now == 0` into
`tcp_push()` → `tcp_write_xmit()` → `tcp_tso_autosize()`, where
the `bytes / mss_now` divide oopses with `R13 = 0`.

`TCP_CLOSE` itself is safe — `__tcp_push_pending_frames()`
bails on `sk_state == TCP_CLOSE` before reaching the divide.
The AccECN beacon refresh in `tcp_write_xmit()` would mask
`mss_now == 0` if active, but is gated on
`tcp_ecn_mode_accecn() && tcp_accecn_option_beacon_check()` —
so the bug is reachable on non-AccECN flows.

## Prior art

This is a re-emergence of a bug class first reported by
Florian Westphal in 2021.  Jiang Biao proposed a defensive fix
(<https://lore.kernel.org/all/20210824071926.68019-1-benbjiang@gmail.com/>);
Matt Martineau and Paolo Abeni instead landed a structural fix
as commit `1094c6fe7280` ("mptcp: fix possible divide by
zero"), which addressed the **alloc-failure** branch but not
the `-EAGAIN`-before-`tcp_send_mss()` path our reproducer
exercises.

Reference thread (Anubis-blocked from automated fetchers,
human-readable in a browser):
<https://lore.kernel.org/all/1f8942ce-3575-5665-c41d-46d72b6efb72@gmail.com/>

Tracking issue:
<https://github.com/multipath-tcp/mptcp_net-next/issues/219>

## Reproduction

- **Trigger:** `MPTCP_PM_CMD_FLUSH_ADDRS` netlink genl on an
  msk with at least one subflow that `__mptcp_close_ssk()`
  will transition out of `TCP_ESTABLISHED`/`TCP_CLOSE_WAIT`
  before the unconditional
  `__mptcp_push_pending(sk, 0)` at the end of the close path
  (`net/mptcp/protocol.c:2637` on the run's kernel build).
- **Pseudo-syscall:** `syz_mptcp_pm_kernel_flush_addrs` (gap
  10).
- **Crash signature:** syz-manager dedup hash
  `53781e140c84d967e99e3fcb01db97d121313078`;
  `description: divide error in tcp_tso_segs`.
- **Reproducibility:** no auto-reduced repro yet (syz-manager
  `repro 0` at the time of the crash; the 1 MB `log0` in the
  crash dir contains the syz program that triggered).  Worth
  narrowing manually if a minimal C reproducer would
  strengthen the upstream submission.

## Fix

Local patch:
[`0001-mptcp-fix-divide-by-zero-in-__mptcp_push_pending-clo.patch`](0001-mptcp-fix-divide-by-zero-in-__mptcp_push_pending-clo.patch)
in this directory.

Initialise `info->mss_now` and `->size_goal` at
`__subflow_push_pending()` entry, before any early-return
path of the inner machinery.  Idempotent with the assignment
inside `mptcp_sendmsg_frag()`.  Same structural philosophy as
Paolo's 2021 fix (`1094c6fe7280`); extends the invariant
("`info` is valid when `mptcp_push_release()` is reached") to
the second uncovered path.

Kernel branch: `mptcp_push_pending_mss_init` (off
`mptcp_brf_upstream_fixes`), commit `2f0d0fed32e7a`.

## Upstream

- **Status:** sent to `mptcp@lists.linux.dev` on 2026-05-24,
  subject prefix `[PATCH mptcp-net]`.  Awaiting MPTCP CI +
  review.
- **Lore link:** _(add once available)_.
- **Cc:** Paolo Abeni (author of the precursor `1094c6fe7280`)
  and Geliang Tang (author of the 2021 patch that was
  declined).  Per the in-tree `.b4-config`, no broader Cc on
  send — MPTCP maintainers forward to netdev as part of their
  export pull.
- **`Fixes:`** `724cfd2ee8aa ("mptcp: allocate TX skbs in msk
  context")` — same `Fixes:` tag Paolo's 2021 patch carries,
  identifying the original cause-introducing commit.
- **Validation status:** the fix is locally compiled-clean
  (`checkpatch.pl --strict`: 0/0/0).  Re-run-on-patched-kernel
  to confirm the crash signature stops recurring is still
  pending; the upstream submission's harness-credit paragraph
  is therefore phrased as discovery ("the oops is reached on
  the first qualifying run") rather than as fix-validation
  ("no recurrence over N hours") — the latter wording will be
  added if a re-run confirms it.

## Lessons (reusable)

- **Partial structural fixes need re-validation across all
  reachability paths.**  Paolo's 2021 fix covered the
  alloc-failure path inside the inner loop; the
  `__tcp_can_send()`-fails path bypassed
  `mptcp_sendmsg_frag()` entirely, so the assignment was
  never reached, and the same bug class re-surfaced 4 years
  later via a new fuzzer surface.
- **Kernel-PM admin paths (`syz_mptcp_pm_kernel_*`) are
  productive surface.**  This is the second bug from the
  kernel-PM pseudo-syscalls (gap 10), distinct from the
  MP_JOIN surface (gaps 2-9) where finding #001 sits.  Worth
  weighting the kernel-PM corpus in future fuzz allocations.
- **Hand-trace state-transition paths before claiming
  reachability.**  Our first commit message said "FIN_WAIT1/2
  or CLOSE" — wrong: `TCP_CLOSE` is safe
  (`__tcp_push_pending_frames` bails), and the actual
  predicate is `!__tcp_can_send()`.  Read the receivers, not
  just the senders.
- **`get_maintainer.pl` returns the theoretical maximum
  recipient set; subsystems with curated review flows (here,
  the MPTCP `.b4-config`) narrow it.**  Don't blast netdev
  for an MPTCP fix; maintainers forward.
