# Bug case study: `mptcp_pm_destroy()` alloc-during-teardown race

**Subsystem:** `net/mptcp/` (userspace path manager + protocol teardown)
**Class:** kernel memory leak via a small lock-release window during PM
teardown.  Not a use-after-free, not an information disclosure: an
orphaned heap object on a per-msk list whose only iterator has just
finished walking.
**Status (as of 2026-05-23):** patched locally and validated, sent to
mptcp@ on 2026-05-20, awaiting review.  The fix is also cherry-picked
into the fuzzing kernel (`mptcp_brf_fuzz_base`) so the race does not
re-surface in subsequent runs.
**One-line summary:** `mptcp_pm_destroy()`'s `pm.lock`-held splice can
race with a concurrent userspace-PM `ANNOUNCE` genl handler on the same
msk; when destroy wins the lock, a subsequent `list_add()` in the alloc
path lands on a list head that points only at itself and the entry
leaks.

---

## 1. Background

MPTCP carries a per-msk **path manager** (PM) that owns subflow and
address policy.  Two PM modes exist: the in-kernel PM (default,
`pm_type=0`) and the **userspace PM** (`net.mptcp.pm_type=1`), where
policy is driven from userspace through the `mptcp_pm` genl family.
The harness targets the userspace PM because each policy step is an
explicit, deterministic genl call — the exact shape a stateful
pseudo-syscall wants.

Two per-msk lists carry the userspace-PM's outstanding state:

- `msk->pm.anno_list` — pending **ADD_ADDR announcements** awaiting an
  echo / retransmit timer.  Entries are `struct mptcp_pm_add_entry`
  (192 B), allocated by `mptcp_pm_alloc_anno_list()`
  (`net/mptcp/pm.c:434`).
- `msk->pm.userspace_pm_local_addr_list` — the set of locally-registered
  addresses this msk's userspace PM has bound.  Entries are
  `struct mptcp_pm_addr_entry` (64 B), allocated by
  `mptcp_userspace_pm_append_new_local_addr()`
  (`net/mptcp/pm_userspace.c:43`).

`mptcp_pm_destroy()` (`net/mptcp/pm.c:1137`) is the unified teardown
called from `mptcp_destroy_common()` (`net/mptcp/protocol.c:3450`).
For both PM modes it drains `anno_list`; for the userspace PM it also
releases the addr_list (via the userspace PM ops' `release` callback in
`mptcp_pm_ops_release()`).  Each drain takes `msk->pm.lock` briefly,
`list_splice_init()`s into a local head, then releases the lock and
walks the local head freeing entries.

The signal that mattered was kmemleak.  Both list types are real heap
allocations: when an entry is added to a list whose head subsequently
becomes self-referential and no other code path iterates it for that
msk, kmemleak finds the object after its 30 s min-age window and prints
a backtrace rooted at the allocation site.

---

## 2. The bug

The window is small but real.  In `mptcp_pm_destroy()`:

1. `WRITE_ONCE(msk->pm.destroying, true)` — added by the fix; absent
   in the unpatched code.
2. `mptcp_pm_free_anno_list(msk)` —
   ```
   spin_lock_bh(&msk->pm.lock);
   list_splice_init(&msk->pm.anno_list, &free_list);
   spin_unlock_bh(&msk->pm.lock);
   ```
   walks `free_list` outside the lock to stop timers and `kfree_rcu`.
3. `mptcp_pm_ops_release(msk)` — for userspace mode, drains
   `userspace_pm_local_addr_list` under the same `pm.lock`.

Between steps 2 and 3 the lock is released.  More importantly, the
list head left behind by `list_splice_init()` is now self-referential:
`anno_list.next == anno_list.prev == &anno_list`.  An attacker doesn't
need it: any concurrent `list_add()` to that head will succeed, point
nothing else at the new entry, and leave it unreachable the moment the
adder's lock release returns.

Concurrently, `mptcp_pm_nl_announce_doit()`
(`net/mptcp/pm_userspace.c:191`) is running on the same msk.  The
handler:

- Grabs a sock reference via `mptcp_userspace_pm_get_sock()`
  (`mptcp_token_get_sock()` lookup by token; this is the key fact —
  the handler holds a *sock* reference, not a PM lock).
- Calls `mptcp_userspace_pm_append_new_local_addr()` — takes `pm.lock`,
  `list_add_tail_rcu()` to `userspace_pm_local_addr_list`, releases.
- Then `lock_sock(sk)` + `spin_lock_bh(&msk->pm.lock)` and calls
  `mptcp_pm_alloc_anno_list()` — `list_add()` to `anno_list` under
  the same lock.

Because the genl handler holds a sock reference and **not** a PM lock,
nothing prevents `mptcp_destroy_common()` from running on the same msk
on another CPU.  The path: a concurrent `mptcp_disconnect()` invokes
`mptcp_destroy_common()` (`protocol.c:3476`), which calls
`mptcp_pm_destroy()` without dropping the sock refcount the genl
handler is holding.

If the `pm.lock` acquisitions interleave such that destroy's splice
runs first, the subsequent alloc-path `list_add()` from the genl
handler lands on a self-referential head.  `kfree_rcu`'d entries from
the splice are fine — they were captured into `free_list` and freed
correctly.  The new entry, added after the splice, is now the sole
member of a list that nothing else will iterate for this msk.  Kmemleak
reports it ~30 s later.

Both list paths leak independently:

- `mptcp_pm_alloc_anno_list+0x...` from `mptcp_pm_nl_announce_doit+0x...`
  → 192-byte `struct mptcp_pm_add_entry`.
- `mptcp_userspace_pm_append_new_local_addr+0x...` from the same handler
  → 64-byte `struct mptcp_pm_addr_entry`.

The race window is microseconds wide.  Under a syzkaller workload of
`procs: 6`, with the corpus interleaving `pm_announce`, `pair_close`,
and `pm_subflow_destroy` across multiple pairs, kmemleak fired at
roughly **0.34 reports/minute** at baseline.

**Disagreement note:** the finding README says "concurrent userspace
PM `ANNOUNCE` ... `mptcp_pm_destroy()` may run on the same msk via
`mptcp_disconnect()` — which invokes `mptcp_destroy_common()` without
dropping the sock refcount."  This wording is slightly imprecise — it
is the *genl handler* that holds the sock reference; `mptcp_disconnect()`
doesn't itself acquire one, it just isn't blocked by the one the
handler is holding.  Substance unchanged.

---

## 3. How BRF surfaced it

The harness that surfaced this is the Mpiric MPTCP protocol-flow
extension on top of BRF (Hung & Amiri Sani, UCI, arXiv:2305.08782) /
Syzkaller (Vyukov et al., Google).  Five facts make the surfacing
non-trivial:

**1. The genl path is gated.**  `mptcp_pm_nl_announce_doit()` is
unreachable without:
- `net.mptcp.pm_type=1` (userspace PM enabled netns-wide), AND
- A live subscriber to `mptcp_pm_events` multicast (so
  `mptcp_userspace_pm_active(msk)` returns true), AND
- A valid 32-bit `MPTCP_PM_ATTR_TOKEN` matching a registered msk.

A stateless Syzkaller corpus produces none of these in any plausible
budget.  The harness builds them once per executor (`brf_mptcp_ensure_executor_setup`
in `executor/common_brf_linux_mptcp.h`) and threads the token through
its pseudo-syscall state-carrier.

**2. The state-carrier is what makes the call valid.**
`syz_mptcp_pair_init()` creates an MPTCP socket pair on 127.0.0.1,
drives MP_CAPABLE, captures `local_key` / `remote_key` (via the
CONFIG_KCOV-gated `MPTCP_DEBUG_KEYS` getsockopt added in
`kernel_patches/mptcp_kcov/0003-...`), reads the token via
`MPTCP_INFO`, primes both ends to `fully_established` with a 1-byte
round-trip, and stores all of this in `struct brf_mptcp_pair_state`
keyed by a syzlang resource handle.  `syz_mptcp_pm_announce(pair,
addr_id, addr, port)` then issues the genl call using
`pair->token` — every individual call passes the kernel's input
validation.  This is the BRF pseudo-syscall + state-carrier pattern
(`.claude/designs/brf_architecture.md` Sections 2 and 4) applied to
an MPTCP flow.

**3. Concurrency came free from syzkaller's `procs: 6`.**  The race
itself was not specifically designed for; the corpus naturally
interleaves `pm_announce` (calls `mptcp_pm_nl_announce_doit()`)
with `pair_close` (closes msk fds, which can drive
`mptcp_disconnect()` → `mptcp_destroy_common()` →
`mptcp_pm_destroy()` on the same msk's token if the close happens
to win the right lock ordering).  Because the descriptions are
declarative and the executor reuses the pair-pool slot across calls
within a program, six concurrent procs operating on the 16-slot pair
pool produced sustained collision pressure.  The harness's job here
was making the alloc path reachable; syzkaller's standard concurrency
did the rest.

**4. The signal was kmemleak, not KASAN.**  KASAN catches
use-after-free; this bug never frees the orphaned object during the
process lifetime.  The fuzzing kernel build carries
`CONFIG_DEBUG_KMEMLEAK=y`, and the corpus runs for long enough that
the 30-second min-age window matures.  Kmemleak's backtrace at the
allocation site is what made the leak attributable to
`mptcp_pm_alloc_anno_list` and `mptcp_userspace_pm_append_new_local_addr`
without further triage.

**5. Time to first signal: hours.**  The `syz_mptcp_pm_announce`
pseudo-syscall (v05.3) landed in commit `7e5bbbeea` on 2026-05-18.
First kmemleak reports rooted at `mptcp_pm_alloc_anno_list+...` were
observed within hours of starting the syz-manager run.  The
provoking corpus pattern is short — a `pm_announce` followed by a
near-simultaneous `pair_close` on another proc.

---

## 4. Diagnosis

The README lists the diagnosis as a two-phase validation; both phases
were necessary because the obvious instrumentation produced
false-positive reports for an unrelated reason.

**False start: initial WARN_ONCE on non-empty `anno_list` at
`mptcp_pm_data_init()`.**  Fired on every fresh slab allocation —
`CONFIG_INIT_ON_ALLOC=n` means slab returns raw memory whose
`list_head` bytes will fool `list_empty()`'s self-reference test.
31 reports were filed against the wrong condition before the probe
itself was identified as the false-positive source.  This is the kind
of mistake that is fast to make and slow to catch; the lesson recorded
in the finding README ("don't trust your first probe condition; verify
empirically") is the load-bearing one.

**Phase 1 — diagnostic build:** a `bool destroying` field added to
`struct mptcp_pm_data`, set by `mptcp_pm_destroy()` before its
splice; checked by both alloc paths under `pm.lock` but allocation
continues unchanged.  Logs `RACE CAUGHT` when the flag is observed
set.  In a 65-minute run on the userspace-PM workload, **22 kmemleak
reports** were filed at the same ~0.34/min baseline rate that
unpatched runs produced.  This proved the proposed condition fires
at the same rate as the leak — i.e., the proposed mechanism is the
mechanism.

**Phase 2 — fix build:** same flag, but alloc paths now return false /
`-EINVAL` when the flag is observed set.  29-minute run produced
**zero kmemleak reports** against an expected ~10 at baseline.  The
Poisson P(0 | λ=10) ≈ 4.5×10⁻⁵, i.e. if the fix had not been the fix,
the probability of getting zero leaks by chance was negligible.
Multi-hour follow-on runs subsequently stayed at zero.

This two-phase pattern — same flag, two different return behaviors
in the alloc paths — costs two rebuilds and decisively answers
*both* "is this the mechanism?" and "does this prevent the leak?"
in one experiment.  It is generalizable and worth reusing for
similar racy-leak fixes.

**Telemetry caveats the README captured for future debug sessions
(reflected here because they shape what is trustable):**

- syzkaller treats kernel `WARN()` as a crash and resets the VM —
  starving kmemleak's 30-second min-age scan window.  Diagnostic
  instrumentation must use `pr_warn` / `pr_debug`, not `WARN_ONCE`,
  or the leak signal never matures.
- dmesg ring buffer + serial-console bandwidth (~17 KB/s on the
  syzkaller VM) jointly bound how much pre-leak history can be
  captured.  ~125 BRF probe lines/sec saturated the channel;
  destroy-path logs had to be gated on `pm.add_addr_signaled > 0`
  to fit.
- `%p` hashing in dmesg prevents direct alloc-time → leak-time msk
  correlation.  Workaround: read raw `list_head.next` / `.prev`
  pointers from the kmemleak hex dump, subtract
  `offsetof(struct mptcp_sock, pm.anno_list)` to recover the
  msk's address.

---

## 5. The fix

Three files, 17 insertions, no deletions.  Patch:
`findings/001_mptcp_pm_destroy_race/0001-mptcp-pm-fix-memory-leak-from-alloc-during-teardown-.patch`.

```
 net/mptcp/pm.c           | 6 ++++++
 net/mptcp/pm_userspace.c | 4 ++++
 net/mptcp/protocol.h     | 7 +++++++
```

Mechanism:

- New `bool destroying` field in `struct mptcp_pm_data`
  (`net/mptcp/protocol.h`).  Cleared in `mptcp_pm_data_init()` so
  the field is correct after slab reuse.
- `mptcp_pm_destroy()` sets `WRITE_ONCE(msk->pm.destroying, true)`
  **before** its `pm.lock`-held splice.
- `mptcp_pm_alloc_anno_list()` checks `READ_ONCE(msk->pm.destroying)`
  under `pm.lock` and returns `false` if set.
- `mptcp_userspace_pm_append_new_local_addr()` checks the same flag
  under `pm.lock` and returns `-EINVAL` if set.

Either ordering of `pm.lock` acquisition is now correct.  Alloc wins
first: the entry sits on the list when destroy's splice runs and is
freed normally.  Destroy wins first: the subsequent alloc observes
the flag and refuses, so no entry is added to a head about to become
self-referential.  No new lock, no new ordering — the existing
`pm.lock` already serializes both code paths; the flag just
distinguishes pre-splice from post-splice within that serialization.

**Upstream status** (from the finding README, not inferred):

- Patch subject: `[PATCH net] mptcp: pm: fix memory leak from
  alloc-during-teardown race`.
- Local branch in the kernel clone: `mptcp_brf_upstream_fixes`
  (forked from `mptcp/export-net`), tip `0774d3dde5d74`.
- Sent to mptcp@ on 2026-05-20.
- Status: **awaiting review** as of the finding README's last
  update.
- Lore link: not yet recorded (the README has `_(add once available)_`
  in that slot).
- Maintainer Cc list resolved via
  `scripts/get_maintainer.pl net/mptcp/pm.c net/mptcp/pm_userspace.c`
  before send.
- Carries the `Assisted-by: Claude:claude-opus-4-7` trailer per
  `Documentation/process/coding-assistants.rst` and the project's
  current AI-attribution decision (working choice, not policy; see
  task brief).

The patched fuzzing kernel base (`mptcp_brf_fuzz_base`, tip
`faedd54304af9`) carries an equivalent cherry-pick so the race does
not re-surface in subsequent runs.

---

## 6. What this proves — honestly

A small, defensible claim:

> **The Mpiric MPTCP protocol-flow harness, built on Hung & Amiri Sani's
> BRF (UCI, arXiv:2305.08782) — itself a fork of Syzkaller (Vyukov et
> al., Google) — produced one real, upstream-mergeable kernel race in
> `net/mptcp/`, found within hours of the surface-reaching
> pseudo-syscall landing.**

What this is evidence *for*:

- The BRF state-carrier + pseudo-syscall pattern (Hung & Amiri Sani's
  contribution) generalises from eBPF to a stateful network protocol
  flow.  The same pattern that threads a BPF program fd between
  pseudo-syscalls threaded an MPTCP `token` between `pair_init`,
  `pm_announce`, `pair_close`, and the rest of the MPTCP harness.
  This was not a guaranteed result before the work.
- The AI-augmented description authoring workflow can produce a
  pseudo-syscall family whose reachability matches the kernel
  preconditions a stateless fuzzer cannot satisfy.  The
  `syz_mptcp_pm_announce` reachability — token, pm_type sysctl,
  multicast subscription, address attribute byte-order — is exactly
  the kind of multi-fact precondition where AI-drafted descriptions
  go wrong silently if the human verifier doesn't catch them, and
  the bug-finding here is downstream of getting all of those right.
- Concurrency-driven races in MPTCP lifecycle code remain a viable
  bug class for harnesses that combine stateful preconditions with
  standard syzkaller `procs: N` interleaving.

What this is **not** evidence for, and what would be unsafe to claim
from a single finding:

- That the methodology scales beyond MPTCP.  QUIC and tlshd extensions
  are planned but unbuilt; the harness pattern's portability to those
  surfaces is a hypothesis, not a result.
- That AI-augmented description authoring is more productive than
  human authoring at the same level of rigor.  We have no controlled
  comparison; the time-to-bug here was driven by Shardul's existing
  MPTCP MP_JOIN expertise (HMAC fixes A/B upstream, set_rcvbuf merge,
  RST_EMPTCP series in review) at least as much as by description
  productivity.
- That the bug class (alloc-during-teardown on per-msk lists) is
  necessarily what the harness will find again.  It's tempting to
  generalise; the audit-driven coverage backlog
  (`mptcp_coverage_audit_2026-05-21.md`) explicitly enumerates
  other categories of surface and we have no second finding yet to
  validate any extrapolation.
- That kmemleak baseline rate scales with anything portable.  The
  ~0.34 reports/minute number is specific to this kernel build,
  syzkaller config (`procs: 6`), and corpus state.

**One bug is suggestive, not proof.**  The talk's framing must reflect
that.  (Update 2026-05-24: a *second* harness-found bug on a
*different* MPTCP surface — kernel-PM `FLUSH_ADDRS` →
`__mptcp_push_pending` divide-by-zero, see
`findings/002_mptcp_push_pending_divide_zero/case_study.md` — has
since been sent upstream.  Two bugs on two surfaces is meaningfully
stronger than the one-fluke prior, but the absence of a controlled
baseline against kernel-only Syzkaller still stands as the binding
limit on "the methodology produces more bugs than the alternative."
The pre-work caveat below is unchanged.)

---

## 7. Honest caveats — where AI was load-bearing, and where it failed

Per the project's standing principle (`CLAUDE.md`: "AI use is in scope
to discuss openly, not to hide"), this section is the credibility
section.

### Where AI was load-bearing and useful

- **Drafting the syzlang declarations and the executor C scaffolding
  for the pseudo-syscall family.**  The `syz_mptcp_pair_init` /
  `syz_mptcp_pm_announce` skeletons came out of AI drafts; Shardul
  verified protocol validity (token derivation, fully_established
  priming, byte-order quirks) and ran them against the kernel.
- **Excavation under direction.**  Reading the path from
  `mptcp_pm_nl_announce_doit()` through
  `mptcp_userspace_pm_append_new_local_addr()` and
  `mptcp_pm_alloc_anno_list()` to `mptcp_pm_destroy()` is mechanical
  once you know where to point — AI surfaces it; Shardul forms the
  diagnosis.  This is the standing learning model.
- **Drafting the two-phase diagnostic / fix instrumentation and the
  upstream patch's mechanism description.**  Both went through human
  review before being trusted.

### Where AI failed or would have failed without human verification

- **The initial probe condition (`WARN_ONCE` on non-empty `anno_list`
  at `pm_data_init`).**  Plausible at code-reading time, wrong at
  runtime because slab-returned memory under `CONFIG_INIT_ON_ALLOC=n`
  has self-referential `list_head` bytes by coincidence.  This is a
  classic "AI-generated probe looks correct, only the kernel knows
  it isn't" failure.  31 reports filed before catching it.  The
  human-verification step is decisive here: there is no AI-only path
  that catches a probe-condition false positive without empirical
  confrontation.
- **Two earlier botched gotchas during harness bring-up** (recorded in
  the task brief for the v01 NORMAL-mode work, predating this bug):
  the asymmetric host-vs-network byte order on `MPTCP_PM_ADDR_ATTR_PORT`
  (kernel `htons()`'s the value it reads, so userspace must pass host
  order even though the address attribute is network order); and the
  `fully_established` state on the *client* msk requiring a DSS+use_ack
  round-trip before SUBFLOW_CREATE could succeed.  Both are kernel
  quirks that AI-drafted descriptions did not anticipate; the
  signal that something was wrong was empirical (silent SYN going
  to a non-listening port, `-ENOTCONN` on subflow create), and the
  diagnosis required reading specific kernel files (`pm_netlink.c:86`,
  `options.c:942`, `subflow.c:1633`).  AI's contribution here was
  drafting the correct fix once the cause was identified; the
  identification was human work.
- **Reasoning about timing under load.**  The Poisson P(0)
  calculation that closes the validation is mathematically right but
  unimpressive on its own — the load-bearing thing is the choice of
  comparison interval (29 minutes against an expected ~10 leaks at
  baseline).  AI suggested the analysis shape; the call on whether
  the experiment was decisive was Shardul's.
- **The kmemleak telemetry caveats (WARN crashing the VM, dmesg
  bandwidth, `%p` hashing breaking correlation).**  These were
  discovered the expensive way during instrumentation runs.  AI
  generated diagnostic instrumentation that was both useful and
  *too verbose*; the bandwidth saturation that lost early leak
  history was preventable if either of us had thought about
  log-rate budget ahead of time.

### What could have failed and didn't

- The race window is microseconds.  At a worker count below `procs: 6`,
  or at lower per-proc rates, the kmemleak signal might never have
  matured at a useful rate.  The choice of workload was not
  optimised for finding this bug; it was the default syz-manager
  config for the kernel build.  A more conservative workload would
  have plausibly hidden the bug.
- If the harness had not happened to run for long enough between
  restarts to accumulate kmemleak signal beyond noise, the 0.34/min
  rate would have been invisible.  Multi-pair runs that crash
  early (e.g. on an unrelated WARN) starve the leak scan.  Reverting
  the diagnostic instrumentation from `WARN_ONCE` to `pr_warn` was
  the change that made the bug *consistently* visible; before that,
  it was intermittent.
- The 31 false-positive reports filed against the bad
  `WARN_ONCE` probe could easily have led to a wrong-cause patch
  being sent.  The two-phase validation (Phase 1 *does not fix the
  leak, just observes the condition*) is what closed that loop;
  without it, the first plausible-looking patch would have shipped.

### What this bug specifically does **not** prove about AI methodology

- It does not prove that AI accelerates kernel bug-finding.  The
  bug-finding clock here started at hours after the surface-reaching
  pseudo-syscall landed, but the surface-reaching pseudo-syscall took
  weeks to author + verify and required a human with deep MPTCP
  context.  We cannot subtract the human pre-work from the
  cycle-time.
- It does not prove the absence of AI-generated bugs in the harness.
  Several executor changes during the v05.x build-out had latent
  defects (uninitialised `tcp_subflow_fd` array defaulting to stdin
  via `memset`; mptcp event header mis-parsing because the kernel
  emits `MPTcpExt:`, not `MPTCPExt:`).  Those would have shipped if
  Shardul hadn't VM-tested.  The talk's honest version of this
  observation is: AI-augmented authoring is fast and full of small
  defects; the human-VM-test loop is *not optional*.

---

## 8. Provenance and citations

Authorship chain, per the standing citation discipline in `CLAUDE.md`:

```
Syzkaller         Google / Dmitry Vyukov et al.       Apache 2.0
    ↓ fork, Jan 2024
BRF               Hsin-Wei Hung + Ardalan Amiri Sani  (UC Irvine)
                  arXiv:2305.08782 (May 2023)
                  ACM venue version: papers/3643778.pdf
                  Funded by NSF #1763172, NSF #1846230, Google ASPIRE 2020
    ↓ fork, Aug 2025
shardulsb08/brf   Mpiric extensions (this checkout)
                  Branch: protocol_flow_fuzzing_harness
```

**Required attribution for any external artifact built on this
finding** (slide deck, talk paper, blog post, lore message):

- Hung, H. & Amiri Sani, A.  *BRF: Bug Reporting Framework — A
  Practical eBPF Runtime Fuzzer*.  arXiv:2305.08782; ACM venue
  version at `papers/3643778.pdf` (this BRF tree).
- Vyukov, D. et al.  *Syzkaller*, google/syzkaller.
- Funding acknowledgment slide: NSF #1763172, NSF #1846230, Google
  ASPIRE 2020 (Hung & Amiri Sani's BRF was funded under these).

Mpiric's role is **extender**, not author.  The harness extensions
are Mpiric's contribution; BRF itself and the pseudo-syscall +
state-carrier pattern are Hung & Amiri Sani's; the underlying
coverage-guided fuzzing engine is Syzkaller.  No external artifact
refers to BRF as Mpiric's tool or strips upstream attribution from
the published fork.

---

## 9. Files referenced (this repo)

- Bug report: `findings/001_mptcp_pm_destroy_race/README.md`
- Upstream patch:
  `findings/001_mptcp_pm_destroy_race/0001-mptcp-pm-fix-memory-leak-from-alloc-during-teardown-.patch`
- Standalone reproducer (single-process; does not reproduce the leak
  in isolation but proves the harness side is deterministic):
  `kernel_patches/mptcp_kcov/test_mp_pm_announce_leak.c`
- Stability wrapper for the reproducer:
  `kernel_patches/mptcp_kcov/run_stability.sh`
- The pseudo-syscall that surfaced the bug:
  - Syzlang declaration:
    `sys/linux/socket_mptcp_crypto.txt` (`syz_mptcp_pm_announce`)
  - Executor implementation:
    `executor/common_brf_linux_mptcp.h` (`syz_mptcp_pm_announce`,
    introduced in commit `7e5bbbeea` "mptcp_kcov: add
    syz_mptcp_pm_announce pseudo-syscall (v05.3)")
- BRF architecture pattern instantiated by the harness:
  `.claude/designs/brf_architecture.md` Sections 2, 4, 7
- MPTCP-specific harness design (with byte-order / fully_established
  gotchas documented):
  `.claude/designs/mptcp_join_harness_design.md` Sections 5.1, 5.2,
  10
- Coverage audit (independent, post-finding):
  `.claude/tasks/netdev_0x1a_protocol_fuzzing/mptcp_coverage_audit_2026-05-21.md`
