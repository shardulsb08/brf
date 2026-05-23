# Bug case study: `__mptcp_push_pending()` close-path divide-by-zero in `tcp_tso_segs`

**Subsystem:** `net/mptcp/` (subflow close path → push-pending output
machinery), reached from the kernel-PM admin
`MPTCP_PM_CMD_FLUSH_ADDRS` netlink command.
**Class:** kernel divide-by-zero oops in TCP's TSO sizing
arithmetic, reachable from valid (root-equivalent) netlink input.
Not a memory-safety bug; a state-machine oversight in MPTCP's
push-pending entry path that feeds an uninitialised `mss_now` into
`tcp_write_xmit()` → `tcp_tso_autosize()`.
**Status (as of 2026-05-24):** patch sent to mptcp@ on 2026-05-24
(subject prefix `[PATCH mptcp-net]`), compiled clean
(`checkpatch.pl --strict`: 0/0/0), awaiting MPTCP CI + review.
Fix-runtime-validation (re-run on a patched kernel to confirm the
oops signature stops recurring) is pending.
**One-line summary:** `__mptcp_close_ssk()`'s unconditional
trailing `__mptcp_push_pending(sk, 0)` can be invoked with the
just-closed subflow in a state where `__tcp_can_send()` returns
false; `mptcp_sendmsg_frag()` then returns `-EAGAIN` before
reaching its `tcp_send_mss()` assignment, the
`struct mptcp_sendmsg_info` on the caller's stack keeps
`mss_now == 0`, and the trailing `mptcp_push_release()` divides by
zero in `tcp_tso_segs()`.

---

## 1. Background

The MPTCP send path uses a stack-allocated
`struct mptcp_sendmsg_info` to thread per-call sizing state
(`mss_now`, `size_goal`, `flags`, `data_lock_held`) between the
outer push driver and the inner per-subflow machinery.  The two
top-level entry points are:

- `__mptcp_push_pending()` (`net/mptcp/protocol.c:1674`) — process
  context send; iterates scheduled subflows via
  `mptcp_sched_get_send()` and, for each, calls
  `__subflow_push_pending()` then `mptcp_push_release()` to flush
  the chosen subflow's send queue.
- `__mptcp_subflow_push_pending()` (`net/mptcp/protocol.c:1742`) —
  softirq / data_lock_held variant.

Both rely on `mptcp_sendmsg_frag()` (`net/mptcp/protocol.c:1313`)
to do the per-skb allocation and the canonical assignment

```c
info->mss_now = tcp_send_mss(ssk, &info->size_goal, info->flags);
```

at line 1341.  Crucially, that assignment sits **after** an early
return:

```c
1335   if (unlikely(!__tcp_can_send(ssk)))
1336       return -EAGAIN;
```

`__tcp_can_send()` (`include/net/tcp.h`) accepts only
`TCP_ESTABLISHED` and `TCP_CLOSE_WAIT`; every other state
(`TCP_FIN_WAIT1`, `_FIN_WAIT2`, `_CLOSING`, `_LAST_ACK`,
`_TIME_WAIT`, `_SYN_*`, `_LISTEN`, `_NEW_SYN_RECV`) hits the
`-EAGAIN` return without ever touching `info->mss_now`.

`mptcp_push_release()` (`net/mptcp/protocol.c:1581`) is the
trailing flush that runs once for the last selected subflow at the
end of the outer push loop:

```c
1583   tcp_push(ssk, 0, info->mss_now, tcp_sk(ssk)->nonagle,
                info->size_goal);
```

`tcp_push()` → `tcp_write_xmit()` → `tcp_tso_autosize()` divides by
`mss_now`.  If `mss_now == 0`, the kernel oopses with
`divide error in tcp_tso_segs`.

The relevant invariant is:
**`info->mss_now` must be non-zero on every path that reaches
`mptcp_push_release()`** — i.e. the `info` structure must be
"valid" by the time the trailing flush sees it.

---

## 2. The bug

`__mptcp_close_ssk()` (`net/mptcp/protocol.c:2559`) is the unified
subflow teardown; it is called from `mptcp_close_ssk()`
(graceful close), from PM teardown paths
(`mptcp_pm_remove_addr()` and friends — including
`MPTCP_PM_CMD_FLUSH_ADDRS`'s kernel-PM `pm_flush_addrs_and_subflows()`),
and from a few error paths.  Its tail block is the unconditional
push:

```c
2640 out:
2641     __mptcp_sync_sndbuf(sk);
2642     if (need_push)
2643         __mptcp_push_pending(sk, 0);
```

`need_push` is set earlier from
`(flags & MPTCP_CF_PUSH) && __mptcp_retransmit_pending_data(sk)`.
By the time the unconditional `__mptcp_push_pending()` runs, the
just-closed subflow's TCP state has been advanced by
`__tcp_close(ssk, 0)` (line 2625) — typically to `TCP_FIN_WAIT1`
or `TCP_FIN_WAIT2`, sometimes `TCP_CLOSING` or `TCP_LAST_ACK`
depending on what the peer has sent.

Inside `__mptcp_push_pending()`'s outer loop (lines 1684–1726),
the scheduler can hand back exactly this just-closed subflow as a
"scheduled" candidate; `__subflow_push_pending()` calls
`mptcp_sendmsg_frag()`, which hits the `!__tcp_can_send(ssk)`
guard and returns `-EAGAIN` without ever assigning `info->mss_now`.
The outer loop's exit-counter logic (lines 1717–1721)

```c
if (ret != -EAGAIN ||
    (1 << ssk->sk_state) &
    (TCPF_FIN_WAIT1 | TCPF_FIN_WAIT2 | TCPF_CLOSE))
    push_count--;
```

handles the *loop-termination* side correctly — it decrements
`push_count` so the loop exits — but it does **not** repair
`info`.  Control falls through to:

```c
1728   /* at this point we held the socket lock for the last subflow we used */
1729   if (ssk)
1730       mptcp_push_release(ssk, &info);
```

with `info.mss_now` still the zero from the stack initialiser.
`tcp_push()` is called with `mss_now = 0`; `tcp_write_xmit()`
takes the path that calls `tcp_tso_autosize()`; the divide
oopses.

Several adjacent paths *do not* trip this:

- **`TCP_CLOSE` is safe.**  `__tcp_push_pending_frames()` (inside
  `tcp_push()`'s caller chain) bails on `sk_state == TCP_CLOSE`
  before reaching the divide.  Our first commit-message draft
  said "FIN_WAIT1/2 or CLOSE" — that was imprecise; the actual
  reachability set is "every state where `__tcp_can_send()`
  returns false **and** the TCP send path is not short-circuited
  on `TCP_CLOSE`," which excludes `TCP_CLOSE` itself.  See
  Section 4 below.
- **The AccECN beacon refresh would mask `mss_now == 0`** by
  reassigning `mss_now` inside `tcp_write_xmit()` — but the
  refresh is gated on
  `tcp_ecn_mode_accecn() && tcp_accecn_option_beacon_check()`,
  so the bug is reachable on non-AccECN flows (the common case
  on a syzkaller VM).
- **Paolo's 2021 fix `1094c6fe7280`** ("mptcp: fix possible
  divide by zero") moved `tcp_send_mss()` *before* the alloc
  inside `mptcp_sendmsg_frag()` to cover an **alloc-failure**
  branch that previously returned with `mss_now` unassigned.
  That fix landed in the same function; it did not cover the
  `!__tcp_can_send()` early return that sits one branch above
  the call site Paolo moved.  Same bug class, different
  reachability path, four years apart.

---

## 3. How BRF surfaced it

The harness that surfaced this is the Mpiric MPTCP protocol-flow
extension on top of BRF (Hung & Amiri Sani, UCI,
arXiv:2305.08782) / Syzkaller (Vyukov et al., Google).  Three
facts are load-bearing:

**1. The trigger is the kernel-PM admin path, not the userspace
PM.**  The pseudo-syscall is `syz_mptcp_pm_kernel_flush_addrs`
(gap 10 of the 2026-05-21 coverage audit), implemented in
`executor/common_brf_linux_mptcp.h` via
`MPTCP_PM_CMD_FLUSH_ADDRS` over the `mptcp_pm` genl family.  This
is a **separate surface** from finding 001: 001 lived on the
userspace PM (`pm_type=1`) genl handlers (`ANNOUNCE`,
`SUBFLOW_DESTROY`, etc.); 002 lives on the kernel PM (`pm_type=0`)
admin genl handlers.  The MPTCP harness covers both surfaces
because the audit-driven gap closure (Phase 4) added all five
kernel-PM commands (`add_addr`, `del_addr`, `flush_addrs`,
`set_limits`, `set_flags`).  Two findings on two surfaces, not
two on one.

**2. The state-transition timing is what makes the call
reachable.**  `FLUSH_ADDRS` walks every kernel-PM-registered
local-address endpoint, drops each, and as a side effect closes
every subflow currently bound to one of those endpoints via
`pm_flush_addrs_and_subflows() → mptcp_pm_remove_addr_entry() →
__mptcp_close_ssk()`.  Per closed subflow, `__mptcp_close_ssk()`
advances the ssk's TCP state, then unconditionally invokes
`__mptcp_push_pending(sk, 0)`.  If the msk had any retransmit-
pending data and the just-closed subflow is what the scheduler
selects next, the divide-by-zero is reached on the first such
iteration.  Stateless Syzkaller cannot construct this state — the
msk has to be `fully_established`, the kernel-PM has to have at
least one endpoint registered, and the kernel-PM has to have
created a subflow against that endpoint before the flush — but a
state-carrier pseudo-syscall family that has already driven
MP_CAPABLE + kernel-PM `add_addr` + a brief data exchange reaches
exactly this state.

**3. Time to signal: first qualifying iteration.**  The
`syz_mptcp_pm_kernel_flush_addrs` pseudo-syscall was added as part
of the Phase 4 backlog closure (see the `mptcp_kcov:` commit
thread, gap 10).  The first syz-manager run that exercised it
(`workdir_v01`, kernel build
`2026_05_19_005753_brf_mptcp_v01_first_kmemleak_debug`,
`mptcp_brf_fuzz_base` tip `c2e28d808c9b`) produced the oops on
the first qualifying iteration of the
`__mptcp_close_ssk()`-during-pending-data scenario.  The crash
directory is
`workdir_v01/crashes/53781e140c84d967e99e3fcb01db97d121313078/`;
`description: divide error in tcp_tso_segs`.  No auto-reduced C
reproducer was generated (syz-manager `repro 0` at the time of
the crash); the syz program that triggered is preserved in the
1 MB `log0` and would benefit from manual minimisation if the
upstream submission needs a self-contained reproducer.

---

## 4. Diagnosis

The diagnosis chain has three layers — the historical record, a
state-machine read, and a corrected commit message.

**Prior-art chain.**  This is a *re-emergence* of a bug class
first reported by Florian Westphal in 2021
(<https://lore.kernel.org/all/1f8942ce-3575-5665-c41d-46d72b6efb72@gmail.com/>;
Anubis-blocked from automated fetchers, human-readable in a
browser).  Geliang Tang then proposed a defensive fix in
<https://lore.kernel.org/all/20210824071926.68019-1-benbjiang@gmail.com/>
that initialised `info` defensively at the caller.  Matt
Martineau and Paolo Abeni rejected the defensive shape in favour
of a structural one: commit `1094c6fe7280` ("mptcp: fix possible
divide by zero") moved `tcp_send_mss()` ahead of the allocation
inside `mptcp_sendmsg_frag()`, fixing the alloc-failure path that
was the reported reachability.  The MPTCP project's tracking
issue is multipath-tcp/mptcp_net-next#219.

The structural fix's invariant was "by the time `mptcp_push_release()`
runs, `info->mss_now` has been set inside `mptcp_sendmsg_frag()`."
That invariant held for every reachability path the 2021 work
considered.  It does **not** hold for the
`!__tcp_can_send()` early return at line 1335, because that
return is *above* the assignment Paolo moved.  Four years and
several refactors later, the
`__mptcp_close_ssk(MPTCP_CF_PUSH)` path threads an ssk in
FIN_WAIT* state into a push loop that the scheduler picks up,
and the invariant breaks for the first time on a surface a new
fuzzer can reach.

**State-machine read.**  The set of TCP states for which
`__tcp_can_send()` returns false **and** the divide is still
reachable (i.e. the TCP send path is not short-circuited
elsewhere) is:

- `TCP_FIN_WAIT1`, `TCP_FIN_WAIT2`, `TCP_CLOSING`, `TCP_LAST_ACK`
  — local close, peer's ACK / FIN possibly pending.  Reached by
  `__tcp_close(ssk, 0)` inside `__mptcp_close_ssk()`.
- `TCP_TIME_WAIT` — formally not reachable through this path
  (`__tcp_close()` does not transition into `TIME_WAIT` from
  this caller chain) but the predicate would hit it too.
- `TCP_CLOSE` — *not* reachable: `__tcp_push_pending_frames()`
  short-circuits before the divide.  The non-reachability of
  `TCP_CLOSE` is the corner that the first commit message
  conflated; see "false start" below.
- `TCP_SYN_SENT`, `TCP_SYN_RECV`, `TCP_NEW_SYN_RECV`, `TCP_LISTEN`
  — formally subject to `!__tcp_can_send()`, but not reached
  through `__mptcp_close_ssk()`'s post-`__tcp_close` path; a
  separately-reachable variant if a SYN-stage subflow is on the
  scheduler.  Not the path our reproducer exercises.

The reproducer exercises FIN_WAIT1 / FIN_WAIT2 / LAST_ACK /
CLOSING; that is the audited reachability set.

**False start: commit-message imprecision.**  The first draft of
the patch's commit message said the predicate was "FIN_WAIT1/2 or
CLOSE."  This conflates two different predicates:

- `__tcp_can_send(ssk)` — false for all the close-half states,
  including `TCP_CLOSE`.
- `__tcp_push_pending_frames()`'s `TCP_CLOSE` short-circuit —
  which makes the divide unreachable from `TCP_CLOSE`.

The two predicates are not the same.  The corrected commit
message uses `!__tcp_can_send()` as the predicate and explicitly
names the four states actually reachable through
`__mptcp_close_ssk()`'s tail path.  This is the kind of
imprecision that costs maintainer trust if it ships unchecked —
caught in human review (Shardul) before send.

A related conflation also surfaced and was caught: the outer
push loop's `push_count--` exit branch
(line 1717's `(1 << ssk->sk_state) & (TCPF_FIN_WAIT1 | TCPF_FIN_WAIT2 | TCPF_CLOSE)`)
*does* mention `TCPF_CLOSE`, but that mention is the
*loop-termination* condition, not the *crash-reachability*
condition.  Re-using the loop's enum in the fix's reasoning was
tempting and wrong; the correct read separates "when does the
loop exit?" from "when is the divide reached?"

**Why a defensive fix is preferable to Geliang's 2021 shape.**
Geliang's patch initialised `info` defensively at the
`__mptcp_push_pending()` caller (one of several call sites).
Maintainers preferred the structural move because it fixes the
problem at the *function that owns the invariant*, not at one of
its callers.  Our fix follows the same philosophy: move the
`tcp_send_mss()` assignment to the structural point that owns
the invariant — `__subflow_push_pending()`'s entry — so the
invariant holds for every caller without per-call-site
defensive code.

---

## 5. The fix

One file, 7 insertions, no deletions.  Patch:
`findings/002_mptcp_push_pending_divide_zero/0001-mptcp-fix-divide-by-zero-in-__mptcp_push_pending-clo.patch`.

```
 net/mptcp/protocol.c | 7 +++++++
 1 file changed, 7 insertions(+)
```

Mechanism:

- Initialise `info->mss_now` and `info->size_goal` at the entry
  of `__subflow_push_pending()`, before any early-return path of
  the inner machinery.  The assignment is idempotent with the
  one already inside `mptcp_sendmsg_frag()` at line 1341 — both
  call `tcp_send_mss()` against the same ssk and write into the
  same fields, so executing both in series is correct and the
  inner assignment is a harmless re-write when the inner path
  reaches it.
- The comment block explains the invariant
  (`mptcp_sendmsg_frag()` may return before reaching its own
  `tcp_send_mss()`, e.g. on `!__tcp_can_send()`, leaving
  `__mptcp_push_pending()`'s trailing `mptcp_push_release()`
  with `info.mss_now == 0`) so the next reader does not have
  to re-derive it.

Why `__subflow_push_pending()` and not `mptcp_sendmsg_frag()`:
moving the assignment further inward (into `mptcp_sendmsg_frag()`
before the `!__tcp_can_send()` return) would assign on every
call including the early-return one — also correct, but assigns
even when the inner function will return without using the
value.  Doing it at `__subflow_push_pending()` entry assigns
once per outer-loop iteration per ssk, which matches the
lifetime of `info` (one outer iteration) better and is closer in
spirit to Paolo's 2021 placement (the assignment owns the
invariant at the function whose contract carries it).

Why not at `__mptcp_push_pending()`'s entry: the outer function
does not yet know which ssk the scheduler will pick;
`tcp_send_mss(ssk, ...)` needs an ssk argument.  Putting the
assignment at the inner function — the first place an ssk is in
scope — is the structurally aligned choice.

**Upstream status:**

- Patch subject: `[PATCH mptcp-net] mptcp: fix divide-by-zero in
  __mptcp_push_pending close path`.
- Local branch in the kernel clone: `mptcp_push_pending_mss_init`
  (off `mptcp_brf_upstream_fixes`), commit `2f0d0fed32e7a`.
- Sent to `mptcp@lists.linux.dev` on 2026-05-24.
- `Cc:` Paolo Abeni (author of the precursor `1094c6fe7280`) and
  Geliang Tang (author of the 2021 patch that was declined).
  Per the in-tree `.b4-config`, no broader Cc on send — MPTCP
  maintainers forward to netdev as part of their export pull.
  `get_maintainer.pl` returns the theoretical maximum recipient
  set; subsystems with curated review flows narrow it.
- `Fixes:` `724cfd2ee8aa` ("mptcp: allocate TX skbs in msk
  context") — the same `Fixes:` tag Paolo's 2021 patch carries,
  identifying the original cause-introducing commit.
- Carries the `Assisted-by: Claude:claude-opus-4-7` trailer per
  `Documentation/process/coding-assistants.rst` and the project's
  current AI-attribution decision (working choice, not policy).
- Validation: `checkpatch.pl --strict` 0/0/0; locally
  compile-clean.  **Re-run-on-patched-kernel** to confirm the
  crash signature stops recurring is *pending* — the upstream
  submission's harness-credit paragraph is phrased as
  *discovery* ("the oops is reached on the first qualifying
  run") rather than as *fix-validation* ("no recurrence over N
  hours") for that reason.

The patched fuzzing-kernel base does not yet carry the fix as a
cherry-pick (deliberate — keeping the bug live in the fuzzing
kernel for the moment lets a future run double-check the
recurrence question, after which the cherry-pick can land).

---

## 6. What this proves — honestly

A small, defensible claim:

> **The Mpiric MPTCP protocol-flow harness — built on Hung &
> Amiri Sani's BRF (UCI, arXiv:2305.08782), itself a fork of
> Syzkaller (Vyukov et al., Google) — produced a second real,
> upstream-mergeable kernel bug in `net/mptcp/`, on a different
> surface from the first, in a code path that has carried a
> partial structural fix since 2021.**

What this is evidence *for*:

- **Two-surface reach.**  The harness produced bugs on **two
  distinct MPTCP surfaces** — finding 001 on the userspace-PM
  genl handlers, finding 002 on the kernel-PM admin genl
  handlers.  This is a stronger property than two bugs on the
  same surface, because the harness's reachability is not
  concentrated in a single chokepoint.  The audit-driven gap
  closure that added the kernel-PM pseudo-syscalls (gaps 6, 7,
  8, 9, 10 of `mptcp_coverage_audit_2026-05-21.md`) produced
  this finding on its first qualifying run.
- **Long-uncovered code path reachable.**  The
  `!__tcp_can_send()`-before-`tcp_send_mss()` reachability had
  carried a partial fix for four years; the harness exercised
  it.  This is the load-bearing observation: BRF-style
  state-carrier pseudo-syscalls reach code paths that prior
  fuzz work (including the work that motivated Paolo's 2021
  fix) did not.
- **Maintainer-conventions-aligned patch authoring.**  The fix
  follows Paolo's 2021 structural philosophy; carries the same
  `Fixes:` tag; respects the MPTCP `.b4-config`'s narrow Cc
  convention; was reviewed against `checkpatch.pl --strict`
  before send.  The harness produces bugs in a form a
  maintainer-track patch can land.

What this is **not** evidence for, and what would be unsafe to
claim from two findings:

- **Two bugs is still small N.**  Two is better than one for the
  "is this a fluke" question — the prior is no longer "one
  flake from a noisy harness" — but it is not statistically
  significant.  A claim like "the harness produces bugs on
  schedule" still needs more data.
- **No controlled baseline.**  We have not run plain Syzkaller
  against the same kernel for the same time budget with the
  same crash-detection plumbing.  The methodology's value claim
  remains "reaches code the baseline cannot" (demonstrable from
  coverage / reachability) rather than "finds more bugs than
  the baseline" (not demonstrable without that controlled
  run).
- **Pre-work and human MPTCP expertise are not factored out.**
  The kernel-PM pseudo-syscalls (gap 10) were authored as part
  of the audit-driven closure; that closure was Shardul's
  decision and required reading the MPTCP source carefully
  enough to make the audit prescriptive.  The
  audit-to-bug-finding cycle time on this finding is short, but
  the audit-authoring time is not subtractable from the
  finding's clock.
- **Fix not yet runtime-validated.**  The patch compiled clean;
  no recurrence-stop measurement has been recorded yet.  If
  re-running on a patched kernel produces another oops with the
  same dedup hash, the fix is incomplete and the case study
  needs an update.
- **One surface ≠ the surface class.**  "Kernel-PM admin paths"
  is one surface; whether the harness will find more bugs in
  *other* PM admin commands (`add_addr`, `del_addr`,
  `set_limits`, `set_flags`) is an open question.  Two bugs
  does not generalise to a bug-class claim.

**Two bugs on two surfaces is suggestive, not statistically
significant.**  The talk's framing must continue to reflect
that.

---

## 7. Honest caveats — where AI was load-bearing, and where it failed

Per the project's standing principle (`CLAUDE.md`: "AI use is in
scope to discuss openly, not to hide"), this section is the
credibility section for finding 002.  The case-study for finding
001 catalogued AI failures in harness bring-up (byte order,
fully_established, MIB naming, probe condition, instrumentation
verbosity); the failures here are different in shape and
disjoint.

### Where AI was load-bearing and useful

- **Excavation of the call chain.**  Reading the path from
  `MPTCP_PM_CMD_FLUSH_ADDRS` through
  `mptcp_pm_nl_flush_addrs_doit` → kernel-PM endpoint walk →
  `__mptcp_close_ssk()` → `__mptcp_push_pending()` →
  `__subflow_push_pending()` → `mptcp_sendmsg_frag()` →
  `mptcp_push_release()` is mechanical once the entry point and
  the oops symbol are known.  AI surfaces it; Shardul forms the
  diagnosis.  Standing learning model.
- **Surfacing the prior-art chain.**  The 2021 Westphal report,
  the rejected Tang defensive patch, and Paolo's structural
  `1094c6fe7280` are all reachable from the function name; AI
  threaded the chain and pulled the lore links.  Shardul read
  the threads and confirmed the philosophy match.
- **Drafting the structural fix and the commit message.**  The
  one-line `tcp_send_mss()` assignment + the explanatory
  comment came out of an AI draft, reviewed and corrected by
  Shardul before send.

### Where AI failed or would have failed without human verification

- **Commit-message state imprecision: "FIN_WAIT1/2 or CLOSE"
  conflation.**  The first draft of the commit message named
  the reachability set as "FIN_WAIT1/2 or CLOSE."  This was
  wrong: `TCP_CLOSE` is not reachable for the divide because
  `__tcp_push_pending_frames()` short-circuits.  Reading the
  `push_count--` exit branch's `TCPF_CLOSE` and re-using it as
  the crash-reachability predicate looks plausible — two of the
  four state-mask bits agree — but the two predicates are
  different.  Caught in human review (Shardul) before the
  patch went to mptcp@.  The corrected message names
  `!__tcp_can_send()` as the predicate and lists the four
  actually-reachable states.
- **Initial fix comment was too verbose.**  The first draft of
  the comment block above the new `tcp_send_mss()` assignment
  ran to six lines, including a parenthetical about Paolo's
  2021 fix and a redundant restatement of the call chain.
  Maintainer-track patches favour terse, kernel-prose comments;
  the comment was trimmed to four lines (just the invariant
  and a one-clause example).  Caught in human review.  The
  pattern is familiar from finding 001's instrumentation-
  verbosity caveat: AI-generated explanatory text is
  consistently *too long* for the kernel style and needs human
  compression.
- **Conflating the `push_count--` exit predicate with the
  crash-reachability predicate.**  Same shape as the
  commit-message conflation, surfaced during diagnosis rather
  than at write-up: the outer loop's exit logic uses
  `TCPF_FIN_WAIT1 | TCPF_FIN_WAIT2 | TCPF_CLOSE` as its
  termination mask, and an AI-drafted reading of the bug
  inferred that this mask defined the reachability set.  It
  does not — the mask is "when should the outer loop give up
  on this ssk," not "when does the divide oops."  The
  divide-reachability set is the *intersection* of
  `!__tcp_can_send()` and "not short-circuited by
  `__tcp_push_pending_frames()`," which excludes `TCP_CLOSE`.
  Caught by reading `tcp_push()`'s caller chain end-to-end
  rather than trusting the adjacent enum.
- **No auto-reduced reproducer.**  syz-manager's `repro 0` at
  the time of the crash means there is no minimal C reproducer
  in the finding directory.  The 1 MB `log0` contains the syz
  program that triggered.  Without a minimal reproducer the
  upstream submission can credibly cite "found by harness" but
  cannot include a one-file reproducer the maintainer can
  run.  This is a known cost of the harness shape (stateful
  pseudo-syscalls with executor-side orchestration are harder
  to reduce than stateless syscall sequences).  If maintainer
  feedback asks for a C reproducer, manual minimisation is the
  fallback.

### What could have failed and didn't

- The crash hash dedup
  (`53781e140c84d967e99e3fcb01db97d121313078`) means syz-manager
  recognised the oops as distinct from prior crashes in the
  workdir, including 001's kmemleak signatures.  If the
  dedup had folded this into the kmemleak cluster (the leak
  reports also originate inside mptcp_pm machinery), the new
  signal would have been hidden under the existing one.
- If the harness had selected the just-closed subflow as a
  *non-last* iteration of the outer push loop, the divide would
  not have been reached — `mptcp_push_release()` only runs for
  the *last* subflow.  The bug requires the just-closed subflow
  to be the last scheduled one.  Whether that condition is
  scheduler-deterministic or load-dependent has not been
  audited; the first qualifying iteration produced the crash,
  but a careful answer would require running the harness with
  controlled subflow counts.

### What this bug specifically does **not** prove about AI methodology

- **It does not narrow the "AI accelerates bug-finding"
  question.**  The audit-to-bug cycle is short, but the audit
  itself (`mptcp_coverage_audit_2026-05-21.md`) was the
  load-bearing work — and authoring the audit required reading
  `net/mptcp/` carefully enough to enumerate every entry point.
  That was Shardul's pre-work; AI's contribution was excavation
  + drafting, not direction-setting.  The methodology's "human
  verification is the rate-limiter" framing remains correct.
- **It does not prove the absence of AI-introduced defects in
  the harness's kernel-PM pseudo-syscalls.**  Phase 4 closed
  gaps 8, 9, 10 in a short burst.  The
  `syz_mptcp_pm_kernel_flush_addrs` pseudo-syscall produced a
  real bug on first qualifying run — good — but a wider audit
  of the kernel-PM pseudo-syscall family for the same kinds of
  silent-fail-on-byte-order / silent-fail-on-state-precondition
  defects 001's caveats catalogued has not been done.  The
  next finding (or non-finding) on this surface is the
  data point that would settle that.

---

## 8. Provenance and citations

Authorship chain, per the standing citation discipline in
`CLAUDE.md`:

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
- Funding acknowledgment slide: NSF #1763172, NSF #1846230,
  Google ASPIRE 2020 (Hung & Amiri Sani's BRF was funded under
  these).

Mpiric's role is **extender**, not author.  The harness extensions
are Mpiric's contribution; BRF itself and the pseudo-syscall +
state-carrier pattern are Hung & Amiri Sani's; the underlying
coverage-guided fuzzing engine is Syzkaller.  No external
artifact refers to BRF as Mpiric's tool or strips upstream
attribution from the published fork.

The MPTCP prior-art chain cited above (Westphal 2021 report,
Tang 2021 defensive-patch attempt, Abeni 2021 structural fix
`1094c6fe7280`, multipath-tcp/mptcp_net-next#219 tracking
issue) is preserved here in full because the fix's structural
philosophy is *continuous* with that history — this is not an
independent rediscovery, it is an extension of a known partial
fix to a new reachability path that surfaced under a new fuzzer.

---

## 9. Files referenced (this repo)

- Bug report: `findings/002_mptcp_push_pending_divide_zero/README.md`
- Upstream patch:
  `findings/002_mptcp_push_pending_divide_zero/0001-mptcp-fix-divide-by-zero-in-__mptcp_push_pending-clo.patch`
- Crash directory (syz-manager workdir, not in this repo —
  on the fuzzing host):
  `workdir_v01/crashes/53781e140c84d967e99e3fcb01db97d121313078/`
- The pseudo-syscall that surfaced the bug:
  - Syzlang declaration:
    `sys/linux/socket_mptcp_crypto.txt`
    (`syz_mptcp_pm_kernel_flush_addrs`)
  - Executor implementation:
    `executor/common_brf_linux_mptcp.h`
    (`syz_mptcp_pm_kernel_flush_addrs`)
- BRF architecture pattern instantiated by the harness:
  `.claude/designs/brf_architecture.md` Sections 2, 4, 7
- MPTCP-specific harness design (with byte-order /
  fully_established gotchas documented):
  `.claude/designs/mptcp_join_harness_design.md` Sections 5.1,
  5.2, 10
- Coverage audit that ranked gap 10 (kernel-PM `FLUSH_ADDRS`):
  `.claude/tasks/netdev_0x1a_protocol_fuzzing/mptcp_coverage_audit_2026-05-21.md`
- Companion finding (different surface, same harness):
  `findings/001_mptcp_pm_destroy_race/case_study.md`
- Methodology writeup (now integrating N=2 findings):
  `findings/methodology.md`
