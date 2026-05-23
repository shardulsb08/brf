# Methodology: AI-augmented protocol-flow fuzzing for kernel transport security

**Audience.** netdev / LPC / FOSDEM attendees evaluating whether to
adopt this approach for a kernel transport-security subsystem of
their own.  Kernel veterans reviewing the methodology under Q&A.

**Companion evidence.** Two case studies are the load-bearing
bug evidence; this document is the generalised methodology
claim.  Read the case studies for the ground-truth examples:

- `findings/001_mptcp_pm_destroy_race/case_study.md` — userspace-PM
  `ANNOUNCE`-vs-`destroy` race; kmemleak signal; patched, sent
  to mptcp@ 2026-05-20.
- `findings/002_mptcp_push_pending_divide_zero/case_study.md` —
  kernel-PM `FLUSH_ADDRS` → `__mptcp_close_ssk` → divide-by-zero
  in `tcp_tso_segs`; structural fix extending Paolo Abeni's
  2021 `1094c6fe7280`; sent to mptcp@ 2026-05-24.

**Authorship chain (preserve in every external artifact):**

```
Syzkaller        Google / Dmitry Vyukov et al.       Apache 2.0
   ↓ fork, Jan 2024
BRF              Hsin-Wei Hung + Ardalan Amiri Sani  (UC Irvine)
                 arXiv:2305.08782 (May 2023);
                 ACM venue version: papers/3643778.pdf
                 Funded by NSF #1763172, NSF #1846230, Google ASPIRE 2020
   ↓ fork, Aug 2025
shardulsb08/brf  Mpiric extensions (this checkout)
```

Mpiric's role is **extender**, not author.

---

## 1. The headline claim

> **A small team can extend a published academic fuzzer (BRF) to
> reach a kernel transport-security protocol's hardest gates by (i)
> reusing BRF's pseudo-syscall + state-carrier pattern, (ii) using
> AI to draft the syzlang descriptions and executor C, (iii)
> verifying every draft in the VM before the corpus sees it, (iv)
> driving the coverage gaps with a static audit, and (v) keeping a
> continuous instrumentation loop on whichever quality metric the
> generator can degrade silently.  The result is a harness that
> reaches code stateless Syzkaller cannot, with a documented
> human-verification step that determines whether it works.**

The harness this methodology produced is 25 pseudo-syscalls (21
MPTCP + 4 BPF), with wire-level option mutation, a generated BPF
struct_ops MPTCP scheduler (Phase 3 / "the flagship") whose
verifier-accept rate measures at ~93% on 1,422 loads, and **two
real, upstream-mergeable bugs on two distinct surfaces of
`net/mptcp/`**:

- Finding 001: `mptcp_pm_destroy()` alloc-during-teardown race
  on the userspace-PM genl handlers (sent to mptcp@ 2026-05-20).
- Finding 002: `__mptcp_push_pending()` close-path divide-by-zero
  in `tcp_tso_segs`, reached via the kernel-PM
  `MPTCP_PM_CMD_FLUSH_ADDRS` admin command — a partial-fix
  re-emergence of a bug class first patched (incompletely) by
  Paolo Abeni in 2021 (sent to mptcp@ 2026-05-24).

None of this is a controlled comparison against any baseline;
see Section 6.  Two bugs on two surfaces is a stronger property
than two bugs on one surface, but still small N — the framing
below stays cautious about what two findings can prove.

---

## 2. The problem this addresses

Kernel transport-security protocol code is hard to fuzz because
the interesting code is gated by protocol state the fuzzer must
construct first.  For MPTCP MP_JOIN, the gates that reject a
random-byte attempt include:

| Gate                                | Probability of stateless pass | Construction required                                         |
|-------------------------------------|-------------------------------|----------------------------------------------------------------|
| MP_JOIN token lookup                | 0%                            | Live `msk->token` from a prior MP_CAPABLE exchange             |
| Server-side HMAC validation         | < 2^-64                       | HMAC-SHA256(local_key‖remote_key, local_nonce‖remote_nonce)    |
| Client-side HMAC validation         | < 2^-160                      | Full 20-byte HMAC over the same inputs                          |
| DSS mapping / csum                  | ~1:2^32 (if csum on)          | Negotiated csum mode + valid CRC-32C                            |
| Subflow accept readiness            | ~50%                          | `msk` fully established + PM willing to accept subflows         |

A stateless Syzkaller corpus produces none of these.  The
deficit is not coverage tuning — it is **descriptor authoring**:
without an executor that can drive MP_CAPABLE, capture the keys,
prime `fully_established`, and stand up userspace-PM netlink
plumbing on the executor's behalf, every MP_JOIN attempt the
fuzzer makes is rejected at the first gate.  The same shape
recurs for QUIC handshake (key derivation, ChaCha20-Poly1305
headers) and tlshd / NET_HANDSHAKE (a kernel-userspace TLS
handshake handoff that is structurally invisible to a syscall
fuzzer).

The lever already exists.  Hung & Amiri Sani's BRF (UCI,
arXiv:2305.08782, ACM PACMSE 1(FSE) Art. 52) introduced the
**pseudo-syscall + state-carrier** pattern for eBPF: the
generator emits a compiled `.o` artifact on disk, then a small
sequence of pseudo-syscalls (`syz_bpf_prog_open` / `_load` /
`_attach` / `BPF_PROG_TEST_RUN`) that the executor implements in
C and that thread cryptographic / kernel-side state (fds, BTF
ids) through an out-parameter.  That pattern is the bridge
between syzlang's declarative grammar and the kernel's stateful
preconditions: the *executor* — not the generator — is what does
the cryptographic work, opens the netlink sockets, and primes
the state machine; the *descriptor* stays declarative and small
enough that a fuzzer can mutate it productively.

Our methodology is: lift that pattern from eBPF to a network
protocol flow, treat the descriptors as the bottleneck, and use
AI to author them — under a strict human-verification step.

---

## 3. What we actually did (the prescriptive substance)

Five things, in roughly this order:

### 3.1 State-carrier pseudo-syscalls authored against the protocol's reachability gates

The harness's resource type is `mptcp_pair`: a syzlang resource
threaded through every protocol-step pseudo-syscall.  The
executor backs it with a static pool of `struct brf_mptcp_pair_state`
slots; each slot carries `local_key`, `remote_key`, `token`,
`idsn_local`/`idsn_remote`, `csum_enabled`, `family` (v4/v6), and
per-subflow state.  `syz_mptcp_pair_init` stands the pair up:
socket pair on `127.0.0.1` (or `::1`), drive MP_CAPABLE, capture
keys via the new `MPTCP_DEBUG_KEYS` getsockopt
(`kernel_patches/mptcp_kcov/0003-*`, CONFIG_KCOV-gated), read the
token via `MPTCP_INFO`, prime both sides to `fully_established`
with a 1-byte round-trip in each direction, and hand back the
slot index as the resource.

Every later pseudo-syscall — `syz_mptcp_join_subflow`,
`syz_mptcp_drive_traffic`, `syz_mptcp_pm_announce`,
`syz_mptcp_pm_remove`, `syz_mptcp_pm_subflow_destroy`,
`syz_mptcp_pm_set_flags`, `syz_mptcp_pm_kernel_{add,del,flush}_addr`,
`syz_mptcp_pm_set_limits`, `syz_mptcp_diag`,
`syz_mptcp_setsockopt_fuzz`, `syz_mptcp_getsockopt_fuzz`,
`syz_mptcp_set_sysctl`, `syz_mptcp_sock_op`, `syz_mptcp_send_control`,
the v6 dispatch variants, etc. — takes a `mptcp_pair` resource and
uses the captured cryptographic state to satisfy the kernel's
input validation while still leaving every individual byte the
fuzzer chose under mutation pressure.

The final count is **25 pseudo-syscalls** (21 MPTCP + 4 BPF).
This is the BRF state-carrier pattern instantiated for a network
protocol flow.  It is the generalisable artefact: the same shape
will fit QUIC (token = ICID; carrier holds the 1-RTT and
handshake keys after derivation) and tlshd / NET_HANDSHAKE
(carrier holds the handshake-completion fd and the negotiated
session parameters).

### 3.2 AI-augmented description authoring with a strict VM-verification step

The descriptions and executor C scaffolding for the
pseudo-syscall family were drafted by Claude — both the syzlang
fragments under `sys/linux/socket_mptcp_crypto.txt` and the C
implementations in `executor/common_brf_linux_mptcp.h`.  The
build-out ran at roughly one sibling pseudo-syscall per drafting
session (see the v05.4 → v10.2 thread, `ace4822a8` →
`7a552ee63`).  Every draft entered the corpus only after Shardul
ran it under VM smoke tests and read the kernel symbols it
actually exercised.  Where the draft was wrong, Section 4 catalogs
how it failed.

This is the talk's substantive methodology claim.  It is **not**
"AI accelerates harness authoring" (we have no controlled
comparison; Section 8).  It is "AI drafts faster than humans
verify, so the verification step is the rate-limiter — and that
is the methodology's defensible shape."

### 3.3 Kfunc-aware struct_ops generation (Phase 3)

The audit (Section 3.4) ranked the BPF `mptcp_sched_ops`
struct_ops scheduler as the #1 unhit surface: a real
transport-state *write* primitive
(`bpf_mptcp_sched_btf_struct_access`, `net/mptcp/bpf.c:44`,
permitting BPF writes into live `mptcp_sock.snd_burst` and
`mptcp_subflow_context.avg_pacing_rate`) plus 9 MPTCP kfuncs
callable only from a struct_ops program.  This is BRF's eBPF
generator pointed at a kernel write surface other fuzzers cannot
reach.

Phase 3 modifies BRF's program generator (`prog/brf*.go`) — Hung
& Amiri Sani's core artifact.  This is a scope expansion beyond
the original task brief; it is still an *extension*, not a fork
rename, and the citation discipline still applies.  The
implementation is staged:

- **Stage 0** — kernel prerequisites: `CONFIG_BPF_SYSCALL` /
  `BPF_JIT` / `DEBUG_INFO_BTF` in the fuzzing kernel config; the
  kcov scratch-area UAF fix (kernel patches 0006 and 0007).
- **Stage B** — a hand-written fixed `mptcp_sched.bpf.c` proves
  the load / register / select / drive-traffic chain end to end
  (`executor/bpf_progs/README.md`).
- **Stage C-minimal** (`prog/brf_structops.go`) — BRF generates
  fuzzed `mptcp_sched_ops` schedulers: a `BPF_PROG_TYPE_STRUCT_OPS`
  entry in `ProgTypeMap` targeted at `mptcp_sched_ops`; a
  `CtxAccessMap` entry recording the read surface (broad BTF) and
  the two writable fields; a dedicated `genStructOpsSource`
  renderer that emits vmlinux.h + helpers + kfunc externs +
  `init`/`release`/`get_send` callbacks + the
  `SEC(".struct_ops.link")` instance.  The `get_send` body is a
  generated sequence of ctx reads, ctx writes (confined to the
  two `btf_struct_access`-writable fields) and arithmetic over
  the read locals.
- **Stage C-full** (Stages 1 / 2a / 2b) — *contract-aware* kfunc
  call generation against the six common straight-line MPTCP
  kfuncs (each kfunc's `KF_RET_NULL` flag drives a mandatory
  NULL-guard for pointer returns); the open-coded subflow
  iterator (`bpf_iter_mptcp_subflow_new` / `_next` / `_destroy`
  emitted as the complete triple on every path, because the
  verifier rejects an unreleased iterator); non-empty
  `init`/`release` bodies over `msk`-reachable state; generated
  free-form `if/else` over an in-scope scalar local with
  `noReturn` branch bodies (so every path falls through to the
  scheduling epilogue and no per-path scheduling analysis is
  needed); block scoping for branch-local variables; nesting cap
  at depth 2.
- **Stage D** — the executor loads the generated `.o` (`libbpf
  bpf_object__open` / `_load`), detects a `BPF_MAP_TYPE_STRUCT_OPS`
  map, patches a unique `mptcp_sched_ops.name[]` into the map's
  initial value before `bpf_object__load` (so concurrent procs
  don't collide on the kernel-global registry), registers via
  `bpf_map__attach_struct_ops`, selects via
  `/proc/sys/net/mptcp/scheduler`, and keeps the `bpf_link`
  alive for the rest of the program.  A 4-GiB soft-cap pruner
  on `/mnt/brf_work_dir` keeps the generator from filling the
  disk.

**Numbers.** Run `run_20260522_151649` (C-full): total cover
climbed from the C-minimal/D ceiling of ~20,690 to ~24,000 (~+16%),
with the C-full kfuncs (`bpf_iter_mptcp_subflow_*`,
`bpf_mptcp_subflow_tcp_sock`, `bpf_mptcp_subflow_queues_empty`,
`mptcp_subflow_active`, `mptcp_set_timeout`, `mptcp_wnd_end`) all
covered.  Nuance, recorded honestly: the gain is in the BPF
struct_ops/verifier path and the TCP/core code the kfuncs reach,
not in deeper *MPTCP-protocol* coverage (the `net/mptcp` filtered
surface is ~flat at ~43%).  The verifier-accept *rate* on
generated bodies, measured by the instrumentation in Section 3.5,
is **~93%** (1,422 loads in `run_20260522_232150`).

### 3.4 Audit-driven coverage-gap closure

The harness build-out hit a plateau at 16 pseudo-syscalls.  A
systematic read of `net/mptcp/` produced the audit at
`.claude/tasks/netdev_0x1a_protocol_fuzzing/mptcp_coverage_audit_2026-05-21.md`
— a per-entry-point inventory (genl ops, setsockopt /
getsockopt switches, sysctls, BPF struct_ops, the option
parse/write paths, the connect/accept/sendmsg/close core,
syncookies, fastopen, sock_diag) cross-referenced against the 16
existing pseudo-syscalls.  Headline: ~50–55% reachable-surface
coverage; ~45% missing, in four clusters (BPF struct_ops,
error-signalling options, setsockopt/getsockopt fan-out, the
sole netlink `dumpit`).

The audit was prescriptive at two levels.  It produced a
ten-item ranked backlog (bug-value × BRF-fit × inverse-effort)
that drove the next ~ten commits; gaps 2–10 closed across
Phases 1/2/4 (see the `mptcp_kcov: ...` commit thread,
`730b14547` through `0f5e0bf0c`), and gap 1 became Phase 3.  It
also caught **two overclaims** in the existing harness: that
`syz_mptcp_send_control` emitted MP_FAIL / MP_FASTCLOSE /
MP_RST (it did not — it only closed fds with different linger /
shutdown shapes), and that `syz_mptcp_setsockopt_fuzz` reached
`MPTCP_FULL_INFO` / `TCPINFO` / `SUBFLOW_ADDRS` validation
branches (those are *getsockopt*, and the harness had no
getsockopt fuzzer).  The corrections are now reflected in the
syzlang comments and the harness; the lesson is in Section 4.

Without the audit, the next ten commits would have followed the
existing momentum (more wire-level MP_JOIN mutations) rather than
the missing surface.  An audit is a small artifact for a large
direction change.

### 3.5 Kcov-instrumented harness + continuous quality instrumentation

Two distinct instrumentation kinds.

**Coverage instrumentation — kcov on the gated paths.**  Patch
series `kernel_patches/mptcp_kcov/0001` through `0007`:

- Patch 0001 adds an `MPTCP_KCOV_HANDLE` setsockopt + per-msk
  kcov scratch buffer + a `kcov_owner` field that survives
  `sk_clone_lock()`'s memcpy.
- Patch 0002 wraps the MP_JOIN validity gates
  (`subflow_token_join_request`, `subflow_hmac_valid`,
  `subflow_thmac_valid`).
- Patch 0003 adds `MPTCP_DEBUG_KEYS` getsockopt (so the harness
  can capture keys without AF_PACKET wire-peek).
- Patch 0004 extends the kcov wrap to the option parser
  (`mptcp_get_options` / `mptcp_parse_option`).
- Patch 0005 restricts the BRF kcov macros to softirq context
  (`in_serving_softirq()`) — `release_sock()` can drain the
  socket backlog in process context, and `kcov_remote_start()`
  WARNs there if the task has kcov enabled.
- Patches 0006 / 0007 fix two lifetime holes in patch 0001's
  per-msk scratch area: a clone-path memcpy inheritance + a
  synchronous-free race against in-flight softirq parsing
  (0006: `kvfree_rcu`, clone-clear, one-shot pointer snapshot),
  and a `SLAB_TYPESAFE_BY_RCU` recycling hole (0007: zero the
  kcov fields in `__mptcp_init_sock`, which subsumes 0006's
  clone-clear).  Patch 0007 is **VM-verified** as of 2026-05-23:
  zero `kcov_remote_start_prealloc` WARNINGs across
  `run_20260522_232150`.

Without this series, the headline crypto-gate coverage feedback
is dead.  We learned this the hard way: for ~6 weeks the
executor never plumbed `MPTCP_KCOV_HANDLE`, so patch 0002's
instrumentation produced zero coverage signal and the
syz-manager `cover` plateau looked like corpus saturation when
it was partly an instrumentation blind spot (Section 4).

**Quality instrumentation — verifier-accept rate.**  For Phase 3,
coverage alone does not say whether generated struct_ops bodies
are passing the verifier or being rejected wholesale.  Every
struct_ops load now records `ACCEPT` / `REJECT <reason>` to an
append-only stats file on a 9p host share
(`executor/common_brf_linux.h`: VI1 / VI2 / VI3 / VI4):

- `bpf_object__load` is bracketed by `brf_verif_record()`; one
  line per struct_ops load, single bounded `write()` so
  concurrent procs interleave atomically.
- A `libbpf_set_print` callback accumulates the WARN-level
  messages of a load, and on REJECT a host-side picker chooses
  the most-informative line (skipping libbpf's generic
  `failed to load object` wrapper) — the v2 fix to the original
  "last-warning wins" miscapture that polluted the first
  histogram.
- A parallel `struct_ops_verif_recorded[]` array deduplicates
  re-load attempts on the same object — the kernel rejects a
  twice-attempted load with "load can't be attempted twice"
  which is *not* a verifier rejection but was miscounted as one
  in the v1 instrumentation (≈ 37 of 138 first-run "rejects").
- The stats file lives on a per-VM-boot path on the 9p host
  share, so QEMU `-snapshot` restarts don't lose history.
- A host script (`executor/bpf_progs/brf_verifier_tally.sh`)
  buckets rejection reasons by pattern, tunable host-side
  without an executor rebuild.

Result: a measure-driven generator-tuning loop.  The current
number is **~93%** (1,422 loads, raw 90.3% with the load-twice
fix applied → ~93% true), in `run_20260522_232150`.

The principle generalises: whichever quality property the
generator can silently degrade (verifier-accept rate for BPF
generators; for a wire-mutation harness it would be
"fraction of mutations that reach the parser"; for a state-carrier
harness it would be "fraction of gated calls that pass input
validation"), measure it continuously so generator changes are
attributable.

---

## 4. What failed — honestly

This section is the talk's credibility.  Per CLAUDE.md's standing
principle ("AI use is in scope to discuss openly, not to hide"),
the failures are the substance.

### 4.1 AI-drafted descriptions wrong in protocol semantics

- **Asymmetric host vs network byte order on
  `MPTCP_PM_ADDR_ATTR_PORT`** (smoke #2, 2026-05-16).  The
  kernel's `mptcp_pm_parse_pm_addr_attr` (`pm_netlink.c:86`)
  applies `htons()` to the value it reads from the attribute,
  so userspace must pass the port in HOST byte order — even
  though the ADDR4 attribute in the same nested
  `MPTCP_PM_ATTR_ADDR` is network byte order.  AI-drafted code
  passed `sin_port` (NBO).  Failure mode: the kernel byteswapped
  twice, the MP_JOIN SYN went to a random non-listening port
  and was RST'd before any MPTCP code saw it.  *Completely
  silent:* no dmesg, no MIB delta, no `ss` entry.  Caught only
  by VM smoke testing + suspicious zero counters.  Fix:
  `ntohs(sin_port)`, with the executor helpers renamed from
  `*_port_be` to `*_port_h` so the order is obvious to the next
  reader.
- **`MPTCP_ATTR_SERVER_SIDE` only on `MPTCP_EVENT_CREATED`** —
  not on `SUB_ESTABLISHED`.  The uapi docstring suggested it
  was a general "which side" marker; in fact only
  `mptcp_event_created` emits it (`pm_netlink.c:408+`).  Fix:
  correlate by token, not by `SERVER_SIDE`.
- **`MPTcpExt:` not `MPTCPExt:`** in the kernel's
  `/proc/net/netstat` header (`mib.c:115`).  AI-drafted parsing
  always returned -1 on the MIB delta; cosmetic but a red
  herring during the larger debug.
- **Client-side `fully_established` is not set by `connect()`
  alone.**  The client msk's `fully_established` flag flips
  only on receipt of a DSS+use_ack-bearing packet from the
  server (`check_fully_established`, `options.c:942`).
  `__mptcp_subflow_connect` (`subflow.c:1633`) rejects
  SUBFLOW_CREATE with `-ENOTCONN` otherwise.  Fix: drive a
  1-byte send+recv in *both* directions at the end of
  `pair_init`.
- **`MPTCP_MIB_JOINACKMAC` is the *failure* counter, not the
  success counter** (it maps to `MPJoinAckHMacFailure` in
  `/proc/net/netstat`).  The success counter is
  `MPTCP_MIB_JOINACKRX` / `MPJoinAckRx`.  Earlier draft design
  used the failure counter as the success criterion.

Pattern: AI-generated descriptions look correct on
code-reading, fail empirically.  The kernel is the only
authority on what its uapi actually does.

### 4.2 Harness-internal AI-drafted defects

- **Uninitialised `tcp_subflow_fd` array defaulted to 0
  (stdin) via `memset`.**  Latent until the second subflow
  added, then `pair_close` would have called `close(stdin)`.
- **`syz_mptcp_setsockopt_fuzz` drew optname from `{1..7}`,
  and optname 5 was `MPTCP_KCOV_HANDLE` itself.**  The fuzzer
  was `setsockopt`ing the harness's own kcov handle with
  random bytes, filling `msk->kcov_remote_handle` with
  garbage and tripping `kcov.c:971` `WARN_ON(!kcov_check_handle())`.
  Misdiagnosed once (kernel patch 0005 was thought to address it
  but addresses a different WARN at `kcov.c:983`); the actual
  fix was dropping optname 5 from the syzlang enum + a
  hard-reject backstop in the executor (`e45ee7758`).  All 19
  "crashes" in a 6 h run were this one self-inflicted bug.
  Zero real findings hidden behind it once removed.

### 4.3 Instrumentation false alarms and miscounts

Failures of the *instrumentation* itself — every one of which
required human triage to recognise.

- **The first probe condition: `WARN_ONCE` on non-empty
  `anno_list` at `mptcp_pm_data_init`.**  Plausible at
  code-reading time; wrong at runtime because
  `CONFIG_INIT_ON_ALLOC=n` slab returns raw memory whose
  `list_head` bytes coincidentally fool `list_empty()`'s
  self-reference test.  **31 reports filed against the wrong
  condition** before the probe was identified as the
  false-positive source.  This is the AI failure mode that
  motivates the two-phase diagnostic / fix validation in the
  case study: an AI-generated probe condition looks correct on
  paper, and only the kernel's runtime behaviour disproves it.
- **Finding 002 commit-message state imprecision:
  "FIN_WAIT1/2 or CLOSE."**  The first draft of the
  `__mptcp_push_pending()` divide-by-zero commit message named
  the reachability set as "FIN_WAIT1/2 or CLOSE."  This was
  wrong: `TCP_CLOSE` is not reachable for the divide because
  `__tcp_push_pending_frames()` short-circuits before
  `tcp_tso_autosize()`.  The conflation came from re-using the
  outer push loop's `push_count--` *exit* predicate
  (`TCPF_FIN_WAIT1 | TCPF_FIN_WAIT2 | TCPF_CLOSE`) as the
  *crash-reachability* predicate — two different conditions, two
  of four mask bits coincidentally shared.  Caught in human
  review (Shardul) before the patch went to mptcp@; the
  corrected message uses `!__tcp_can_send()` as the predicate
  and names the four actually-reachable states.  This is the
  same shape of failure as 001's probe condition: AI-drafted
  state-machine reasoning that looks right on a single-pass
  read, only the second careful read disproves it.
- **Finding 002 fix comment too verbose.**  The first draft of
  the comment block above the new `tcp_send_mss()` assignment
  ran six lines, including a parenthetical about Paolo's 2021
  fix and a redundant restatement of the call chain.  Trimmed
  to four lines in review.  This is the same verbosity pattern
  as 001's instrumentation: AI-generated explanatory text is
  consistently *too long* for kernel-prose style and needs
  human compression.  The pattern is repeated enough — across
  two findings now — to be a methodology observation rather
  than an incident: schedule a "compress the comment" step
  before any send.
- **The 8-sample 0/8 "regression" misread.**  At one point a
  short window showed the Phase 3 fuzzer producing no new
  coverage; this looked like a regression and triggered a chase
  before being identified as a sampling artifact on too-young
  samples.  The longer run held its plateau then broke it
  stochastically (~+16% above the C-minimal/D ceiling).  The
  lesson: short-window samples lie; the methodology requires
  patience with the instrumentation as much as with the
  generator.
- **The first verifier-accept rate (90.3%) was polluted by
  load-twice miscount.**  Generated programs can call
  `syz_bpf_prog_load` twice on the same `bpf_object`; the
  kernel rejects the second attempt with "load can't be
  attempted twice", which is *not* a verifier rejection.  The
  original instrumentation counted those as REJECT (~37 of
  138).  Fix: a parallel `struct_ops_verif_recorded[]` array
  records outcome on the first load only.  True rate: ~93%.
- **The first verifier-log capture (VI2) grabbed the generic
  wrapper.**  The libbpf print callback `vsnprintf`'d each WARN
  message into a single buffer, *overwriting*; on a load
  failure the buffer held libbpf's *last* warning
  (`libbpf: failed to load object '...'`) rather than the
  *informative* earlier line.  The rejection-reason histogram
  degenerated to "100% other".  Fix (v2): accumulate every WARN
  into an 8-KiB file-scope buffer and pick the most informative
  line (a specific `libbpf: prog '...': ...` line above a
  non-generic line above any non-empty line, skipping libbpf's
  generic wrappers).
- **`cover_filter` blind spot.**  The syz-manager
  `cover_filter` was scoped to `^mptcp_.*` / `^__mptcp_.*` /
  `^subflow_.*` / `^__subflow_.*`; none matched
  `net/mptcp/bpf.c`'s `bpf_mptcp_*` functions, so on the first
  Phase 3 run the struct_ops surface was neither measured nor
  guiding the fuzzer.  Fix: add `^bpf_mptcp_.*`.  The
  generalisable point: a coverage filter scoped before the new
  surface exists becomes a structural blind spot once it does.
- **The 6-week instrumentation blind spot.**  For ~6 weeks the
  executor never called `setsockopt(SOL_MPTCP, MPTCP_KCOV_HANDLE)`
  in `pair_init`, so patch 0002's MP_JOIN-gate instrumentation
  was inert and the headline crypto-gate coverage feedback was
  dead.  The syz-manager `cover` figure (~12,895) plateaued at
  what looked like corpus saturation; it was partly an
  instrumentation gap.  Caught by a *parallel* review session
  (Claude, not Shardul) reading the executor against the
  patches — Phase 0 (commit `35ab4ed8d`) wires the handle.  The
  pattern that produced the bug was: kernel patches were
  authored and reviewed; executor changes were authored and
  reviewed; the *integration* between them was never
  end-to-end-tested against the actual coverage signal.

### 4.4 Strategic mis-framings

- **The original draft v0 framing was MIB-counter taxonomy** —
  patch-review trivia at a netdev altitude.  Rejected
  internally on 2026-05-14.  The current framing (BRF
  extension, AI-augmented description authoring, bugs as
  evidence) is what survived; it is also what the work
  *actually demonstrates*.  The lesson: a framing that doesn't
  match what the work demonstrates will not survive Q&A.
- **The first headline candidate was "AI-augmented syzlang
  authoring."**  Prior-art density (KernelGPT, NLSaber,
  SyzSpec, SyzGPT, ChatAFL, SyzMutateX, HarnessAgent) makes
  that a crowded space to lead with.  The current talk frames
  AI-augmented authoring as a *supporting tactic* and shifts
  the headline weight to the cryptographic-dependency tracking
  / state-carrier extension for transport-security state
  machines.  AI is honestly disclosed, not headlined.

---

## 5. What to adopt — the pattern

If you are extending BRF (or a comparable fuzzer with a
generator + executor + syscall-description separation) to a
new kernel transport-security subsystem, the pattern is:

1. **Lift the state-carrier pseudo-syscall family from BRF.**
   Identify the protocol's "token-equivalent" — the
   small piece of cryptographic state that gates the
   interesting code paths (MPTCP: 32-bit token; QUIC: ICID;
   tlshd: session handle).  The carrier struct lives in static
   executor memory; the syzlang resource is the index.  Every
   stateful pseudo-syscall takes the resource and uses the
   carrier-held state to satisfy the kernel's input validation
   while still letting the fuzzer mutate the *other* bytes.  The
   harness's job is to keep the kernel preconditions met; the
   fuzzer's job is to mutate the rest.  The case study's bug
   surfaced inside the alloc path that this pattern made
   reachable.

2. **AI-draft, human-verify, in tight loops.**  Draft the
   syzlang fragment + executor C, run the smoke test in the
   VM, read the kernel's coverage / MIB counters / dmesg /
   selftests output, fix the description if any of them
   disagree with the draft.  Estimate: one sibling
   pseudo-syscall per drafting session, **iff** there is a
   tight verification step that the human owns end-to-end.
   Drafts ship to the corpus only after VM verification.
   *AI failures are not optional information* — write them
   down: they are the credibility.

3. **Audit-drive the gap closure.**  Once the harness has
   plateaued (and it will, around ~50% of the subsystem's
   reachable surface), do a per-entry-point inventory against
   the existing pseudo-syscalls.  Rank the gaps by bug-value ×
   inverse-effort and close the cheap ones first.  Expect the
   audit to catch overclaims in the existing harness; ours
   caught two.  An audit is small and prescriptive; it is
   worth the day.

4. **kcov-instrument the gated paths.**  Coverage signal on the
   softirq / option-parsing / HMAC-validation code paths is
   invisible without it — a stateless fuzzer's kcov is
   task-context coverage only.  The instrumentation pattern
   (per-flow handle, scratch area, `BRF_*_KCOV_START` /
   `_STOP` macros, softirq context guard) is reusable.
   *Test the instrumentation end-to-end against the coverage
   signal, not just patch-by-patch* — our 6-week blind spot
   was a textbook integration failure.

5. **Continuous instrumentation on whichever quality knob the
   generator can silently degrade.**  For an eBPF struct_ops
   generator that is the verifier-accept rate; for a
   wire-mutation harness it would be the fraction of mutations
   that reach the parser; for a state-carrier harness it is
   the fraction of gated calls that pass input validation.
   Append-only stats file, host-side categorisation,
   per-VM-boot to survive `-snapshot` restarts.  Make
   generator changes attributable.

These are the prescriptive contributions.  None of them is
specific to MPTCP.

---

## 6. What it does **not** prove

Single-substrate, single-harness, two-bug data — across two
distinct MPTCP surfaces.  The two-surface property is what
genuinely strengthens; the rest of the limits are unchanged.
Honest limits:

- **It does not prove AI-augmented description authoring is
  faster than human authoring at the same level of rigor.**
  There is no controlled comparison.  Time-to-first-bug and
  time-to-second-bug were both driven at least as much by
  Shardul's existing MPTCP expertise (HMAC fixes A/B upstream,
  set_rcvbuf merge, RST_EMPTCP series in review) as by
  description productivity.  Finding 002 in particular sits
  downstream of a careful per-entry-point audit of
  `net/mptcp/` — the audit was the load-bearing pre-work, and
  audit authoring is not subtractable from the
  finding-discovery clock.
- **It does not prove the methodology produces bugs on
  schedule.**  Two bugs across ~6 weeks of harness build-out
  is *suggestive*, not predictive.  N=2 is small.  The
  bug-finding *rate* is not extrapolatable from two data
  points, and a third finding (or a barren stretch) is the
  observation that would change the picture.  The talk's
  framing is "the *method* produces harnesses that produce
  bugs"; the bug *rate* and *spacing* remain unknown.
- **What the second finding *does* strengthen.**  The
  two-surface property — finding 001 on the userspace-PM
  handlers, finding 002 on the kernel-PM admin handlers — is
  stronger than two findings on the same surface.  The
  harness's reachability is not concentrated in a single
  chokepoint, and the audit-driven gap closure that added the
  kernel-PM pseudo-syscalls produced a bug on its first
  qualifying run.  "Audit identifies a gap; closing the gap
  surfaces a bug" is a small piece of methodology validation
  in itself.
- **It does not prove portability beyond MPTCP.**  QUIC and
  tlshd extensions are planned but unbuilt; the state-carrier
  pattern's fit to those surfaces is a hypothesis, not a
  result.  QUIC's handshake key derivation is structurally
  similar enough that the pattern is *plausibly* portable;
  tlshd is a different shape (userspace-driven handshake) and
  may need a different carrier abstraction.
- **It does not include a controlled comparison against a
  kernel-only Syzkaller baseline.**  We have not run plain
  Syzkaller against the same kernel for the same time-budget
  with the same crash-detection plumbing.  Two findings on two
  surfaces does not change this — both findings sit on code
  paths that require state stateless Syzkaller cannot
  construct, so the "harness reaches what the baseline cannot"
  claim is demonstrable from reachability; but the
  "harness *finds more bugs than* the baseline" claim still
  requires the controlled run.  Both case studies flag this
  as a backfill before publication.  The prescriptive part
  of the talk does not depend on it.
- **It does not prove the absence of AI-generated bugs in the
  harness.**  Several latent defects shipped to the corpus
  before VM testing caught them (Section 4.2).  The talk's
  honest version is: AI-augmented authoring is fast and full
  of small defects; the human-VM-test loop is not optional.
- **It does not prove that the BPF struct_ops scheduler
  surface produces bugs.**  Phase 3 is implemented, the
  pipeline runs end-to-end, the verifier-accept rate is ~93%,
  total coverage gained +16%.  No crashes from the
  struct_ops/kfunc surface itself.  The reachability is
  demonstrated; the bug-finding from this surface is not.

If the talk's "we found a bug" line is the only takeaway the
audience receives, the audience has under-counted what the
work actually demonstrates and over-counted what one bug
proves.

---

## 7. Citation discipline (non-negotiable)

Every external artifact (talk, paper, blog post, lore message)
that references BRF must cite both:

- **BRF** — Hung, H. & Amiri Sani, A.  *BRF: eBPF Runtime
  Fuzzer.*  arXiv:2305.08782 (May 2023); ACM venue version at
  `papers/3643778.pdf` in this tree.
- **Syzkaller** — Vyukov, D. et al., `google/syzkaller`.

Funding acknowledgment for any presentation built on BRF: **NSF
#1763172, NSF #1846230, Google ASPIRE 2020** (Hung & Amiri Sani's
BRF was funded under these).

License: Apache 2.0.  `LICENSE`, `AUTHORS`, and `CONTRIBUTORS`
are preserved in this fork.  Mpiric's role is *extender*; we
never refer to BRF as ours, rename the project, or claim
authorship of BRF.  The harness extensions in this tree are
Mpiric's contribution; the pseudo-syscall + state-carrier
pattern is Hung & Amiri Sani's; the underlying coverage-guided
fuzzing engine is Syzkaller.

---

## 8. The honest summary

The methodology is a small, opinionated, prescriptive recipe:
**state-carrier pseudo-syscalls + AI-drafted descriptions +
strict VM verification + audit-driven gap closure + kcov on the
gated paths + continuous quality instrumentation**.  It is
demonstrably effective at reaching protocol-flow code that
stateless fuzzing cannot reach (25 pseudo-syscalls, +16%
coverage on the BPF flagship, ~93% verifier-accept on
generated struct_ops bodies, **two upstream-mergeable bugs on
two distinct surfaces of `net/mptcp/`** — userspace-PM
handlers and kernel-PM admin handlers).  It is honestly
limited by the single-substrate two-bug data shape it
currently has, by the absence of a controlled baseline, and —
most importantly — by the documented AI failure modes the
human verification step exists to catch (state-machine
imprecision and comment verbosity recurred across both
findings, which is a methodology observation rather than a
per-finding incident).

The talk's defensible posture: *extend a published academic
fuzzer with a methodology that demonstrably reaches new
surfaces, be honest about where AI breaks, and let the
prescriptive recipe stand on what it actually did rather than
on what one bug could be made to prove.*
