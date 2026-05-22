# Phase 3 — fuzzing the MPTCP BPF struct_ops scheduler

Design doc for **Phase 3** of the MPTCP harness coverage-gap
backlog (audit gap 1).  As of 2026-05-22: Stage 0/A/B are done and
verified; Stage C-minimal and Stage D are implemented, committed
and host-verified, and VM-verified by the fuzz run; Stage C-full is
implemented through **Stage 2b** -- Stage 1 (straight-line,
contract-aware kfunc-call generation), Stage 2a (subflow iterator +
non-empty init/release) and Stage 2b (generated free-form
`if/else`) -- and **host-verified** (build / test / clang).
Stage C-full is **VM-confirmed** (2026-05-22): the fuzz run
`run_20260522_151649` cleared the C-minimal/D ~20,690 cover
ceiling and reached ~24,000 (~+16%), with the C-full kfuncs and
the subflow iterator covered.  See the per-stage
Status section below.

Auto-loads (per repo `CLAUDE.md`) when work touches the BRF program
generator (`prog/brf*.go`) for the BPF struct_ops scheduler.

## Provenance and scope note

Phase 3 = **gap 1** of `mptcp_coverage_audit_2026-05-21.md` — "the
BPF flagship."  The audit ranked it #1: BRF's own eBPF-generation
strength pointed at a transport-state *write* primitive
(`bpf_mptcp_sched_btf_struct_access`, `net/mptcp/bpf.c:44`) plus 9
MPTCP kfuncs — a surface completely unhit by the rest of the
harness.  The other nine gaps (Phases 1/2/4 — gaps 2-10) are DONE
and committed; Phase 3 is the last item and the netdev talk's
defensible flagship.

**Scope note:** Phase 3 modifies BRF's *program generator*
(`prog/brf*.go`) — Hung + Sani's core artifact.  The task brief's
original scope said BRF-core changes are "Hung's call."  Pursuing
Phase 3 is a deliberate scope expansion (Shardul's decision,
2026-05-22) and a strong reason to send the drafted Hung+Sani
outreach email.  It remains an *extension* of BRF, not a fork
rename — citation discipline applies.

## Status (2026-05-22)

Three-state legend used below: **VERIFIED-WORKING** (host- and
VM-confirmed) / **IMPLEMENTED, VM-VERIFICATION IN PROGRESS**
(committed + host-verified; live behaviour unconfirmed) /
**NOT DONE**.

- **Stage 0** — kernel prerequisites — **DONE** (VERIFIED-WORKING).
- **Stage A** — generator scoping + design — **DONE** (this doc).
- **Stage B** — fixed-scheduler floor — **DONE, VERIFIED-WORKING**
  (2026-05-22; the smoke test passes — see
  `executor/bpf_progs/README.md`).
- **Stage C-minimal** — generator core — **DONE, VERIFIED-WORKING**
  (2026-05-22; see "Stage C-minimal — implemented" below).  BRF's
  program generator generates and renders a fuzzed
  `mptcp_sched_ops` struct_ops scheduler.  Host-verified (go
  build/test/vet clean; a rendered sample clang-compiles to a valid
  struct_ops `.o`) and **VM-confirmed**: the fuzz run
  `run_20260522_100632` accumulated coverage across the
  `bpf_mptcp_*` surface (see "VM run" below).
- **Stage D** — wire generated schedulers into live fuzzing —
  **DONE, VERIFIED-WORKING** (2026-05-22; see "Stage D —
  implemented" below).  The executor loads + registers + selects a
  generated scheduler and drives MPTCP traffic over it.
  Host-verified (go build clean; executor C reviewed; a -Werror
  build issue found + fixed) and **VM-confirmed** by the same run.
- **Stage C-full Stage 1** — straight-line, contract-aware
  kfunc-call generation — **DONE, host-verified** (see "Stage
  C-full — Stage 1 — implemented" below).  Generated `get_send`
  bodies now call six more common MPTCP kfuncs.
- **Stage C-full Stage 2a** — subflow iterator + non-empty
  `init`/`release` — **DONE, host-verified** (see "Stage C-full —
  Stage 2a — implemented" below).  `get_send` bodies may now emit
  the open-coded `bpf_iter_mptcp_subflow_*` iterator; `init` and
  `release` get generated `msk`-reachable bodies.
- **Stage C-full Stage 2b** — generated free-form `if/else` —
  **DONE, host-verified** (see "Stage C-full — Stage 2b —
  implemented" below).  `get_send` bodies may now emit
  `if (<cond>) { … } [else { … }]` over an in-scope scalar local,
  with `noReturn` branch bodies so every path still falls through to
  the fixed scheduling epilogue.  **This completes Stage C-full.**

With Stage 2b done, **Stage C-full is implemented through Stage 2b
and host-verified** (`go build` / `go vet` clean, `go test ./prog/
-run StructOps` passes, the regenerated sample clang-compiles).
Stage C-full is **VM-confirmed** (2026-05-22): the fuzz run
`run_20260522_151649` cleared the C-minimal/D ~20,690 cover
ceiling — see "C-full rebuild + run" below.  Phase 3's whole
implementation is now coverage-verified end to end.  Two honest
caveats remain: the verifier-accept *rate* on generated bodies is
not quantified from coverage alone — now **addressed** by the
verifier-accept instrumentation (see "Verifier-accept
instrumentation" under Stage D below): every struct_ops load
records ACCEPT/REJECT + the rejection reason to an append-only
stats file, tallied host-side — and a `kcov_remote_start_prealloc`
WARNING in the BRF coverage instrumentation (not an MPTCP/BPF bug)
is being fixed separately.

### VM run — first observations (2026-05-22)

First fuzz run on the Stage C/D build (`run_20260522_073845`):

- **25 syscalls enabled** — the 4 BPF pseudo-syscalls are now
  active on the BPF-enabled kernel (Stage 0).
- **patch 0006 holds** — 0 crashes over the run; the recurring
  `kcov_remote_start_prealloc` use-after-free has not recurred.
- **cover_filter gap (fixed).**  The syz-manager `cover_filter`
  was `^mptcp_.*` / `^__mptcp_.*` / `^subflow_.*` / `^__subflow_.*`
  — none match `net/mptcp/bpf.c`'s `bpf_mptcp_*` functions, so the
  Phase 3 surface was neither measured nor guiding the fuzzer.
  `^bpf_mptcp_.*` has been added to
  `mptcp_v01_first_kmemleak_debug.cfg`.  Any future Phase 3 run
  config must keep `^bpf_mptcp_.*` in the filter.
- **struct_ops generation CONFIRMED.**  With the widened filter,
  the run `run_20260522_100632` accumulated coverage across the
  whole `bpf_mptcp_*` surface — `bpf_mptcp_sched_reg` (a generated
  scheduler registered, i.e. passed the kernel verifier),
  `bpf_mptcp_sched_btf_struct_access` (the verifier checked a
  generated scheduler's writes), `bpf_mptcp_subflow_ctx` and
  `bpf_mptcp_sched_get_send` (a scheduler's `get_send` ran).  The
  Phase 3 chain — generate → compile → load → verify → register →
  run — is confirmed live (~2.5 h, 2026-05-22).  The
  verifier-accept *rate* is not quantified from coverage alone.
- **One non-kernel crash.**  The run logged one `panic: disabled
  syscall` — a syz-fuzzer Go panic (`checkDisabledCalls`), not a
  kernel bug and not a Phase 3 finding; a BRF fuzzer-robustness
  nit (once in 2.5 h).

### C-full rebuild + run (2026-05-22)

`run_20260522_100632` (the Stage C-minimal/D build) later broke
its ~18,600 plateau on its own — a stochastic breakthrough to a
new region took total cover to ~20,700.  That is the C-minimal/D
harness's ceiling, not a C-full result.

BRF was then rebuilt with Stage C-full (Stages 1/2a/2b) and the
fuzzer restarted 2026-05-22 ~15:17 — run `run_20260522_151649`.

**Verdict (2026-05-22, ~6.5 h in): C-full broke the plateau.**
The run re-attained the ~20,690 ceiling and held it ~1 h
(17:17–18:17), then at 18:37 jumped to 23,096 and kept climbing —
**cover ~23,983, ~+16% over the C-minimal/D ceiling.**  The cover
page confirms the C-full surface is live: the iterator kfuncs
`bpf_iter_mptcp_subflow_{new,next,destroy}`,
`bpf_mptcp_subflow_tcp_sock`, `bpf_mptcp_subflow_queues_empty`,
`mptcp_subflow_active`, `mptcp_set_timeout`, `mptcp_wnd_end` are
all covered.  Nuance: the filtered `net/mptcp` surface is ~flat
(43%) — the gain is mostly in the BPF struct_ops/verifier path
and the TCP/core code the kfuncs reach, i.e. deeper BPF/kfunc
coverage rather than more MPTCP-protocol coverage.

Crashes over the run (6): **none are findings** — a
`kcov_remote_start_prealloc` WARNING (×24) in the BRF coverage
instrumentation, reached via `mptcp_incoming_options`
(self-inflicted, not an MPTCP/BPF bug — being fixed separately);
the known `panic: disabled syscall` syz-fuzzer nit (×2); and a
syzkaller-suppressed empty report (×4).  No genuine kernel bug
surfaced.

### Stage C-minimal — implemented (2026-05-22)

Implemented in five pieces, all in `prog/`:

1. **struct_ops prog-type + ctxAccess plumbing.** The commented-out
   `BPF_PROG_TYPE_STRUCT_OPS` stub in `ProgTypeMap`
   (`brf_types.go`) is replaced with a real entry targeted at
   `mptcp_sched_ops` (`User`/`Kern`: `struct mptcp_sock`,
   `SecDefs`: `{"struct_ops", nil, false}`, empty `FuncProtos` —
   struct_ops uses kfuncs, not numbered helpers).  A
   `CtxAccessMap[BPF_PROG_TYPE_STRUCT_OPS]` entry documents the
   read/write surface: broad BTF-typed reads, writes only to
   `snd_burst` / `avg_pacing_rate`.  `mptcp_sock` is deliberately
   *not* added to `ctxStructsMap`, so `InitFromSrc`'s field-access
   loop is skipped (no nil-panic; the struct_ops renderer does not
   use that machinery).
2. **kfunc modelling.** `prog/brf_structops.go` adds `BpfKfunc`
   (a kfunc's `extern … __ksym;` decl) and `mptcpSchedKfuncs` — the
   two kfuncs the fixed `get_send` skeleton needs
   (`bpf_mptcp_subflow_ctx`, `mptcp_subflow_set_scheduled`).
   Arbitrary kfunc-call generation is Stage C-full, out of scope.
3. **`genStructOpsSource()`** — new renderer in
   `prog/brf_structops.go`.  Emits `vmlinux.h` +
   `bpf_helpers.h`/`bpf_tracing.h` includes, the kfunc externs, the
   three `SEC("struct_ops")` `BPF_PROG` callbacks
   (`init`/`release`/`get_send`), and the `SEC(".struct_ops.link")
   struct mptcp_sched_ops` instance.  `get_send` = fixed kfunc
   prologue + generated body + fixed kfunc epilogue.
4. **context-write generation.** `genStructOpsBody` generates a
   short randomised sequence of ctx reads, **ctx writes**
   (`msk->snd_burst = <val>;` / `subflow->avg_pacing_rate = <val>;`
   — the headline write primitive, confined to exactly the two
   `bpf_mptcp_sched_btf_struct_access`-writable fields), and
   arithmetic over the read locals; at least one write per body.
5. **wiring.** `writeCSource` (`brf_prog.go`) routes a struct_ops
   `BpfProg` to `genStructOpsSource`.  `GenBpfProg`
   (`brf_legacy.go`) adds `STRUCT_OPS` as a fourth rotation choice
   and dispatches to `genStructOpsBpfProg`, a separate path that
   leaves the `{LSM,SYSCALL,NETFILTER}` helper-call generator
   untouched.  `BpfProg` gains a `StructOps *StructOpsProg` field
   (gob-serialisable); `isStructOps()` is the discriminator.
   `MutBpfProg` re-rolls a struct_ops body rather than spinning on
   the empty `Calls` list.

Verification status: **host-verified 2026-05-22** (commits
`e894ba00d` + `d2f5aa96b`).  `go build ./prog/...` and `go vet
./prog/` are clean; `go test ./prog/ -run StructOps` passes (64
rendered schedulers; structural, write-target and gob-roundtrip
checks); the rendered sample
`executor/bpf_progs/generated_mptcp_sched_sample.bpf.c`
clang-compiles to a valid struct_ops `.o` (struct_ops +
.struct_ops.link + .BTF).  Remaining: generated schedulers
passing the kernel BPF verifier and registering on a live kernel
-- the VM follow-up, cleanest once Stage D wires executor-side
loading.

### Stage C-full — Stage 1 — implemented (2026-05-22)

Stage 1 of Stage C-full adds **straight-line, contract-aware
kfunc-call generation** to the `get_send` body.  Before this, every
generated scheduler called the same two kfuncs (the fixed
prologue/epilogue skeleton) and the harness coverage plateaued on
that fixed kfunc surface.  Stage 1 makes generated `get_send`
bodies additionally call **six more common MPTCP kfuncs**, each of
which reaches new kernel code.

All changes are in `prog/brf_structops.go` + `prog/brf_structops_test.go`.

**The kfunc set.**  The six kfuncs added to the model — every
straight-line entry of `bpf_mptcp_common_kfunc_ids` in
`net/mptcp/bpf.c` not already modelled:

| kfunc | return | args | contract |
|---|---|---|---|
| `bpf_mptcp_subflow_tcp_sock` | `struct sock *` | `const struct mptcp_subflow_context *` | KF_RET_NULL pointer — NULL-guard required |
| `bpf_sk_stream_memory_free` | `bool` | `const struct sock *` | KF_RET_NULL but scalar — no guard |
| `bpf_mptcp_subflow_queues_empty` | `bool` | `struct sock *` | scalar |
| `mptcp_subflow_active` | `bool` | `struct mptcp_subflow_context *` | scalar |
| `mptcp_set_timeout` | `void` | `struct sock *` | call for effect |
| `mptcp_wnd_end` | `__u64` | `const struct mptcp_sock *` | scalar |

Signatures are transcribed verbatim from `net/mptcp/bpf.c` (the
`__bpf_kfunc` definitions) and `net/mptcp/protocol.h`.
**Deliberately excluded** (Stage 2 / not usable):
`mptcp_pm_subflow_chk_stale` (KF_SLEEPABLE — not callable from the
non-sleepable `get_send`) and the three `bpf_iter_mptcp_subflow_*`
iterator kfuncs.

**CF1 — kfunc model.**  `BpfKfunc` gains `RetType`, `ArgTypes`,
`IsPtrRet` and `RetNull` (the latter mirrors the kernel
`KF_RET_NULL` flag).  `BpfKfunc.needsNullGuard()` encodes the
verifier-accurate rule: a NULL-check is required **only** for a
`KF_RET_NULL` *pointer* return (`IsPtrRet && RetNull`).
`KF_RET_NULL` on a scalar-returning kfunc (here
`bpf_sk_stream_memory_free`, registered `KF_RET_NULL` but returning
`bool`) only means the scalar may be 0 — no guard.

**CF2 — contract-aware generation.**  `genStructOpsBody` threads a
pool of **typed values**, seeded with the three values the fixed
prologue establishes (`msk` : `struct mptcp_sock *`; `msk->first` :
`struct sock *`; `subflow` : `struct mptcp_subflow_context *`) and
grown by every typed local (ctx-read, arithmetic, kfunc result).
A new `StructOpsStmtKfuncCall` statement kind is emitted only when
**every argument type of the kfunc is satisfiable from the pool**
(`pickKfuncArgs`; type matching strips `const`).  Per-return
contract: a void kfunc is emitted for effect; a scalar result is
bound to a local (and, if integer-like, made available to later
arithmetic); a `KF_RET_NULL` pointer result is bound to a local
and the local enters the pool **only after** the renderer emits the
mandatory `if (!local) return -1;` guard — so no later statement
can use an unguarded pointer.  The fixed prologue and the fixed
epilogue (`mptcp_subflow_set_scheduled(subflow, true); return 0;`)
are untouched, so `get_send` still schedules a subflow.

**CF3 — renderer.**  `genStructOpsSource` renders `KfuncCall`
statements (void call / result-bound call) and the immediate
`if (!local)` / `return -1;` guard for a `NullGuard` statement.
`StructOpsProg.usedKfuncIdxs()` filters the emitted `extern …
__ksym;` decls to exactly the kfuncs the scheduler references (the
two fixed-skeleton kfuncs plus every called kfunc).  The leftover
`fmt.Printf` debug dump was removed.

**Verifier-contract decisions.**
- `bpf_sk_stream_memory_free` is `KF_RET_NULL` in the kernel but
  returns `bool`; modelled `RetNull: true, IsPtrRet: false` so
  `needsNullGuard()` is false — no guard, matching the verifier.
- `bool` parameters (only `mptcp_subflow_set_scheduled`'s
  `scheduled`, which the fixed epilogue supplies) are additionally
  satisfiable by the literals `true` / `false`, so a generated
  bool argument is never blocked.
- Scope boundary: the only generated branching is the mandatory
  `KF_RET_NULL` NULL-check; `get_send` is otherwise straight-line.
  No subflow iterator, no non-empty `init`/`release` — Stage 2.

Verification status: **host-verified 2026-05-22** —
`go build ./prog/...` and `go vet ./prog/` clean.
`prog/brf_structops_test.go` is extended:
`TestStructOpsKfuncCalls` asserts kfunc calls are generated across
256 seeds, that every `KF_RET_NULL` pointer result is
NULL-checked immediately in both the model and the rendered C, and
that arguments are only typed in-scope values;
`TestStructOpsGobRoundTrip` is extended to confirm `KfuncCall`
statements (with `KfuncArgs` + `NullGuard`) gob-round-trip.
`go test ./prog/ -run StructOps` could not be **run** in the
implementing sandbox (the `sys/test/gen` descriptions are not
generated there — a pre-existing limitation that fails the
pre-existing `TestNotEscaping` identically); the test file
compiles clean (`go test -count=0`).  The regenerated sample
`executor/bpf_progs/generated_mptcp_sched_sample.bpf.c` exercises
all six new kfuncs incl. the `KF_RET_NULL` guard; the
clang-compile is the parent's follow-up.

### Stage C-full — Stage 2a — implemented (2026-05-22)

Stage 2a adds two pieces to the generator, both in
`prog/brf_structops.go` + `prog/brf_structops_test.go`.  Stage 2b
(generated free-form `if/else`) remains out of scope.

**Piece 1 — the subflow iterator.**  The three
`bpf_iter_mptcp_subflow_*` kfuncs (`bpf_mptcp_iter_kfunc_ids` in
`net/mptcp/bpf.c`) become one possible `get_send` body statement
kind, `StructOpsStmtSubflowIter`.  The BPF verifier enforces the
open-coded-iterator lifecycle `new → next* → destroy` on **every
path**, so the iterator is always rendered as the complete triple —
one atomic compound statement, never partial:

```
struct bpf_iter_mptcp_subflow itN;
struct mptcp_subflow_context *sfN;
bpf_iter_mptcp_subflow_new(&itN, (struct sock *)msk);
while ((sfN = bpf_iter_mptcp_subflow_next(&itN))) {
        /* short generated body over sfN */
}
bpf_iter_mptcp_subflow_destroy(&itN);
```

The idiom is modelled on the kernel selftest
`tools/testing/selftests/bpf/progs/mptcp_bpf_rr.c`, whose
`bpf_for_each(mptcp_subflow, subflow, (struct sock *)msk)` macro
expands to exactly this `new`/`next`/`destroy` shape — the `_new`
socket argument is the verbatim `(struct sock *)msk` (the MPTCP
`struct sock *`, a cast of the `msk` context).  The generator emits
the **explicit** three-kfunc form rather than the `bpf_for_each`
macro: BRF renders self-contained BPF C and the explicit form keeps
the generated lifecycle visible and auditable.

`bpf_iter_mptcp_subflow_next` is `KF_ITER_NEXT | KF_RET_NULL`, so
the `while` condition **is** the mandatory NULL-check; inside the
loop `sfN` is a valid `struct mptcp_subflow_context *` and feeds a
short generated read/write/arith/kfunc-call body (the same
`genStructOpsBody` machinery, re-seeded with `sfN` in the typed-value
pool and the `avg_pacing_rate` write field re-based onto `sfN`).

Key verifier-safety decision: the explicit idiom has **no**
`__attribute__((cleanup))` (which is how the `bpf_for_each` macro
auto-destroys the iterator).  A `return` from inside the `while`
loop would therefore skip `bpf_iter_mptcp_subflow_destroy` and the
verifier would reject the program for an unreleased iterator.  The
iterator loop body is consequently generated with a new
`bodyScope.noReturn` flag set, which excludes the only `return`-emitting
statement — a `KF_RET_NULL`-pointer kfunc call (its guard is
`if (!v) return -1;`).  Non-guarded scalar/void kfuncs are still
offered inside the loop.

**Piece 2 — non-empty init/release.**  `init` and `release` —
previously rendered with empty `{}` — get a generated body each.
They are `void BPF_PROG(..., struct mptcp_sock *msk)`: only `msk`
is in scope, no scheduling.  Their `bodyScope` (`initReleaseScope`)
seeds the pool with just `msk` / `msk->first`, restricts the
writable surface to `msk->snd_burst` (the only `msk`-reachable
writable field — `avg_pacing_rate` lives on a subflow, and there is
no `subflow` here), forbids the iterator, and sets `noReturn`
(these callbacks are `void`, so a `return -1;` would be invalid C).
`mptcp_subflow_set_scheduled` is structurally unreachable from
`init`/`release` — it needs a `struct mptcp_subflow_context *`,
which never enters the pool.

**Refactor.**  `genStructOpsBody` is parameterised by a `bodyScope`
(seed pool, resolved writable fields, `allowIter` / `requireWrite` /
`noReturn` flags, statement-count bounds) so the same generator
serves four surfaces: the top-level `get_send` body, an iterator
loop body, and the `init` / `release` bodies.  A shared `varId`
counter keeps every local across the whole callback (including
nested iterator loop bodies) uniquely named.  `StructOpsStmt` gains
`FieldAccessor` / `FieldCType` (a self-contained ctx-field lvalue —
context-correct even inside a loop where the subflow base local is
`sfN`, not the fixed `subflow`) and the iterator fields (`IterId`,
`IterSockExpr`, `IterBody`).  The renderer factors body rendering
into `renderBody` (recurses into a `SubflowIter`'s loop body at
`indent+"\t"`) and `renderSubflowIter`.  `usedKfuncIdxs` and the new
`usesSubflowIter` walk every body — `get_send` / `init` / `release`,
recursing into iterator loop bodies via `walkStmts` — so the emitted
`extern … __ksym;` set is exactly the referenced kfuncs; the three
iterator externs are emitted only when a body uses the iterator.

Verification status: **host-verified by self-review 2026-05-22** —
build/test/`go vet` could not be **run** in the implementing
sandbox (`Bash`/git denied; same pre-existing `sys/test/gen`
limitation as Stage 1).  Code self-reviewed for compile- and
verifier-correctness.  `prog/brf_structops_test.go` is extended:
`TestStructOpsSubflowIter` asserts the iterator is generated, is
always the complete `new → next* → destroy` triple in the rendered
C (call-site counts, well-formed `while`-condition, `_new`/`_destroy`
bracketing, all three externs present) and never appears in
`init`/`release`; `TestStructOpsInitReleaseBodies` asserts both
bodies are non-empty in model and rendered C and never call
`mptcp_subflow_set_scheduled`; `TestStructOpsGobRoundTrip` is
extended to recurse into `IterBody` and cover `InitBody`/`ReleaseBody`;
`TestStructOpsGenAndRender`'s write-lvalue check now also allows
`sfN->avg_pacing_rate`.  The regenerated sample
`executor/bpf_progs/generated_mptcp_sched_sample.bpf.c` exercises
the iterator and the non-empty `init`/`release`; the clang-compile
is the parent's follow-up.

### Stage C-full — Stage 2b — implemented (2026-05-22)

Stage 2b adds **generated free-form `if/else`** to the `get_send`
body generator and **completes Stage C-full**.  All changes are in
`prog/brf_structops.go` + `prog/brf_structops_test.go`.

**The statement kind.**  A new `StructOpsStmtIfElse` body statement
kind renders as

```
if (<cond>) {
        <if-body>
} [else {
        <else-body>
}]
```

`StructOpsStmt` gains five fields for it: `CondVar` / `CondOp` /
`CondVal` (the condition) and `IfBody` / `ElseBody` (the two branch
bodies, recursive `[]StructOpsStmt`).  `walkStmts` now recurses into
both branch bodies, so `usedKfuncIdxs` / `usesSubflowIter` and the
tests see the whole statement tree; the gob round-trip covers the
recursive `IfBody` / `ElseBody` path.

**The condition — scalar only.**  The condition is a simple boolean
expression over an **in-scope scalar local** — a ctx-read local, an
arithmetic local, or a scalar kfunc-return local (the generator
already tracks exactly these in its `readVars` set).  `CondOp` is
one of `>`, `<`, `==`, `!=`, `&` against a 16-bit fuzzer constant,
or the empty string for a bare truthiness test `if (s0)`.  Pointers
are **never** branched on: prologue and kfunc-return pointers are
already NULL-guarded, so a pointer condition would be redundant or
constant-true.  When no scalar local is yet in scope the chosen
`if/else` falls back to a ctx read (which produces one), the same
fallback pattern Arith uses.

**Branch bodies — `noReturn`, the key correctness lever.**  Each
branch body is generated with the existing `genStructOpsBody`
machinery under a `bodyScope` with **`noReturn` set**.  With no
`return` in any branch, every path falls through to the fixed
scheduling epilogue (`mptcp_subflow_set_scheduled(subflow, true);
return 0;`), so `get_send` always schedules ≥ 1 subflow — no
per-path scheduling analysis is needed.  `noReturn` already existed
(Stage 2a, for the iterator loop body) and already excludes the
only `return`-emitting statement, a `KF_RET_NULL`-pointer kfunc
call; that exclusion now also applies inside a branch.  Stage-1
scalar/void kfunc calls and the Stage-2a iterator remain available
as branch-body statements (`allowIter` carries the enclosing
scope's setting, so a top-level branch may still contain the
iterator).

**Block scoping — branch-local variables do not leak.**  The
typed-value pool is block-scoped: each branch body is a separate
`genStructOpsBody` call with its **own** copied `pool` / `readVars`,
seeded from the values in scope at the `if` but never feeding new
locals back into the enclosing function's pool.  That is exactly C
block scope — a local declared inside a branch renders inside the
branch's `{ }` and is unreachable after the branch closes.  The
`else` branch is generated from a fresh copy of the same seed
scope, so its locals are independent of the `if` branch.

**Nesting cap.**  `bodyScope` gains `allowIf` (permits the new
statement kind) and `depth` (current nesting depth); a branch scope
is `depth+1`.  `ifElseMaxDepth` (= 2) caps it — at the cap `allowIf`
is effectively cleared so the deepest branch is straight-line.
Together with the existing per-body `minStmt`/`maxStmt` bounds
(branch bodies are 1–3 statements) this keeps a generated
`get_send` body well within the BPF verifier's instruction- and
branch-complexity limits.  `init`/`release` keep `allowIf` false —
they stay straight-line; iterator loop bodies likewise.

**Refactor.**  `genStructOpsBody`'s statement-kind draw was changed
from an `r.Intn(nKinds)` over a contiguous enum range to an
explicit `kinds` slice built per scope (the four straight-line
kinds always, `SubflowIter` when `allowIter`, `IfElse` when
`allowIf && depth < ifElseMaxDepth`) — the iterator and `if/else`
are independently gated, which the old contiguous draw could not
express.  `genIfElse` builds one `IfElse` statement; `renderIfElse`
renders it (recursing into `renderBody` at `indent+"\t"` for each
branch).

Verification status: **host-verified 2026-05-22** —
`go build ./prog/...` and `go vet ./prog/` clean;
`go test ./prog/ -run StructOps` passes all seven StructOps tests.
`prog/brf_structops_test.go` gains `TestStructOpsIfElse`: across 256
seeds it asserts an `if/else` (and an `if/else` with an `else`) is
generated, the rendered C is brace-balanced and properly nested, no
branch body emits a `return` (model and rendered C), the condition
tests a declared scalar local (never a pointer), generated nesting
never exceeds `ifElseMaxDepth`, and — via `assertNoScopeLeak`, a
brace-scope walk of the rendered C — no branch-local variable is
referenced after its block closes.  `TestStructOpsGobRoundTrip` now
also covers a seed that exercises `if/else`.  The regenerated
sample `executor/bpf_progs/generated_mptcp_sched_sample.bpf.c`
exercises a generated `if/else` (an `if`-branch containing the
subflow iterator, an `else`-branch with a kfunc call and a ctx
write); it clang-compiles with the README recipe.

## What it is

MPTCP has a pluggable packet scheduler — `struct mptcp_sched_ops`
(`include/net/mptcp.h:104`): `get_send` / `get_retrans` (pick a
subflow) + `init` / `release`.  The kernel lets that scheduler be
supplied as an eBPF **struct_ops** program; `net/mptcp/bpf.c`
registers `mptcp_sched_ops` as a BPF struct_ops and exposes 9
MPTCP kfuncs callable only from such a program.  Phase 3 makes BRF
**generate, load, and fuzz** such a scheduler.

## Stage 0 — kernel prerequisites (DONE)

- **patch 0006** (`faedd54304af9`, kernel patch `0006-*`) — kcov
  scratch-area UAF fix.  Not Phase-3-specific but required for a
  stable BPF-enabled kernel.
- **BPF kernel config** — `tools/configs/samples/brf_mptcp_harness.config`
  now sets `CONFIG_BPF_SYSCALL` / `BPF_JIT` / `DEBUG_INFO_BTF` plus
  the BRF eBPF config set.  `DEBUG_INFO_BTF` needs `pahole` (host
  has v1.30).  `net/mptcp/bpf.c` builds with `BPF_SYSCALL` + `MPTCP`.
- **clang path** — `prog/brf.go` now resolves `clang-21` via PATH
  (commit `50577fe00`); the host has clang-21 v21.1.0.  No custom
  LLVM build is needed — BRF only ever wanted a *recent* stock
  clang (confirmed from the fork README / `setup_brf.sh`).
  **Needs a BRF rebuild to take effect.**
- **vmlinux.h** — must be regenerated from the now-BTF-enabled
  kernel into `/mnt/brf_work_dir` (a Stage B step — see below).

## How BRF's program generator works (Stage A finding)

Pipeline: `newBpfProg` → `NewBpfProg(progType,…)` builds a `BpfProg`
model (helper/kfunc `Calls`, `Maps`, `Structs`, context vars, a
return value) → `genCSource()` renders it to `.c` → `compileBpfProg`
runs `clang-21` → `.o` (+ a `.gob` of the Go model), all under
`/mnt/brf_work_dir`.

Every generatable program type is **one table entry** —
`ProgTypeMap[enum] = &BpfProgType{Name, User, Kern (context type),
SecDefs, FuncProtos, Helpers, ctxAccess}` (`prog/brf_types.go:504`):

- `SecDefs` — `{SEC-prefix, SecDefGenFunc, sleepable}`
  (`prog/brf_legacy.go:12`).  The gen func is *tiny* — `GenLsmEntry`
  picks one of 7 LSM hook names; `GenBPFTrampoline` returns a single
  string (`brf_types.go:1492-1508`).  It picks the **attach
  target**, nothing more.
- `FuncProtos` / `Helpers` — the helper/kfunc set.
- `ctxAccess` (`CtxAccessMap`, `brf_types.go:1510`) — which context
  fields the program may read/write.

The program *body* is generated generically by `NewBpfProg`
(`brf_legacy.go:305`) from that table entry.  **Key finding: adding
a program type is mostly filling in a table entry, not writing a
generator.**

## The struct_ops gap (Stage A finding)

`BPF_PROG_TYPE_STRUCT_OPS` is stubbed in **three places**:

1. `ProgTypeMap` — the entry is **commented out**
   (`brf_types.go:1302-1311`); its `SecDef` gen func is `nil` and
   `FuncProtos` is empty (`//XXX: why missing this prog type`).
2. `BPF_MAP_TYPE_STRUCT_OPS` — present in the map-type table but
   `continue`-skipped in two spots (`brf_legacy.go` ~1064, ~1161).
3. No `CtxAccessMap` entry — no context model.

BRF's authors sketched struct_ops and bailed.

## Design — targeted, not generic

Reviving struct_ops **generically** (for arbitrary kernel structs
— `tcp_congestion_ops`, `sched_ext`, …) is the L+ trap the authors
abandoned.  **We do not do that.**  Phase 3 makes BRF generate
struct_ops programs **specifically for `mptcp_sched_ops`** — one
struct, 2-4 callbacks, a known kfunc set, a small known context
(`struct mptcp_sock *`).  That reuses BRF's body generator
wholesale; the new code is table entries + one scaffold branch.

### Stage B — load plumbing + the lite floor (DONE 2026-05-22)

Implemented in `executor/bpf_progs/` (`mptcp_sched.bpf.c` +
`test_mptcp_bpf_sched.c`); build/run procedure and verified
output in `executor/bpf_progs/README.md`.  Original plan:

- Hand-write one fixed `mptcp_sched.bpf.c` — a minimal valid
  scheduler (`get_send`/`get_retrans` returning a subflow), with
  the `SEC(".struct_ops") struct mptcp_sched_ops` instance.
- Regenerate `/mnt/brf_work_dir/vmlinux.h` from the BTF-enabled
  kernel (`bpftool btf dump file <vmlinux> format c`).
- Compile it with `clang-21` (the existing `compileBpfProg` flags).
- Load + register via libbpf — already linked into `syz-executor`
  (`-lbpf`); `bpf_object__open` + `bpf_map__attach_struct_ops`.
- Select it with the `scheduler` sysctl — `syz_mptcp_set_sysctl`
  (gap 6, `MPTCP_SYSCTL_SCHEDULER`).
- This proves the kernel path end to end and **is the Phase-3-lite
  floor** — a guaranteed-demoable result even if Stage C overruns.

### Stage C — the generator core (~2-3 weeks, the bulk + the risk)

**Stage C-minimal is implemented** — see "Stage C-minimal —
implemented" under Status above for the as-built five-piece
breakdown.  The original plan, for reference:

- Uncomment / add the `BPF_PROG_TYPE_STRUCT_OPS` entry in
  `ProgTypeMap`, **targeted at `mptcp_sched_ops`**.  *(As built: a
  real entry; `SecDefs` `{"struct_ops", nil, false}` — the callback
  names are fixed by the renderer so no `SecDefGenFunc`; kfuncs are
  modelled separately as `BpfKfunc`, so `FuncProtos` is empty.)*
- Add a `CtxAccessMap` entry — the read/write surface. *(As built:
  `CtxAccessMap[BPF_PROG_TYPE_STRUCT_OPS]` records broad reads +
  the two writable fields.)*
- Render the `SEC(".struct_ops.link") struct mptcp_sched_ops`
  instance. *(As built: a dedicated `genStructOpsSource` renderer
  rather than a branch in `genCSource` — the struct_ops C shape is
  different enough that a separate renderer is cleaner and leaves
  `genCSource` untouched.)*
- Generate the callback bodies. *(As built: `genStructOpsBody`
  generates the `get_send` body — ctx reads/writes + arithmetic;
  `init`/`release` are empty for Stage C-minimal.)*

**Stage C-full Stage 1 is implemented** — straight-line,
contract-aware calls to the six common straight-line kfuncs; see
"Stage C-full — Stage 1 — implemented" under Status above.

**Stage C-full Stage 2a is implemented** — the subflow iterator and
generated non-empty `init`/`release`; see "Stage C-full — Stage 2a
— implemented" under Status above.

**Stage C-full Stage 2b is implemented** — generated free-form
`if/else`; see "Stage C-full — Stage 2b — implemented" under Status
above.  **Stage C-full is now complete through Stage 2b.**

**Still pending after Stage C-full (future work, not Stage 2b):**
- A richer `init`/`release` surface (e.g. `BPF_MAP_TYPE_SK_STORAGE`
  per-msk state, as in `mptcp_bpf_rr.c`) — Stage 2a's `init`/`release`
  bodies are reads/writes/arith/kfunc-calls over `msk` only.
- Verifier-pass iteration on generated bodies — the genuine risk;
  unknown until a VM run.  The bodies are deliberately
  conservative (writes confined to the two
  `bpf_mptcp_sched_btf_struct_access` fields; every `KF_RET_NULL`
  pointer immediately NULL-checked; the iterator always the complete
  `new → next* → destroy` triple with no `return` inside the loop;
  generated `if/else` branch bodies carry `noReturn` so every path
  reaches the scheduling epilogue, and nesting is capped at depth 2;
  only typed in-scope values passed as kfunc arguments) to maximise
  the first-pass verifier-accept rate.

### Stage D — wire + fuzz — implemented (2026-05-22)

Stage D wires Stage C-minimal's *generated* struct_ops schedulers
into live fuzzing: the executor loads + registers + selects each
generated scheduler and drives MPTCP traffic so the kernel runs its
`get_send`.  Implemented in four pieces (D1–D4); no new
pseudo-syscall was needed — extending `syz_bpf_prog_attach` covered
it.

**D1 — executor struct_ops load / attach / select**
(`executor/common_brf_linux.h`).  `syz_bpf_prog_open` /
`syz_bpf_prog_load` are object-type-agnostic and reused as-is.
`syz_bpf_prog_attach` gained a struct_ops branch:
`brf_find_struct_ops_map` detects a `BPF_MAP_TYPE_STRUCT_OPS` map via
`bpf_object__for_each_map`; if present, `brf_struct_ops_attach` calls
`bpf_map__attach_struct_ops` (register) and keeps the returned
`bpf_link` alive in `struct_ops_link_list[]` (parallel to
`bpf_object_list[]`); then `brf_struct_ops_select` writes the
scheduler name to `/proc/sys/net/mptcp/scheduler`.  The per-program
callback-attach loop is skipped for struct_ops objects.  Logic ports
`executor/bpf_progs/test_mptcp_bpf_sched.c`.

**D2 — generator → syz-program wiring** (`prog/brf.go`).
`GenPrologue` gained an `isStructOps()` branch → `genStructOpsPrologue`,
which emits `syz_bpf_prog_open` → `_load` → `_attach` (struct_ops) →
`syz_mptcp_pair_init` → `syz_mptcp_drive_traffic`.  open/load/attach
reuse `genBpfProgOpenCall` / `LoadCall` / `AttachCall`; the two MPTCP
calls are built by new `genMptcpPairInitCall` / `genMptcpDriveTrafficCall`
helpers that generate every arg generically and thread the
`mptcp_pair` resource from `pair_init`'s `Ret` into `drive_traffic`
(the same pattern `genBpfProgTestRunCall` uses for the load fd).  The
regular LSM/SYSCALL/NETFILTER prologue path is untouched.  There is
no `BPF_PROG_TEST_RUN` for a struct_ops program — the callbacks run
from the MPTCP stack under traffic.

**D3 — scheduler-name uniqueness.**  `mptcp_register_scheduler` is
kernel-global; concurrent procs (and successive struct_ops programs
within one proc, each keeping its `bpf_link` alive) must not register
the same name.  Mechanism: the executor patches the
`mptcp_sched_ops.name[]` member of the struct_ops map's *initial
value* — in `syz_bpf_prog_load`, **before** `bpf_object__load`
(libbpf folds the initial value into the kernel struct_ops value at
load time, so a post-load patch would be ignored).  The original
name is located by searching the initial-value blob for the
generator's `brf_<hash>` string (which equals the libbpf map name
and occurs exactly once, at `name[]` — no BTF walking).  The patched
name is `brf_<11 hex>` filling `MPTCP_SCHED_NAME_MAX` exactly:
44 bits = `(getpid()&0xFFFFFF)<<20 | counter&0xFFFFF` — pid bits
distinguish concurrent procs, a per-proc monotonic counter
distinguishes programs within a proc.  The chosen name is stashed in
`struct_ops_name_list[]` so `syz_bpf_prog_attach` selects exactly
what was registered.  The generator (`brf_structops.go`) is
unchanged — `SchedName` is still the search key.

**D4 — work-dir pruning** (`prog/brf.go`).  `pruneWorkDir`, called
at the top of `genSeedBpfProg`, keeps `/mnt/brf_work_dir` under a
soft cap (`brfWorkDirCapBytes`, 4 GiB) by deleting the oldest
`prog_*.{c,o,gob}` artifacts first.  Only the generator's own
`prog_*` / `test_prog.*` files are swept — `vmlinux.h` and the
hand-written `executor/bpf_progs/` scaffold are never touched.
Oldest-first means the most recently generated artifacts (the ones
a live corpus program is most likely to still reference by path)
survive longest.  Best-effort: any error logs and stops; generation
never fails.  The generator is not frozen.

**Verification status:** **host-verified and VM-verified
2026-05-22**.  Go side is build-clean (`go build ./prog/... &&
go build ./syz-manager`) and `go test ./prog/ -run StructOps`
passes; the executor C (`common_brf_linux.h`) was reviewed and a
`-Werror=stringop-truncation` build issue found + fixed (commit
`22834b91a`).  Live verification: the fuzz run
`run_20260522_100632` accumulated coverage across the
`bpf_mptcp_*` surface — generated schedulers load, the kernel
verifier processes them, they register and `get_send` runs.  The
verifier-accept *rate* is not yet quantified.

### Verifier-accept instrumentation (2026-05-22)

The verifier-accept *rate* — what fraction of generated
`mptcp_sched_ops` schedulers the kernel BPF verifier accepts, and
*why* the rest are rejected — is the missing measurement that makes
the generator-tuning loop measure-driven.  Coverage alone does not
quantify it.  This instrumentation closes that gap: every
struct_ops load records its verifier outcome to an append-only
stats file, continuously, every run.

Three pieces, all gated **struct_ops only** (`brf_find_struct_ops_map`)
— regular BPF loads are untouched.

**VI1 — outcome recording + stats file**
(`executor/common_brf_linux.h`).  `syz_bpf_prog_load` already
detects a struct_ops object via `brf_find_struct_ops_map`; that
result is now also kept in a local `is_struct_ops` flag.  Around
the existing `bpf_object__load(obj)` call — *the* verifier step —
`brf_verif_record()` appends one line per struct_ops load to
`/mnt/brf_work_dir/brf_verifier_stats.log` (fallback
`/tmp/brf_verifier_stats.log` when the work dir is absent).  The
file is opened `O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC` and each
record is emitted as a SINGLE bounded `write()` (≤ 511 bytes, far
under `PIPE_BUF` = 4 KiB) so concurrent writes from many executor
procs interleave atomically.  The file accumulates over the whole
run.  Instrumentation is pure observation — it never alters the
load path or its return value, and every failure (open/write
error) is silently swallowed.

Record format, one line each:

```
<unix-ts> <pid> ACCEPT
<unix-ts> <pid> REJECT <sanitised verifier-log line>
```

**VI2 — verifier-log capture**
(`executor/common_brf_linux.h`).  A `libbpf_set_print` callback
(`brf_verif_libbpf_print`) buffers libbpf's most recent
`LIBBPF_WARN` message into a file-scope static; on a struct_ops
`bpf_object__load` failure that buffer holds the verifier's
rejection text.  The callback is installed once, lazily, on the
first struct_ops load.  `brf_verif_record` folds the first line of
the captured text into the `REJECT` record (`brf_verif_sanitize`
strips newlines / control chars and caps the length at 320 bytes
so the whole record stays bounded and one line).  The
`libbpf_set_print` route was chosen over `bpf_object__open`'s
`kernel_log_buf` open-opts: `syz_bpf_prog_open` (a separate
function) does the open, so the open-opts route would mean
threading a buffer across functions, whereas the print callback is
a single self-contained install with no change to the open path.

**VI3 — host-side tally script**
(`executor/bpf_progs/brf_verifier_tally.sh`).  Reads one or more
stats files (defaults to the guest path + fallback; accepts
multiple per-VM files as arguments) and prints total struct_ops
loads, accept / reject counts, accept rate %, and a
rejection-reason histogram.  Reason categorization lives **here**,
host-side — `categorize_reason()` buckets the raw verifier-log
lines by pattern (unreleased reference, invalid memory access,
pointer bounds, bad return value, unchecked NULL, program too
large, unknown kfunc, BTF/type mismatch, disallowed context write,
…), tunable without an executor rebuild.

**Scope boundary.**  Surfacing is deliberately the append-only
file, not a syz-manager stat line — wiring the rate into
syz-manager's stats plumbing is noted as future polish.

**Verification status:** **host-reviewed 2026-05-22** — the
executor C cannot be host-built (the executor build is VM-only),
so the C change (~110 lines incl. comments in `common_brf_linux.h`)
was self-reviewed for C++-safety (explicit casts, file-scope
statics, callback signature matching `libbpf_print_fn_t` exactly),
bounded buffers, and the no-disturb-on-failure property.  Human
follow-up: rebuild BRF, run the fuzzer, then run
`brf_verifier_tally.sh` against the accumulated
`brf_verifier_stats.log` to read the accept rate and
rejection-reason histogram.

## Estimate

**~3-5 weeks of focused work.**  As of 2026-05-22: Stages B,
C-minimal and D are done and VM-verified — the Phase 3 pipeline
runs end-to-end; Stage C-full is not done.  The submission
(2026-06-01) can present Phase 3 as a working flagship; the
**2026-07-13 talk** is the landing target.  Remaining overrun risk
lives in Stage C-full and in the generated-body verifier-accept
rate.

## Risks / open items

- `mutBpfProg` (lowercase, `brf.go`) is a dead stub; the real
  mutation function is `MutBpfProg` (capital, `brf_legacy.go`),
  which BRF does call — and `MutBpfProg` re-rolls a struct_ops body
  rather than spinning on the empty `Calls` list (Stage C-minimal
  piece 5).  So BRF *does* mutate generated schedulers; the open
  item is the depth of that mutation, a post-Stage-D consideration.
- `/mnt/brf_work_dir` disk growth — **addressed in Stage D4**:
  `pruneWorkDir` sweeps oldest `prog_*` artifacts under a 4 GiB soft
  cap each generation.  The generator is not frozen.
- Verifier-pass rate on generated struct_ops bodies — still unknown
  until a VM run.  The fixed Stage B scheduler de-risks the
  load/registration path; Stage D wires the generated path so a VM
  run now exercises generated bodies end to end.

## Key files

BRF generator: `prog/brf.go` (orchestrator, `compileBpfProg`),
`prog/brf_prog.go` (`BpfProg`, `genCSource`, `writeCSource`),
`prog/brf_types.go` (`ProgTypeMap`, `CtxAccessMap`, the struct_ops
stub at 1302), `prog/brf_legacy.go` (`SecDef`/`BpfProgType` defs,
`NewBpfProg`, the struct_ops-map skips).

Kernel: `net/mptcp/bpf.c` (the `mptcp_sched_ops` struct_ops + 9
kfuncs), `net/mptcp/sched.c` (scheduler dispatch),
`include/net/mptcp.h` (`struct mptcp_sched_ops`).

Harness: `executor/common_brf_linux_mptcp.h`,
`sys/linux/socket_mptcp_crypto.txt`, `executor/bpf/` (bundled
libbpf headers).
