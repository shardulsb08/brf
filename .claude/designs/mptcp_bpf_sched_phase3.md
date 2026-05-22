# Phase 3 — fuzzing the MPTCP BPF struct_ops scheduler

Design doc for **Phase 3** of the MPTCP harness coverage-gap
backlog (audit gap 1).  Stage A (scoping) is complete and captured
here; Stages B/C/D are the implementation plan.

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

- **Stage 0** — kernel prerequisites — **DONE**.
- **Stage A** — generator scoping + design — **DONE** (this doc).
- **Stage B** — fixed-scheduler floor — **DONE** (2026-05-22; the
  smoke test passes — see `executor/bpf_progs/README.md`).
- **Stage C-minimal** — generator core — **IMPLEMENTED** (2026-05-22;
  see "Stage C-minimal — implemented" below).  BRF's program
  generator now generates and renders a fuzzed `mptcp_sched_ops`
  struct_ops scheduler.  VM/verifier verification is the follow-up.
- **Stage D** — wire generated schedulers into live fuzzing —
  **IMPLEMENTED** (2026-05-22; see "Stage D — implemented" below).
  The executor loads + registers + selects a generated scheduler and
  drives MPTCP traffic over it.  VM verification is the follow-up.
- **Stage C-full** — pending (arbitrary kfunc-call generation,
  non-empty `init`/`release`).

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

**Still pending (Stage C-full):**
- Arbitrary MPTCP kfunc-call generation (the other 7 kfuncs,
  iterator kfuncs, `bpf_for_each(mptcp_subflow, …)`).
- Generated non-empty `init`/`release` (e.g. `BPF_MAP_TYPE_SK_STORAGE`
  per-msk state, as in `mptcp_bpf_rr.c`).
- Verifier-pass iteration on generated bodies — the genuine risk;
  unknown until a VM run.  The Stage C-minimal body is deliberately
  conservative (writes confined to the two
  `bpf_mptcp_sched_btf_struct_access` fields, no kfunc-return
  dereferences beyond the null-checked `subflow`) to maximise the
  first-pass verifier-accept rate.

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

**Verification status:** Go-side host-verified is the parent's to
run (`go build ./prog/... && go build ./syz-manager`,
`go test ./prog/ -run StructOps`).  The executor C
(`common_brf_linux.h`) is VM-build-only and self-reviewed.  Live
verification — generated scheduler loads, registers under the
unique name, is selected, and `get_send` runs under
`drive_traffic` — is the VM follow-up, cleanest now that the
load/register/select path is executor-wired.

## Estimate

**~3-5 weeks of focused work.**  Stage B ships in days and is the
guaranteed-demoable floor.  Stage C is the genuine flagship and
where overrun risk lives.  **Not done by the 2026-06-01
submission** — the submission presents Phase 3 as the
flagship-in-progress; the **2026-07-13 talk** is the landing
target.

## Risks / open items

- `mutBpfProg` (`brf.go`) is a stub — BRF only generates fresh
  programs, never mutates them.  This caps coverage-guided
  exploration of the scheduler.  A post-Stage-D consideration.
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
