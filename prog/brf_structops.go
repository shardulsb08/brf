package prog

// BRF Phase 3, Stage C-full -- generation and rendering of a fuzzed
// MPTCP `mptcp_sched_ops` BPF struct_ops packet scheduler.
//
// This file is deliberately self-contained: the generic helper-call
// generator (`genBpfHelperCall`, `genCSource`) renders an attached
// program with a single `SEC(...) int func(ctx)` shape and a flat
// `p.Calls` list.  A struct_ops scheduler has a different shape -- two
// `void` callbacks, one `int` callback, and a `SEC(".struct_ops.link")`
// map instance -- so it gets its own model and its own renderer rather
// than overloading the helper-call path.  The {LSM,SYSCALL,NETFILTER}
// generator is untouched.
//
// Scope (Stage C-minimal): the `get_send` callback is a FIXED kfunc
// prologue/epilogue skeleton (`bpf_mptcp_subflow_ctx` ->
// `mptcp_subflow_set_scheduled`) wrapped around a BRF-generated body of
// context reads, context *writes*, and arithmetic.  The two writable
// fields are exactly those accepted by `bpf_mptcp_sched_btf_struct_access`
// in net/mptcp/bpf.c: `struct mptcp_sock.snd_burst` and
// `struct mptcp_subflow_context.avg_pacing_rate`.
//
// Scope (Stage C-full, Stage 1): the generated body additionally emits
// straight-line, contract-aware calls to six more common MPTCP kfuncs
// (`bpf_mptcp_common_kfunc_ids` in net/mptcp/bpf.c).  Each call is
// generated only when every argument type is satisfiable from the typed
// values in scope (`msk`, `msk->first`, `subflow`, and earlier
// kfunc/ctx-read locals); a KF_RET_NULL pointer result is bound to a
// local and immediately NULL-checked before any use; a scalar result is
// bound to a local usable in later arithmetic; a void kfunc is emitted
// for effect.  No generated branching beyond the mandatory KF_RET_NULL
// guards.
//
// Scope (Stage C-full, Stage 2a): two additions.  (1) The subflow
// iterator -- the three `bpf_iter_mptcp_subflow_*` kfuncs
// (`bpf_mptcp_iter_kfunc_ids` in net/mptcp/bpf.c) -- becomes one
// possible `get_send` body statement kind.  It is ALWAYS rendered as the
// complete, verifier-required `new -> next* -> destroy` triple (an
// atomic compound statement, never partial): an open-coded iterator
// declaration, a `while ((sfN = ..._next(&it)))` loop whose condition is
// the KF_RET_NULL NULL-check, and the mandatory `..._destroy(&it)`.  The
// loop body is a short generated read/write/arith/kfunc-call sequence
// over the loop variable `sfN`.  (2) `init`/`release` -- previously
// empty `{}` -- get a generated `msk`-reachable body (reads/writes/arith
// and `msk`-satisfiable kfunc calls; never `mptcp_subflow_set_scheduled`
// -- those callbacks do not schedule).
//
// Scope (Stage C-full, Stage 2b): generated free-form `if/else`.  An
// `if (<cond>) { <branch> } [else { <branch> }]` statement kind is added
// to the `get_send` body generator.  The condition is a simple boolean
// expression -- a comparison / bit-test against a fuzzer constant or the
// truthiness of an in-scope SCALAR local (never a pointer: prologue and
// kfunc-return pointers are already NULL-guarded, so a pointer condition
// is redundant or constant-true).  Each branch body is generated with the
// existing body machinery under a `bodyScope` with `noReturn` SET: with no
// `return` in any branch every path falls through to the fixed scheduling
// epilogue, so `get_send` always schedules >= 1 subflow -- no per-path
// scheduling analysis is needed.  A KF_RET_NULL-pointer kfunc (its guard
// emits a `return`) is therefore not offered inside a branch body, the
// same exclusion the iterator loop body applies.  Branch-local variables
// are block-scoped: each branch is its own generated statement slice with
// its own typed-value pool, so a local declared inside a branch is never
// referenced after the branch closes.  Nesting depth and total statement
// count are capped so generated programs stay within the verifier's
// instruction/complexity limits.

import (
	"bytes"
	"fmt"
)

// schedNameMax mirrors MPTCP_SCHED_NAME_MAX (include/net/mptcp.h); the
// rendered `.name` must fit.
const schedNameMax = 16

// BpfKfunc models a kernel kfunc callable from a struct_ops program.
// BRF models BPF *helpers* (BpfHelper); kfuncs are a distinct ABI --
// they are plain extern symbols resolved via `__ksym` rather than the
// numbered helper-id mechanism -- so they need their own tiny model.
//
// CDecl is the full `extern ... __ksym;` declaration text.  The
// remaining fields carry enough to *generate a correct call*: the
// return type, the argument types, and the verifier contract on the
// return value.
//
// Argument and return types are stored as plain C type strings (with
// any `const` qualifier kept verbatim from the kernel signature).
// Type matching in the call generator strips `const` -- a `struct
// sock *` value satisfies a `const struct sock *` parameter.
type BpfKfunc struct {
	Name  string
	CDecl string
	// RetType is the C type of the return value; "" means void.
	RetType string
	// ArgTypes are the C types of the parameters, in order.
	ArgTypes []string
	// IsPtrRet is true when the return value is a pointer.
	IsPtrRet bool
	// RetNull mirrors the kernel KF_RET_NULL flag.  The verifier
	// requires a NULL-check before use ONLY for a *pointer* return
	// (IsPtrRet && RetNull); KF_RET_NULL on a scalar-returning kfunc
	// just means the scalar may be 0 -- no guard is needed.
	RetNull bool
}

// needsNullGuard reports whether a kfunc's return value must be bound
// to a local and NULL-checked before any use.  This is precisely the
// verifier rule for a KF_RET_NULL *pointer* return.
func (kf *BpfKfunc) needsNullGuard() bool {
	return kf.IsPtrRet && kf.RetNull
}

// mptcpSchedKfuncs are the kfuncs the get_send body may use.
// net/mptcp/bpf.c registers MPTCP kfuncs via `bpf_mptcp_common_kfunc_ids`
// and `bpf_mptcp_iter_kfunc_ids`.  Modelled here:
//
//   - the two the FIXED prologue/epilogue needs
//     (`bpf_mptcp_subflow_ctx`, `mptcp_subflow_set_scheduled`);
//   - the six straight-line common kfuncs the Stage C-full Stage 1
//     call generator draws on.
//
// The three `bpf_iter_mptcp_subflow_*` iterator kfuncs are modelled
// separately (`mptcpSubflowIterKfuncs`) -- they are not callable
// individually by the kfunc-call generator; the renderer emits the
// verifier-required `new -> next* -> destroy` triple as one atomic unit.
//
// Deliberately EXCLUDED: `mptcp_pm_subflow_chk_stale` (KF_SLEEPABLE --
// not callable from the non-sleepable `get_send`).
//
// Signatures are transcribed verbatim from net/mptcp/bpf.c (the
// `__bpf_kfunc` definitions) and net/mptcp/protocol.h.
var mptcpSchedKfuncs = []BpfKfunc{
	{
		Name: "bpf_mptcp_subflow_ctx",
		CDecl: "extern struct mptcp_subflow_context *\n" +
			"bpf_mptcp_subflow_ctx(const struct sock *sk) __ksym;",
		RetType:  "struct mptcp_subflow_context *",
		ArgTypes: []string{"const struct sock *"},
		IsPtrRet: true,
		RetNull:  true, // BTF_ID_FLAGS(..., KF_RET_NULL)
	},
	{
		Name: "mptcp_subflow_set_scheduled",
		CDecl: "extern void\n" +
			"mptcp_subflow_set_scheduled(struct mptcp_subflow_context *subflow,\n" +
			"\t\t\t    bool scheduled) __ksym;",
		RetType:  "", // void
		ArgTypes: []string{"struct mptcp_subflow_context *", "bool"},
	},
	{
		// __bpf_kfunc struct sock *
		// bpf_mptcp_subflow_tcp_sock(const struct mptcp_subflow_context *subflow)
		Name: "bpf_mptcp_subflow_tcp_sock",
		CDecl: "extern struct sock *\n" +
			"bpf_mptcp_subflow_tcp_sock(const struct mptcp_subflow_context *subflow) __ksym;",
		RetType:  "struct sock *",
		ArgTypes: []string{"const struct mptcp_subflow_context *"},
		IsPtrRet: true,
		RetNull:  true, // BTF_ID_FLAGS(..., KF_RET_NULL)
	},
	{
		// __bpf_kfunc bool bpf_sk_stream_memory_free(const struct sock *sk)
		// Registered KF_RET_NULL, but the return is a scalar (bool), so
		// no NULL-guard is required -- KF_RET_NULL on a scalar return
		// only means the value may be 0.
		Name: "bpf_sk_stream_memory_free",
		CDecl: "extern bool\n" +
			"bpf_sk_stream_memory_free(const struct sock *sk) __ksym;",
		RetType:  "bool",
		ArgTypes: []string{"const struct sock *"},
		IsPtrRet: false,
		RetNull:  true, // KF_RET_NULL, but scalar -> no guard (see needsNullGuard)
	},
	{
		// __bpf_kfunc bool bpf_mptcp_subflow_queues_empty(struct sock *sk)
		Name: "bpf_mptcp_subflow_queues_empty",
		CDecl: "extern bool\n" +
			"bpf_mptcp_subflow_queues_empty(struct sock *sk) __ksym;",
		RetType:  "bool",
		ArgTypes: []string{"struct sock *"},
	},
	{
		// bool mptcp_subflow_active(struct mptcp_subflow_context *subflow);
		Name: "mptcp_subflow_active",
		CDecl: "extern bool\n" +
			"mptcp_subflow_active(struct mptcp_subflow_context *subflow) __ksym;",
		RetType:  "bool",
		ArgTypes: []string{"struct mptcp_subflow_context *"},
	},
	{
		// void mptcp_set_timeout(struct sock *sk);
		Name: "mptcp_set_timeout",
		CDecl: "extern void\n" +
			"mptcp_set_timeout(struct sock *sk) __ksym;",
		RetType:  "", // void
		ArgTypes: []string{"struct sock *"},
	},
	{
		// u64 mptcp_wnd_end(const struct mptcp_sock *msk);
		Name: "mptcp_wnd_end",
		CDecl: "extern __u64\n" +
			"mptcp_wnd_end(const struct mptcp_sock *msk) __ksym;",
		RetType:  "__u64",
		ArgTypes: []string{"const struct mptcp_sock *"},
	},
}

// mptcpSubflowIterKfuncs are the three open-coded-iterator kfuncs from
// `bpf_mptcp_iter_kfunc_ids` in net/mptcp/bpf.c.  They are not callable
// individually by the kfunc-call generator: the BPF verifier enforces
// the lifecycle `new -> next* -> destroy` on EVERY path, so the renderer
// only ever emits all three together as the atomic iterator idiom (see
// renderSubflowIter).  Modelled here purely to carry the
// `extern ... __ksym;` decls and the verbatim signatures.
//
//   - bpf_iter_mptcp_subflow_new(struct bpf_iter_mptcp_subflow *it,
//                                struct sock *sk)         -> int, KF_ITER_NEW
//   - bpf_iter_mptcp_subflow_next(struct bpf_iter_mptcp_subflow *it)
//        -> struct mptcp_subflow_context *, KF_ITER_NEXT | KF_RET_NULL
//   - bpf_iter_mptcp_subflow_destroy(struct bpf_iter_mptcp_subflow *it)
//        -> void, KF_ITER_DESTROY
//
// `struct bpf_iter_mptcp_subflow` is the opaque public iterator type
// (net/mptcp/bpf.c: `__u64 __opaque[2]`); it is BTF-exported and so
// resolved from vmlinux.h -- no local definition is emitted.
var mptcpSubflowIterKfuncs = []BpfKfunc{
	{
		Name: "bpf_iter_mptcp_subflow_new",
		CDecl: "extern int\n" +
			"bpf_iter_mptcp_subflow_new(struct bpf_iter_mptcp_subflow *it,\n" +
			"\t\t\t   struct sock *sk) __ksym;",
		RetType:  "int",
		ArgTypes: []string{"struct bpf_iter_mptcp_subflow *", "struct sock *"},
	},
	{
		Name: "bpf_iter_mptcp_subflow_next",
		CDecl: "extern struct mptcp_subflow_context *\n" +
			"bpf_iter_mptcp_subflow_next(struct bpf_iter_mptcp_subflow *it) __ksym;",
		RetType:  "struct mptcp_subflow_context *",
		ArgTypes: []string{"struct bpf_iter_mptcp_subflow *"},
		IsPtrRet: true,
		RetNull:  true, // KF_ITER_NEXT | KF_RET_NULL
	},
	{
		Name: "bpf_iter_mptcp_subflow_destroy",
		CDecl: "extern void\n" +
			"bpf_iter_mptcp_subflow_destroy(struct bpf_iter_mptcp_subflow *it) __ksym;",
		RetType:  "", // void
		ArgTypes: []string{"struct bpf_iter_mptcp_subflow *"},
	},
}

// StructOpsCtxField models one writable context field reachable from a
// struct_ops scheduler callback.  Owner is the C struct type the field
// lives on; Accessor is the C lvalue used to reach it from the callback
// (relative to the fixed locals `msk` / `subflow`).  CType drives the
// generated value's range.
type StructOpsCtxField struct {
	Owner    string // e.g. "struct mptcp_sock"
	Field    string // e.g. "snd_burst"
	Accessor string // e.g. "msk->snd_burst"
	CType    string // e.g. "int", "unsigned long"
}

// mptcpSchedWriteFields is the EXACT writable surface accepted by
// bpf_mptcp_sched_btf_struct_access (net/mptcp/bpf.c:44) -- a write to
// any other field is a verifier -EACCES.  This is the audit's headline
// transport-state write primitive.
var mptcpSchedWriteFields = []StructOpsCtxField{
	{
		Owner:    "struct mptcp_sock",
		Field:    "snd_burst",
		Accessor: "msk->snd_burst",
		CType:    "int",
	},
	{
		Owner:    "struct mptcp_subflow_context",
		Field:    "avg_pacing_rate",
		Accessor: "subflow->avg_pacing_rate",
		CType:    "unsigned long",
	},
}

// StructOpsStmtKind tags the kind of a generated body statement.
type StructOpsStmtKind int

const (
	// StructOpsStmtCtxRead -- read a writable ctx field into a local.
	StructOpsStmtCtxRead StructOpsStmtKind = iota
	// StructOpsStmtCtxWrite -- write a fuzzer-chosen value to a
	// writable ctx field (the headline write primitive).
	StructOpsStmtCtxWrite
	// StructOpsStmtArith -- derive a fresh local from arithmetic over
	// an earlier local and a fuzzer-chosen constant.
	StructOpsStmtArith
	// StructOpsStmtKfuncCall -- call a modelled MPTCP kfunc with
	// typed, in-scope arguments.  A pointer return that is
	// KF_RET_NULL is bound to a local and IMMEDIATELY followed by a
	// `if (!local) return -1;` guard (rendered as part of this same
	// statement); a scalar return is bound to a local; a void kfunc
	// is emitted for effect.
	StructOpsStmtKfuncCall
	// StructOpsStmtSubflowIter -- the open-coded subflow iterator.
	// Rendered as ONE atomic compound statement: the iterator
	// declaration, `bpf_iter_mptcp_subflow_new`, a
	// `while ((sfN = bpf_iter_mptcp_subflow_next(&it)))` loop with a
	// short generated body over `sfN`, and the mandatory
	// `bpf_iter_mptcp_subflow_destroy`.  The verifier enforces the
	// `new -> next* -> destroy` lifecycle on every path, so the three
	// kfuncs are never emitted apart.
	StructOpsStmtSubflowIter
	// StructOpsStmtIfElse -- a generated free-form `if/else` (Stage
	// 2b).  Rendered as `if (<cond>) { <IfBody> }` optionally followed
	// by `else { <ElseBody> }`.  The condition is a simple boolean
	// expression over an in-scope scalar local (Cond* fields); both
	// branch bodies are generated with the existing body machinery
	// under a `noReturn` scope, so no branch emits a `return` and every
	// path falls through to the fixed scheduling epilogue.
	StructOpsStmtIfElse
)

// StructOpsStmt is one statement of the BRF-generated get_send body.
// All fields are exported so a StructOpsProg gob-serializes cleanly
// alongside the rest of BpfProg.
type StructOpsStmt struct {
	Kind StructOpsStmtKind
	// Field index into the program's WriteFields slice -- valid for
	// CtxRead and CtxWrite generated against the fixed get_send
	// surface.  Retained for introspection; the renderer uses
	// FieldAccessor / FieldCType (which are context-correct even
	// inside an iterator loop body, where the subflow base local is
	// `sfN`, not the fixed `subflow`).
	FieldIdx int
	// FieldAccessor is the fully-resolved C lvalue of a CtxRead /
	// CtxWrite (e.g. "msk->snd_burst", "sf3->avg_pacing_rate").
	FieldAccessor string
	// FieldCType is the C type of FieldAccessor.
	FieldCType string
	// Var is the local declared by CtxRead / Arith / KfuncCall
	// (e.g. "s0").  Empty for a void KfuncCall.
	Var string
	// CType is the C type of Var.
	CType string
	// Val is the fuzzer-chosen constant -- valid for CtxWrite and
	// Arith.
	Val int64
	// SrcVar is the operand local for Arith.
	SrcVar string
	// Op is the arithmetic operator for Arith ("+", "-", "*", "^",
	// "|", "&").
	Op string
	// KfuncIdx indexes the program's Kfuncs slice -- valid for
	// KfuncCall.
	KfuncIdx int
	// KfuncArgs are the C expressions passed as arguments to the
	// kfunc -- valid for KfuncCall.  Each is a typed, in-scope value
	// (`msk`, `msk->first`, `subflow`, or an earlier local).
	KfuncArgs []string
	// NullGuard is true when this KfuncCall's pointer result is
	// KF_RET_NULL and the renderer must emit the mandatory
	// `if (!Var) return -1;` guard immediately after the call.
	NullGuard bool
	// IterId is a per-statement unique id for a SubflowIter -- it
	// names the iterator local (`itN`) and the loop variable
	// (`sfN`), keeping nested/repeated iterators non-colliding.
	IterId int
	// IterSockExpr is the `struct sock *` expression passed to
	// `bpf_iter_mptcp_subflow_new` -- the MPTCP socket, `(struct
	// sock *)msk`.  Valid for SubflowIter.
	IterSockExpr string
	// IterBody is the (possibly empty) short generated loop body of a
	// SubflowIter, executed with the loop variable `sfN` in scope as
	// a valid `struct mptcp_subflow_context *`.  Reuses the same
	// StructOpsStmt kinds as the top-level body.
	IterBody []StructOpsStmt
	// CondVar is the in-scope scalar local the condition tests --
	// valid for IfElse.  Always a scalar (`int` / `unsigned long` /
	// `bool` / `__u64`); never a pointer (see StructOpsStmtIfElse).
	CondVar string
	// CondOp is the condition operator for IfElse: one of ">", "<",
	// "==", "!=", "&", or "" (the empty string meaning a bare
	// truthiness test `if (CondVar)`).
	CondOp string
	// CondVal is the fuzzer-chosen constant the condition compares /
	// bit-tests against -- valid for IfElse when CondOp != "".
	CondVal int64
	// IfBody is the generated body of the `if` branch -- valid for
	// IfElse.  Always non-empty.  Generated under a `noReturn` scope,
	// so it emits no `return`.
	IfBody []StructOpsStmt
	// ElseBody is the generated body of the optional `else` branch --
	// valid for IfElse.  When nil/empty the renderer emits no `else`.
	// Generated under the same `noReturn` scope as IfBody.
	ElseBody []StructOpsStmt
}

// StructOpsProg is the per-program model of a generated MPTCP struct_ops
// scheduler.  It hangs off BpfProg.StructOps and is what
// genStructOpsSource renders.  It is intentionally small: a scheduler
// name, the writable-field table the body draws on, the kfunc model the
// body's calls draw on, and the generated get_send / init / release
// bodies.
//
// Stage C-full Stage 2a: InitBody / ReleaseBody carry the generated
// (previously empty) `init` / `release` bodies.  IterKfuncs carries the
// three subflow-iterator kfuncs' externs, emitted only when a generated
// body actually uses the iterator.
type StructOpsProg struct {
	SchedName   string
	WriteFields []StructOpsCtxField
	Kfuncs      []BpfKfunc
	IterKfuncs  []BpfKfunc
	GetSendBody []StructOpsStmt
	InitBody    []StructOpsStmt
	ReleaseBody []StructOpsStmt
}

// isStructOps reports whether a BpfProg is a generated struct_ops
// scheduler rather than a helper-call attached program.
func (p *BpfProg) isStructOps() bool {
	return p.StructOps != nil
}

// structOpsArithOps -- the operators genStructOpsBody may pick.  No
// division/modulo: a generated `/0` would be a compile-time-constant
// UB the verifier rejects, which is noise rather than signal here.
var structOpsArithOps = []string{"+", "-", "*", "^", "|", "&"}

// genStructOpsCtxValue picks a fuzzer value sized to a writable field's
// C type.  `int` (snd_burst) gets a signed 32-bit draw -- negative
// values are interesting transport state; `unsigned long`
// (avg_pacing_rate) gets a non-negative draw.
func genStructOpsCtxValue(r *randGen, ctype string) int64 {
	switch ctype {
	case "int":
		return int64(r.Intn(1<<32)) - (1 << 31)
	default: // "unsigned long" and any future unsigned field
		return int64(r.Intn(1 << 31))
	}
}

// normalizeCType strips a leading `const ` qualifier so a value's type
// can be matched against a kfunc parameter type regardless of
// const-ness.  `const struct sock *` and `struct sock *` denote the
// same value for call-argument purposes.
func normalizeCType(t string) string {
	for {
		if len(t) > 6 && t[:6] == "const " {
			t = t[6:]
			continue
		}
		break
	}
	return t
}

// typedVal is one value in scope inside the generated get_send body: a
// C expression and its (normalized) C type.  The pool starts with the
// three fixed values -- `msk`, `msk->first`, `subflow` -- and grows
// with every ctx-read local, arithmetic local, and (Stage 1) typed
// kfunc-call result local.
type typedVal struct {
	expr  string // C expression, e.g. "msk", "msk->first", "s3"
	ctype string // normalized C type, e.g. "struct sock *"
}

// scalarCType reports whether a C type is a usable arithmetic scalar
// (an integer-like value an Arith statement may operate on).  Pointer
// types are excluded.
func scalarCType(t string) bool {
	switch normalizeCType(t) {
	case "int", "unsigned long", "bool", "__u64", "u64", "long":
		return true
	default:
		return false
	}
}

// pickKfuncArgs tries to satisfy every parameter type of kf from the
// typed-value pool.  It returns the chosen argument expressions and
// true on success; if any parameter type has no matching in-scope
// value it returns false and the kfunc is not called.  The verifier
// contract "pass only typed, in-scope values" is enforced here: an
// argument is only ever a pool entry whose normalized type equals the
// parameter's normalized type.
func pickKfuncArgs(r *randGen, kf *BpfKfunc, pool []typedVal) ([]string, bool) {
	args := make([]string, 0, len(kf.ArgTypes))
	for _, pt := range kf.ArgTypes {
		want := normalizeCType(pt)
		var cands []string
		for _, v := range pool {
			if v.ctype == want {
				cands = append(cands, v.expr)
			}
		}
		if want == "bool" {
			// `bool` is also satisfiable by a fuzzer-chosen literal
			// -- mptcp_subflow_set_scheduled's `scheduled` arg is the
			// only bool parameter, and the fixed epilogue always
			// passes `true`; for any generated bool arg, offer both
			// literals as candidates so a call is never blocked.
			cands = append(cands, "true", "false")
		}
		if len(cands) == 0 {
			return nil, false
		}
		args = append(args, cands[r.Intn(len(cands))])
	}
	return args, true
}

// ctxWriteField is one writable ctx field available to a body, with the
// accessor already resolved for the body's surface -- e.g. the top-level
// get_send body sees `subflow->avg_pacing_rate`, but an iterator loop
// body sees `sfN->avg_pacing_rate` (same field, different base local).
type ctxWriteField struct {
	accessor string // resolved C lvalue
	ctype    string // C type
}

// bodyScope parameterises genStructOpsBody for the three surfaces it
// renders: the top-level get_send body, an iterator loop body, and the
// init/release bodies.  It carries the seed typed-value pool, the
// writable fields resolved for this surface, and whether the subflow
// iterator is an allowed statement kind here.
type bodyScope struct {
	// pool is the set of typed values in scope at body entry.
	pool []typedVal
	// writeFields are the ctx fields writable/readable from this body.
	writeFields []ctxWriteField
	// allowIter permits StructOpsStmtSubflowIter as a statement kind.
	// True only for the top-level get_send body -- iterator loop
	// bodies do not nest an iterator, and init/release do not iterate.
	allowIter bool
	// requireWrite biases the last statement toward a ctx write so the
	// headline write primitive is reliably exercised.  True for
	// get_send; false for the (short) iterator loop body and for
	// init/release, where a guaranteed write is not wanted.
	requireWrite bool
	// noReturn forbids any statement that emits a `return` -- i.e. a
	// KF_RET_NULL-pointer kfunc call (whose mandatory guard is
	// `if (!v) return -1;`).  Set TRUE for an iterator loop body: this
	// explicit iterator idiom has no `__attribute__((cleanup))`, so a
	// `return` from inside the `while` loop would skip
	// `bpf_iter_mptcp_subflow_destroy` and the verifier would reject
	// the program for an unreleased iterator.  Set TRUE for an
	// `if`/`else` branch body too (Stage 2b): a `return` inside a
	// branch would make `get_send` skip the fixed scheduling epilogue
	// on that path, so no branch may return -- every path then falls
	// through to the epilogue and always schedules.  A KF_RET_NULL-
	// pointer kfunc is simply not offered when noReturn is set; a
	// non-guarded scalar/void kfunc still is.
	noReturn bool
	// allowIf permits StructOpsStmtIfElse as a statement kind (Stage
	// 2b).  True for the top-level get_send body and -- subject to the
	// depth cap -- for an `if`/`else` branch body, so generated
	// branching may nest.  False for init/release and for an iterator
	// loop body, which are kept straight-line.
	allowIf bool
	// depth is the current `if`/`else` nesting depth (0 at a callback's
	// top level).  ifElseMaxDepth caps it -- a branch body deeper than
	// the cap is generated with allowIf cleared, so generated programs
	// stay within the verifier's instruction/complexity limits.
	depth int
	// minStmt / maxStmt bound the generated statement count.
	minStmt, maxStmt int
}

// ifElseMaxDepth caps generated `if`/`else` nesting (Stage 2b).  A
// branch body at this depth is generated with `if`/`else` no longer an
// offered statement kind, so the deepest branch is straight-line.  Kept
// small (2) so a generated `get_send` body stays well within the BPF
// verifier's instruction- and branch-complexity limits.
const ifElseMaxDepth = 2

// genStructOpsBody generates a BRF struct_ops body: a short,
// randomly-ordered sequence of ctx reads, ctx writes (the write
// primitive), arithmetic over the read locals, Stage-1 straight-line
// contract-aware kfunc calls, and -- when sc.allowIter -- the Stage-2a
// subflow iterator.  Fixed prologue/epilogue text is added by the
// renderer, not here -- this is purely the generated middle.
//
// The generator threads a pool of TYPED values seeded from sc.pool and
// grown with every typed local it produces.  A kfunc call is generated
// only when every argument type is satisfiable from the pool; a
// KF_RET_NULL pointer result is bound to a local and IMMEDIATELY
// guarded, and only then enters the pool.  varId is a shared counter so
// every local across the whole callback (including nested iterator loop
// bodies) is uniquely named.
func genStructOpsBody(r *randGen, sop *StructOpsProg, sc bodyScope, varId *int) []StructOpsStmt {
	var body []StructOpsStmt
	// readVars tracks (local name, C type) of scalar locals available
	// as arithmetic operands.
	type readVar struct {
		name  string
		ctype string
	}
	var readVars []readVar

	// pool is the set of typed values in scope -- seeded from the
	// scope and grown locally.  Copied so the caller's slice is not
	// aliased.
	pool := append([]typedVal(nil), sc.pool...)

	// callableKfuncs returns the indices of kfuncs whose every
	// argument type is satisfiable from the current pool.  The two
	// fixed-skeleton kfuncs (bpf_mptcp_subflow_ctx,
	// mptcp_subflow_set_scheduled) are excluded from generation -- the
	// renderer emits those itself as the fixed prologue/epilogue.
	// When sc.noReturn is set, a KF_RET_NULL-pointer kfunc is excluded
	// too: its mandatory guard emits a `return`, which is unsafe
	// inside an iterator loop body (see bodyScope.noReturn).
	callableKfuncs := func() []int {
		var idxs []int
		for ki := range sop.Kfuncs {
			kf := &sop.Kfuncs[ki]
			if kf.Name == "bpf_mptcp_subflow_ctx" ||
				kf.Name == "mptcp_subflow_set_scheduled" {
				continue
			}
			if sc.noReturn && kf.needsNullGuard() {
				continue
			}
			if _, ok := pickKfuncArgs(r, kf, pool); ok {
				idxs = append(idxs, ki)
			}
		}
		return idxs
	}

	// emitCtxRead appends a ctx read of writeFields[fi], registering
	// the new local in readVars and the pool.  Factored out because
	// it is also the fallback when a chosen kind is not satisfiable.
	emitCtxRead := func(fi int) {
		f := sc.writeFields[fi]
		v := fmt.Sprintf("s%d", *varId)
		*varId++
		body = append(body, StructOpsStmt{
			Kind:          StructOpsStmtCtxRead,
			FieldIdx:      fi,
			FieldAccessor: f.accessor,
			FieldCType:    f.ctype,
			Var:           v,
			CType:         f.ctype,
		})
		readVars = append(readVars, readVar{v, f.ctype})
		pool = append(pool, typedVal{expr: v, ctype: normalizeCType(f.ctype)})
	}

	// kinds is the set of statement kinds the generator may draw from
	// for this scope.  The four straight-line kinds are always in;
	// the iterator is added only when sc.allowIter; the `if`/`else`
	// statement (Stage 2b) only when sc.allowIf and the nesting cap is
	// not yet reached.
	kinds := []StructOpsStmtKind{
		StructOpsStmtCtxRead, StructOpsStmtCtxWrite,
		StructOpsStmtArith, StructOpsStmtKfuncCall,
	}
	if sc.allowIter {
		kinds = append(kinds, StructOpsStmtSubflowIter)
	}
	if sc.allowIf && sc.depth < ifElseMaxDepth {
		kinds = append(kinds, StructOpsStmtIfElse)
	}

	span := sc.maxStmt - sc.minStmt + 1
	if span < 1 {
		span = 1
	}
	nStmt := sc.minStmt + r.Intn(span)
	for i := 0; i < nStmt; i++ {
		// Pick freely among the statement kinds available to this scope.
		kind := kinds[r.Intn(len(kinds))]
		if sc.requireWrite && i == nStmt-1 {
			// Bias the last statement toward a write so the headline
			// primitive is reliably exercised.
			haveWrite := false
			for _, st := range body {
				if st.Kind == StructOpsStmtCtxWrite {
					haveWrite = true
				}
			}
			if !haveWrite {
				kind = StructOpsStmtCtxWrite
			}
		}
		if kind == StructOpsStmtArith && len(readVars) == 0 {
			// No operand yet -- fall back to a read.
			kind = StructOpsStmtCtxRead
		}
		if kind == StructOpsStmtKfuncCall && len(callableKfuncs()) == 0 {
			// No kfunc satisfiable from the pool -- fall back to a
			// read (always satisfiable).
			kind = StructOpsStmtCtxRead
		}
		if kind == StructOpsStmtIfElse && len(readVars) == 0 {
			// The condition tests an in-scope scalar local; none yet --
			// fall back to a read, which produces one.
			kind = StructOpsStmtCtxRead
		}

		switch kind {
		case StructOpsStmtCtxRead:
			emitCtxRead(r.Intn(len(sc.writeFields)))
		case StructOpsStmtCtxWrite:
			fi := r.Intn(len(sc.writeFields))
			f := sc.writeFields[fi]
			body = append(body, StructOpsStmt{
				Kind:          StructOpsStmtCtxWrite,
				FieldIdx:      fi,
				FieldAccessor: f.accessor,
				FieldCType:    f.ctype,
				Val:           genStructOpsCtxValue(r, f.ctype),
			})
		case StructOpsStmtArith:
			src := readVars[r.Intn(len(readVars))]
			v := fmt.Sprintf("s%d", *varId)
			*varId++
			body = append(body, StructOpsStmt{
				Kind:   StructOpsStmtArith,
				Var:    v,
				CType:  src.ctype,
				SrcVar: src.name,
				Op:     structOpsArithOps[r.Intn(len(structOpsArithOps))],
				Val:    int64(r.Intn(1 << 16)),
			})
			readVars = append(readVars, readVar{v, src.ctype})
			pool = append(pool, typedVal{expr: v, ctype: normalizeCType(src.ctype)})
		case StructOpsStmtKfuncCall:
			idxs := callableKfuncs()
			ki := idxs[r.Intn(len(idxs))]
			kf := &sop.Kfuncs[ki]
			// pickKfuncArgs already succeeded inside callableKfuncs;
			// re-roll a fresh argument choice for this call.
			args, ok := pickKfuncArgs(r, kf, pool)
			if !ok {
				// Defensive -- pool only grows, so this cannot
				// happen; fall back to a read rather than emit a
				// malformed call.
				emitCtxRead(r.Intn(len(sc.writeFields)))
				continue
			}
			st := StructOpsStmt{
				Kind:      StructOpsStmtKfuncCall,
				KfuncIdx:  ki,
				KfuncArgs: args,
			}
			switch {
			case kf.RetType == "":
				// void -- call for effect, no local, no pool entry.
			case kf.needsNullGuard():
				// KF_RET_NULL pointer -- bind, guard, then publish.
				v := fmt.Sprintf("s%d", *varId)
				*varId++
				st.Var = v
				st.CType = kf.RetType
				st.NullGuard = true
				// The local enters the pool only AFTER the guard --
				// which the renderer emits immediately after the
				// call, so any later statement sees a guarded value.
				pool = append(pool, typedVal{
					expr: v, ctype: normalizeCType(kf.RetType),
				})
			default:
				// Scalar (or non-RET_NULL pointer) -- bind to a
				// local usable later.
				v := fmt.Sprintf("s%d", *varId)
				*varId++
				st.Var = v
				st.CType = kf.RetType
				if scalarCType(kf.RetType) {
					readVars = append(readVars, readVar{v, kf.RetType})
				}
				pool = append(pool, typedVal{
					expr: v, ctype: normalizeCType(kf.RetType),
				})
			}
			body = append(body, st)
		case StructOpsStmtSubflowIter:
			body = append(body, genSubflowIter(r, sop, varId))
		case StructOpsStmtIfElse:
			// readVars is non-empty here (the fallback above guarantees
			// it); build the condition over an in-scope scalar local,
			// then generate the branch bodies.  Pass the CURRENT pool /
			// scalar-local set as the branch seeds -- a branch sees
			// everything declared before the `if`.  Branch-body locals
			// do NOT re-enter this function's pool / readVars: each
			// branch is a separate genStructOpsBody call with its own
			// pool, which is exactly C block scoping (a local declared
			// inside a branch is unreachable after the branch closes).
			condNames := make([]string, len(readVars))
			for ci, rv := range readVars {
				condNames[ci] = rv.name
			}
			body = append(body, genIfElse(r, sop, sc, varId, pool, condNames))
		}
	}
	return body
}

// structOpsCondOps -- the condition operators genIfElse may pick for an
// `if`/`else`.  The empty string is the bare truthiness test
// `if (s0)`; the rest are a comparison or a bit-test against a fuzzer
// constant.  No division/modulo and no assignment: a condition is a
// pure read of an in-scope scalar.
var structOpsCondOps = []string{"", ">", "<", "==", "!=", "&"}

// genIfElse builds one StructOpsStmtIfElse: a generated free-form
// `if`/`else` (Stage 2b).  condNames are the in-scope scalar locals the
// condition may test (guaranteed non-empty by the caller); seedPool is
// the typed-value pool visible at the `if` -- the branch bodies are
// generated against a COPY of it, so a branch may use any value declared
// before the `if` but a branch-local value never escapes the branch.
//
// Both branch bodies are generated with `noReturn` set: with no `return`
// in either branch every path falls through to the fixed scheduling
// epilogue, so `get_send` always schedules >= 1 subflow.  `allowIf`
// stays on (subject to the depth cap via sc.depth+1) so branching may
// nest; `allowIter` carries the parent's setting so a branch of the
// top-level body may still contain the subflow iterator.  `requireWrite`
// is cleared -- a forced write per branch is not wanted.
func genIfElse(r *randGen, sop *StructOpsProg, sc bodyScope, varId *int,
	seedPool []typedVal, condNames []string) StructOpsStmt {
	st := StructOpsStmt{
		Kind:    StructOpsStmtIfElse,
		CondVar: condNames[r.Intn(len(condNames))],
		CondOp:  structOpsCondOps[r.Intn(len(structOpsCondOps))],
	}
	if st.CondOp != "" {
		// A 16-bit constant keeps comparisons / bit-tests in a range
		// that is meaningful against the scalar locals in scope.
		st.CondVal = int64(r.Intn(1 << 16))
	}

	// The branch scope: same writable surface and same iterator
	// permission as the enclosing scope, but `noReturn` set (no branch
	// may return) and `requireWrite` cleared.  depth+1 lets the nesting
	// cap stop runaway recursion.
	branchScope := bodyScope{
		pool:         append([]typedVal(nil), seedPool...),
		writeFields:  sc.writeFields,
		allowIter:    sc.allowIter,
		requireWrite: false,
		noReturn:     true,
		allowIf:      sc.allowIf,
		depth:        sc.depth + 1,
		minStmt:      1,
		maxStmt:      3,
	}
	st.IfBody = genStructOpsBody(r, sop, branchScope, varId)
	if r.bin() {
		// Optional `else` -- generated against a fresh copy of the same
		// seed scope so its locals are independent of the `if` branch.
		elseScope := branchScope
		elseScope.pool = append([]typedVal(nil), seedPool...)
		st.ElseBody = genStructOpsBody(r, sop, elseScope, varId)
	}
	return st
}

// genSubflowIter builds one StructOpsStmtSubflowIter: the open-coded
// subflow iterator.  The verifier requires the `new -> next* -> destroy`
// lifecycle on every path, so this statement is ALWAYS rendered as the
// complete triple (see renderSubflowIter) -- it is never partial.
//
// The loop variable `sfN` is a valid `struct mptcp_subflow_context *`
// inside the loop (the `while` condition is the KF_RET_NULL NULL-check),
// so the loop body is generated with `sfN` seeded into a fresh pool and
// the avg_pacing_rate write field re-based onto `sfN`.  The loop body
// does NOT nest another iterator (allowIter false) and is kept short.
func genSubflowIter(r *randGen, sop *StructOpsProg, varId *int) StructOpsStmt {
	id := *varId
	*varId++
	sfVar := fmt.Sprintf("sf%d", id)

	// The loop body sees `sfN` (the per-iteration subflow) plus the
	// callback's `msk` and `msk->first`.  Writes are confined to the
	// subflow field re-based onto `sfN`; reading/writing msk->snd_burst
	// is also valid inside the loop.
	loopScope := bodyScope{
		pool: []typedVal{
			{expr: "msk", ctype: "struct mptcp_sock *"},
			{expr: "msk->first", ctype: "struct sock *"},
			{expr: sfVar, ctype: "struct mptcp_subflow_context *"},
		},
		writeFields: []ctxWriteField{
			{accessor: "msk->snd_burst", ctype: "int"},
			{accessor: sfVar + "->avg_pacing_rate", ctype: "unsigned long"},
		},
		allowIter:    false,
		requireWrite: false,
		noReturn:     true, // no `return` inside the loop -- see noReturn
		minStmt:      0,
		maxStmt:      3,
	}
	loopBody := genStructOpsBody(r, sop, loopScope, varId)

	return StructOpsStmt{
		Kind:         StructOpsStmtSubflowIter,
		IterId:       id,
		Var:          sfVar,
		CType:        "struct mptcp_subflow_context *",
		IterSockExpr: "(struct sock *)msk",
		IterBody:     loopBody,
	}
}

// getSendScope is the bodyScope for the top-level get_send body: the
// three fixed-prologue values are in scope, both writable fields are
// available against their fixed accessors, the iterator and generated
// `if`/`else` are allowed, and a write is required.
func getSendScope() bodyScope {
	return bodyScope{
		pool: []typedVal{
			{expr: "msk", ctype: "struct mptcp_sock *"},
			{expr: "msk->first", ctype: "struct sock *"},
			{expr: "subflow", ctype: "struct mptcp_subflow_context *"},
		},
		writeFields:  schedWriteFieldsResolved(),
		allowIter:    true,
		requireWrite: true,
		allowIf:      true,
		depth:        0,
		minStmt:      3,
		maxStmt:      8,
	}
}

// initReleaseScope is the bodyScope for the init / release bodies.  Only
// `msk` (and the derived `msk->first`) is in scope -- there is no
// scheduling and no `subflow` prologue -- so the writable surface is
// just `msk->snd_burst`, the iterator is not allowed, and no write is
// forced.  `mptcp_subflow_set_scheduled` is never reachable here because
// it needs a `struct mptcp_subflow_context *`, which is not in the pool.
//
// noReturn is set: `init`/`release` are `void BPF_PROG(...)`, so a
// generated `if (!v) return -1;` (the KF_RET_NULL-pointer guard) would
// be `return` of a value from a void function -- invalid C.  A
// KF_RET_NULL-pointer kfunc is therefore not offered here; the
// straight-line scalar/void kfuncs still are.
func initReleaseScope() bodyScope {
	return bodyScope{
		pool: []typedVal{
			{expr: "msk", ctype: "struct mptcp_sock *"},
			{expr: "msk->first", ctype: "struct sock *"},
		},
		writeFields: []ctxWriteField{
			{accessor: "msk->snd_burst", ctype: "int"},
		},
		allowIter:    false,
		requireWrite: false,
		noReturn:     true,
		minStmt:      2,
		maxStmt:      4,
	}
}

// schedWriteFieldsResolved returns mptcpSchedWriteFields as the
// renderer-facing ctxWriteField list (accessor + ctype), for the
// top-level get_send body where the subflow base local is the fixed
// `subflow`.
func schedWriteFieldsResolved() []ctxWriteField {
	out := make([]ctxWriteField, len(mptcpSchedWriteFields))
	for i, f := range mptcpSchedWriteFields {
		out[i] = ctxWriteField{accessor: f.Accessor, ctype: f.CType}
	}
	return out
}

// genStructOpsProg builds a fully-generated MPTCP struct_ops scheduler
// model.  Called by GenBpfProg on the struct_ops branch.
func genStructOpsProg(r *randGen) *StructOpsProg {
	sop := &StructOpsProg{
		WriteFields: mptcpSchedWriteFields,
		Kfuncs:      mptcpSchedKfuncs,
		IterKfuncs:  mptcpSubflowIterKfuncs,
	}
	// A short, unique-enough scheduler name within MPTCP_SCHED_NAME_MAX.
	name := fmt.Sprintf("brf_%x", r.Intn(1<<24))
	if len(name) >= schedNameMax {
		name = name[:schedNameMax-1]
	}
	sop.SchedName = name

	varId := 0
	sop.GetSendBody = genStructOpsBody(r, sop, getSendScope(), &varId)
	sop.InitBody = genStructOpsBody(r, sop, initReleaseScope(), &varId)
	sop.ReleaseBody = genStructOpsBody(r, sop, initReleaseScope(), &varId)
	return sop
}

// walkStmts invokes fn on every statement in body, recursing into the
// loop body of every SubflowIter and both branch bodies of every IfElse
// so callers see the whole statement tree.
func walkStmts(body []StructOpsStmt, fn func(*StructOpsStmt)) {
	for i := range body {
		st := &body[i]
		fn(st)
		switch st.Kind {
		case StructOpsStmtSubflowIter:
			walkStmts(st.IterBody, fn)
		case StructOpsStmtIfElse:
			walkStmts(st.IfBody, fn)
			walkStmts(st.ElseBody, fn)
		}
	}
}

// usesSubflowIter reports whether any generated body uses the subflow
// iterator -- the renderer emits the three `bpf_iter_mptcp_subflow_*`
// externs only when at least one does.
func (sop *StructOpsProg) usesSubflowIter() bool {
	found := false
	for _, b := range [][]StructOpsStmt{
		sop.GetSendBody, sop.InitBody, sop.ReleaseBody,
	} {
		walkStmts(b, func(st *StructOpsStmt) {
			if st.Kind == StructOpsStmtSubflowIter {
				found = true
			}
		})
	}
	return found
}

// usedKfuncIdxs returns the indices of every kfunc the rendered
// translation unit actually references -- the two the fixed
// prologue/epilogue needs plus every kfunc a generated KfuncCall
// statement targets in ANY body (get_send / init / release, including
// inside iterator loop bodies) -- so genStructOpsSource emits an
// `extern … __ksym;` decl for exactly those and no more.  An unused
// extern is harmless, but emitting only the used set keeps each rendered
// scheduler honest about its kfunc surface.
func (sop *StructOpsProg) usedKfuncIdxs() []int {
	used := make(map[int]bool)
	for ki, kf := range sop.Kfuncs {
		if kf.Name == "bpf_mptcp_subflow_ctx" ||
			kf.Name == "mptcp_subflow_set_scheduled" {
			used[ki] = true // fixed prologue / epilogue
		}
	}
	for _, b := range [][]StructOpsStmt{
		sop.GetSendBody, sop.InitBody, sop.ReleaseBody,
	} {
		walkStmts(b, func(st *StructOpsStmt) {
			if st.Kind == StructOpsStmtKfuncCall {
				used[st.KfuncIdx] = true
			}
		})
	}
	// Return indices in Kfuncs order for a stable render.
	var idxs []int
	for ki := range sop.Kfuncs {
		if used[ki] {
			idxs = append(idxs, ki)
		}
	}
	return idxs
}

// renderBody renders a generated body to BPF C.  indent is the leading
// whitespace prefixed to every statement (one tab at callback scope,
// two inside an iterator loop).  The body may itself contain a
// SubflowIter, whose loop body is rendered recursively at indent+"\t".
func (sop *StructOpsProg) renderBody(s *bytes.Buffer, body []StructOpsStmt, indent string) {
	for _, st := range body {
		switch st.Kind {
		case StructOpsStmtCtxRead:
			fmt.Fprintf(s, "%s%s %s = %s;\n",
				indent, st.FieldCType, st.Var, st.FieldAccessor)
		case StructOpsStmtCtxWrite:
			fmt.Fprintf(s, "%s%s = %d;\n", indent, st.FieldAccessor, st.Val)
		case StructOpsStmtArith:
			fmt.Fprintf(s, "%s%s %s = %s %s %d;\n",
				indent, st.CType, st.Var, st.SrcVar, st.Op, st.Val)
		case StructOpsStmtKfuncCall:
			kf := &sop.Kfuncs[st.KfuncIdx]
			argList := ""
			for ai, a := range st.KfuncArgs {
				if ai > 0 {
					argList += ", "
				}
				argList += a
			}
			if st.Var == "" {
				// void kfunc -- call for effect.
				fmt.Fprintf(s, "%s%s(%s);\n", indent, kf.Name, argList)
			} else {
				// kfunc with a result -- bind to a typed local.
				fmt.Fprintf(s, "%s%s %s = %s(%s);\n",
					indent, st.CType, st.Var, kf.Name, argList)
			}
			if st.NullGuard {
				// Mandatory KF_RET_NULL pointer guard -- emitted
				// IMMEDIATELY after the call so the local is only
				// ever used after the verifier sees it null-checked.
				fmt.Fprintf(s, "%sif (!%s)\n", indent, st.Var)
				fmt.Fprintf(s, "%s\treturn -1;\n", indent)
			}
		case StructOpsStmtSubflowIter:
			sop.renderSubflowIter(s, st, indent)
		case StructOpsStmtIfElse:
			sop.renderIfElse(s, st, indent)
		}
	}
}

// renderIfElse renders one IfElse (Stage 2b) as
// `if (<cond>) { <IfBody> }` optionally followed by
// `else { <ElseBody> }`.  The condition is a comparison / bit-test
// against a fuzzer constant, or -- when CondOp is empty -- the bare
// truthiness of an in-scope scalar local.  Both branch bodies are
// rendered recursively at indent+"\t"; they were generated under a
// `noReturn` scope, so neither emits a `return` and every path falls
// through to the caller's fixed scheduling epilogue.
func (sop *StructOpsProg) renderIfElse(s *bytes.Buffer, st StructOpsStmt, indent string) {
	var cond string
	if st.CondOp == "" {
		// Bare truthiness test.
		cond = st.CondVar
	} else {
		cond = fmt.Sprintf("%s %s %d", st.CondVar, st.CondOp, st.CondVal)
	}
	fmt.Fprintf(s, "%s/* BRF-generated if/else. */\n", indent)
	fmt.Fprintf(s, "%sif (%s) {\n", indent, cond)
	sop.renderBody(s, st.IfBody, indent+"\t")
	if len(st.ElseBody) > 0 {
		fmt.Fprintf(s, "%s} else {\n", indent)
		sop.renderBody(s, st.ElseBody, indent+"\t")
	}
	fmt.Fprintf(s, "%s}\n", indent)
}

// renderSubflowIter renders one SubflowIter as the complete,
// verifier-required `new -> next* -> destroy` triple -- ALWAYS all three
// together, never partial.  The `while` condition is the KF_RET_NULL
// NULL-check on `bpf_iter_mptcp_subflow_next`; inside the loop `sfN` is a
// valid `struct mptcp_subflow_context *`.  Modelled on the kernel
// selftest `tools/testing/selftests/bpf/progs/mptcp_bpf_rr.c`, whose
// `bpf_for_each(mptcp_subflow, subflow, (struct sock *)msk)` expands to
// exactly this idiom; the socket argument is `(struct sock *)msk`.
func (sop *StructOpsProg) renderSubflowIter(s *bytes.Buffer, st StructOpsStmt, indent string) {
	itVar := fmt.Sprintf("it%d", st.IterId)
	sfVar := st.Var
	fmt.Fprintf(s, "%s/* BRF-generated subflow iterator. */\n", indent)
	fmt.Fprintf(s, "%sstruct bpf_iter_mptcp_subflow %s;\n", indent, itVar)
	fmt.Fprintf(s, "%sstruct mptcp_subflow_context *%s;\n", indent, sfVar)
	fmt.Fprintf(s, "%sbpf_iter_mptcp_subflow_new(&%s, %s);\n",
		indent, itVar, st.IterSockExpr)
	fmt.Fprintf(s, "%swhile ((%s = bpf_iter_mptcp_subflow_next(&%s))) {\n",
		indent, sfVar, itVar)
	sop.renderBody(s, st.IterBody, indent+"\t")
	fmt.Fprintf(s, "%s}\n", indent)
	fmt.Fprintf(s, "%sbpf_iter_mptcp_subflow_destroy(&%s);\n", indent, itVar)
}

// genStructOpsSource renders a struct_ops BpfProg to a complete BPF C
// translation unit: vmlinux.h, the kfunc externs, the three
// `SEC("struct_ops")` callbacks, and the `SEC(".struct_ops.link")`
// mptcp_sched_ops instance.  The get_send callback interleaves the
// fixed kfunc skeleton with the generated body.  Mirrors the shape of
// executor/bpf_progs/mptcp_sched.bpf.c (the hand-written Stage B
// scaffold) and tools/testing/selftests/bpf/progs/mptcp_bpf_first.c.
func (p *BpfProg) genStructOpsSource() string {
	sop := p.StructOps
	s := new(bytes.Buffer)

	fmt.Fprintf(s, "// SPDX-License-Identifier: GPL-2.0\n")
	fmt.Fprintf(s, "/* BRF-generated MPTCP struct_ops scheduler (Phase 3, Stage C). */\n")
	fmt.Fprintf(s, "#include \"vmlinux.h\"\n")
	fmt.Fprintf(s, "#include <bpf/bpf_helpers.h>\n")
	fmt.Fprintf(s, "#include <bpf/bpf_tracing.h>\n\n")

	fmt.Fprintf(s, "char _license[] SEC(\"license\") = \"GPL\";\n\n")

	// MPTCP scheduler kfunc externs -- net/mptcp/bpf.c registers
	// these; they are callable only from an mptcp_sched_ops program.
	// Emit only the kfuncs this scheduler actually references.
	fmt.Fprintf(s, "/* MPTCP scheduler kfuncs (net/mptcp/bpf.c). */\n")
	for _, ki := range sop.usedKfuncIdxs() {
		fmt.Fprintf(s, "%s\n", sop.Kfuncs[ki].CDecl)
	}
	// Subflow-iterator kfuncs -- emitted only when a generated body
	// uses the iterator.  The verifier requires the full
	// new -> next* -> destroy triple, so either all three externs are
	// needed or none are.
	if sop.usesSubflowIter() {
		fmt.Fprintf(s, "/* MPTCP subflow-iterator kfuncs (net/mptcp/bpf.c). */\n")
		for i := range sop.IterKfuncs {
			fmt.Fprintf(s, "%s\n", sop.IterKfuncs[i].CDecl)
		}
	}
	fmt.Fprintf(s, "\n")

	// init / release -- generated `msk`-reachable bodies (Stage C-full
	// Stage 2a; previously empty `{}`).  Only `msk` is in scope; these
	// callbacks do not schedule, so the renderer emits no fixed
	// skeleton -- just the generated body.
	for _, cb := range []struct {
		suffix string
		body   []StructOpsStmt
	}{
		{"_init", sop.InitBody},
		{"_release", sop.ReleaseBody},
	} {
		fmt.Fprintf(s, "SEC(\"struct_ops\")\n")
		fmt.Fprintf(s, "void BPF_PROG(%s%s, struct mptcp_sock *msk)\n{\n",
			sop.SchedName, cb.suffix)
		fmt.Fprintf(s, "\t/* BRF-generated body. */\n")
		if len(cb.body) == 0 {
			fmt.Fprintf(s, "\t/* (empty) */\n")
		}
		sop.renderBody(s, cb.body, "\t")
		fmt.Fprintf(s, "}\n\n")
	}

	// get_send -- fixed kfunc prologue, generated body, fixed kfunc
	// epilogue.
	fmt.Fprintf(s, "SEC(\"struct_ops\")\n")
	fmt.Fprintf(s, "int BPF_PROG(%s_get_send, struct mptcp_sock *msk)\n{\n",
		sop.SchedName)
	// Fixed prologue.
	fmt.Fprintf(s, "\tstruct mptcp_subflow_context *subflow;\n\n")
	fmt.Fprintf(s, "\tsubflow = bpf_mptcp_subflow_ctx(msk->first);\n")
	fmt.Fprintf(s, "\tif (!subflow)\n")
	fmt.Fprintf(s, "\t\treturn -1;\n\n")

	// BRF-generated body.
	fmt.Fprintf(s, "\t/* BRF-generated body. */\n")
	if len(sop.GetSendBody) == 0 {
		fmt.Fprintf(s, "\t/* (empty) */\n")
	}
	sop.renderBody(s, sop.GetSendBody, "\t")
	fmt.Fprintf(s, "\n")

	// Fixed epilogue.
	fmt.Fprintf(s, "\tmptcp_subflow_set_scheduled(subflow, true);\n")
	fmt.Fprintf(s, "\treturn 0;\n")
	fmt.Fprintf(s, "}\n\n")

	// The struct_ops map instance -- registered via
	// bpf_map__attach_struct_ops.
	fmt.Fprintf(s, "SEC(\".struct_ops.link\")\n")
	fmt.Fprintf(s, "struct mptcp_sched_ops %s = {\n", sop.SchedName)
	fmt.Fprintf(s, "\t.init\t\t= (void *)%s_init,\n", sop.SchedName)
	fmt.Fprintf(s, "\t.release\t= (void *)%s_release,\n", sop.SchedName)
	fmt.Fprintf(s, "\t.get_send\t= (void *)%s_get_send,\n", sop.SchedName)
	fmt.Fprintf(s, "\t.name\t\t= \"%s\",\n", sop.SchedName)
	fmt.Fprintf(s, "};\n")

	return s.String()
}
