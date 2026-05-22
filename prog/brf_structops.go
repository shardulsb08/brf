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
// guards; no subflow iterator -- those are Stage 2.

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
// net/mptcp/bpf.c registers nine MPTCP kfuncs in total via
// `bpf_mptcp_common_kfunc_ids`.  Modelled here:
//
//   - the two the FIXED prologue/epilogue needs
//     (`bpf_mptcp_subflow_ctx`, `mptcp_subflow_set_scheduled`);
//   - the six straight-line common kfuncs the Stage C-full Stage 1
//     call generator draws on.
//
// Deliberately EXCLUDED: `mptcp_pm_subflow_chk_stale` (KF_SLEEPABLE --
// not callable from the non-sleepable `get_send`) and the three
// `bpf_iter_mptcp_subflow_*` iterator kfuncs (Stage 2).
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
)

// StructOpsStmt is one statement of the BRF-generated get_send body.
// All fields are exported so a StructOpsProg gob-serializes cleanly
// alongside the rest of BpfProg.
type StructOpsStmt struct {
	Kind StructOpsStmtKind
	// Field index into the program's WriteFields slice -- valid for
	// CtxRead and CtxWrite.
	FieldIdx int
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
}

// StructOpsProg is the per-program model of a generated MPTCP struct_ops
// scheduler.  It hangs off BpfProg.StructOps and is what
// genStructOpsSource renders.  It is intentionally small: a scheduler
// name, the writable-field table the body draws on, the kfunc model the
// body's calls draw on, and the generated get_send body.  init/release
// are empty (non-empty callbacks are Stage 2).
type StructOpsProg struct {
	SchedName   string
	WriteFields []StructOpsCtxField
	Kfuncs      []BpfKfunc
	GetSendBody []StructOpsStmt
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

// genStructOpsBody generates the BRF body of the get_send callback: a
// short, randomly-ordered sequence of ctx reads, ctx writes (the write
// primitive), arithmetic over the read locals, and -- Stage C-full,
// Stage 1 -- straight-line contract-aware kfunc calls.  The fixed
// kfunc prologue/epilogue is added by genStructOpsSource, not here --
// this is purely the generated middle.
//
// The generator threads a pool of TYPED values.  It seeds the pool
// with the three values the fixed prologue establishes -- `msk`
// (`struct mptcp_sock *`), `msk->first` (`struct sock *`) and
// `subflow` (`struct mptcp_subflow_context *`) -- and grows it with
// every typed local it produces.  A kfunc call is generated only when
// every one of its argument types is satisfiable from the pool; a
// KF_RET_NULL pointer result is bound to a local and IMMEDIATELY
// guarded, and only then enters the pool.
func genStructOpsBody(r *randGen, sop *StructOpsProg, varId *int) []StructOpsStmt {
	var body []StructOpsStmt
	// readVars tracks (local name, C type) of scalar locals available
	// as arithmetic operands.
	type readVar struct {
		name  string
		ctype string
	}
	var readVars []readVar

	// pool is the set of typed values in scope -- seeded with the
	// fixed prologue locals.  Types are stored normalized.
	pool := []typedVal{
		{expr: "msk", ctype: "struct mptcp_sock *"},
		{expr: "msk->first", ctype: "struct sock *"},
		{expr: "subflow", ctype: "struct mptcp_subflow_context *"},
	}

	// callableKfuncs returns the indices of kfuncs whose every
	// argument type is satisfiable from the current pool.  The two
	// fixed-skeleton kfuncs (bpf_mptcp_subflow_ctx,
	// mptcp_subflow_set_scheduled) are excluded from generation -- the
	// renderer emits those itself as the fixed prologue/epilogue.
	callableKfuncs := func() []int {
		var idxs []int
		for ki := range sop.Kfuncs {
			kf := &sop.Kfuncs[ki]
			if kf.Name == "bpf_mptcp_subflow_ctx" ||
				kf.Name == "mptcp_subflow_set_scheduled" {
				continue
			}
			if _, ok := pickKfuncArgs(r, kf, pool); ok {
				idxs = append(idxs, ki)
			}
		}
		return idxs
	}

	nStmt := 3 + r.Intn(6) // 3..8 statements
	for i := 0; i < nStmt; i++ {
		// Bias toward a write at least once so the headline
		// primitive is reliably exercised; otherwise pick freely
		// among the four statement kinds.
		kind := StructOpsStmtKind(r.Intn(4))
		if i == nStmt-1 {
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

		switch kind {
		case StructOpsStmtCtxRead:
			fi := r.Intn(len(sop.WriteFields))
			v := fmt.Sprintf("s%d", *varId)
			*varId++
			ct := sop.WriteFields[fi].CType
			body = append(body, StructOpsStmt{
				Kind:     StructOpsStmtCtxRead,
				FieldIdx: fi,
				Var:      v,
				CType:    ct,
			})
			readVars = append(readVars, readVar{v, ct})
			pool = append(pool, typedVal{expr: v, ctype: normalizeCType(ct)})
		case StructOpsStmtCtxWrite:
			fi := r.Intn(len(sop.WriteFields))
			body = append(body, StructOpsStmt{
				Kind:     StructOpsStmtCtxWrite,
				FieldIdx: fi,
				Val:      genStructOpsCtxValue(r, sop.WriteFields[fi].CType),
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
				fi := r.Intn(len(sop.WriteFields))
				v := fmt.Sprintf("s%d", *varId)
				*varId++
				ct := sop.WriteFields[fi].CType
				body = append(body, StructOpsStmt{
					Kind: StructOpsStmtCtxRead, FieldIdx: fi,
					Var: v, CType: ct,
				})
				readVars = append(readVars, readVar{v, ct})
				pool = append(pool, typedVal{expr: v, ctype: normalizeCType(ct)})
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
		}
	}
	return body
}

// genStructOpsProg builds a fully-generated MPTCP struct_ops scheduler
// model.  Called by GenBpfProg on the struct_ops branch.
func genStructOpsProg(r *randGen) *StructOpsProg {
	sop := &StructOpsProg{
		WriteFields: mptcpSchedWriteFields,
		Kfuncs:      mptcpSchedKfuncs,
	}
	// A short, unique-enough scheduler name within MPTCP_SCHED_NAME_MAX.
	name := fmt.Sprintf("brf_%x", r.Intn(1<<24))
	if len(name) >= schedNameMax {
		name = name[:schedNameMax-1]
	}
	sop.SchedName = name

	varId := 0
	sop.GetSendBody = genStructOpsBody(r, sop, &varId)
	return sop
}

// usedKfuncIdxs returns the indices of every kfunc the rendered
// translation unit actually references -- the two the fixed
// prologue/epilogue needs plus every kfunc a generated KfuncCall
// statement targets -- so genStructOpsSource emits an `extern … __ksym;`
// decl for exactly those and no more.  An unused extern is harmless,
// but emitting only the used set keeps each rendered scheduler honest
// about its kfunc surface.
func (sop *StructOpsProg) usedKfuncIdxs() []int {
	used := make(map[int]bool)
	for ki, kf := range sop.Kfuncs {
		if kf.Name == "bpf_mptcp_subflow_ctx" ||
			kf.Name == "mptcp_subflow_set_scheduled" {
			used[ki] = true // fixed prologue / epilogue
		}
	}
	for _, st := range sop.GetSendBody {
		if st.Kind == StructOpsStmtKfuncCall {
			used[st.KfuncIdx] = true
		}
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
	fmt.Fprintf(s, "\n")

	// init / release -- empty (non-empty init/release is Stage 2).
	fmt.Fprintf(s, "SEC(\"struct_ops\")\n")
	fmt.Fprintf(s, "void BPF_PROG(%s_init, struct mptcp_sock *msk)\n{\n}\n\n",
		sop.SchedName)
	fmt.Fprintf(s, "SEC(\"struct_ops\")\n")
	fmt.Fprintf(s, "void BPF_PROG(%s_release, struct mptcp_sock *msk)\n{\n}\n\n",
		sop.SchedName)

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
	for _, st := range sop.GetSendBody {
		switch st.Kind {
		case StructOpsStmtCtxRead:
			f := sop.WriteFields[st.FieldIdx]
			fmt.Fprintf(s, "\t%s %s = %s;\n", st.CType, st.Var, f.Accessor)
		case StructOpsStmtCtxWrite:
			f := sop.WriteFields[st.FieldIdx]
			fmt.Fprintf(s, "\t%s = %d;\n", f.Accessor, st.Val)
		case StructOpsStmtArith:
			fmt.Fprintf(s, "\t%s %s = %s %s %d;\n",
				st.CType, st.Var, st.SrcVar, st.Op, st.Val)
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
				fmt.Fprintf(s, "\t%s(%s);\n", kf.Name, argList)
			} else {
				// kfunc with a result -- bind to a typed local.
				fmt.Fprintf(s, "\t%s %s = %s(%s);\n",
					st.CType, st.Var, kf.Name, argList)
			}
			if st.NullGuard {
				// Mandatory KF_RET_NULL pointer guard -- emitted
				// IMMEDIATELY after the call so the local is only
				// ever used after the verifier sees it null-checked.
				fmt.Fprintf(s, "\tif (!%s)\n", st.Var)
				fmt.Fprintf(s, "\t\treturn -1;\n")
			}
		}
	}
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
