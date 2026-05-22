package prog

// BRF Phase 3, Stage C-minimal -- generation and rendering of a fuzzed
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
// `struct mptcp_subflow_context.avg_pacing_rate`.  Arbitrary kfunc-call
// generation is Stage C-full and out of scope here.

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
// CDecl is the full `extern ... __ksym;` declaration text.
type BpfKfunc struct {
	Name  string
	CDecl string
}

// mptcpSchedKfuncs are the kfuncs used by the FIXED get_send skeleton.
// net/mptcp/bpf.c registers nine MPTCP kfuncs in total; Stage C-minimal
// only emits the two the fixed prologue/epilogue needs.  Stage C-full
// would model and generate calls to the remaining seven.
var mptcpSchedKfuncs = []BpfKfunc{
	{
		Name: "bpf_mptcp_subflow_ctx",
		CDecl: "extern struct mptcp_subflow_context *\n" +
			"bpf_mptcp_subflow_ctx(const struct sock *sk) __ksym;",
	},
	{
		Name: "mptcp_subflow_set_scheduled",
		CDecl: "extern void\n" +
			"mptcp_subflow_set_scheduled(struct mptcp_subflow_context *subflow,\n" +
			"\t\t\t    bool scheduled) __ksym;",
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
)

// StructOpsStmt is one statement of the BRF-generated get_send body.
// All fields are exported so a StructOpsProg gob-serializes cleanly
// alongside the rest of BpfProg.
type StructOpsStmt struct {
	Kind StructOpsStmtKind
	// Field index into the program's WriteFields slice -- valid for
	// CtxRead and CtxWrite.
	FieldIdx int
	// Var is the local declared by CtxRead / Arith (e.g. "s0").
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
}

// StructOpsProg is the per-program model of a generated MPTCP struct_ops
// scheduler.  It hangs off BpfProg.StructOps and is what
// genStructOpsSource renders.  It is intentionally small: a scheduler
// name, the writable-field table the body draws on, and the generated
// get_send body.  init/release are empty for Stage C-minimal.
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

// genStructOpsBody generates the BRF body of the get_send callback: a
// short, randomly-ordered sequence of ctx reads, ctx writes (the write
// primitive), and arithmetic over the read locals.  The fixed kfunc
// prologue/epilogue is added by genStructOpsSource, not here -- this is
// purely the generated middle.
func genStructOpsBody(r *randGen, sop *StructOpsProg, varId *int) []StructOpsStmt {
	var body []StructOpsStmt
	// readVars tracks (local name, C type) of locals available as
	// arithmetic operands.
	type readVar struct {
		name  string
		ctype string
	}
	var readVars []readVar

	nStmt := 2 + r.Intn(6) // 2..7 statements
	for i := 0; i < nStmt; i++ {
		// Bias toward a write at least once so the headline
		// primitive is reliably exercised; otherwise pick freely.
		kind := StructOpsStmtKind(r.Intn(3))
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

		switch kind {
		case StructOpsStmtCtxRead:
			fi := r.Intn(len(sop.WriteFields))
			v := fmt.Sprintf("s%d", *varId)
			*varId++
			body = append(body, StructOpsStmt{
				Kind:     StructOpsStmtCtxRead,
				FieldIdx: fi,
				Var:      v,
				CType:    sop.WriteFields[fi].CType,
			})
			readVars = append(readVars, readVar{v, sop.WriteFields[fi].CType})
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
	fmt.Fprintf(s, "/* MPTCP scheduler kfuncs (net/mptcp/bpf.c). */\n")
	for _, kf := range sop.Kfuncs {
		fmt.Fprintf(s, "%s\n", kf.CDecl)
	}
	fmt.Fprintf(s, "\n")

	// init / release -- empty for Stage C-minimal.
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

	fmt.Printf("\n%v\n", s)
	return s.String()
}
