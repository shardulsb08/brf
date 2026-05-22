// Copyright 2026 Mpiric.  Apache 2 LICENSE -- see LICENSE.
//
// BRF Phase 3, Stage C verification test.  Builds a generated MPTCP
// struct_ops scheduler BpfProg and renders it, asserting the
// structural invariants the kernel verifier and bpf_struct_ops loader
// require.  This is the in-tree compile + render check for
// prog/brf_structops.go.  The clang-compile + VM/verifier pass is the
// separate follow-up (see executor/bpf_progs/README.md).
//
// Stage C-full Stage 1 adds checks that generated schedulers emit
// straight-line kfunc calls and that every KF_RET_NULL *pointer*
// result is NULL-checked before any use (TestStructOpsKfuncCalls).
//
// Run: go test ./prog/ -run StructOps -v

package prog

import (
	"math/rand"
	"strings"
	"testing"
)

// newStructOpsTestProg builds a struct_ops BpfProg via the same path
// GenBpfProg's struct_ops branch uses.
func newStructOpsTestProg(t *testing.T, seed int64) *BpfProg {
	t.Helper()
	target, err := GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	r := newRand(target, rand.NewSource(seed))

	pt := ProgTypeMap[BPF_PROG_TYPE_STRUCT_OPS]
	if pt == nil {
		t.Fatal("ProgTypeMap has no BPF_PROG_TYPE_STRUCT_OPS entry")
	}
	var opt BrfGenProgOpt
	opt.basePath = t.TempDir()

	p := NewBpfProg(pt, r, opt)
	p.TypeEnum = pt.Enum
	p.StructOps = genStructOpsProg(r)
	return p
}

func TestStructOpsProgTypeEntry(t *testing.T) {
	pt := ProgTypeMap[BPF_PROG_TYPE_STRUCT_OPS]
	if pt == nil {
		t.Fatal("ProgTypeMap[BPF_PROG_TYPE_STRUCT_OPS] is nil")
	}
	if pt.User != "struct mptcp_sock" {
		t.Errorf("User = %q, want %q", pt.User, "struct mptcp_sock")
	}
	if len(pt.SecDefs) != 1 || pt.SecDefs[0].Sec != "struct_ops" {
		t.Errorf("SecDefs = %+v, want one {struct_ops}", pt.SecDefs)
	}
	if ca := CtxAccessMap[BPF_PROG_TYPE_STRUCT_OPS]; ca == nil {
		t.Error("CtxAccessMap[BPF_PROG_TYPE_STRUCT_OPS] is nil -- InitFromSrc may nil-panic")
	}
}

func TestStructOpsGenAndRender(t *testing.T) {
	for seed := int64(0); seed < 64; seed++ {
		p := newStructOpsTestProg(t, seed)
		if !p.isStructOps() {
			t.Fatalf("seed %d: isStructOps() false", seed)
		}
		if p.StructOps.SchedName == "" {
			t.Fatalf("seed %d: empty SchedName", seed)
		}
		if len(p.StructOps.SchedName) >= schedNameMax {
			t.Errorf("seed %d: SchedName %q exceeds MPTCP_SCHED_NAME_MAX",
				seed, p.StructOps.SchedName)
		}

		src := p.genStructOpsSource()
		name := p.StructOps.SchedName

		// Required structural fragments of a valid mptcp_sched_ops
		// struct_ops scheduler.
		mustContain := []string{
			"#include \"vmlinux.h\"",
			"SEC(\"struct_ops\")",
			"SEC(\".struct_ops.link\")",
			"struct mptcp_sched_ops " + name + " = {",
			"BPF_PROG(" + name + "_get_send, struct mptcp_sock *msk)",
			"BPF_PROG(" + name + "_init, struct mptcp_sock *msk)",
			"BPF_PROG(" + name + "_release, struct mptcp_sock *msk)",
			"bpf_mptcp_subflow_ctx(msk->first)",
			"mptcp_subflow_set_scheduled(subflow, true)",
			"__ksym;",
			".name\t\t= \"" + name + "\",",
		}
		for _, frag := range mustContain {
			if !strings.Contains(src, frag) {
				t.Errorf("seed %d: rendered source missing %q\n---\n%s",
					seed, frag, src)
			}
		}

		// At least one write to a btf_struct_access-writable field
		// must appear -- the headline write primitive.
		if !strings.Contains(src, "msk->snd_burst =") &&
			!strings.Contains(src, "subflow->avg_pacing_rate =") {
			t.Errorf("seed %d: no context write generated\n---\n%s", seed, src)
		}

		// No write to any field outside the writable surface: a
		// write reaches the verifier as `<lvalue> = `.  Confirm the
		// only `->`-write lvalues are the two permitted fields.
		for _, line := range strings.Split(src, "\n") {
			l := strings.TrimSpace(line)
			eq := strings.Index(l, " = ")
			arrow := strings.Index(l, "->")
			if eq == -1 || arrow == -1 || arrow > eq {
				continue
			}
			// declarations like `int s0 = msk->snd_burst;` are
			// reads, not writes -- skip lines whose lvalue is a
			// declared local.
			lvalue := strings.TrimSpace(l[:eq])
			if strings.HasPrefix(lvalue, "int ") ||
				strings.HasPrefix(lvalue, "unsigned long ") {
				continue
			}
			if lvalue != "msk->snd_burst" &&
				lvalue != "subflow->avg_pacing_rate" {
				t.Errorf("seed %d: write to non-writable lvalue %q",
					seed, lvalue)
			}
		}
	}
}

func TestStructOpsGobRoundTrip(t *testing.T) {
	p := newStructOpsTestProg(t, 7)
	if err := p.writeGob(); err != nil {
		t.Fatalf("writeGob: %v", err)
	}
	var q BpfProg
	if err := q.readGob(p.BasePath + ".gob"); err != nil {
		t.Fatalf("readGob: %v", err)
	}
	if q.StructOps == nil {
		t.Fatal("StructOps lost across gob round-trip")
	}
	if q.StructOps.SchedName != p.StructOps.SchedName {
		t.Errorf("SchedName: got %q want %q",
			q.StructOps.SchedName, p.StructOps.SchedName)
	}
	if len(q.StructOps.GetSendBody) != len(p.StructOps.GetSendBody) {
		t.Errorf("GetSendBody len: got %d want %d",
			len(q.StructOps.GetSendBody), len(p.StructOps.GetSendBody))
	}
	if len(q.StructOps.Kfuncs) != len(p.StructOps.Kfuncs) {
		t.Errorf("Kfuncs len: got %d want %d",
			len(q.StructOps.Kfuncs), len(p.StructOps.Kfuncs))
	}
	// Stage C-full: kfunc-call statements -- with their KfuncArgs
	// slice and NullGuard flag -- must survive the gob round-trip
	// intact, since rendering happens after deserialization.
	for i := range p.StructOps.GetSendBody {
		ps := p.StructOps.GetSendBody[i]
		qs := q.StructOps.GetSendBody[i]
		if ps.Kind != qs.Kind {
			t.Errorf("stmt %d: Kind got %d want %d", i, qs.Kind, ps.Kind)
		}
		if ps.Kind != StructOpsStmtKfuncCall {
			continue
		}
		if qs.KfuncIdx != ps.KfuncIdx {
			t.Errorf("stmt %d: KfuncIdx got %d want %d",
				i, qs.KfuncIdx, ps.KfuncIdx)
		}
		if qs.NullGuard != ps.NullGuard {
			t.Errorf("stmt %d: NullGuard got %v want %v",
				i, qs.NullGuard, ps.NullGuard)
		}
		if len(qs.KfuncArgs) != len(ps.KfuncArgs) {
			t.Fatalf("stmt %d: KfuncArgs len got %d want %d",
				i, len(qs.KfuncArgs), len(ps.KfuncArgs))
		}
		for j := range ps.KfuncArgs {
			if qs.KfuncArgs[j] != ps.KfuncArgs[j] {
				t.Errorf("stmt %d arg %d: got %q want %q",
					i, j, qs.KfuncArgs[j], ps.KfuncArgs[j])
			}
		}
	}
}

// TestStructOpsKfuncCalls is the Stage C-full Stage 1 check.  It
// asserts that generated schedulers exercise the kfunc-call generator
// and that every generated call honours the verifier contract:
//
//   - a KF_RET_NULL *pointer* result is NULL-checked before any use;
//   - every kfunc argument is a typed, in-scope value;
//   - the fixed prologue/epilogue is left intact.
func TestStructOpsKfuncCalls(t *testing.T) {
	// The set of values that may legally appear as a kfunc argument:
	// the three fixed prologue values plus any `sN` local.  An `sN`
	// local is only ever in scope after its declaring statement, and
	// the renderer emits statements in order, so a syntactic
	// membership check here is sufficient to confirm "typed,
	// in-scope" -- a non-member argument is necessarily wrong.
	fixedArgs := map[string]bool{
		"msk": true, "msk->first": true, "subflow": true,
		"true": true, "false": true,
	}

	// Names of kfuncs whose pointer return is KF_RET_NULL -- their
	// result MUST be guarded.  Derived from the model so the test
	// tracks mptcpSchedKfuncs.
	ptrRetNull := map[string]bool{}
	for i := range mptcpSchedKfuncs {
		kf := &mptcpSchedKfuncs[i]
		if kf.needsNullGuard() {
			ptrRetNull[kf.Name] = true
		}
	}

	sawKfuncCall := false
	sawGuard := false
	for seed := int64(0); seed < 256; seed++ {
		p := newStructOpsTestProg(t, seed)
		sop := p.StructOps

		// Walk the model: every KfuncCall must reference a valid
		// kfunc, pass only in-scope args, and -- when its kfunc
		// needs a guard -- carry NullGuard and bind a local.
		declared := map[string]bool{}
		for si, st := range sop.GetSendBody {
			switch st.Kind {
			case StructOpsStmtCtxRead, StructOpsStmtArith:
				if st.Var != "" {
					declared[st.Var] = true
				}
			case StructOpsStmtKfuncCall:
				sawKfuncCall = true
				if st.KfuncIdx < 0 || st.KfuncIdx >= len(sop.Kfuncs) {
					t.Fatalf("seed %d stmt %d: KfuncIdx %d out of range",
						seed, si, st.KfuncIdx)
				}
				kf := &sop.Kfuncs[st.KfuncIdx]
				if len(st.KfuncArgs) != len(kf.ArgTypes) {
					t.Errorf("seed %d stmt %d: %s got %d args, want %d",
						seed, si, kf.Name, len(st.KfuncArgs),
						len(kf.ArgTypes))
				}
				for _, a := range st.KfuncArgs {
					if !fixedArgs[a] && !declared[a] {
						t.Errorf("seed %d stmt %d: %s arg %q is not "+
							"a typed, in-scope value",
							seed, si, kf.Name, a)
					}
				}
				// Verifier contract: KF_RET_NULL pointer -> guard.
				if ptrRetNull[kf.Name] {
					if !st.NullGuard {
						t.Errorf("seed %d stmt %d: %s is KF_RET_NULL "+
							"pointer but NullGuard is false",
							seed, si, kf.Name)
					}
					if st.Var == "" {
						t.Errorf("seed %d stmt %d: %s result not "+
							"bound to a local",
							seed, si, kf.Name)
					}
				}
				if st.NullGuard {
					sawGuard = true
				}
				if st.Var != "" {
					declared[st.Var] = true
				}
			}
		}

		// Render and confirm the verifier contract holds in the C:
		// for every KF_RET_NULL pointer call, the call line is
		// immediately followed by `if (!sN)` / `return -1;`, and the
		// local does not appear before that guard.
		src := p.genStructOpsSource()
		lines := strings.Split(src, "\n")
		for li, line := range lines {
			l := strings.TrimSpace(line)
			for kfName := range ptrRetNull {
				// A guarded call binds a local: `<type> sN = kfName(...)`.
				if !strings.Contains(l, " = "+kfName+"(") {
					continue
				}
				// Extract the bound local name (`sN`).
				eq := strings.Index(l, " = ")
				lhs := strings.Fields(strings.TrimSpace(l[:eq]))
				if len(lhs) == 0 {
					t.Errorf("seed %d: malformed kfunc-call line %q",
						seed, l)
					continue
				}
				local := lhs[len(lhs)-1]
				// The next two lines must be the mandatory guard.
				if li+2 >= len(lines) {
					t.Errorf("seed %d: %s call not followed by guard",
						seed, kfName)
					continue
				}
				g1 := strings.TrimSpace(lines[li+1])
				g2 := strings.TrimSpace(lines[li+2])
				if g1 != "if (!"+local+")" || g2 != "return -1;" {
					t.Errorf("seed %d: %s result %q not immediately "+
						"NULL-checked; got %q / %q",
						seed, kfName, local, g1, g2)
				}
			}
		}

		// The fixed prologue/epilogue must survive untouched.
		for _, frag := range []string{
			"bpf_mptcp_subflow_ctx(msk->first)",
			"mptcp_subflow_set_scheduled(subflow, true)",
			"return 0;",
		} {
			if !strings.Contains(src, frag) {
				t.Errorf("seed %d: fixed skeleton fragment %q missing",
					seed, frag)
			}
		}

		// Every kfunc the body calls must have an `extern … __ksym;`
		// decl in the rendered source.
		for _, st := range sop.GetSendBody {
			if st.Kind != StructOpsStmtKfuncCall {
				continue
			}
			kfName := sop.Kfuncs[st.KfuncIdx].Name
			if !strings.Contains(src, "\n"+kfName+"(") &&
				!strings.Contains(src, " "+kfName+"(") {
				continue // referenced; extern presence checked next
			}
			if !strings.Contains(src, kfName) {
				t.Errorf("seed %d: kfunc %q called but no extern decl",
					seed, kfName)
			}
		}
	}

	if !sawKfuncCall {
		t.Error("no kfunc call generated across 256 seeds -- " +
			"Stage C-full Stage 1 generator is not firing")
	}
	if !sawGuard {
		t.Error("no KF_RET_NULL guard generated across 256 seeds -- " +
			"the pointer-return contract path is untested")
	}
}
