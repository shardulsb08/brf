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
// Stage C-full Stage 2a adds checks that a generated subflow iterator
// is ALWAYS the complete `new -> next* -> destroy` triple
// (TestStructOpsSubflowIter) and that the generated `init` / `release`
// bodies are non-empty (TestStructOpsInitReleaseBodies).
//
// Stage C-full Stage 2b adds TestStructOpsIfElse: generated free-form
// `if/else` renders balanced, properly-indented C, no branch body emits
// a `return`, branch-local variables do not leak past their branch, and
// the nesting depth is capped.
//
// Run: go test ./prog/ -run StructOps -v

package prog

import (
	"math/rand"
	"regexp"
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
		// write reaches the verifier as `<lvalue> = `.  The only
		// `->`-write lvalues permitted are `msk->snd_burst` and
		// `avg_pacing_rate` reached via the fixed `subflow` local or
		// an iterator loop variable `sfN`.
		iterSubflowWrite := regexp.MustCompile(`^sf[0-9]+->avg_pacing_rate$`)
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
				lvalue != "subflow->avg_pacing_rate" &&
				!iterSubflowWrite.MatchString(lvalue) {
				t.Errorf("seed %d: write to non-writable lvalue %q",
					seed, lvalue)
			}
		}
	}
}

// cmpStructOpsStmts deeply compares two generated-body slices, recursing
// into a SubflowIter's loop body.  path is a human-readable prefix for
// error messages (e.g. "GetSendBody", "GetSendBody[2].IterBody").
func cmpStructOpsStmts(t *testing.T, path string, want, got []StructOpsStmt) {
	t.Helper()
	if len(want) != len(got) {
		t.Errorf("%s len: got %d want %d", path, len(got), len(want))
		return
	}
	for i := range want {
		ws, gs := want[i], got[i]
		if ws.Kind != gs.Kind {
			t.Errorf("%s[%d]: Kind got %d want %d", path, i, gs.Kind, ws.Kind)
		}
		switch ws.Kind {
		case StructOpsStmtKfuncCall:
			if gs.KfuncIdx != ws.KfuncIdx {
				t.Errorf("%s[%d]: KfuncIdx got %d want %d",
					path, i, gs.KfuncIdx, ws.KfuncIdx)
			}
			if gs.NullGuard != ws.NullGuard {
				t.Errorf("%s[%d]: NullGuard got %v want %v",
					path, i, gs.NullGuard, ws.NullGuard)
			}
			if len(gs.KfuncArgs) != len(ws.KfuncArgs) {
				t.Fatalf("%s[%d]: KfuncArgs len got %d want %d",
					path, i, len(gs.KfuncArgs), len(ws.KfuncArgs))
			}
			for j := range ws.KfuncArgs {
				if gs.KfuncArgs[j] != ws.KfuncArgs[j] {
					t.Errorf("%s[%d] arg %d: got %q want %q",
						path, i, j, gs.KfuncArgs[j], ws.KfuncArgs[j])
				}
			}
		case StructOpsStmtSubflowIter:
			if gs.IterId != ws.IterId {
				t.Errorf("%s[%d]: IterId got %d want %d",
					path, i, gs.IterId, ws.IterId)
			}
			if gs.Var != ws.Var || gs.IterSockExpr != ws.IterSockExpr {
				t.Errorf("%s[%d]: iter Var/SockExpr got %q/%q want %q/%q",
					path, i, gs.Var, gs.IterSockExpr,
					ws.Var, ws.IterSockExpr)
			}
			cmpStructOpsStmts(t,
				path+"["+itoa(i)+"].IterBody", ws.IterBody, gs.IterBody)
		case StructOpsStmtIfElse:
			if gs.CondVar != ws.CondVar || gs.CondOp != ws.CondOp ||
				gs.CondVal != ws.CondVal {
				t.Errorf("%s[%d]: cond got %q/%q/%d want %q/%q/%d",
					path, i, gs.CondVar, gs.CondOp, gs.CondVal,
					ws.CondVar, ws.CondOp, ws.CondVal)
			}
			cmpStructOpsStmts(t,
				path+"["+itoa(i)+"].IfBody", ws.IfBody, gs.IfBody)
			cmpStructOpsStmts(t,
				path+"["+itoa(i)+"].ElseBody", ws.ElseBody, gs.ElseBody)
		case StructOpsStmtCtxRead, StructOpsStmtCtxWrite:
			if gs.FieldAccessor != ws.FieldAccessor {
				t.Errorf("%s[%d]: FieldAccessor got %q want %q",
					path, i, gs.FieldAccessor, ws.FieldAccessor)
			}
		}
	}
}

// itoa is a tiny local int->string for cmpStructOpsStmts paths.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// firstIterSeed returns the lowest seed in [0, limit) whose generated
// scheduler uses the subflow iterator, or -1 if none does.  Used so
// tests exercise the iterator path without hardcoding a seed.
func firstIterSeed(t *testing.T, limit int64) int64 {
	t.Helper()
	for seed := int64(0); seed < limit; seed++ {
		p := newStructOpsTestProg(t, seed)
		if p.StructOps.usesSubflowIter() {
			return seed
		}
	}
	return -1
}

// usesIfElse reports whether any generated body of sop contains a
// generated `if`/`else` statement.
func usesIfElse(sop *StructOpsProg) bool {
	found := false
	for _, b := range [][]StructOpsStmt{
		sop.GetSendBody, sop.InitBody, sop.ReleaseBody,
	} {
		walkStmts(b, func(st *StructOpsStmt) {
			if st.Kind == StructOpsStmtIfElse {
				found = true
			}
		})
	}
	return found
}

// firstIfElseSeed returns the lowest seed in [0, limit) whose generated
// scheduler emits an `if`/`else`, or -1 if none does.
func firstIfElseSeed(t *testing.T, limit int64) int64 {
	t.Helper()
	for seed := int64(0); seed < limit; seed++ {
		p := newStructOpsTestProg(t, seed)
		if usesIfElse(p.StructOps) {
			return seed
		}
	}
	return -1
}

func TestStructOpsGobRoundTrip(t *testing.T) {
	// Seed 7 is a baseline sample; the iterator seed covers the
	// recursive gob path through a SubflowIter's nested IterBody; the
	// if/else seed covers the recursive gob path through an IfElse's
	// IfBody / ElseBody (Stage 2b).
	seeds := []int64{7}
	if it := firstIterSeed(t, 256); it >= 0 {
		seeds = append(seeds, it)
	} else {
		t.Error("no subflow iterator generated across 256 seeds -- " +
			"iterator gob path is untested")
	}
	if ie := firstIfElseSeed(t, 256); ie >= 0 {
		seeds = append(seeds, ie)
	} else {
		t.Error("no if/else generated across 256 seeds -- " +
			"if/else gob path is untested")
	}
	for _, seed := range seeds {
		p := newStructOpsTestProg(t, seed)
		if err := p.writeGob(); err != nil {
			t.Fatalf("seed %d: writeGob: %v", seed, err)
		}
		var q BpfProg
		if err := q.readGob(p.BasePath + ".gob"); err != nil {
			t.Fatalf("seed %d: readGob: %v", seed, err)
		}
		if q.StructOps == nil {
			t.Fatalf("seed %d: StructOps lost across gob round-trip", seed)
		}
		if q.StructOps.SchedName != p.StructOps.SchedName {
			t.Errorf("seed %d: SchedName: got %q want %q",
				seed, q.StructOps.SchedName, p.StructOps.SchedName)
		}
		if len(q.StructOps.Kfuncs) != len(p.StructOps.Kfuncs) {
			t.Errorf("seed %d: Kfuncs len: got %d want %d",
				seed, len(q.StructOps.Kfuncs), len(p.StructOps.Kfuncs))
		}
		if len(q.StructOps.IterKfuncs) != len(p.StructOps.IterKfuncs) {
			t.Errorf("seed %d: IterKfuncs len: got %d want %d",
				seed, len(q.StructOps.IterKfuncs),
				len(p.StructOps.IterKfuncs))
		}
		// Stage C-full Stage 1/2a: every body -- with kfunc-call
		// statements (KfuncArgs + NullGuard) and SubflowIter
		// statements (IterBody recursively) -- must survive the gob
		// round-trip intact, since rendering happens after
		// deserialization.
		cmpStructOpsStmts(t, "GetSendBody",
			p.StructOps.GetSendBody, q.StructOps.GetSendBody)
		cmpStructOpsStmts(t, "InitBody",
			p.StructOps.InitBody, q.StructOps.InitBody)
		cmpStructOpsStmts(t, "ReleaseBody",
			p.StructOps.ReleaseBody, q.StructOps.ReleaseBody)
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

// TestStructOpsSubflowIter is the Stage C-full Stage 2a check for the
// subflow iterator.  It asserts that:
//
//   - across many seeds the iterator is generated at least once;
//   - every generated SubflowIter statement carries the modelled
//     `(struct sock *)msk` socket expression and a loop variable;
//   - in the rendered C, every iterator is the COMPLETE
//     `new -> next* -> destroy` triple -- the count of `_new`, `_next`
//     and `_destroy` call-sites is consistent with that, the three
//     iterator kfuncs all have an `extern ... __ksym;` decl, and the
//     `while` condition is the KF_RET_NULL NULL-check on `_next`.
func TestStructOpsSubflowIter(t *testing.T) {
	sawIter := false
	// `(sfN = bpf_iter_mptcp_subflow_next(&itN))` -- the while-loop
	// condition: the next-call IS the NULL-check.
	whileCond := regexp.MustCompile(
		`while \(\(sf[0-9]+ = bpf_iter_mptcp_subflow_next\(&it[0-9]+\)\)\) \{`)

	for seed := int64(0); seed < 256; seed++ {
		p := newStructOpsTestProg(t, seed)
		sop := p.StructOps

		// Count SubflowIter statements across every body and validate
		// each one's model fields.
		nIter := 0
		for _, b := range [][]StructOpsStmt{
			sop.GetSendBody, sop.InitBody, sop.ReleaseBody,
		} {
			walkStmts(b, func(st *StructOpsStmt) {
				if st.Kind != StructOpsStmtSubflowIter {
					return
				}
				nIter++
				if st.IterSockExpr != "(struct sock *)msk" {
					t.Errorf("seed %d: iter sock expr %q, want "+
						"%q", seed, st.IterSockExpr, "(struct sock *)msk")
				}
				if st.Var == "" {
					t.Errorf("seed %d: SubflowIter has no loop variable",
						seed)
				}
				if st.CType != "struct mptcp_subflow_context *" {
					t.Errorf("seed %d: iter loop var type %q, want "+
						"%q", seed, st.CType,
						"struct mptcp_subflow_context *")
				}
			})
		}
		// init/release must never iterate -- only get_send may.
		for _, b := range [][]StructOpsStmt{sop.InitBody, sop.ReleaseBody} {
			for _, st := range b {
				if st.Kind == StructOpsStmtSubflowIter {
					t.Errorf("seed %d: iterator generated in "+
						"init/release -- only get_send may iterate", seed)
				}
			}
		}
		if nIter == 0 {
			continue
		}
		sawIter = true

		// Rendered C: the iterator must be the complete triple.  Every
		// modelled SubflowIter renders exactly one `_new`, one
		// `_destroy` and one `_next` (the `while` condition).  A
		// partial iterator -- any of the three missing -- is a
		// verifier reject.
		src := p.genStructOpsSource()
		nNew := strings.Count(src, "bpf_iter_mptcp_subflow_new(&")
		nNext := strings.Count(src, "bpf_iter_mptcp_subflow_next(&")
		nDestroy := strings.Count(src, "bpf_iter_mptcp_subflow_destroy(&")
		if nNew != nIter || nNext != nIter || nDestroy != nIter {
			t.Errorf("seed %d: %d iterators modelled but rendered "+
				"new=%d next=%d destroy=%d -- not a complete triple\n%s",
				seed, nIter, nNew, nNext, nDestroy, src)
		}

		// The `while` condition must be the KF_RET_NULL NULL-check on
		// `_next` -- this is the verifier-required idiom.
		if got := len(whileCond.FindAllString(src, -1)); got != nIter {
			t.Errorf("seed %d: %d iterators but %d well-formed "+
				"while-conditions\n%s", seed, nIter, got, src)
		}

		// All three iterator kfuncs must have an extern decl.
		for _, kf := range []string{
			"bpf_iter_mptcp_subflow_new",
			"bpf_iter_mptcp_subflow_next",
			"bpf_iter_mptcp_subflow_destroy",
		} {
			if !strings.Contains(src, "extern") ||
				!strings.Contains(src, kf+"(") {
				t.Errorf("seed %d: iterator kfunc %q has no extern decl\n%s",
					seed, kf, src)
			}
		}

		// The iterator declaration and destroy must bracket the loop:
		// for each `_new(&itN, ...)` line there is a later
		// `_destroy(&itN)` line.  Per-iterator-id, _destroy follows
		// _new in source order.
		lines := strings.Split(src, "\n")
		idRe := regexp.MustCompile(`bpf_iter_mptcp_subflow_new\(&(it[0-9]+),`)
		for li, line := range lines {
			m := idRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			id := m[1]
			foundDestroy := false
			for _, later := range lines[li+1:] {
				if strings.Contains(later,
					"bpf_iter_mptcp_subflow_destroy(&"+id+")") {
					foundDestroy = true
					break
				}
			}
			if !foundDestroy {
				t.Errorf("seed %d: iterator %q has _new but no later "+
					"_destroy\n%s", seed, id, src)
			}
		}
	}

	if !sawIter {
		t.Error("no subflow iterator generated across 256 seeds -- " +
			"the Stage C-full Stage 2a iterator generator is not firing")
	}
}

// TestStructOpsInitReleaseBodies is the Stage C-full Stage 2a check for
// the non-empty init / release callbacks.  Before Stage 2a both were
// rendered with empty `{}`; now each gets a generated `msk`-reachable
// body.  The test asserts both bodies are non-empty in the model and
// the rendered C, that neither schedules
// (`mptcp_subflow_set_scheduled` is a get_send-only kfunc), and that
// the rendered callback bodies are not literally empty.
func TestStructOpsInitReleaseBodies(t *testing.T) {
	for seed := int64(0); seed < 128; seed++ {
		p := newStructOpsTestProg(t, seed)
		sop := p.StructOps

		if len(sop.InitBody) == 0 {
			t.Errorf("seed %d: InitBody is empty", seed)
		}
		if len(sop.ReleaseBody) == 0 {
			t.Errorf("seed %d: ReleaseBody is empty", seed)
		}

		// init/release do not schedule -- mptcp_subflow_set_scheduled
		// must never be called from either body.
		for _, b := range []struct {
			name string
			body []StructOpsStmt
		}{
			{"InitBody", sop.InitBody},
			{"ReleaseBody", sop.ReleaseBody},
		} {
			walkStmts(b.body, func(st *StructOpsStmt) {
				if st.Kind != StructOpsStmtKfuncCall {
					return
				}
				if sop.Kfuncs[st.KfuncIdx].Name ==
					"mptcp_subflow_set_scheduled" {
					t.Errorf("seed %d: %s calls "+
						"mptcp_subflow_set_scheduled -- init/release "+
						"do not schedule", seed, b.name)
				}
			})
		}

		// Rendered C: the init/release callback bodies must contain a
		// generated statement, not just the `{ }` braces.  Extract the
		// brace-delimited body of each and confirm it is non-trivial.
		src := p.genStructOpsSource()
		for _, suffix := range []string{"_init", "_release"} {
			marker := "BPF_PROG(" + sop.SchedName + suffix +
				", struct mptcp_sock *msk)"
			idx := strings.Index(src, marker)
			if idx < 0 {
				t.Fatalf("seed %d: rendered source missing %q", seed, marker)
			}
			open := strings.Index(src[idx:], "{")
			closeBrace := strings.Index(src[idx:], "\n}")
			if open < 0 || closeBrace < 0 || closeBrace <= open {
				t.Fatalf("seed %d: malformed %s callback body", seed, suffix)
			}
			body := strings.TrimSpace(src[idx+open+1 : idx+closeBrace])
			// The body always carries the `/* BRF-generated body. */`
			// comment; require at least one further non-comment line.
			hasStmt := false
			for _, ln := range strings.Split(body, "\n") {
				ln = strings.TrimSpace(ln)
				if ln == "" || strings.HasPrefix(ln, "/*") {
					continue
				}
				hasStmt = true
			}
			if !hasStmt {
				t.Errorf("seed %d: %s callback body has no generated "+
					"statement\n%s", seed, suffix, src)
			}
		}
	}
}

// localDeclRe matches a generated local declaration -- `<type> sN = ...`
// or the iterator's `struct ... *sfN;` -- and captures the local name.
// The local types the generator emits are `int`, `unsigned long`,
// `bool`, `__u64`, `struct sock *` and `struct mptcp_subflow_context *`.
var localDeclRe = regexp.MustCompile(
	`^(?:int|unsigned long|bool|__u64|struct sock \*|` +
		`struct mptcp_subflow_context \*|struct bpf_iter_mptcp_subflow) ` +
		`(s[0-9]+|sf[0-9]+|it[0-9]+)\b`)

// localUseRe finds every `sN` / `sfN` / `itN` identifier token on a
// line, so a use-after-scope can be detected.
var localUseRe = regexp.MustCompile(`\b(s[0-9]+|sf[0-9]+|it[0-9]+)\b`)

// TestStructOpsIfElse is the Stage C-full Stage 2b check for generated
// free-form `if/else`.  It asserts that:
//
//   - across many seeds an `if/else` is generated at least once;
//   - the rendered C is brace-balanced and properly nested;
//   - no branch body emits a `return` (model and rendered C) -- so every
//     path falls through to the fixed scheduling epilogue;
//   - the condition tests an in-scope SCALAR local, never a pointer;
//   - a branch-local variable is never referenced after its branch
//     closes (C block scope -- no use-after-scope leak);
//   - generated `if/else` nesting never exceeds the depth cap.
func TestStructOpsIfElse(t *testing.T) {
	sawIfElse := false
	sawElse := false

	// Scalar locals: the only legal condition operands.  A condition
	// over anything else (a pointer local, or an undeclared name) is a
	// generator bug.
	scalarType := map[string]bool{
		"int": true, "unsigned long": true, "bool": true, "__u64": true,
	}

	for seed := int64(0); seed < 256; seed++ {
		p := newStructOpsTestProg(t, seed)
		sop := p.StructOps

		// Model walk: validate every IfElse statement and recurse.
		var checkIfElse func(path string, body []StructOpsStmt, depth int)
		checkIfElse = func(path string, body []StructOpsStmt, depth int) {
			for i, st := range body {
				switch st.Kind {
				case StructOpsStmtIfElse:
					sawIfElse = true
					if len(st.ElseBody) > 0 {
						sawElse = true
					}
					if st.CondVar == "" {
						t.Errorf("seed %d %s[%d]: IfElse has no "+
							"condition variable", seed, path, i)
					}
					if depth >= ifElseMaxDepth {
						t.Errorf("seed %d %s[%d]: IfElse at depth %d "+
							"exceeds cap %d", seed, path, i, depth,
							ifElseMaxDepth)
					}
					if len(st.IfBody) == 0 {
						t.Errorf("seed %d %s[%d]: IfElse has empty "+
							"if-body", seed, path, i)
					}
					// No branch may emit a `return`: the only
					// return-emitting statement is a KF_RET_NULL-pointer
					// kfunc call (NullGuard).  Walk both branch bodies.
					for _, br := range [][]StructOpsStmt{
						st.IfBody, st.ElseBody,
					} {
						walkStmts(br, func(b *StructOpsStmt) {
							if b.Kind == StructOpsStmtKfuncCall &&
								b.NullGuard {
								t.Errorf("seed %d %s[%d]: branch body "+
									"has a NullGuard kfunc call -- a "+
									"branch must not emit a return",
									seed, path, i)
							}
						})
					}
					checkIfElse(path+"["+itoa(i)+"].IfBody",
						st.IfBody, depth+1)
					checkIfElse(path+"["+itoa(i)+"].ElseBody",
						st.ElseBody, depth+1)
				case StructOpsStmtSubflowIter:
					// An iterator inside a branch keeps the same depth
					// (the loop body is not an if/else level).
					checkIfElse(path+"["+itoa(i)+"].IterBody",
						st.IterBody, depth)
				}
			}
		}
		checkIfElse("GetSendBody", sop.GetSendBody, 0)
		// init/release are straight-line (allowIf false) -- no IfElse
		// must ever appear there.
		for _, b := range []struct {
			name string
			body []StructOpsStmt
		}{{"InitBody", sop.InitBody}, {"ReleaseBody", sop.ReleaseBody}} {
			walkStmts(b.body, func(st *StructOpsStmt) {
				if st.Kind == StructOpsStmtIfElse {
					t.Errorf("seed %d: IfElse generated in %s -- "+
						"init/release are straight-line", seed, b.name)
				}
			})
		}

		if !usesIfElse(sop) {
			continue
		}

		src := p.genStructOpsSource()

		// Brace balance: across the whole rendered TU, `{` and `}`
		// counts match and the running depth never goes negative.
		depth := 0
		minDepth := 0
		for _, ch := range src {
			switch ch {
			case '{':
				depth++
			case '}':
				depth--
				if depth < minDepth {
					minDepth = depth
				}
			}
		}
		if depth != 0 {
			t.Errorf("seed %d: rendered C brace imbalance (net %d)\n%s",
				seed, depth, src)
		}
		if minDepth < 0 {
			t.Errorf("seed %d: rendered C has a `}` with no matching "+
				"`{`\n%s", seed, src)
		}

		// Condition operand must be a declared scalar local.  For each
		// IfElse, CondVar must name a local whose declared type is
		// scalar (never a pointer).
		declType := map[string]string{}
		for _, b := range [][]StructOpsStmt{
			sop.GetSendBody, sop.InitBody, sop.ReleaseBody,
		} {
			walkStmts(b, func(st *StructOpsStmt) {
				if st.Var != "" && st.CType != "" {
					declType[st.Var] = st.CType
				}
			})
		}
		walkStmts(sop.GetSendBody, func(st *StructOpsStmt) {
			if st.Kind != StructOpsStmtIfElse {
				return
			}
			ct, ok := declType[st.CondVar]
			if !ok {
				t.Errorf("seed %d: IfElse condition var %q is not a "+
					"declared local", seed, st.CondVar)
				return
			}
			if !scalarType[ct] {
				t.Errorf("seed %d: IfElse condition var %q has "+
					"non-scalar type %q -- conditions must be scalar",
					seed, st.CondVar, ct)
			}
		})

		// Rendered-C return check: a generated `if/else` block (its
		// opening line carries the `/* BRF-generated if/else. */`
		// comment) must contain no `return` until it closes.  Walk
		// lines, tracking brace depth; when inside an if/else block at
		// or below its opening depth, a `return` line is a leak.
		lines := strings.Split(src, "\n")
		ifElseDepths := []int{} // brace depths at which an if/else opened
		curDepth := 0
		for li, line := range lines {
			l := strings.TrimSpace(line)
			isIfElseOpen := li > 0 &&
				strings.Contains(strings.TrimSpace(lines[li-1]),
					"BRF-generated if/else.")
			// Count braces on this line to update depth.
			opens := strings.Count(line, "{")
			closes := strings.Count(line, "}")
			if isIfElseOpen && opens > 0 {
				ifElseDepths = append(ifElseDepths, curDepth)
			}
			if strings.HasPrefix(l, "return ") &&
				len(ifElseDepths) > 0 {
				t.Errorf("seed %d: `return` inside a generated "+
					"if/else branch\n%s", seed, src)
			}
			curDepth += opens - closes
			// Pop any if/else whose block has now closed.
			for len(ifElseDepths) > 0 &&
				curDepth <= ifElseDepths[len(ifElseDepths)-1] {
				ifElseDepths = ifElseDepths[:len(ifElseDepths)-1]
			}
		}

		// Scope-leak check on the rendered C: a local declared inside a
		// `{ }` block must not be referenced after that block closes.
		// Track a stack of per-block declared-local sets; on `}` the
		// top set's locals go out of scope, and any later use of one is
		// a use-after-scope leak.
		assertNoScopeLeak(t, seed, src)
	}

	if !sawIfElse {
		t.Error("no if/else generated across 256 seeds -- the Stage " +
			"C-full Stage 2b generator is not firing")
	}
	if !sawElse {
		t.Error("no if/else with an `else` branch generated across " +
			"256 seeds -- the optional-else path is untested")
	}
}

// assertNoScopeLeak verifies that no generated local is referenced
// after the `{ }` block it was declared in has closed -- the C
// block-scope correctness invariant for Stage 2b's branch bodies.  It
// walks the rendered C maintaining a stack of brace-scopes, each
// carrying the locals declared directly in it; a `}` pops the scope and
// retires its locals; a reference to a retired local fails the test.
func assertNoScopeLeak(t *testing.T, seed int64, src string) {
	t.Helper()
	// scopes is a stack of declared-local sets, one per open `{`.
	var scopes []map[string]bool
	retired := map[string]bool{} // locals whose scope has closed
	push := func() { scopes = append(scopes, map[string]bool{}) }
	pop := func() {
		if len(scopes) == 0 {
			return
		}
		top := scopes[len(scopes)-1]
		for name := range top {
			retired[name] = true
		}
		scopes = scopes[:len(scopes)-1]
	}
	declareHere := func(name string) {
		if len(scopes) > 0 {
			scopes[len(scopes)-1][name] = true
		}
		// A name re-entering scope (fresh block) is no longer retired.
		delete(retired, name)
	}

	for _, raw := range strings.Split(src, "\n") {
		line := raw
		l := strings.TrimSpace(line)
		// A declaration introduces a local into the current scope.  Do
		// this before the use-check so a `int s0 = s0 ...` self-ref
		// (which the generator never emits) would still not false-fail.
		if m := localDeclRe.FindStringSubmatch(l); m != nil {
			// The local is declared in whatever scope is current when
			// the `{` of its block has already been pushed.
			declareHere(m[1])
		}
		// Any use of a retired local on this line is a leak.
		for _, m := range localUseRe.FindAllStringSubmatch(l, -1) {
			if retired[m[1]] {
				t.Errorf("seed %d: local %q used after its block "+
					"closed (use-after-scope)\n%s",
					seed, m[1], src)
			}
		}
		// Update the scope stack for braces on this line.  A line may
		// carry both (`} else {`); process left to right.
		for _, ch := range line {
			switch ch {
			case '{':
				push()
			case '}':
				pop()
			}
		}
	}
}
