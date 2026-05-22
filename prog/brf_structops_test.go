// Copyright 2026 Mpiric.  Apache 2 LICENSE -- see LICENSE.
//
// BRF Phase 3, Stage C-minimal verification test.  Builds a generated
// MPTCP struct_ops scheduler BpfProg and renders it, asserting the
// structural invariants the kernel verifier and bpf_struct_ops loader
// require.  This is the in-tree compile + render check for
// prog/brf_structops.go.  The clang-compile + VM/verifier pass is the
// separate follow-up (see executor/bpf_progs/README.md).
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
}
