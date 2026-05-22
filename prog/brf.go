package prog

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

type BpfRuntimeFuzzer struct {
	isEnabled     bool
	workDir       string

	helperFuncMap map[string]*BpfHelper
	progTypeMap   map[BpfProgTypeEnum]*BpfProgType
	ctxAccessMap  map[BpfProgTypeEnum]*BpfCtxAccess
}

func NewBpfRuntimeFuzzer(enable bool) *BpfRuntimeFuzzer {
	brf := new(BpfRuntimeFuzzer)

	if (!enable) {
		return brf
	}

	brf.workDir = "/mnt/brf_work_dir"
	err := mountBrfWorkDir(brf.workDir)
	if (err != nil) {
		fmt.Printf("⚠️ BRF Debug: Mount failed, but continuing with local directory: %v\n", err)
		// Don't fail completely - we can still use the local directory
		// The mount is only needed for VM sharing, not for local file operations
	}

	fmt.Printf("BRF Debug: Setting brf.isEnabled to true!\n")
	brf.isEnabled = true
	brf.helperFuncMap = make(map[string]*BpfHelper)
	brf.progTypeMap = make(map[BpfProgTypeEnum]*BpfProgType)
	brf.ctxAccessMap = make(map[BpfProgTypeEnum]*BpfCtxAccess)

	brf.InitFromSrc(HelperFuncMap, ProgTypeMap, CtxAccessMap)

	return brf
}

func mountBrfWorkDir(dir string) error {
	var timeout time.Duration = 10000000000

	// Check if directory already exists
	if _, err := os.Stat(dir); err == nil {
		fmt.Printf("🔍 BRF Debug: Work directory already exists: %s\n", dir)
		// Directory exists, try to mount anyway (might already be mounted)
		args := []string{"-t", "9p", "-o", "trans=virtio,version=9p2000.L", "brf", dir}
		_, err := osutil.RunCmd(timeout, "", "mount", args...)
		if err != nil {
			fmt.Printf("⚠️ BRF Debug: Mount failed (might already be mounted): %v\n", err)
			// Don't fail if mount fails - directory might already be mounted
			return nil
		}
		return nil
	}

	// Directory doesn't exist, create it
	err := os.Mkdir(dir, os.ModeDir)
	if err != nil {
		fmt.Printf("❌ BRF Debug: Failed to create brf work dir: %v\n", err)
		return err
	}
	fmt.Printf("✅ BRF Debug: Created work directory: %s\n", dir)

	args := []string{"-t", "9p", "-o", "trans=virtio,version=9p2000.L", "brf", dir}
	_, err = osutil.RunCmd(timeout, "", "mount", args...)
	if err != nil {
		fmt.Printf("❌ BRF Debug: Failed to mount brf work dir: %v\n", err)
		return err
	}
	fmt.Printf("✅ BRF Debug: Successfully mounted work directory\n")
	return nil
}

func (brf *BpfRuntimeFuzzer) IsEnabled() bool {
	return brf.isEnabled
}

func (brf *BpfRuntimeFuzzer) GenPrologue(r *randGen, s *state, prog *Prog) {
	fmt.Printf("🔍 BRF Debug: GenPrologue called, isEnabled: %v\n", brf.isEnabled)

	var p *BpfProg

	if !brf.isEnabled {
		fmt.Printf("❌ BRF Debug: GenPrologue returning early - BRF is disabled\n")
		return
	}

	fmt.Printf("✅ BRF Debug: BRF is enabled, generating seed BPF program...\n")
	p = brf.genSeedBpfProg(r)

	if p == nil {
		fmt.Printf("❌ BRF Debug: Failed to generate seed BPF program\n")
		return
	}

	fmt.Printf("✅ BRF Debug: Successfully generated BPF program at: %s\n", p.BasePath)

	// BRF Phase 3, Stage D2: a generated struct_ops MPTCP scheduler
	// takes a different prologue.  It is loaded + registered (the
	// executor's syz_bpf_prog_attach detects the struct_ops map and
	// does bpf_map__attach_struct_ops + scheduler-sysctl select), then
	// MPTCP traffic is driven so the kernel runs the scheduler's
	// get_send on the send path.  There is no BPF_PROG_TEST_RUN for a
	// struct_ops program -- the callbacks run from the MPTCP stack.
	if p.isStructOps() {
		brf.genStructOpsPrologue(r, s, prog, p)
		return
	}

	c0 := genBpfProgOpenCall(r, s, p)
	s.analyze(c0)
	prog.Calls = append(prog.Calls, c0)
	fmt.Printf("✅ BRF Debug: Added syz_bpf_prog_open call\n")

	c1 := genBpfProgLoadCall(r, s, p)
	s.analyze(c1)
	prog.Calls = append(prog.Calls, c1)
	fmt.Printf("✅ BRF Debug: Added syz_bpf_prog_load call\n")

	c2 := genBpfProgAttachCall(r, s, p)
	s.analyze(c2)
	prog.Calls = append(prog.Calls, c2)
	fmt.Printf("✅ BRF Debug: Added syz_bpf_prog_attach call\n")

	c3 := genBpfProgTestRunCall(r, s, p, c1.Ret)
	s.analyze(c3)
	prog.Calls = append(prog.Calls, c3)
	fmt.Printf("✅ BRF Debug: Added bpf$BPF_PROG_TEST_RUN call\n")

	fmt.Printf("✅ BRF Debug: GenPrologue completed successfully with %d calls\n", len(prog.Calls))
}

// genStructOpsPrologue wires a generated struct_ops MPTCP scheduler
// into the syz program (BRF Phase 3, Stage D2).  Sequence:
//
//	syz_bpf_prog_open    -- bpf_object__open the generated .o
//	syz_bpf_prog_load    -- bpf_object__load (+ Stage D3 name uniquify)
//	syz_bpf_prog_attach  -- struct_ops detected -> bpf_map__attach_struct_ops
//	                        + select via /proc/sys/net/mptcp/scheduler
//	syz_mptcp_pair_init  -- establish an MP_CAPABLE pair
//	syz_mptcp_drive_traffic -- send data so the kernel runs get_send
//
// open/load/attach reuse the existing helpers (object-type-agnostic;
// the executor's syz_bpf_prog_attach does the struct_ops branching).
// The pair resource from pair_init is threaded into drive_traffic the
// way genBpfProgTestRunCall threads the load call's fd result.
func (brf *BpfRuntimeFuzzer) genStructOpsPrologue(r *randGen, s *state, prog *Prog, p *BpfProg) {
	c0 := genBpfProgOpenCall(r, s, p)
	s.analyze(c0)
	prog.Calls = append(prog.Calls, c0)
	fmt.Printf("✅ BRF Debug: [struct_ops] Added syz_bpf_prog_open call\n")

	c1 := genBpfProgLoadCall(r, s, p)
	s.analyze(c1)
	prog.Calls = append(prog.Calls, c1)
	fmt.Printf("✅ BRF Debug: [struct_ops] Added syz_bpf_prog_load call\n")

	c2 := genBpfProgAttachCall(r, s, p)
	s.analyze(c2)
	prog.Calls = append(prog.Calls, c2)
	fmt.Printf("✅ BRF Debug: [struct_ops] Added syz_bpf_prog_attach call\n")

	c3 := genMptcpPairInitCall(r, s)
	s.analyze(c3)
	prog.Calls = append(prog.Calls, c3)
	fmt.Printf("✅ BRF Debug: [struct_ops] Added syz_mptcp_pair_init call\n")

	c4 := genMptcpDriveTrafficCall(r, s, c3.Ret)
	s.analyze(c4)
	prog.Calls = append(prog.Calls, c4)
	fmt.Printf("✅ BRF Debug: [struct_ops] Added syz_mptcp_drive_traffic call\n")

	fmt.Printf("✅ BRF Debug: GenPrologue (struct_ops) completed with %d calls\n",
		len(prog.Calls))
}

// genMptcpPairInitCall builds a syz_mptcp_pair_init call: establish an
// MP_CAPABLE pair on loopback so the generated scheduler has live
// MPTCP state to run against.  All four args (server_addr, client_addr,
// init_flags, out_state) are simple ptr/flags args generated by the
// generic generator.  The call's Ret is the mptcp_pair resource.
func genMptcpPairInitCall(r *randGen, s *state) *Call {
	meta := r.target.SyscallMap["syz_mptcp_pair_init"]
	args := make([]Arg, len(meta.Args))
	c := MakeCall(meta, nil)

	for i, field := range meta.Args {
		args[i], _ = r.generateArg(s, field.Type, field.Dir(DirIn))
	}

	c.Args = args
	r.target.assignSizesCall(c)
	return c
}

// genMptcpDriveTrafficCall builds a syz_mptcp_drive_traffic call: send
// data through the established pair so the kernel's MPTCP send path
// invokes the registered scheduler's get_send.  The `pair` arg (a
// resource) is threaded from pair_init's Ret; every other arg
// (subflow_id, data ptr, data_len bytesize, map_mut flags) is generated
// generically.  Mirrors genBpfProgTestRunCall's resource threading.
func genMptcpDriveTrafficCall(r *randGen, s *state, pair *ResultArg) *Call {
	meta := r.target.SyscallMap["syz_mptcp_drive_traffic"]
	args := make([]Arg, len(meta.Args))
	c := MakeCall(meta, nil)

	for i, field := range meta.Args {
		if resType, ok := field.Type.(*ResourceType); ok {
			// The mptcp_pair resource -- thread the pair_init
			// result rather than generating a fresh value.
			args[i] = MakeResultArg(resType, field.Dir(DirIn), pair, 0)
			continue
		}
		args[i], _ = r.generateArg(s, field.Type, field.Dir(DirIn))
	}

	c.Args = args
	r.target.assignSizesCall(c)
	return c
}

func genBpfProgOpenCall(r *randGen, s *state, p *BpfProg) *Call {
	meta := r.target.SyscallMap["syz_bpf_prog_open"]
	args := make([]Arg, len(meta.Args))
	c := MakeCall(meta, nil)

	pathStr := []byte(p.BasePath + ".o")
	pathArg := meta.Args[0]
	pathPtr := pathArg.Type.(*PtrType)
	pathBuffer := pathPtr.Elem.(*BufferType)
	pathBufferDir := pathPtr.ElemDir
	pathBufferArg := MakeDataArg(pathBuffer, pathBufferDir, pathStr)
	args[0] = r.allocAddr(s, pathArg.Type, pathArg.Dir(DirIn), pathBufferArg.Size(), pathBufferArg)

	c.Args = args
	r.target.assignSizesCall(c)
	return c
}

func genBpfProgLoadCall(r *randGen, s *state, p *BpfProg) *Call {
	meta := r.target.SyscallMap["syz_bpf_prog_load"]
	args := make([]Arg, len(meta.Args))
	c := MakeCall(meta, nil)

	pathStr := []byte(p.BasePath + ".o")
	pathArg := meta.Args[0]
	pathPtr := pathArg.Type.(*PtrType)
	pathBuffer := pathPtr.Elem.(*BufferType)
	pathBufferDir := pathPtr.ElemDir
	pathBufferArg := MakeDataArg(pathBuffer, pathBufferDir, pathStr)
	args[0] = r.allocAddr(s, pathArg.Type, pathArg.Dir(DirIn), pathBufferArg.Size(), pathBufferArg)
	args[1], _ = r.generateArg(s, meta.Args[1].Type, meta.Args[1].Dir(DirIn))

	c.Args = args
	r.target.assignSizesCall(c)
	return c
}

func genBpfProgAttachCall(r *randGen, s *state, p *BpfProg) *Call {
	meta := r.target.SyscallMap["syz_bpf_prog_attach"]
	args := make([]Arg, len(meta.Args))
	c := MakeCall(meta, nil)

	pathStr := []byte(p.BasePath + ".o")
	pathArg := meta.Args[0]
	pathPtr := pathArg.Type.(*PtrType)
	pathBuffer := pathPtr.Elem.(*BufferType)
	pathBufferDir := pathPtr.ElemDir
	pathBufferArg := MakeDataArg(pathBuffer, pathBufferDir, pathStr)
	args[0] = r.allocAddr(s, pathArg.Type, pathArg.Dir(DirIn), pathBufferArg.Size(), pathBufferArg)

	c.Args = args
	r.target.assignSizesCall(c)
	return c
}

func genBpfProgTestRunCall(r *randGen, s *state, p *BpfProg, fd *ResultArg) *Call {
	meta := r.target.SyscallMap["bpf$BPF_PROG_TEST_RUN"]
	args := make([]Arg, len(meta.Args))
	c := MakeCall(meta, nil)

	cmdArg := meta.Args[0]
	args[0], _ = r.generateArg(s, cmdArg.Type, cmdArg.Dir(DirIn))

	testProgArg := meta.Args[1]
	testProgPtr := testProgArg.Type.(*PtrType)
	testProgStruct := testProgPtr.Elem.(*StructType)
	testProgStructDir := testProgPtr.ElemDir

	testProgStructFields := make([]Arg, len(testProgStruct.Fields))
	for i, field := range testProgStruct.Fields {
		if i == 0 {
			resArg := field
			resType := resArg.Type.(*ResourceType)
			testProgStructFields[i] = MakeResultArg(resType, resArg.Dir(DirIn), fd, 0)
		} else {
			testProgStructFields[i], _ = r.generateArg(s, field.Type, field.Dir(DirIn))
		}
	}

	testProgStructArg := MakeGroupArg(testProgStruct, testProgStructDir, testProgStructFields)
	args[1] = r.allocAddr(s, testProgArg.Type, testProgArg.Dir(DirIn), testProgStructArg.Size(), testProgStructArg)

	lenArg := meta.Args[2]
	args[2], _ = r.generateArg(s, lenArg.Type, lenArg.Dir(DirIn))

	c.Args = args
	r.target.assignSizesCall(c)
	return c
}

// brfWorkDirCapBytes is the soft cap for /mnt/brf_work_dir.  Once
// struct_ops generation runs, every generated program leaves a
// .c/.o/.gob triple behind; without pruning the dir grows unbounded
// (the design doc records it at 73 GB of stale artifacts).  pruneWorkDir
// sweeps oldest-first back under this cap.  4 GiB is generous enough
// that recently-generated artifacts (the ones still likely referenced
// by an active corpus program) survive, while stale ones are reclaimed.
const brfWorkDirCapBytes = int64(4) << 30

// pruneWorkDir keeps brf.workDir under brfWorkDirCapBytes by deleting
// the oldest generated-program artifacts (prog_*.c / .o / .gob) first.
// BRF Phase 3, Stage D4.
//
// Safety:
//   - Only files matching the generator's own prog_* naming are
//     touched; vmlinux.h, the hand-written executor/bpf_progs scaffold
//     and anything else in the dir are never swept.
//   - Oldest-first: the most recently generated artifacts -- the ones
//     a live corpus program is most likely to still reference by path
//     -- are the last to go.
//   - Best-effort: any error (stat / readdir / remove) is logged and
//     pruning stops; it never fails program generation.
//   - Not called on every generation -- only when the dir is over cap.
func (brf *BpfRuntimeFuzzer) pruneWorkDir() {
	dir := brf.workDir
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Printf("⚠️ BRF Debug: pruneWorkDir: ReadDir %s: %v\n", dir, err)
		return
	}

	type artifact struct {
		path  string
		size  int64
		mtime time.Time
	}
	var arts []artifact
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Only the generator's own artifacts.  prog_<hex>.{c,o,gob}
		// (and the useTestSrc test_prog.* variant) are generated;
		// everything else (vmlinux.h, scaffolds) is left alone.
		isProg := strings.HasPrefix(name, "prog_") ||
			strings.HasPrefix(name, "test_prog.")
		if !isProg {
			continue
		}
		if !strings.HasSuffix(name, ".c") &&
			!strings.HasSuffix(name, ".o") &&
			!strings.HasSuffix(name, ".gob") {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		arts = append(arts, artifact{
			path:  filepath.Join(dir, name),
			size:  info.Size(),
			mtime: info.ModTime(),
		})
		total += info.Size()
	}

	if total <= brfWorkDirCapBytes {
		return
	}
	fmt.Printf("🔍 BRF Debug: pruneWorkDir: %d artifacts, %d bytes "+
		"(cap %d) -- sweeping oldest-first\n",
		len(arts), total, brfWorkDirCapBytes)

	// Oldest first.
	sort.Slice(arts, func(i, j int) bool {
		return arts[i].mtime.Before(arts[j].mtime)
	})

	for _, a := range arts {
		if total <= brfWorkDirCapBytes {
			break
		}
		if err := os.Remove(a.path); err != nil {
			fmt.Printf("⚠️ BRF Debug: pruneWorkDir: remove %s: %v\n",
				a.path, err)
			return
		}
		total -= a.size
	}
	fmt.Printf("✅ BRF Debug: pruneWorkDir: swept down to %d bytes\n", total)
}

func (brf *BpfRuntimeFuzzer) genSeedBpfProg(r *randGen) *BpfProg {
	fmt.Printf("🔍 BRF Debug: genSeedBpfProg called\n")
	var opt BrfGenProgOpt
	var p *BpfProg
	var ok bool

//	opt.useTestSrc = true
	opt.genProgAttempt = 20
	opt.basePath = brf.workDir
	fmt.Printf("🔍 BRF Debug: Using basePath: %s\n", opt.basePath)

	// BRF Phase 3, Stage D4: keep /mnt/brf_work_dir bounded.  Each
	// generated program leaves a .c/.o/.gob triple; sweep the oldest
	// back under the cap before generating the next.  Cheap when the
	// dir is under cap (one ReadDir), so safe to call every time.
	brf.pruneWorkDir()

	for i := 0; i < opt.genProgAttempt; i++ {
		fmt.Printf("🔍 BRF Debug: Attempt %d/%d to generate BPF program\n", i+1, opt.genProgAttempt)

		if p, ok = brf.GenBpfProg(r, opt); !ok {
			fmt.Printf("❌ BRF Debug: GenBpfProg failed on attempt %d\n", i+1)
			continue
		}
		fmt.Printf("✅ BRF Debug: GenBpfProg succeeded on attempt %d\n", i+1)

		p.FixRef(r)
		p.FixSpinLock(r)

		if err := p.writeCSource(); err != nil {
			fmt.Printf("❌ BRF Debug: Failed to write C source: %v\n", err)
			return nil
		}
		fmt.Printf("✅ BRF Debug: Successfully wrote C source to: %s.c\n", p.BasePath)

		if err := p.writeGob(); err != nil {
			fmt.Printf("❌ BRF Debug: Failed to serialize program: %v\n", err)
			return nil
		}
		fmt.Printf("✅ BRF Debug: Successfully wrote serialized data to: %s.gob\n", p.BasePath)

		if err := brf.compileBpfProg(p); err != nil {
			fmt.Printf("❌ BRF Debug: Failed to compile BPF program: %v\n", err)
			continue
		}
		fmt.Printf("✅ BRF Debug: Successfully compiled BPF program to: %s.o\n", p.BasePath)
		return p
	}
	fmt.Printf("❌ BRF Debug: Failed to generate BPF program after %d attempts\n", opt.genProgAttempt)
	return nil
}

func (brf *BpfRuntimeFuzzer) mutSeedBpfProg(r *randGen, path string) *BpfProg {
	var opt BrfGenProgOpt
	var p *BpfProg

//	opt.useTestSrc = true
	opt.genProgAttempt = 20
	opt.basePath = brf.workDir

	p = NewBpfProg(nil, nil, opt)
	p.readGob(path)
	p.pt = brf.progTypeMap[p.TypeEnum]

	for i := 0; i < opt.genProgAttempt; i++ {
		for ok := false; !ok; {
			ok = brf.MutBpfProg(r, p, opt)
		}
		p.FixRef(r)
		p.FixSpinLock(r)

		if err := p.writeCSource(); err != nil {
			fmt.Printf("failed to write bpf program c source: %v\n", err)
			return nil
		}

		if err := p.writeGob(); err != nil {
			fmt.Printf("failed to serialize bpf program: %v\n", err)
			return nil
		}

		if err := brf.compileBpfProg(p); err != nil {
			fmt.Printf("failed to compile bpf program: %v\n", err)
			continue
		}
		return p
	}
	return nil
}

func (brf *BpfRuntimeFuzzer) genBpfProg(r *randGen, opt BrfGenProgOpt) (*BpfProg, bool) {
	p := newBpfProg(r, opt)

	return p, true
}

func (brf *BpfRuntimeFuzzer) mutBpfProg(r *randGen, p *BpfProg, opt BrfGenProgOpt) bool {
	return true
}

func (brf *BpfRuntimeFuzzer) compileBpfProg(p *BpfProg) error {
	var timeout time.Duration = 10000000000
	// clang-21 is resolved via PATH: BRF's BPF generator needs a
	// recent clang (-mcpu=v3, BTF emission).  The previous hardcoded
	// Fedora-docker path (/home/user/llvm-project/...) does not exist
	// on the dev_env host, which has clang-21 in /usr/local/bin.
	cmd := exec.Command("clang-21", "-g", "-D__TARGET_ARCH_x86", "-mlittle-endian",
		"-idirafter", "/usr/local/include",
		"-idirafter", "/usr/local/llvm/include",
		"-idirafter", "/usr/include/x86_64-linux-gnu",
		"-idirafter", "/usr/include",
		"-Wno-compare-distinct-pointer-types",
		"-Wno-int-conversion",
		"-O2", "-target", "bpf", "-mcpu=v3",
		"-c", p.BasePath + ".c",
		"-o", p.BasePath + ".o")
	cmd.Dir = brf.workDir

	_, err := osutil.Run(timeout, cmd)
	return err
}
