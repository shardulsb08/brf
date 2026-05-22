# Phase 3 -- BPF struct_ops MPTCP scheduler (build & run)

Hand-written BPF MPTCP scheduler for **Phase 3** of the harness
(audit gap 1 -- the BPF flagship).  Full design and the Stage
B/C/D plan: `../../.claude/designs/mptcp_bpf_sched_phase3.md`.

Files in this directory:

- **`mptcp_sched.bpf.c`** -- the fixed `mptcp_sched_ops` struct_ops
  scheduler (`init` / `release` / `get_send`; always schedules the
  first subflow).  Stage B test vehicle *and* the Stage C scaffold
  (BRF's generator will replace the `get_send` body).  Modelled on
  the kernel's `tools/testing/selftests/bpf/progs/mptcp_bpf_first.c`.
- **`test_mptcp_bpf_sched.c`** -- the Stage B smoke test: libbpf
  load -> register the struct_ops -> select it via sysctl -> drive
  MPTCP traffic over it.

## Stage B -- status: DONE (verified 2026-05-22)

The smoke test passes on the BPF/BTF-enabled fuzzing kernel:

```
PASS: bpf_object__open_file
PASS: bpf_object__load
PASS: find struct_ops map 'brf_sched'
PASS: bpf_map__attach_struct_ops (register)
info: default scheduler was 'default'
PASS: write /proc/sys/net/mptcp/scheduler = brf_sched
PASS: scheduler sysctl reads back 'brf_sched'
PASS: MPTCP connect / accept
PASS: data transfer over brf_sched
result: PASS (BPF struct_ops MPTCP scheduler load + register + select + traffic)
```

## Prerequisites

**Host:** `clang-21` (`/usr/local/bin/clang-21`, v21.1.0 -- a
recent *stock* clang; no custom build needed), `bpftool`
(`/usr/sbin/bpftool`, v7.4.0), and the BTF-enabled fuzzing kernel
(built with `CONFIG_DEBUG_INFO_BTF` via `brf_mptcp_harness.config`).

**VM:** `libbpf-dev` (`apt install libbpf-dev` -- pulls libelf)
and `gcc`.  No clang is needed in the VM for Stage B -- the BPF
object is built on the host.

## Build & run

Paths below are correct as of 2026-05-22.  The kernel build dir
name changes per build -- find the current one with
`ls -t open/build/linux/` or read `kernel_obj` in the syz-manager
config.

### 1. Host -- regenerate vmlinux.h from the fuzzing kernel BTF

```sh
ROOT=/mnt/work_4gb/Dev/mpiric_kernel_dev_env
KBUILD=$ROOT/open/build/linux/2026_05_19_005753_brf_mptcp_v01_first_kmemleak_debug
bpftool btf dump file "$KBUILD/vmlinux" format c > /tmp/vmlinux.h
```

`vmlinux.h` is kernel-version-specific -- regenerate it whenever
the fuzzing kernel is rebuilt.

### 2. Host -- compile the BPF object

Flags match BRF's `compileBpfProg` (`prog/brf.go`):

```sh
BRF=$ROOT/open/src/fuzzing/brf
clang-21 -g -O2 -target bpf -mcpu=v3 -D__TARGET_ARCH_x86 \
  -Wno-compare-distinct-pointer-types -Wno-int-conversion \
  -I/tmp -I"$BRF/executor" \
  -c "$BRF/executor/bpf_progs/mptcp_sched.bpf.c" \
  -o mptcp_sched.bpf.o
```

`-I/tmp` is where vmlinux.h lives; `-I.../executor` resolves
`<bpf/bpf_helpers.h>` to BRF's bundled `executor/bpf/`.  The 8
`-Wmissing-declarations` warnings are a benign `bpftool btf dump`
artifact inside vmlinux.h -- not errors.

### 3. Stage into a VM-visible directory

Copy `mptcp_sched.bpf.o` and `test_mptcp_bpf_sched.c` into a dir
the VM mounts -- the convention used so far:

```
shared/mpiric/027_netdev_0x1a_proposal/work/brf_protocol_fuzz_setup/mptcp_bpf_sched_test/
```

which the VM sees as
`/mnt/host/mpiric/027_netdev_0x1a_proposal/work/brf_protocol_fuzz_setup/mptcp_bpf_sched_test/`.

### 4. VM -- build and run the smoke test

As root, on the fuzzing kernel:

```sh
gcc -O2 -Wall -o test_mptcp_bpf_sched test_mptcp_bpf_sched.c -lbpf -lelf
./test_mptcp_bpf_sched ./mptcp_sched.bpf.o
```

Expect the `PASS` block shown above.

## Notes

- The `.o` carries its own BTF (clang `-g`), so the **VM does not
  need vmlinux.h** -- only the host compile step (2) does.
- `mptcp_sched.bpf.c` is the Stage C scaffold -- keep it minimal;
  BRF's generator replaces the `get_send` body.
- Stage C-minimal and Stage D (executor-driven loading, with BRF
  compiling generated struct_ops schedulers into
  `/mnt/brf_work_dir`) are **done and VM-verified** as of
  2026-05-22 -- the fuzz run confirmed generated struct_ops
  schedulers load, pass the kernel verifier, register and run.
  See `../../.claude/designs/mptcp_bpf_sched_phase3.md` for
  per-stage status.  This directory's smoke test remains the
  Stage B fixed-scheduler floor and the Stage C scaffold.
