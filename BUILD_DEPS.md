# BRF build dependencies (running list)

A scratch log of build-time dependencies and notable environment
quirks we hit while bringing the MPTCP harness up.  Maintained
ad-hoc; **promote to a proper setup script when the list stabilises**
(target: end of v02, once the NFQUEUE mutation infrastructure is
in and we know the full surface).

## Host (Debian trixie / dev_env VM)

```bash
# Build BRF and the in-VM smoke tests
apt-get install -y libbpf-dev libelf-dev libdw-dev libzstd-dev zlib1g-dev

# v02 NFQUEUE mutation work (smoke test side).  Executor side uses
# raw netlink so does not need these.
apt-get install -y libnetfilter-queue-dev libnfnetlink-dev
```

Toolchain:
- Go 1.21+ (Debian trixie ships 1.23.x; fine).
- gcc with `-pie` support (any modern gcc).

## Quirks worked around

| Where it surfaced | Quirk | Workaround |
|-------------------|-------|------------|
| Debian trixie elfutils 0.192-4 | libelf.a internally calls `eu_search_tree_init` / `_fini` but the helper archive providing them is not packaged.  Static linking fails. | `sys/targets/targets.go` switched from `-static-pie` to `-pie` for Linux.  Dynamic linking only.  Restore `-static-pie` when either Debian fixes the packaging or we move distro. |
| Distro libbpf 1.5.0 | Missing `bpf_object__add_kcov_handle` symbol (provided by `kernel_patches/bpf_kcov/0003-...patch` modifications to `tools/lib/bpf/`, which we have deliberately not applied since eBPF revival is parked). | Weak no-op stub in `executor/common_brf_linux.h`.  eBPF kcov coverage becomes a no-op until v06/0003 is applied + libbpf rebuilt; MPTCP harness path is unaffected. |
| `go build` hash step | `error: readlink("dashboard/app/static/common.js"): Too many levels of symbolic links` printed by every build. | Cosmetic only -- the build proceeds.  Stale symlink in BRF's dashboard webroot from the upstream Syzkaller fork.  Not worth fixing until/unless we touch dashboard. |
| `apt-get` package name | Package is `libnetfilter-queue-dev` with a hyphen, not `libnetfilter_queue-dev` with an underscore. | -- |
| Deprecated libnetfilter_queue ritual | `nfq_bind_pf(handle, AF_INET)` returns `EINVAL` on kernel >=7.x (and probably earlier).  The protocol-family bind it used to do is implicit in `nfq_create_queue()` now.  Old man-page examples still show it. | Don't call `nfq_unbind_pf` / `nfq_bind_pf` at all.  See `kernel_patches/mptcp_kcov/test_mp_join_hmac_bitflip.c` for the modern pattern. |

## Kernel config requirements

These are added to `brf_mptcp_harness.config` (Mpiric's
`tools/configs/samples/` + `to_load/` for `apply_configs.sh`).  Listed
here so future contributors who hand-roll a kernel know the surface.

| Config | Why we need it |
|--------|----------------|
| `CONFIG_KCOV=y` | coverage feedback (BRF baseline) |
| `CONFIG_KASAN=y`, `CONFIG_UBSAN=y`, `CONFIG_DEBUG_INFO_DWARF4=y` | sanitizers + symbolisation |
| `CONFIG_LOCKDEP=y`, `CONFIG_PROVE_LOCKING=y` | catch MPTCP locking bugs (MPTCP has three lock layers) |
| `CONFIG_MPTCP=y` (from `mptcp.config`) | the protocol under test |
| `CONFIG_PACKET=y`, `CONFIG_VETH=y` | reserved for future netns + AF_PACKET work, currently unused |
| `CONFIG_NETFILTER_NETLINK_QUEUE=y`, `CONFIG_NETFILTER_XT_TARGET_NFQUEUE=y` | **v02 mutation** -- `nfq_create_queue` fails with `EINVAL` and `iptables -j NFQUEUE` fails to apply without these.  Required for `test_mp_join_hmac_bitflip` and the executor-side NFQUEUE in `syz_mptcp_join_subflow` mutation modes. |

## Runtime quirks (running syz-execprog / syz-executor in the dev_env VM)

Captured alongside build quirks for the same reason -- so the setup-
script promotion later folds these in instead of re-discovering.

| Where it surfaced | Quirk | Workaround |
|-------------------|-------|------------|
| `syz-execprog ... /tmp/prog` from `/mnt/src/fuzzing/brf` (9p mount) | `SYZFAIL: mkswap failed (errno 95: Operation not supported)` -- syz-executor's setup creates `./swap-file` in the cwd, calls `mkswap` + `swapon`; 9p's superblock has no `swap_activate` op so `swapon` returns EOPNOTSUPP regardless of file size. | `cd /root` (or any local-rootfs dir) before running syz-execprog.  Wrapper script does this. |
| Repeat-run noise on stdout | `mkdir(/syzcgroup) failed: 17`, `mount(binfmt_misc) failed: 16`, `write(/proc/sys/fs/binfmt_misc/register) failed: 17` -- the sandbox setup tries to recreate things that survived from a previous run. | `-sandbox=none` -- our MPTCP harness runs in the executor's root namespace, the sandbox isolates from the kernel state we want to fuzz.  Wrapper script defaults to this. |
| `mount -t 9p brf /mnt/brf_work_dir: special device brf does not exist` at executor startup | BRF's eBPF runtime path mounts a 9p share named `brf` for compiled BPF objects.  The dev_env VM only exposes `hostshare` (at `/mnt/host`). | Benign -- BRF logs the failure and falls back to a local directory.  Our MPTCP harness path doesn't use this.  Would matter only if/when we revive eBPF runtime fuzzing. |
| syz-executor invoked directly | `./bin/linux_amd64/syz-executor` and `--help`/`-help` print "unknown command" and exit. | Expected.  syz-executor is meant to be invoked by syz-execprog / syz-fuzzer / syz-manager which pass it specific subcommand verbs (`setup`, `exec`, `cover` etc.).  Use syz-execprog wrapper for direct prog runs. |

### Wrapper script

`/mnt/host/mpiric/027_netdev_0x1a_proposal/work/brf_protocol_fuzz_setup/scripts/run_brf_prog.sh`
folds the above into a single invocation:

```bash
/mnt/host/mpiric/027_netdev_0x1a_proposal/work/brf_protocol_fuzz_setup/scripts/run_brf_prog.sh \
    /mnt/host/mpiric/027_netdev_0x1a_proposal/work/brf_protocol_fuzz_setup/progs/pair_init.prog
```

Env-var overrides: `BRF` (path to BRF tree, default `/mnt/src/fuzzing/brf`),
`REPEAT`, `THREADED`, `DEBUG`.  See the script's header comment for the
full rationale.

Sample progs live alongside in `progs/`.  The first one is
`pair_init.prog` -- single-syscall smoke test for syz_mptcp_pair_init.

## When to promote to a setup script

Triggers:
- We bring on a second human contributor who has to reproduce the env.
- We want CI on the harness build.
- v02 work converges and the dep list stops growing.

Whichever comes first.  Until then this running list is the source
of truth; new lines get added as new deps surface.
