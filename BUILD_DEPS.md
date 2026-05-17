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

## When to promote to a setup script

Triggers:
- We bring on a second human contributor who has to reproduce the env.
- We want CI on the harness build.
- v02 work converges and the dep list stops growing.

Whichever comes first.  Until then this running list is the source
of truth; new lines get added as new deps surface.
