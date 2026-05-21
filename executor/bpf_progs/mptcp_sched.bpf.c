// SPDX-License-Identifier: GPL-2.0
/*
 * BRF Phase 3 -- fixed MPTCP BPF struct_ops packet scheduler.
 *
 * Stage B test vehicle: proves the load / register / select path
 * for a bpf_struct_ops mptcp_sched_ops scheduler end to end.  Also
 * the Stage C scaffold -- BRF's program generator will replace the
 * get_send body with generated statements operating on `msk` and
 * the MPTCP scheduler kfuncs.
 *
 * Modelled on the kernel's
 *   tools/testing/selftests/bpf/progs/mptcp_bpf_first.c
 * -- a minimal scheduler that always schedules the first subflow.
 *
 * Compile (see .claude/designs/mptcp_bpf_sched_phase3.md):
 *   clang-21 -g -O2 -target bpf -mcpu=v3 -c mptcp_sched.bpf.c \
 *            -o mptcp_sched.bpf.o
 * vmlinux.h must be generated from the *fuzzing kernel's* BTF
 *   bpftool btf dump file <vmlinux> format c > vmlinux.h
 * and be on the include path, along with libbpf's bpf_helpers.h /
 * bpf_tracing.h (executor/bpf/ in this tree).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

/*
 * MPTCP scheduler kfuncs -- registered by net/mptcp/bpf.c, callable
 * only from an mptcp_sched_ops struct_ops program.
 */
extern struct mptcp_subflow_context *
bpf_mptcp_subflow_ctx(const struct sock *sk) __ksym;
extern void
mptcp_subflow_set_scheduled(struct mptcp_subflow_context *subflow,
			    bool scheduled) __ksym;

SEC("struct_ops")
void BPF_PROG(brf_sched_init, struct mptcp_sock *msk)
{
}

SEC("struct_ops")
void BPF_PROG(brf_sched_release, struct mptcp_sock *msk)
{
}

/*
 * get_send -- choose the subflow for the next data send.  This
 * fixed body always schedules the first subflow; Stage C swaps it
 * for a BRF-generated body.
 */
SEC("struct_ops")
int BPF_PROG(brf_sched_get_send, struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow;

	subflow = bpf_mptcp_subflow_ctx(msk->first);
	if (!subflow)
		return -1;

	mptcp_subflow_set_scheduled(subflow, true);
	return 0;
}

SEC(".struct_ops.link")
struct mptcp_sched_ops brf_sched = {
	.init		= (void *)brf_sched_init,
	.release	= (void *)brf_sched_release,
	.get_send	= (void *)brf_sched_get_send,
	.name		= "brf_sched",
};
