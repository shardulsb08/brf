// SPDX-License-Identifier: GPL-2.0
/* BRF-generated MPTCP struct_ops scheduler (Phase 3, Stage C). */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

/* MPTCP scheduler kfuncs (net/mptcp/bpf.c). */
extern struct mptcp_subflow_context *
bpf_mptcp_subflow_ctx(const struct sock *sk) __ksym;
extern void
mptcp_subflow_set_scheduled(struct mptcp_subflow_context *subflow,
			    bool scheduled) __ksym;

SEC("struct_ops")
void BPF_PROG(brf_3a7f12_init, struct mptcp_sock *msk)
{
}

SEC("struct_ops")
void BPF_PROG(brf_3a7f12_release, struct mptcp_sock *msk)
{
}

SEC("struct_ops")
int BPF_PROG(brf_3a7f12_get_send, struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow;

	subflow = bpf_mptcp_subflow_ctx(msk->first);
	if (!subflow)
		return -1;

	/* BRF-generated body. */
	int s0 = msk->snd_burst;
	int s1 = s0 ^ 4919;
	subflow->avg_pacing_rate = 1234567;
	msk->snd_burst = -42;

	mptcp_subflow_set_scheduled(subflow, true);
	return 0;
}

SEC(".struct_ops.link")
struct mptcp_sched_ops brf_3a7f12 = {
	.init		= (void *)brf_3a7f12_init,
	.release	= (void *)brf_3a7f12_release,
	.get_send	= (void *)brf_3a7f12_get_send,
	.name		= "brf_3a7f12",
};
