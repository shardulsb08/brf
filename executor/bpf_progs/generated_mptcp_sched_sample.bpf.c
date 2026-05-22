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
extern struct sock *
bpf_mptcp_subflow_tcp_sock(const struct mptcp_subflow_context *subflow) __ksym;
extern bool
bpf_sk_stream_memory_free(const struct sock *sk) __ksym;
extern bool
mptcp_subflow_active(struct mptcp_subflow_context *subflow) __ksym;
extern void
mptcp_set_timeout(struct sock *sk) __ksym;
extern __u64
mptcp_wnd_end(const struct mptcp_sock *msk) __ksym;

SEC("struct_ops")
void BPF_PROG(brf_c0ffee_init, struct mptcp_sock *msk)
{
}

SEC("struct_ops")
void BPF_PROG(brf_c0ffee_release, struct mptcp_sock *msk)
{
}

SEC("struct_ops")
int BPF_PROG(brf_c0ffee_get_send, struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow;

	subflow = bpf_mptcp_subflow_ctx(msk->first);
	if (!subflow)
		return -1;

	/* BRF-generated body. */
	int s0 = msk->snd_burst;
	bool s1 = mptcp_subflow_active(subflow);
	struct sock *s2 = bpf_mptcp_subflow_tcp_sock(subflow);
	if (!s2)
		return -1;
	__u64 s3 = mptcp_wnd_end(msk);
	bool s4 = bpf_sk_stream_memory_free(s2);
	mptcp_set_timeout(s2);
	int s5 = s0 ^ 4919;
	subflow->avg_pacing_rate = 1234567;
	msk->snd_burst = -42;

	mptcp_subflow_set_scheduled(subflow, true);
	return 0;
}

SEC(".struct_ops.link")
struct mptcp_sched_ops brf_c0ffee = {
	.init		= (void *)brf_c0ffee_init,
	.release	= (void *)brf_c0ffee_release,
	.get_send	= (void *)brf_c0ffee_get_send,
	.name		= "brf_c0ffee",
};
