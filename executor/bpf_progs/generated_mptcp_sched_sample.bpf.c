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
/* MPTCP subflow-iterator kfuncs (net/mptcp/bpf.c). */
extern int
bpf_iter_mptcp_subflow_new(struct bpf_iter_mptcp_subflow *it,
			   struct sock *sk) __ksym;
extern struct mptcp_subflow_context *
bpf_iter_mptcp_subflow_next(struct bpf_iter_mptcp_subflow *it) __ksym;
extern void
bpf_iter_mptcp_subflow_destroy(struct bpf_iter_mptcp_subflow *it) __ksym;

SEC("struct_ops")
void BPF_PROG(brf_5ed1ec_init, struct mptcp_sock *msk)
{
	/* BRF-generated body. */
	int s7 = msk->snd_burst;
	__u64 s8 = mptcp_wnd_end(msk);
	int s9 = s7 + 4919;
	msk->snd_burst = -42;
}

SEC("struct_ops")
void BPF_PROG(brf_5ed1ec_release, struct mptcp_sock *msk)
{
	/* BRF-generated body. */
	bool s10 = bpf_sk_stream_memory_free(msk->first);
	mptcp_set_timeout(msk->first);
	int s11 = msk->snd_burst;
}

SEC("struct_ops")
int BPF_PROG(brf_5ed1ec_get_send, struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow;

	subflow = bpf_mptcp_subflow_ctx(msk->first);
	if (!subflow)
		return -1;

	/* BRF-generated body. */
	int s0 = msk->snd_burst;
	bool s1 = mptcp_subflow_active(subflow);
	/* BRF-generated subflow iterator. */
	struct bpf_iter_mptcp_subflow it2;
	struct mptcp_subflow_context *sf2;
	bpf_iter_mptcp_subflow_new(&it2, (struct sock *)msk);
	while ((sf2 = bpf_iter_mptcp_subflow_next(&it2))) {
		unsigned long s3 = sf2->avg_pacing_rate;
		bool s4 = mptcp_subflow_active(sf2);
		sf2->avg_pacing_rate = 987654;
	}
	bpf_iter_mptcp_subflow_destroy(&it2);
	__u64 s5 = mptcp_wnd_end(msk);
	struct sock *s6 = bpf_mptcp_subflow_tcp_sock(subflow);
	if (!s6)
		return -1;
	msk->snd_burst = -42;

	mptcp_subflow_set_scheduled(subflow, true);
	return 0;
}

SEC(".struct_ops.link")
struct mptcp_sched_ops brf_5ed1ec = {
	.init		= (void *)brf_5ed1ec_init,
	.release	= (void *)brf_5ed1ec_release,
	.get_send	= (void *)brf_5ed1ec_get_send,
	.name		= "brf_5ed1ec",
};
