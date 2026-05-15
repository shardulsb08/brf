// SPDX-License-Identifier: Apache-2.0
//
// test_setsockopt_handle.c -- post-boot smoke test for the MPTCP
// kcov-handle patches.
//
// Purpose: verify that the new setsockopt(SOL_MPTCP, MPTCP_KCOV_HANDLE,
// ...) is accepted by the patched kernel.  This is the load-bearing
// "patch is actually in" test; it does NOT validate coverage
// collection (v01 only instruments MP_JOIN-path gates, which a plain
// MP_CAPABLE handshake does not exercise -- see
// .claude/designs/mptcp_join_harness_design.md Section 7.2).
//
// Build (inside the VM, or any libc-dev environment):
//   gcc -O2 -Wall -o test_setsockopt_handle test_setsockopt_handle.c
//
// Run (as root inside the patched VM):
//   ./test_setsockopt_handle
//
// Exit codes:
//   0  pass: sockopt accepted (patch loaded)
//   1  fail: prerequisite syscall failed (kcov fd, socket, etc.)
//   2  fail: setsockopt returned ENOPROTOOPT (patch not loaded)
//   3  fail: setsockopt returned some other error
//
// Author: Shardul Bankar.  Co-developed-by: Claude Opus 4.7
// (1M context).

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

/* Fallback definitions for hosts where the distro userspace headers
 * are older than our patched kernel.  Match the kernel-side values.
 */
#ifndef SOL_MPTCP
#define SOL_MPTCP	284
#endif
#ifndef MPTCP_KCOV_HANDLE
#define MPTCP_KCOV_HANDLE	5
#endif
#ifndef MPTCP_DEBUG_KEYS
#define MPTCP_DEBUG_KEYS	6
struct mptcp_debug_keys {
	uint64_t local_key;
	uint64_t remote_key;
};
#endif
#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP	262
#endif

/* kcov uapi (subset).  Don't pull in <linux/kcov.h> to keep the
 * dependency surface small.
 *
 * Handle encoding (per include/uapi/linux/kcov.h):
 *   bits 56-63: subsystem ID (KCOV_SUBSYSTEM_COMMON = 0x00,
 *                              KCOV_SUBSYSTEM_USB    = 0x01)
 *   bits 32-55: must be zero
 *   bits  0-31: instance ID
 * kcov_check_handle() in kernel/kcov.c rejects anything else with
 * EINVAL.  Picking 0x4242... or other random values is therefore
 * always rejected.
 */
#define KCOV_INIT_TRACE		_IOR('c', 1, unsigned long)
#define KCOV_ENABLE		_IO('c', 100)
#define KCOV_DISABLE		_IO('c', 101)
#define KCOV_REMOTE_ENABLE	_IOW('c', 102, struct kcov_remote_arg)
#define KCOV_TRACE_PC		0

#define KCOV_SUBSYSTEM_COMMON	(0x00ULL << 56)
#define KCOV_SUBSYSTEM_USB	(0x01ULL << 56)

struct kcov_remote_arg {
	uint32_t	trace_mode;
	uint32_t	area_size;
	uint32_t	num_handles;
	uint64_t	common_handle;
	uint64_t	handles[0];
};

#define COVER_SIZE	(256u << 10)	/* 256K PC slots */

static int set_up_kcov(uint64_t handle, unsigned long **cover_out)
{
	struct kcov_remote_arg *arg;
	unsigned long *cover;
	int kcov_fd;

	kcov_fd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (kcov_fd < 0) {
		perror("open /sys/kernel/debug/kcov");
		return -1;
	}
	if (ioctl(kcov_fd, KCOV_INIT_TRACE, (unsigned long)COVER_SIZE)) {
		perror("ioctl KCOV_INIT_TRACE");
		close(kcov_fd);
		return -1;
	}

	cover = mmap(NULL, COVER_SIZE * sizeof(unsigned long),
		     PROT_READ | PROT_WRITE, MAP_SHARED, kcov_fd, 0);
	if (cover == MAP_FAILED) {
		perror("mmap kcov");
		close(kcov_fd);
		return -1;
	}

	arg = calloc(1, sizeof(*arg));
	if (!arg) {
		perror("calloc kcov_remote_arg");
		munmap(cover, COVER_SIZE * sizeof(unsigned long));
		close(kcov_fd);
		return -1;
	}
	arg->trace_mode = KCOV_TRACE_PC;
	arg->area_size = COVER_SIZE;
	arg->num_handles = 0;		/* no "remote" handles; use common */
	arg->common_handle = handle;	/* registers + sets current->kcov_handle */

	if (ioctl(kcov_fd, KCOV_REMOTE_ENABLE, arg)) {
		perror("ioctl KCOV_REMOTE_ENABLE");
		free(arg);
		munmap(cover, COVER_SIZE * sizeof(unsigned long));
		close(kcov_fd);
		return -1;
	}
	free(arg);

	*cover_out = cover;
	return kcov_fd;
}

int main(void)
{
	/* Common-subsystem handle keyed on our pid.  Valid encoding per
	 * kcov_check_handle() rules.  KCOV_REMOTE_ENABLE with this as
	 * common_handle both (a) registers the handle in kcov's table
	 * and (b) sets current->kcov_handle so kcov_common_handle()
	 * returns the same value to in-task code in the kernel. */
	uint64_t handle = KCOV_SUBSYSTEM_COMMON | (uint64_t)getpid();
	struct sockaddr_in addr = { .sin_family = AF_INET };
	unsigned long *cover = NULL;
	socklen_t alen = sizeof(addr);
	int kcov_fd = -1;
	int server = -1, client = -1, accepted = -1;
	int rc = 1;
	unsigned long n;
	int one = 1;

	/* 1. Kcov setup (so we can also read coverage at the end,
	 *    even though v01 doesn't instrument MP_CAPABLE paths). */
	kcov_fd = set_up_kcov(handle, &cover);
	if (kcov_fd < 0)
		goto out;

	/* 2. Listening MPTCP server. */
	server = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (server < 0) {
		perror("socket(IPPROTO_MPTCP) server");
		goto out;
	}
	setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	addr.sin_port = htons(0);	/* ephemeral */
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(server, (struct sockaddr *)&addr, sizeof(addr))) {
		perror("bind");
		goto out;
	}
	if (getsockname(server, (struct sockaddr *)&addr, &alen)) {
		perror("getsockname");
		goto out;
	}
	if (listen(server, 1)) {
		perror("listen");
		goto out;
	}
	printf("server: bound to 127.0.0.1:%d, listening\n",
	       ntohs(addr.sin_port));

	/* 3. THE PATCH TEST: setsockopt(SOL_MPTCP, MPTCP_KCOV_HANDLE).
	 *    On an unpatched kernel this returns -1 / errno=ENOPROTOOPT.
	 *    On our patched kernel it returns 0. */
	if (setsockopt(server, SOL_MPTCP, MPTCP_KCOV_HANDLE,
		       &handle, sizeof(handle))) {
		fprintf(stderr,
			"setsockopt(SOL_MPTCP, MPTCP_KCOV_HANDLE) failed: %s\n",
			strerror(errno));
		if (errno == ENOPROTOOPT) {
			fprintf(stderr,
				"FAIL: kernel does not know MPTCP_KCOV_HANDLE.\n"
				"      Patch series mptcp_kcov is not loaded.\n");
			rc = 2;
		} else {
			rc = 3;
		}
		goto out;
	}
	printf("PASS: setsockopt(SOL_MPTCP, MPTCP_KCOV_HANDLE) -> 0\n");
	printf("      patch series mptcp_kcov is loaded.\n");

	/* 4. Drive an MP_CAPABLE handshake just to exercise the kernel
	 *    code paths and confirm nothing crashes / WARN_ONs.  This
	 *    will NOT generate kcov coverage from our v01 wrappers
	 *    (those fire only on MP_JOIN paths), so the buffer count
	 *    is expected to be zero. */
	client = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (client < 0) {
		perror("socket(IPPROTO_MPTCP) client");
		goto out;
	}
	if (connect(client, (struct sockaddr *)&addr, sizeof(addr))) {
		perror("connect");
		goto out;
	}
	accepted = accept(server, NULL, NULL);
	if (accepted < 0) {
		perror("accept");
		goto out;
	}
	printf("MP_CAPABLE handshake: completed without errors.\n");

	/* 4.5. PATCH 0003 TEST: read both keys via MPTCP_DEBUG_KEYS.
	 *      On unpatched kernel: -1 / errno=ENOPROTOOPT.
	 *      On patched kernel: 0, with non-zero keys after MP_CAPABLE. */
	{
		struct mptcp_debug_keys keys = { 0 };
		socklen_t klen = sizeof(keys);

		if (getsockopt(client, SOL_MPTCP, MPTCP_DEBUG_KEYS,
			       &keys, &klen)) {
			fprintf(stderr,
				"getsockopt(MPTCP_DEBUG_KEYS) failed: %s\n",
				strerror(errno));
			if (errno == ENOPROTOOPT) {
				fprintf(stderr,
					"FAIL: kernel does not know "
					"MPTCP_DEBUG_KEYS; patch 0003 missing.\n");
				rc = 2;
			} else {
				rc = 3;
			}
			goto out;
		}
		printf("PASS: getsockopt(MPTCP_DEBUG_KEYS) -> 0\n");
		printf("      local_key=0x%016llx\n",
		       (unsigned long long)keys.local_key);
		printf("      remote_key=0x%016llx\n",
		       (unsigned long long)keys.remote_key);
		if (keys.local_key == 0 || keys.remote_key == 0) {
			fprintf(stderr,
				"WARN: zero key returned -- MP_CAPABLE state "
				"may not have settled yet on this fd.\n");
		}
	}

	/* 5. Read coverage buffer count.  Expected zero for MP_CAPABLE
	 *    in v01; non-zero is fine too if the kernel got more
	 *    instrumented later. */
	n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
	printf("kcov: collected %lu PC(s) from handshake (zero is expected\n",
	       n);
	printf("      for v01 + MP_CAPABLE; non-zero would mean either\n");
	printf("      our wrappers fired or the kernel is more instrumented\n");
	printf("      than v01 documents).\n");
	if (n > 0 && n < 16) {
		unsigned long i;
		printf("First %lu PCs (resolve via\n", n);
		printf("  addr2line -e <kernel-build>/vmlinux <PC>):\n");
		for (i = 0; i < n; i++)
			printf("  0x%lx\n", cover[1 + i]);
	}

	rc = 0;	/* PASS */

out:
	if (accepted >= 0) close(accepted);
	if (client >= 0)   close(client);
	if (server >= 0)   close(server);
	if (cover && cover != MAP_FAILED)
		munmap(cover, COVER_SIZE * sizeof(unsigned long));
	if (kcov_fd >= 0) {
		ioctl(kcov_fd, KCOV_DISABLE);
		close(kcov_fd);
	}
	if (rc == 0)
		printf("\nresult: PASS (setsockopt plumbing verified)\n");
	else
		fprintf(stderr,
			"\nresult: FAIL (rc=%d) -- see messages above\n", rc);
	return rc;
}
