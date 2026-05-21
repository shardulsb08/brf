// SPDX-License-Identifier: GPL-2.0
/*
 * test_mptcp_bpf_sched.c -- BRF Phase 3 Stage B smoke test.
 *
 * Proves the load / register / select path for a BPF struct_ops
 * MPTCP scheduler end to end, on the fuzzing kernel:
 *   1. libbpf-load mptcp_sched.bpf.o and register the struct_ops
 *      scheduler (bpf_map__attach_struct_ops);
 *   2. select it as the netns default via the
 *      /proc/sys/net/mptcp/scheduler sysctl;
 *   3. drive an MPTCP connection on 127.0.0.1 and confirm data
 *      transfers -- i.e. brf_sched.get_send ran on the send path.
 *
 * Companion: executor/bpf_progs/mptcp_sched.bpf.c
 * Design:    .claude/designs/mptcp_bpf_sched_phase3.md
 *
 * Build the BPF object first (host or VM, clang-21):
 *   clang-21 -g -O2 -target bpf -mcpu=v3 -D__TARGET_ARCH_x86 \
 *     -Wno-compare-distinct-pointer-types -Wno-int-conversion \
 *     -I<dir with vmlinux.h> -I<brf>/executor \
 *     -c mptcp_sched.bpf.c -o mptcp_sched.bpf.o
 * Build this test (in the VM):
 *   gcc -O2 -Wall -o test_mptcp_bpf_sched test_mptcp_bpf_sched.c \
 *       -lbpf -lelf
 * Run in the VM, as root, on the BPF/BTF-enabled fuzzing kernel:
 *   ./test_mptcp_bpf_sched [./mptcp_sched.bpf.o]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>

#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif

#define SCHED_SYSCTL "/proc/sys/net/mptcp/scheduler"
#define SCHED_NAME   "brf_sched"
#define BPF_OBJ      "mptcp_sched.bpf.o"

static int fails;

#define CHECK(cond, msg) do {					\
	if (cond) {						\
		printf("PASS: %s\n", (msg));			\
	} else {						\
		printf("FAIL: %s (errno=%d %s)\n", (msg),	\
		       errno, strerror(errno));			\
		fails++;					\
	}							\
} while (0)

static int read_file(const char *path, char *buf, size_t len)
{
	int fd = open(path, O_RDONLY);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = read(fd, buf, len - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = '\0';
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == ' '))
		buf[--n] = '\0';
	return 0;
}

static int write_file(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = write(fd, val, strlen(val));
	close(fd);
	return n == (ssize_t)strlen(val) ? 0 : -1;
}

/* Open an MPTCP connected pair on 127.0.0.1; 0 on success. */
static int mptcp_pair(int *cli, int *srv)
{
	struct sockaddr_in a = { .sin_family = AF_INET };
	socklen_t alen = sizeof(a);
	int lfd, cfd, sfd;

	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	lfd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (lfd < 0)
		return -1;
	if (bind(lfd, (struct sockaddr *)&a, sizeof(a)) < 0 ||
	    listen(lfd, 1) < 0 ||
	    getsockname(lfd, (struct sockaddr *)&a, &alen) < 0) {
		close(lfd);
		return -1;
	}
	cfd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (cfd < 0) {
		close(lfd);
		return -1;
	}
	if (connect(cfd, (struct sockaddr *)&a, sizeof(a)) < 0) {
		close(lfd);
		close(cfd);
		return -1;
	}
	sfd = accept(lfd, NULL, NULL);
	close(lfd);
	if (sfd < 0) {
		close(cfd);
		return -1;
	}
	*cli = cfd;
	*srv = sfd;
	return 0;
}

int main(int argc, char **argv)
{
	const char *objpath = argc > 1 ? argv[1] : BPF_OBJ;
	const char *payload = "brf phase3 stage B payload";
	char saved[64] = {0}, readback[64] = {0}, rx[64] = {0};
	struct bpf_object *obj;
	struct bpf_map *map = NULL;
	struct bpf_link *link = NULL;
	int cli = -1, srv = -1;

	/* 1. load + register the struct_ops scheduler */
	obj = bpf_object__open_file(objpath, NULL);
	CHECK(obj != NULL, "bpf_object__open_file");
	if (!obj)
		return 1;
	CHECK(bpf_object__load(obj) == 0, "bpf_object__load");

	map = bpf_object__find_map_by_name(obj, SCHED_NAME);
	CHECK(map != NULL, "find struct_ops map '" SCHED_NAME "'");

	if (map)
		link = bpf_map__attach_struct_ops(map);
	CHECK(link != NULL, "bpf_map__attach_struct_ops (register)");

	/* 2. select it as the netns default scheduler */
	if (read_file(SCHED_SYSCTL, saved, sizeof(saved)) == 0)
		printf("info: default scheduler was '%s'\n", saved);
	CHECK(write_file(SCHED_SYSCTL, SCHED_NAME) == 0,
	      "write " SCHED_SYSCTL " = " SCHED_NAME);
	read_file(SCHED_SYSCTL, readback, sizeof(readback));
	CHECK(strcmp(readback, SCHED_NAME) == 0,
	      "scheduler sysctl reads back '" SCHED_NAME "'");

	/* 3. drive an MPTCP connection over the new scheduler */
	CHECK(mptcp_pair(&cli, &srv) == 0, "MPTCP connect / accept");
	if (cli >= 0 && srv >= 0) {
		ssize_t w = write(cli, payload, strlen(payload));
		ssize_t r = read(srv, rx, sizeof(rx) - 1);

		CHECK(w == (ssize_t)strlen(payload) && r == w &&
		      memcmp(payload, rx, w) == 0,
		      "data transfer over brf_sched");
	}

	/* cleanup */
	if (cli >= 0)
		close(cli);
	if (srv >= 0)
		close(srv);
	if (saved[0])
		write_file(SCHED_SYSCTL, saved);	/* restore default */
	if (link)
		bpf_link__destroy(link);
	if (obj)
		bpf_object__close(obj);

	if (fails == 0) {
		printf("\nresult: PASS (BPF struct_ops MPTCP scheduler "
		       "load + register + select + traffic)\n");
		return 0;
	}
	printf("\nresult: FAIL (%d check(s) failed)\n", fails);
	return 1;
}
