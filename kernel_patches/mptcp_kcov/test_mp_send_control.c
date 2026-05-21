// SPDX-License-Identifier: Apache-2.0
//
// test_mp_send_control.c -- gap 2 Step 1 smoke test.
//
// Verifies that the two fastclose triggers syz_mptcp_send_control uses
// actually make the kernel emit MP_FASTCLOSE + MP_RST on the wire.
// Mirrors the trigger logic in executor/common_brf_linux_mptcp.h:
//
//   CTL_FASTCLOSE -> SO_LINGER{1,0} close      (__mptcp_close cond 3)
//   CTL_RST       -> close with unread rx data (__mptcp_close cond 1)
//
// Both reach mptcp_do_fastclose(); the resulting RST carries
// MP_FASTCLOSE and (mptcp_established_options_rst) MP_RST.  The test
// checks the /proc/net/netstat MPTcpExt deltas.
//
// Build + run in the dev VM:
//   gcc -O2 -Wall -o test_mp_send_control test_mp_send_control.c
//   ./test_mp_send_control
//
// Counter names (MPFastcloseTx / MPRstTx) come from net/mptcp/mib.c;
// if mib() returns -1 the spelling there has changed.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif

/* Read a named MPTcpExt counter from /proc/net/netstat.  Returns the
 * value, or -1 if the counter name is not found. */
static long mib(const char *name)
{
	FILE *f = fopen("/proc/net/netstat", "r");
	char line[16384], hdr[16384] = "";
	long out = -1;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		char h[16384], *t, *s;
		int col = -1, i = 0;

		if (strncmp(line, "MPTcpExt:", 9))
			continue;
		if (!hdr[0]) {			/* first MPTcpExt line: names */
			strcpy(hdr, line);
			continue;
		}
		strcpy(h, hdr);			/* second line: values */
		for (t = strtok_r(h, " \t\n", &s); t;
		     t = strtok_r(NULL, " \t\n", &s), i++)
			if (i && !strcmp(t, name)) {
				col = i;
				break;
			}
		if (col < 0)
			break;
		i = 0;
		for (t = strtok_r(line, " \t\n", &s); t;
		     t = strtok_r(NULL, " \t\n", &s), i++)
			if (i == col) {
				out = atol(t);
				break;
			}
		break;
	}
	fclose(f);
	return out;
}

/* Create an MP_CAPABLE pair on 127.0.0.1; fill the client msk, the
 * accepted server msk, and the listener fd. */
static int mk_pair(int *cli, int *acc, int *lst)
{
	struct sockaddr_in a;
	socklen_t al = sizeof(a);
	int one = 1;

	*lst = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (*lst < 0) {
		perror("socket(listener)");
		return -1;
	}
	setsockopt(*lst, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(*lst, (void *)&a, sizeof(a)) || listen(*lst, 1)) {
		perror("bind/listen");
		return -1;
	}
	if (getsockname(*lst, (void *)&a, &al)) {
		perror("getsockname");
		return -1;
	}
	*cli = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (*cli < 0) {
		perror("socket(client)");
		return -1;
	}
	if (connect(*cli, (void *)&a, sizeof(a))) {
		perror("connect");
		return -1;
	}
	*acc = accept(*lst, NULL, NULL);
	if (*acc < 0) {
		perror("accept");
		return -1;
	}
	return 0;
}

int main(void)
{
	struct linger lg = { .l_onoff = 1, .l_linger = 0 };
	long fc0, rst0, fc1, rst1, fc2, rst2;
	int cli, acc, lst, fails = 0;
	char buf[8] = "rstdata";

	fc0 = mib("MPFastcloseTx");
	rst0 = mib("MPRstTx");
	printf("MIB start: MPFastcloseTx=%ld MPRstTx=%ld\n", fc0, rst0);
	if (fc0 < 0 || rst0 < 0) {
		printf("FAIL: counter not found -- check net/mptcp/mib.c\n");
		return 1;
	}

	/* --- CTL_FASTCLOSE path: SO_LINGER{1,0} close --- */
	if (mk_pair(&cli, &acc, &lst))
		return 1;
	setsockopt(cli, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
	close(cli);
	usleep(150000);
	close(acc);
	close(lst);
	fc1 = mib("MPFastcloseTx");
	rst1 = mib("MPRstTx");
	printf("after SO_LINGER fastclose:   MPFastcloseTx=%ld (+%ld)  "
	       "MPRstTx=%ld (+%ld)\n", fc1, fc1 - fc0, rst1, rst1 - rst0);
	if (fc1 > fc0)
		printf("PASS: MP_FASTCLOSE emitted (SO_LINGER path)\n");
	else {
		printf("FAIL: no MP_FASTCLOSE on SO_LINGER close\n");
		fails++;
	}
	if (rst1 > rst0)
		printf("PASS: MP_RST emitted alongside\n");
	else {
		printf("FAIL: no MP_RST on the fastclose RST\n");
		fails++;
	}

	/* --- CTL_RST path: close with unread rx data --- */
	if (mk_pair(&cli, &acc, &lst))
		return 1;
	if (send(acc, buf, sizeof(buf), 0) != (ssize_t)sizeof(buf)) {
		perror("send(server->client)");
		return 1;
	}
	usleep(50000);			/* let the bytes land in cli's rx queue */
	close(cli);			/* unread rx data -> fastclose */
	usleep(150000);
	close(acc);
	close(lst);
	fc2 = mib("MPFastcloseTx");
	rst2 = mib("MPRstTx");
	printf("after unread-data fastclose: MPFastcloseTx=%ld (+%ld)  "
	       "MPRstTx=%ld (+%ld)\n", fc2, fc2 - fc1, rst2, rst2 - rst1);
	if (fc2 > fc1)
		printf("PASS: MP_FASTCLOSE emitted (unread-data path)\n");
	else {
		printf("FAIL: no MP_FASTCLOSE on unread-data close\n");
		fails++;
	}
	if (rst2 > rst1)
		printf("PASS: MP_RST emitted alongside\n");
	else {
		printf("FAIL: no MP_RST on the unread-data fastclose RST\n");
		fails++;
	}

	printf("\nresult: %s\n",
	       fails ? "FAIL" : "PASS (gap 2 Step 1 -- MP_FASTCLOSE + MP_RST emit)");
	return fails ? 1 : 0;
}
