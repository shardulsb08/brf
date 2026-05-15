// SPDX-License-Identifier: Apache-2.0
//
// test_mp_join_normal.c -- post-boot end-to-end smoke test for the
// MPTCP MP_JOIN NORMAL-mode harness flow.  Mirrors what the executor's
// syz_mptcp_join_subflow pseudo-syscall does (executor/common_brf_linux_mptcp.h)
// so we can validate the flow on the booted kernel without bringing up
// the full fuzzer.
//
// What this exercises
// -------------------
//   1. Flip net.mptcp.pm_type=1 (so all msks created henceforth use the
//      userspace path manager).
//   2. Open a netlink socket subscribed to the mptcp_pm_events multicast
//      group -- this is what makes mptcp_userspace_pm_active() return
//      true on every msk in the netns, satisfying the server-side
//      acceptance gate (mptcp_can_accept_new_subflow, net/mptcp/subflow.c).
//   3. Open an IPPROTO_MPTCP listening server on 127.0.0.1:ephemeral.
//   4. Open a client IPPROTO_MPTCP socket; connect+accept drives MP_CAPABLE.
//   5. Snapshot /proc/net/netstat for the MPJoinAckRx counter.
//   6. Issue MPTCP_PM_CMD_SUBFLOW_CREATE pointing local=127.0.0.2,
//      remote=127.0.0.1:<server_port>, token=<client msk token>.
//   7. Poll server-side MPTCP_INFO.mptcpi_subflows for >= 1 with a 1s
//      ceiling.
//   8. Re-snapshot /proc/net/netstat -- expect MPJoinAckRx to have
//      incremented by exactly 1 and MPJoinAckHMacFailure to be unchanged.
//
// Counter naming caveat: the kernel symbol MPTCP_MIB_JOINACKMAC
// (include/uapi/linux/mptcp.h via net/mptcp/mib.c:30) maps to the
// /proc/net/netstat name "MPJoinAckHMacFailure" -- it is the HMAC-failure
// counter, not the success counter.  The success counter is "MPJoinAckRx"
// (MPTCP_MIB_JOINACKRX, mib.c:29).  The harness design doc
// (.claude/designs/mptcp_join_harness_design.md Section 9.1) refers to
// MPTCP_MIB_JOINACKMAC; that's a naming bug in the doc -- this test uses
// the correct success counter.
//
// Build (inside the VM, or any libc-dev environment):
//   gcc -O2 -Wall -o test_mp_join_normal test_mp_join_normal.c
//
// Run (as root inside the patched VM):
//   ./test_mp_join_normal
//
// Exit codes:
//   0  pass: subflow established, MPJoinAckRx incremented, no HMAC failure
//   1  fail: prerequisite syscall failed (socket, netlink, etc.)
//   2  fail: kernel did not accept SUBFLOW_CREATE
//   3  fail: subflow count did not increment within timeout
//   4  fail: MPJoinAckRx counter did not increment as expected
//
// Author: Shardul Bankar.  Co-developed-by: Claude Opus 4.7 (1M context).

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/genetlink.h>
#include <linux/netlink.h>

#ifndef SOL_MPTCP
#define SOL_MPTCP		284
#endif
#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP		262
#endif
#ifndef MPTCP_INFO
#define MPTCP_INFO		1
#endif

/* Subset of struct mptcp_info we need.  Match include/uapi/linux/mptcp.h
 * at the kernel base; this is the prefix we read via getsockopt. */
struct mptcp_info_short {
	uint8_t  mptcpi_subflows;
	uint8_t  mptcpi_add_addr_signal;
	uint8_t  mptcpi_add_addr_accepted;
	uint8_t  mptcpi_subflows_max;
	uint8_t  mptcpi_add_addr_signal_max;
	uint8_t  mptcpi_add_addr_accepted_max;
	uint8_t  _pad[2];
	uint32_t mptcpi_flags;
	uint32_t mptcpi_token;
	uint64_t mptcpi_write_seq;
	uint64_t mptcpi_snd_una;
	uint64_t mptcpi_rcv_nxt;
	uint8_t  mptcpi_local_addr_used;
	uint8_t  mptcpi_local_addr_max;
	uint8_t  mptcpi_csum_enabled;
} __attribute__((packed));

/* mptcp_pm.h enum values (auto-generated from a yaml spec, may not be in
 * older distro headers; values match the kernel at commit 232989ca65248). */
enum {
	MPTCP_PM_ATTR_UNSPEC_TEST,
	MPTCP_PM_ATTR_ADDR,
	MPTCP_PM_ATTR_RCV_ADD_ADDRS,
	MPTCP_PM_ATTR_SUBFLOWS,
	MPTCP_PM_ATTR_TOKEN,
	MPTCP_PM_ATTR_LOC_ID,
	MPTCP_PM_ATTR_ADDR_REMOTE,
};
enum {
	MPTCP_PM_ADDR_ATTR_UNSPEC_TEST,
	MPTCP_PM_ADDR_ATTR_FAMILY,
	MPTCP_PM_ADDR_ATTR_ID,
	MPTCP_PM_ADDR_ATTR_ADDR4,
	MPTCP_PM_ADDR_ATTR_ADDR6,
	MPTCP_PM_ADDR_ATTR_PORT,
	MPTCP_PM_ADDR_ATTR_FLAGS,
	MPTCP_PM_ADDR_ATTR_IF_IDX,
};
#define MPTCP_PM_CMD_SUBFLOW_CREATE_VAL  10
#define MPTCP_PM_VER_VAL                 1

static bool write_sysctl(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return false;
	}
	int len = strlen(val);
	if (write(fd, val, len) != len) {
		fprintf(stderr, "write %s: %s\n", path, strerror(errno));
		close(fd);
		return false;
	}
	close(fd);
	return true;
}

/* Resolve mptcp_pm family id + mptcp_pm_events multicast group id. */
static int resolve_mptcp_pm_family(int sock, uint16_t *family_id,
				   uint32_t *event_grp_id)
{
	char buf[1024];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct genlmsghdr *ghdr;
	struct nlattr *attr;
	const char fname[] = "mptcp_pm";

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = GENL_ID_CTRL;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq   = 1;
	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	ghdr->cmd     = CTRL_CMD_GETFAMILY;
	ghdr->version = 1;
	attr = (struct nlattr *)((char *)NLMSG_DATA(nlh) +
				 NLMSG_ALIGN(sizeof(*ghdr)));
	attr->nla_type = CTRL_ATTR_FAMILY_NAME;
	attr->nla_len  = NLA_HDRLEN + sizeof(fname);
	memcpy((char *)attr + NLA_HDRLEN, fname, sizeof(fname));
	nlh->nlmsg_len = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ghdr)) +
			 NLA_ALIGN(attr->nla_len);

	if (send(sock, buf, nlh->nlmsg_len, 0) < 0) {
		perror("send GETFAMILY");
		return -1;
	}
	ssize_t n = recv(sock, buf, sizeof(buf), 0);
	if (n < 0) {
		perror("recv GETFAMILY");
		return -1;
	}
	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *ne = (struct nlmsgerr *)NLMSG_DATA(nlh);
		fprintf(stderr, "GETFAMILY err=%d (%s)\n", ne->error,
			strerror(-ne->error));
		return -1;
	}
	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	attr = (struct nlattr *)((char *)NLMSG_DATA(nlh) +
				 NLMSG_ALIGN(sizeof(*ghdr)));
	ssize_t left = nlh->nlmsg_len - NLMSG_HDRLEN -
		       NLMSG_ALIGN(sizeof(*ghdr));
	uint16_t fid = 0;
	uint32_t egid = 0;
	while (left >= (ssize_t)NLA_HDRLEN && attr->nla_len >= NLA_HDRLEN) {
		switch (attr->nla_type & NLA_TYPE_MASK) {
		case CTRL_ATTR_FAMILY_ID:
			if (attr->nla_len >= NLA_HDRLEN + sizeof(uint16_t))
				fid = *(uint16_t *)((char *)attr + NLA_HDRLEN);
			break;
		case CTRL_ATTR_MCAST_GROUPS: {
			char *gpos = (char *)attr + NLA_HDRLEN;
			char *gend = (char *)attr + attr->nla_len;
			while (gpos + NLA_HDRLEN <= gend) {
				struct nlattr *grp = (struct nlattr *)gpos;
				if (grp->nla_len < NLA_HDRLEN ||
				    gpos + grp->nla_len > gend) break;
				char *ipos = (char *)grp + NLA_HDRLEN;
				char *iend = (char *)grp + grp->nla_len;
				const char *gname = NULL;
				uint32_t gid = 0;
				while (ipos + NLA_HDRLEN <= iend) {
					struct nlattr *in = (struct nlattr *)ipos;
					if (in->nla_len < NLA_HDRLEN ||
					    ipos + in->nla_len > iend) break;
					if ((in->nla_type & NLA_TYPE_MASK) ==
					    CTRL_ATTR_MCAST_GRP_NAME)
						gname = (const char *)in + NLA_HDRLEN;
					else if ((in->nla_type & NLA_TYPE_MASK) ==
						 CTRL_ATTR_MCAST_GRP_ID &&
						 in->nla_len >= NLA_HDRLEN + sizeof(uint32_t))
						gid = *(uint32_t *)((char *)in + NLA_HDRLEN);
					ipos += NLA_ALIGN(in->nla_len);
				}
				if (gname && strcmp(gname, "mptcp_pm_events") == 0)
					egid = gid;
				gpos += NLA_ALIGN(grp->nla_len);
			}
			break;
		}
		}
		left -= NLA_ALIGN(attr->nla_len);
		attr = (struct nlattr *)((char *)attr +
					 NLA_ALIGN(attr->nla_len));
	}
	if (!fid || !egid) {
		fprintf(stderr, "GETFAMILY parse incomplete: fid=%u egid=%u\n",
			fid, egid);
		return -1;
	}
	*family_id = fid;
	*event_grp_id = egid;
	return 0;
}

/* Note on byte order: addresses (MPTCP_PM_ADDR_ATTR_ADDR4) are network-byte
 * order in the netlink attribute (kernel's nla_get_in_addr reads them raw).
 * Ports (MPTCP_PM_ADDR_ATTR_PORT) are HOST-byte order in the attribute --
 * the kernel applies htons() on the way in (net/mptcp/pm_netlink.c:86).
 * Pass ports as host-order uint16 here. */
static int genl_subflow_create(int sock, uint16_t family_id, uint32_t token,
			       uint8_t addr_id,
			       uint32_t local_addr_be, uint16_t local_port_h,
			       uint32_t remote_addr_be, uint16_t remote_port_h)
{
	char buf[256];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct genlmsghdr *ghdr;
	struct nlattr *attr, *nest;
	char *p;
#define PUT_ATTR(typ, src, sz) do {				\
		attr = (struct nlattr *)p;			\
		attr->nla_type = (typ);				\
		attr->nla_len  = NLA_HDRLEN + (sz);		\
		memcpy((char *)attr + NLA_HDRLEN, (src), (sz));	\
		p += NLA_ALIGN(attr->nla_len);			\
	} while (0)

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = 2;
	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	ghdr->cmd     = MPTCP_PM_CMD_SUBFLOW_CREATE_VAL;
	ghdr->version = MPTCP_PM_VER_VAL;
	p = (char *)NLMSG_DATA(nlh) + NLMSG_ALIGN(sizeof(*ghdr));

	PUT_ATTR(MPTCP_PM_ATTR_TOKEN, &token, sizeof(token));

	{
		uint16_t fam_v = AF_INET;
		nest = (struct nlattr *)p;
		nest->nla_type = MPTCP_PM_ATTR_ADDR | NLA_F_NESTED;
		p += NLA_HDRLEN;
		PUT_ATTR(MPTCP_PM_ADDR_ATTR_FAMILY, &fam_v, sizeof(fam_v));
		PUT_ATTR(MPTCP_PM_ADDR_ATTR_ID, &addr_id, sizeof(addr_id));
		PUT_ATTR(MPTCP_PM_ADDR_ATTR_ADDR4, &local_addr_be,
			 sizeof(local_addr_be));
		PUT_ATTR(MPTCP_PM_ADDR_ATTR_PORT, &local_port_h,
			 sizeof(local_port_h));
		nest->nla_len = p - (char *)nest;
	}
	{
		uint16_t fam_v = AF_INET;
		nest = (struct nlattr *)p;
		nest->nla_type = MPTCP_PM_ATTR_ADDR_REMOTE | NLA_F_NESTED;
		p += NLA_HDRLEN;
		PUT_ATTR(MPTCP_PM_ADDR_ATTR_FAMILY, &fam_v, sizeof(fam_v));
		PUT_ATTR(MPTCP_PM_ADDR_ATTR_ADDR4, &remote_addr_be,
			 sizeof(remote_addr_be));
		PUT_ATTR(MPTCP_PM_ADDR_ATTR_PORT, &remote_port_h,
			 sizeof(remote_port_h));
		nest->nla_len = p - (char *)nest;
	}
	nlh->nlmsg_len = p - buf;

	if (send(sock, buf, nlh->nlmsg_len, 0) < 0) {
		perror("send SUBFLOW_CREATE");
		return -1;
	}
	ssize_t n = recv(sock, buf, sizeof(buf), 0);
	if (n < 0) {
		perror("recv SUBFLOW_CREATE ack");
		return -1;
	}
	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type != NLMSG_ERROR) {
		fprintf(stderr, "SUBFLOW_CREATE: unexpected ack type %u\n",
			nlh->nlmsg_type);
		return -1;
	}
	struct nlmsgerr *ne = (struct nlmsgerr *)NLMSG_DATA(nlh);
	if (ne->error) {
		fprintf(stderr, "SUBFLOW_CREATE kernel err=%d (%s)\n",
			ne->error, strerror(-ne->error));
		return -1;
	}
	return 0;
#undef PUT_ATTR
}

/* Read /proc/net/netstat and return the value of the named MPTCP counter,
 * or -1 if not found.  The MPTcpExt line shows counter names on one row
 * and values on the next, with the literal prefix "MPTcpExt:".  Pass
 * verbose=1 on the first call to dump the raw header line, so we can
 * diagnose when counters come back as -1. */
static long read_mib_counter_verbose(const char *name, int verbose)
{
	FILE *f = fopen("/proc/net/netstat", "r");
	if (!f) {
		if (verbose)
			fprintf(stderr, "MIB: open /proc/net/netstat: %s\n",
				strerror(errno));
		return -1;
	}
	char header[16384], values[16384];
	long val = -1;
	int found_mptcpext = 0;
	while (fgets(header, sizeof(header), f)) {
		if (strncmp(header, "MPTcpExt:", 9) != 0)
			continue;
		found_mptcpext = 1;
		if (!fgets(values, sizeof(values), f))
			break;

		if (verbose) {
			/* Trim trailing newline for readable diagnostics. */
			size_t l = strlen(header);
			if (l && header[l - 1] == '\n') header[l - 1] = 0;
			fprintf(stderr, "MIB raw header: %.200s%s\n",
				header, strlen(header) > 200 ? "..." : "");
		}

		char *hp = header + 9;
		char *vp = values + 9;
		while (*hp == ' ' || *hp == '\t') hp++;
		while (*vp == ' ' || *vp == '\t') vp++;
		char *hsave = NULL, *vsave = NULL;
		char *htok = strtok_r(hp, " \t\n", &hsave);
		char *vtok = strtok_r(vp, " \t\n", &vsave);
		while (htok && vtok) {
			if (strcmp(htok, name) == 0) {
				val = strtol(vtok, NULL, 10);
				break;
			}
			htok = strtok_r(NULL, " \t\n", &hsave);
			vtok = strtok_r(NULL, " \t\n", &vsave);
		}
		break;
	}
	if (!found_mptcpext && verbose)
		fprintf(stderr,
			"MIB: no MPTcpExt: line in /proc/net/netstat -- "
			"is CONFIG_MPTCP=y and the module exposing counters?\n");
	fclose(f);
	return val;
}

static long read_mib_counter(const char *name)
{
	return read_mib_counter_verbose(name, 0);
}

int main(void)
{
	struct sockaddr_in addr = { .sin_family = AF_INET };
	struct sockaddr_nl nlsa = { .nl_family = AF_NETLINK };
	socklen_t alen = sizeof(addr);
	int server = -1, client = -1, accepted = -1;
	int nl_send = -1, nl_event = -1;
	uint16_t family_id = 0;
	uint32_t event_grp_id = 0;
	int rc = 1;
	int one = 1;

	/* 1. Userspace PM mode netns-wide. */
	if (!write_sysctl("/proc/sys/net/mptcp/pm_type", "1")) {
		fprintf(stderr, "FAIL: cannot set pm_type=1 (need root + CONFIG_MPTCP)\n");
		goto out;
	}
	printf("PASS: net.mptcp.pm_type = 1 (userspace PM enabled)\n");

	/* 2. Genl socket for sending PM commands; resolve family + event group. */
	nl_send = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (nl_send < 0) {
		perror("socket(genl send)");
		goto out;
	}
	if (bind(nl_send, (struct sockaddr *)&nlsa, sizeof(nlsa)) < 0) {
		perror("bind(genl send)");
		goto out;
	}
	if (resolve_mptcp_pm_family(nl_send, &family_id, &event_grp_id) < 0)
		goto out;
	printf("PASS: mptcp_pm family resolved: id=%u, events grp=%u\n",
	       family_id, event_grp_id);

	/* 3. Second genl socket subscribed to mptcp_pm_events.  This is the
	 *    listener that makes mptcp_userspace_pm_active(msk) return true. */
	nl_event = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (nl_event < 0) {
		perror("socket(genl event)");
		goto out;
	}
	if (bind(nl_event, (struct sockaddr *)&nlsa, sizeof(nlsa)) < 0) {
		perror("bind(genl event)");
		goto out;
	}
	if (setsockopt(nl_event, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
		       &event_grp_id, sizeof(event_grp_id)) < 0) {
		perror("NETLINK_ADD_MEMBERSHIP mptcp_pm_events");
		goto out;
	}
	printf("PASS: subscribed to mptcp_pm_events (userspace_pm_active=true)\n");

	/* 4. Server side: listen on 127.0.0.1:ephemeral. */
	server = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (server < 0) {
		perror("socket(server IPPROTO_MPTCP)");
		goto out;
	}
	setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	addr.sin_port = 0;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind server");
		goto out;
	}
	if (getsockname(server, (struct sockaddr *)&addr, &alen) < 0) {
		perror("getsockname");
		goto out;
	}
	if (listen(server, 1) < 0) {
		perror("listen");
		goto out;
	}
	uint16_t server_port_h = ntohs(addr.sin_port);
	printf("server: bound 127.0.0.1:%u\n", server_port_h);

	/* 5. Client side: drive MP_CAPABLE. */
	client = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (client < 0) {
		perror("socket(client IPPROTO_MPTCP)");
		goto out;
	}
	if (connect(client, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		goto out;
	}
	accepted = accept(server, NULL, NULL);
	if (accepted < 0) {
		perror("accept");
		goto out;
	}
	printf("PASS: MP_CAPABLE handshake completed\n");

	/* 5.5. 1-byte round-trip to force the client-side
	 *      msk->fully_established transition.  Without this, the
	 *      subsequent MPTCP_PM_CMD_SUBFLOW_CREATE returns -ENOTCONN at
	 *      __mptcp_subflow_connect's "userspace PM sent the request
	 *      too early?" check (net/mptcp/subflow.c).  The server msk
	 *      is fully_established once accept() returns; the client msk
	 *      needs an inbound DSS+use_ack first (net/mptcp/options.c
	 *      check_fully_established).  Round-trip in both directions
	 *      makes the test robust against either-side detection paths. */
	{
		char b = 'x';
		if (send(client, &b, 1, 0) != 1) {
			perror("prime send c->s");
			goto out;
		}
		if (recv(accepted, &b, 1, MSG_WAITALL) != 1) {
			perror("prime recv on server");
			goto out;
		}
		if (send(accepted, &b, 1, 0) != 1) {
			perror("prime send s->c");
			goto out;
		}
		if (recv(client, &b, 1, MSG_WAITALL) != 1) {
			perror("prime recv on client");
			goto out;
		}
		printf("PASS: 1-byte round-trip primed fully_established\n");
	}

	/* 6. Read token. */
	struct mptcp_info_short info;
	socklen_t ilen = sizeof(info);
	memset(&info, 0, sizeof(info));
	if (getsockopt(client, SOL_MPTCP, MPTCP_INFO, &info, &ilen) < 0) {
		perror("getsockopt(MPTCP_INFO) client");
		goto out;
	}
	uint32_t token = info.mptcpi_token;
	printf("client token: 0x%08x  csum_enabled=%u\n",
	       token, info.mptcpi_csum_enabled);

	/* 7. Snapshot MIB counters.  Verbose on the first call so we get the
	 *    raw MPTcpExt header on stderr if the parser returns -1 -- helps
	 *    diagnose whether the counter is genuinely absent or just mis-
	 *    parsed.  Counter naming caveat: MPJoinAckHMacFailure is the
	 *    kernel's MPTCP_MIB_JOINACKMAC symbol (a failure counter); the
	 *    success counter we actually want is MPJoinAckRx (mib.c:29). */
	long syn_rx_before = read_mib_counter_verbose("MPJoinSynRx", 1);
	long ack_rx_before = read_mib_counter("MPJoinAckRx");
	long ack_fail_before = read_mib_counter("MPJoinAckHMacFailure");
	printf("MIB before: MPJoinSynRx=%ld MPJoinAckRx=%ld MPJoinAckHMacFailure=%ld\n",
	       syn_rx_before, ack_rx_before, ack_fail_before);

	/* 8. MPTCP_PM_CMD_SUBFLOW_CREATE: local 127.0.0.2 -> remote 127.0.0.1:port. */
	if (genl_subflow_create(nl_send, family_id, token, 1,
				htonl(0x7f000002), 0,
				htonl(0x7f000001), server_port_h) < 0) {
		rc = 2;
		goto out;
	}
	printf("PASS: SUBFLOW_CREATE acked by kernel\n");

	/* 9. Poll server-side MPTCP_INFO for the new subflow. */
	int established = 0;
	for (int retry = 0; retry < 20; retry++) {
		memset(&info, 0, sizeof(info));
		ilen = sizeof(info);
		if (getsockopt(accepted, SOL_MPTCP, MPTCP_INFO, &info, &ilen) == 0
		    && info.mptcpi_subflows >= 1) {
			established = 1;
			printf("PASS: server msk mptcpi_subflows=%u after %d polls\n",
			       info.mptcpi_subflows, retry + 1);
			break;
		}
		usleep(50000);
	}
	if (!established) {
		fprintf(stderr, "FAIL: subflow count did not increment within ~1s\n");
		rc = 3;
		goto out;
	}

	/* Give the kernel a beat to log MIB increments before re-snapshotting. */
	usleep(100000);

	/* 10. Re-snapshot MIB and verify the success counter moved. */
	long ack_rx_after = read_mib_counter("MPJoinAckRx");
	long ack_fail_after = read_mib_counter("MPJoinAckHMacFailure");
	long syn_rx_after = read_mib_counter("MPJoinSynRx");
	printf("MIB after:  MPJoinSynRx=%ld MPJoinAckRx=%ld MPJoinAckHMacFailure=%ld\n",
	       syn_rx_after, ack_rx_after, ack_fail_after);

	long ack_delta = ack_rx_after - ack_rx_before;
	long fail_delta = ack_fail_after - ack_fail_before;
	if (ack_delta != 1) {
		fprintf(stderr,
			"FAIL: MPJoinAckRx delta = %ld, expected 1\n",
			ack_delta);
		rc = 4;
		goto out;
	}
	if (fail_delta != 0) {
		fprintf(stderr,
			"FAIL: MPJoinAckHMacFailure delta = %ld, expected 0\n",
			fail_delta);
		rc = 4;
		goto out;
	}
	printf("PASS: MPJoinAckRx incremented by 1, no HMAC failure\n");

	rc = 0;
out:
	if (accepted >= 0) close(accepted);
	if (client   >= 0) close(client);
	if (server   >= 0) close(server);
	if (nl_event >= 0) close(nl_event);
	if (nl_send  >= 0) close(nl_send);
	if (rc == 0)
		printf("\nresult: PASS (MP_JOIN NORMAL mode end-to-end)\n");
	else
		fprintf(stderr,
			"\nresult: FAIL (rc=%d) -- see messages above\n", rc);
	return rc;
}
