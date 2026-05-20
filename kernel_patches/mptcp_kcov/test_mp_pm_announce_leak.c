// SPDX-License-Identifier: Apache-2.0
//
// test_mp_pm_announce_leak.c -- standalone reproducer for the kernel
// memory leak surfaced by BRF's protocol-flow fuzzing harness on
// 2026-05-18.  The harness's syz_mptcp_pm_announce pseudo-syscall (v05.3,
// commit 7e5bbbeea on shardulsb08/brf:protocol_flow_fuzzing_harness)
// triggered kmemleak reports of the form:
//
//   BUG: memory leak
//   unreferenced object 0xffff... (size 192):
//     ...
//     mptcp_pm_alloc_anno_list+0x1ea/0x4e0 net/mptcp/pm.c:452
//     mptcp_pm_nl_announce_doit+0x1ee/0x6b0 net/mptcp/pm_userspace.c:231
//     genl_family_rcv_msg_doit+0x1ff/0x2f0
//     ...
//     __x64_sys_sendto
//
// What this program does (no harness, no fuzzer, just standard syscalls
// + genl + the patched kernel's kmemleak):
//
//   1. /proc/sys/net/mptcp/pm_type = 1   (userspace path manager)
//   2. Subscribe to mptcp_pm_events multicast group (required for
//      mptcp_userspace_pm_active() to return true)
//   3. socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP) for server + client
//      on 127.0.0.1, complete MP_CAPABLE handshake
//   4. 1-byte round-trip to prime msk->fully_established on both sides
//   5. getsockopt(client, SOL_MPTCP, MPTCP_INFO) -> mptcpi_token
//   6. Send genl MPTCP_PM_CMD_ANNOUNCE for additional address
//      127.0.0.3:1234 with MPTCP_PM_ADDR_FLAG_SIGNAL set, addressed by
//      our token.  Kernel handles this in mptcp_pm_nl_announce_doit
//      which calls mptcp_pm_alloc_anno_list -- the leak site.
//   7. close() everything
//   8. Wait kmemleak's min-age (30s) so the scan flags genuinely
//      unreachable objects, then trigger scan + read
//      /sys/kernel/debug/kmemleak
//   9. Grep for mptcp_pm_alloc_anno_list in the kmemleak dump
//
// Verifies the bug presence on the running kernel.  When upstream
// proposes a fix, rerun this against the patched build to confirm.
//
// Prerequisites
//   - CONFIG_MPTCP=y, CONFIG_DEBUG_KMEMLEAK=y, CONFIG_KMEMLEAK_DEFAULT_OFF
//     can be either (we explicitly do `echo scan` so off-by-default is ok)
//   - Root, in a netns that allows /proc/sys/net/mptcp/pm_type writes
//
// Build:
//   gcc -O2 -Wall -o test_mp_pm_announce_leak test_mp_pm_announce_leak.c
//
// Run (as root inside the target VM):
//   ./test_mp_pm_announce_leak
//
// Exit codes:
//   0   bug present (kmemleak report mentions mptcp_pm_alloc_anno_list)
//   1   bug appears fixed (kmemleak quiet after our trigger sequence)
//   2   prerequisite failure (no MPTCP, no kmemleak, no root, etc.)
//   3   the ANNOUNCE genl call itself failed (kernel API mismatch)
//   4   stability fast-path: trigger sequence reached, no kmemleak check
//       (only emitted when env BRF_STABILITY=1)
//
// Stability mode (env BRF_STABILITY=1) skips the 35s kmemleak wait so
// the wrapper run_stability.sh can cheaply repeat the run-up-to-trigger
// sequence many times and tally how often the MP_CAPABLE handshake +
// MPTCP_INFO read succeeds (= no fallback-race ghost) vs fails.
//
// Author: Shardul Bankar.  Co-developed-by: Claude Opus 4.7 (1M context).
// Bug found via BRF protocol-flow fuzzing harness
// (github.com/shardulsb08/brf, branch protocol_flow_fuzzing_harness).

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
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

/* mptcp_pm.h enum values (auto-generated from yaml spec, may not be in
 * older distro headers).  Values match kernel at the BRF base commit. */
enum {
	MPTCP_PM_ATTR_UNSPEC,
	MPTCP_PM_ATTR_ADDR,
	MPTCP_PM_ATTR_RCV_ADD_ADDRS,
	MPTCP_PM_ATTR_SUBFLOWS,
	MPTCP_PM_ATTR_TOKEN,
};
enum {
	MPTCP_PM_ADDR_ATTR_UNSPEC,
	MPTCP_PM_ADDR_ATTR_FAMILY,
	MPTCP_PM_ADDR_ATTR_ID,
	MPTCP_PM_ADDR_ATTR_ADDR4,
	MPTCP_PM_ADDR_ATTR_ADDR6,
	MPTCP_PM_ADDR_ATTR_PORT,
	MPTCP_PM_ADDR_ATTR_FLAGS,
	MPTCP_PM_ADDR_ATTR_IF_IDX,
};
#define MPTCP_PM_CMD_ANNOUNCE_VAL	8
#define MPTCP_PM_VER_VAL		1
#define MPTCP_PM_ADDR_FLAG_SIGNAL_VAL	(1U << 0)

/* Minimal subset of struct mptcp_info -- we only need mptcpi_token (and
 * the fields before it for layout). */
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
} __attribute__((packed));

static int write_file(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	int len = strlen(val);
	int rc = write(fd, val, len) == len ? 0 : -1;
	close(fd);
	return rc;
}

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

	if (send(sock, buf, nlh->nlmsg_len, 0) < 0)
		return -1;
	ssize_t n = recv(sock, buf, sizeof(buf), 0);
	if (n < 0)
		return -1;
	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type == NLMSG_ERROR)
		return -1;
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
	if (!fid || !egid)
		return -1;
	*family_id = fid;
	*event_grp_id = egid;
	return 0;
}

/* Send MPTCP_PM_CMD_ANNOUNCE.  Same wire shape and byte-order quirks
 * as MPTCP_PM_CMD_SUBFLOW_CREATE: port is host-byte-order in the
 * attribute (kernel htons() on the way in).  MPTCP_PM_ADDR_FLAG_SIGNAL
 * must be set in flags for the kernel to actually emit ADD_ADDR on
 * the wire -- without it the address is just stored. */
static int genl_pm_announce(int sock, uint16_t family_id, uint32_t token,
			    uint8_t addr_id, uint32_t addr_be, uint16_t port_h)
{
	char buf[256];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct genlmsghdr *ghdr;
	struct nlattr *attr, *nest;
	uint32_t flags = MPTCP_PM_ADDR_FLAG_SIGNAL_VAL;
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
	nlh->nlmsg_seq   = 3;
	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	ghdr->cmd     = MPTCP_PM_CMD_ANNOUNCE_VAL;
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
		PUT_ATTR(MPTCP_PM_ADDR_ATTR_ADDR4, &addr_be, sizeof(addr_be));
		PUT_ATTR(MPTCP_PM_ADDR_ATTR_PORT, &port_h, sizeof(port_h));
		PUT_ATTR(MPTCP_PM_ADDR_ATTR_FLAGS, &flags, sizeof(flags));
		nest->nla_len = p - (char *)nest;
	}

	nlh->nlmsg_len = p - buf;

	if (send(sock, buf, nlh->nlmsg_len, 0) < 0) {
		perror("send ANNOUNCE");
		return -1;
	}
	ssize_t n = recv(sock, buf, sizeof(buf), 0);
	if (n < 0) {
		perror("recv ANNOUNCE ack");
		return -1;
	}
	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type != NLMSG_ERROR) {
		fprintf(stderr, "ANNOUNCE: unexpected ack type %u\n",
			nlh->nlmsg_type);
		return -1;
	}
	struct nlmsgerr *ne = (struct nlmsgerr *)NLMSG_DATA(nlh);
	if (ne->error) {
		fprintf(stderr, "ANNOUNCE kernel err=%d (%s)\n",
			ne->error, strerror(-ne->error));
		return -1;
	}
	return 0;
#undef PUT_ATTR
}

/* Trigger a kmemleak scan and read the report; grep for our symbol.
 * Returns 1 if found, 0 if not found, -1 on prereq error. */
static int kmemleak_check_for_anno_leak(void)
{
	const char *kml = "/sys/kernel/debug/kmemleak";

	/* Need >30s since allocation for kmemleak to flag.  Default
	 * jiffies_min_age = 5s in newer kernels but kmemleak_scan
	 * waits internally before declaring unreferenced; padding
	 * generously here. */
	fprintf(stderr, "Waiting 35s for kmemleak min-age...\n");
	sleep(35);

	if (write_file(kml, "scan") < 0) {
		fprintf(stderr, "kmemleak: cannot write 'scan' to %s: %s\n"
				"  (need root + CONFIG_DEBUG_KMEMLEAK=y)\n",
			kml, strerror(errno));
		return -1;
	}
	fprintf(stderr, "Triggered kmemleak scan, waiting 8s for sweep...\n");
	sleep(8);

	FILE *f = fopen(kml, "r");
	if (!f) {
		perror("open kmemleak for read");
		return -1;
	}
	char line[1024];
	int found = 0;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, "mptcp_pm_alloc_anno_list")) {
			fprintf(stdout, "%s", line);
			found = 1;
			/* print a few more lines of context */
			for (int i = 0; i < 8 && fgets(line, sizeof(line), f); i++)
				fprintf(stdout, "%s", line);
			break;
		}
	}
	fclose(f);
	return found;
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
	int rc = 2;
	int one = 1;

	if (write_file("/proc/sys/net/mptcp/pm_type", "1") < 0) {
		fprintf(stderr, "FAIL: cannot set pm_type=1 (need root + "
				"CONFIG_MPTCP)\n");
		goto out;
	}
	printf("PASS: net.mptcp.pm_type = 1\n");

	nl_send = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (nl_send < 0) { perror("socket(genl send)"); goto out; }
	if (bind(nl_send, (struct sockaddr *)&nlsa, sizeof(nlsa)) < 0) {
		perror("bind(genl send)"); goto out;
	}
	if (resolve_mptcp_pm_family(nl_send, &family_id, &event_grp_id) < 0) {
		fprintf(stderr, "FAIL: cannot resolve mptcp_pm genl family\n");
		goto out;
	}
	printf("PASS: mptcp_pm family id=%u event_grp=%u\n",
	       family_id, event_grp_id);

	nl_event = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (nl_event < 0) { perror("socket(genl event)"); goto out; }
	if (bind(nl_event, (struct sockaddr *)&nlsa, sizeof(nlsa)) < 0) {
		perror("bind(genl event)"); goto out;
	}
	if (setsockopt(nl_event, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
		       &event_grp_id, sizeof(event_grp_id)) < 0) {
		perror("NETLINK_ADD_MEMBERSHIP mptcp_pm_events"); goto out;
	}
	printf("PASS: subscribed to mptcp_pm_events\n");

	server = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (server < 0) { perror("socket(server)"); goto out; }
	setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	addr.sin_port = 0;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind server"); goto out;
	}
	if (getsockname(server, (struct sockaddr *)&addr, &alen) < 0) {
		perror("getsockname"); goto out;
	}
	if (listen(server, 1) < 0) { perror("listen"); goto out; }
	printf("server: 127.0.0.1:%u\n", ntohs(addr.sin_port));

	client = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (client < 0) { perror("socket(client)"); goto out; }
	if (connect(client, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect"); goto out;
	}
	accepted = accept(server, NULL, NULL);
	if (accepted < 0) { perror("accept"); goto out; }
	printf("PASS: MP_CAPABLE handshake\n");

	/* Read token from the SERVER's accepted msk BEFORE any data flows.
	 * On the May 9-15 mptcp/export base there's a race where the 1-byte
	 * primer used to force fully_established also triggers
	 * MPCAPABLEDATAFALLBACK with high probability, leaving the msk in
	 * fallback state and making subsequent MPTCP_INFO return EOPNOTSUPP.
	 * Reading from the accepted side avoids that path -- the server msk
	 * is in TCP_ESTABLISHED right after accept() returns and MPTCP_INFO
	 * works on it before any data exchange.  If the kernel later requires
	 * fully_established for ANNOUNCE, we'll see ENOTCONN from the genl
	 * call and revisit. */
	struct mptcp_info_short info;
	socklen_t ilen = sizeof(info);
	uint32_t token = 0;

	memset(&info, 0, sizeof(info));
	ilen = sizeof(info);
	if (getsockopt(accepted, SOL_MPTCP, MPTCP_INFO, &info, &ilen) < 0) {
		perror("getsockopt(MPTCP_INFO) on accepted msk");
		goto out;
	}
	token = info.mptcpi_token;
	printf("server token: 0x%08x (via accepted msk, no primer)\n", token);

	/* The leak trigger.  Announce an additional address on the server
	 * msk's token.  Address 127.0.0.3:1234 chosen arbitrarily; the
	 * specific values don't matter -- it's the alloc_anno_list +
	 * msk-teardown sequence that leaks. */
	if (genl_pm_announce(nl_send, family_id, token, 1,
			     htonl(0x7f000003), 1234) < 0) {
		fprintf(stderr, "FAIL: ANNOUNCE genl call failed (API mismatch?)\n");
		rc = 3;
		goto out;
	}
	printf("PASS: ANNOUNCE sent for 127.0.0.3:1234 addr_id=1\n");

	/* Tear down -- this is where mptcp_pm_destroy SHOULD run and
	 * free the anno_list entry, but apparently doesn't (or some
	 * teardown path skips it). */
	close(client); client = -1;
	close(accepted); accepted = -1;
	close(server); server = -1;
	close(nl_send); nl_send = -1;
	close(nl_event); nl_event = -1;
	printf("PASS: sockets closed\n");

	if (getenv("BRF_STABILITY")) {
		printf("\nresult: STABILITY PASS -- trigger sequence completed, "
		       "skipping kmemleak scan (BRF_STABILITY set)\n");
		rc = 4;
		goto out;
	}

	int found = kmemleak_check_for_anno_leak();
	if (found == 1) {
		printf("\nresult: BUG PRESENT -- "
		       "kmemleak shows mptcp_pm_alloc_anno_list leak\n");
		rc = 0;
	} else if (found == 0) {
		printf("\nresult: bug appears fixed -- "
		       "no mptcp_pm_alloc_anno_list in kmemleak report\n");
		rc = 1;
	} else {
		printf("\nresult: INCONCLUSIVE -- "
		       "could not run kmemleak (prereq missing)\n");
		rc = 2;
	}

out:
	if (client    >= 0) close(client);
	if (accepted  >= 0) close(accepted);
	if (server    >= 0) close(server);
	if (nl_send   >= 0) close(nl_send);
	if (nl_event  >= 0) close(nl_event);
	return rc;
}
