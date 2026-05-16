// SPDX-License-Identifier: Apache-2.0
//
// test_mp_join_backup.c -- VM smoke test that verifies the backup-flag
// plumbing the BRF executor uses for syz_mptcp_join_subflow.
//
// Mirrors test_mp_join_normal.c, but issues SUBFLOW_CREATE with
// MPTCP_PM_ADDR_FLAG_BACKUP set on the local address attribute, then
// listens on the mptcp_pm_events multicast group for the resulting
// MPTCP_EVENT_SUB_ESTABLISHED event and checks its MPTCP_ATTR_BACKUP
// attribute.
//
// Verifies, end-to-end on a real kernel:
//   1. The kernel accepts SUBFLOW_CREATE with FLAGS attr present.
//   2. The kernel honours the BACKUP flag (the subflow is marked
//      backup; this is observable in the SUB_ESTABLISHED event).
//   3. The MP_JOIN handshake still completes normally (BACKUP only
//      changes priority, not validity).
//
// Build (inside the VM, or any libc-dev environment):
//   gcc -O2 -Wall -o test_mp_join_backup test_mp_join_backup.c
//
// Run (as root inside the patched VM):
//   ./test_mp_join_backup
//
// Exit codes:
//   0  pass
//   1  prerequisite syscall failed
//   2  SUBFLOW_CREATE was rejected by the kernel
//   3  subflow count did not increment within timeout
//   4  MIB delta sanity check failed
//   5  did not receive MPTCP_EVENT_SUB_ESTABLISHED within timeout
//   6  event's MPTCP_ATTR_BACKUP was missing or != 1
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
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
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

#define MPTCP_PM_ADDR_FLAG_BACKUP	(1U << 2)

/* mptcp_pm.h attribute / command / event enum values; mirroring the kernel
 * tree's include/uapi/linux/mptcp_pm.h. */
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
enum {
	MPTCP_ATTR_UNSPEC_TEST,
	MPTCP_ATTR_TOKEN,
	MPTCP_ATTR_FAMILY,
	MPTCP_ATTR_LOC_ID,
	MPTCP_ATTR_REM_ID,
	MPTCP_ATTR_SADDR4,
	MPTCP_ATTR_SADDR6,
	MPTCP_ATTR_DADDR4,
	MPTCP_ATTR_DADDR6,
	MPTCP_ATTR_SPORT,
	MPTCP_ATTR_DPORT,
	MPTCP_ATTR_BACKUP,
	MPTCP_ATTR_ERROR,
	MPTCP_ATTR_FLAGS,
	MPTCP_ATTR_TIMEOUT,
	MPTCP_ATTR_IF_IDX,
	MPTCP_ATTR_RESET_REASON,
	MPTCP_ATTR_RESET_FLAGS,
	MPTCP_ATTR_SERVER_SIDE,
};
#define MPTCP_PM_CMD_SUBFLOW_CREATE_VAL   10
#define MPTCP_EVENT_SUB_ESTABLISHED_VAL   10
#define MPTCP_PM_VER_VAL                  1

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

static bool write_sysctl(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) { fprintf(stderr, "open %s: %s\n", path, strerror(errno)); return false; }
	int len = strlen(val);
	if (write(fd, val, len) != len) { perror("write sysctl"); close(fd); return false; }
	close(fd);
	return true;
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
	attr = (struct nlattr *)((char *)NLMSG_DATA(nlh) + NLMSG_ALIGN(sizeof(*ghdr)));
	attr->nla_type = CTRL_ATTR_FAMILY_NAME;
	attr->nla_len  = NLA_HDRLEN + sizeof(fname);
	memcpy((char *)attr + NLA_HDRLEN, fname, sizeof(fname));
	nlh->nlmsg_len = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ghdr)) +
			 NLA_ALIGN(attr->nla_len);

	if (send(sock, buf, nlh->nlmsg_len, 0) < 0) { perror("send GETFAMILY"); return -1; }
	ssize_t n = recv(sock, buf, sizeof(buf), 0);
	if (n < 0) { perror("recv GETFAMILY"); return -1; }
	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *ne = (struct nlmsgerr *)NLMSG_DATA(nlh);
		fprintf(stderr, "GETFAMILY err=%d (%s)\n", ne->error, strerror(-ne->error));
		return -1;
	}
	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	attr = (struct nlattr *)((char *)NLMSG_DATA(nlh) + NLMSG_ALIGN(sizeof(*ghdr)));
	ssize_t left = nlh->nlmsg_len - NLMSG_HDRLEN - NLMSG_ALIGN(sizeof(*ghdr));
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
				if (grp->nla_len < NLA_HDRLEN || gpos + grp->nla_len > gend) break;
				char *ipos = (char *)grp + NLA_HDRLEN;
				char *iend = (char *)grp + grp->nla_len;
				const char *gname = NULL;
				uint32_t gid = 0;
				while (ipos + NLA_HDRLEN <= iend) {
					struct nlattr *in = (struct nlattr *)ipos;
					if (in->nla_len < NLA_HDRLEN || ipos + in->nla_len > iend) break;
					if ((in->nla_type & NLA_TYPE_MASK) == CTRL_ATTR_MCAST_GRP_NAME)
						gname = (const char *)in + NLA_HDRLEN;
					else if ((in->nla_type & NLA_TYPE_MASK) == CTRL_ATTR_MCAST_GRP_ID &&
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
		attr = (struct nlattr *)((char *)attr + NLA_ALIGN(attr->nla_len));
	}
	if (!fid || !egid) { fprintf(stderr, "GETFAMILY parse incomplete\n"); return -1; }
	*family_id = fid;
	*event_grp_id = egid;
	return 0;
}

/* SUBFLOW_CREATE with FLAGS attribute set.  Port arguments are host byte
 * order -- see test_mp_join_normal.c's note on the kernel uapi quirk. */
static int genl_subflow_create_backup(int sock, uint16_t family_id,
				      uint32_t token, uint8_t addr_id,
				      uint32_t addr_flags,
				      uint32_t local_addr_be, uint16_t local_port_h,
				      uint32_t remote_addr_be, uint16_t remote_port_h)
{
	char buf[256];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct genlmsghdr *ghdr;
	struct nlattr *attr, *nest;
	char *p;
#define PUT_ATTR(typ, src, sz) do {					\
		attr = (struct nlattr *)p;				\
		attr->nla_type = (typ);					\
		attr->nla_len  = NLA_HDRLEN + (sz);			\
		memcpy((char *)attr + NLA_HDRLEN, (src), (sz));		\
		p += NLA_ALIGN(attr->nla_len);				\
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
		PUT_ATTR(MPTCP_PM_ADDR_ATTR_ADDR4, &local_addr_be, sizeof(local_addr_be));
		PUT_ATTR(MPTCP_PM_ADDR_ATTR_PORT, &local_port_h, sizeof(local_port_h));
		PUT_ATTR(MPTCP_PM_ADDR_ATTR_FLAGS, &addr_flags, sizeof(addr_flags));
		nest->nla_len = p - (char *)nest;
	}
	{
		uint16_t fam_v = AF_INET;
		nest = (struct nlattr *)p;
		nest->nla_type = MPTCP_PM_ATTR_ADDR_REMOTE | NLA_F_NESTED;
		p += NLA_HDRLEN;
		PUT_ATTR(MPTCP_PM_ADDR_ATTR_FAMILY, &fam_v, sizeof(fam_v));
		PUT_ATTR(MPTCP_PM_ADDR_ATTR_ADDR4, &remote_addr_be, sizeof(remote_addr_be));
		PUT_ATTR(MPTCP_PM_ADDR_ATTR_PORT, &remote_port_h, sizeof(remote_port_h));
		nest->nla_len = p - (char *)nest;
	}
	nlh->nlmsg_len = p - buf;

	if (send(sock, buf, nlh->nlmsg_len, 0) < 0) { perror("send SUBFLOW_CREATE"); return -1; }
	ssize_t n = recv(sock, buf, sizeof(buf), 0);
	if (n < 0) { perror("recv SUBFLOW_CREATE ack"); return -1; }
	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type != NLMSG_ERROR) {
		fprintf(stderr, "SUBFLOW_CREATE: unexpected ack type %u\n", nlh->nlmsg_type);
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

/* Drain anything currently queued on the event socket.  Used to clear
 * MPTCP_EVENT_CREATED / _ESTABLISHED events generated by our own MP_CAPABLE
 * setup, so the post-SUBFLOW_CREATE read only sees the new subflow event. */
static void drain_events(int sock)
{
	char buf[8192];
	int drained = 0;
	for (;;) {
		ssize_t n = recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) break;
			perror("drain recv");
			break;
		}
		drained++;
	}
	if (drained)
		fprintf(stderr, "drained %d pre-existing event(s) from mptcp_pm_events\n",
			drained);
}

/* Wait up to timeout_ms for the SERVER-SIDE SUB_ESTABLISHED event,
 * return its MPTCP_ATTR_BACKUP attribute value (0 or 1), or -1.
 *
 * Why server-side specifically: the MPTCP subflow context's `backup` field
 * reflects the PEER's backup status (set from the incoming SYN's bkup bit
 * on the server-side path, net/mptcp/subflow.c:225+2090; set from the
 * server's SYN-ACK bkup bit on the client-side path, subflow.c:583).  Our
 * request placed MPTCP_PM_ADDR_FLAG_BACKUP on the CLIENT's local address,
 * so the wire SYN carried bkup=1.  The server reads "peer is backup",
 * stores it in its subflow ctx, and that's the sf->backup the event
 * reports.  The client-side event sees the server's SYN-ACK with bkup=0
 * (server didn't mark its endpoint backup), so client-side sf->backup=0.
 *
 * How to distinguish sides: MPTCP_ATTR_SERVER_SIDE is only emitted for
 * MPTCP_EVENT_CREATED (mptcp_event_created in pm_netlink.c:408+); the
 * SUB_ESTABLISHED emitter (mptcp_event_put_token_and_ssk, pm_netlink.c:345)
 * does NOT include it.  Use the TOKEN attribute instead -- each msk has
 * its own token, so events whose MPTCP_ATTR_TOKEN matches our client's
 * token come from the client-side msk, and the others come from the
 * server-side msk. */
static int wait_for_sub_established_backup(int sock, uint16_t family_id,
					   uint32_t client_token,
					   int timeout_ms)
{
	char buf[8192];
	struct timeval deadline_tv;
	gettimeofday(&deadline_tv, NULL);
	deadline_tv.tv_usec += (timeout_ms % 1000) * 1000;
	deadline_tv.tv_sec  += timeout_ms / 1000;
	if (deadline_tv.tv_usec >= 1000000) {
		deadline_tv.tv_sec++;
		deadline_tv.tv_usec -= 1000000;
	}
	int events_seen = 0;

	while (1) {
		struct timeval now_tv;
		gettimeofday(&now_tv, NULL);
		long remain_ms =
			(deadline_tv.tv_sec - now_tv.tv_sec) * 1000 +
			(deadline_tv.tv_usec - now_tv.tv_usec) / 1000;
		if (remain_ms <= 0)
			break;

		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);
		struct timeval tv = {
			.tv_sec  = remain_ms / 1000,
			.tv_usec = (remain_ms % 1000) * 1000,
		};
		int rc = select(sock + 1, &rfds, NULL, NULL, &tv);
		if (rc <= 0)
			break;

		ssize_t n = recv(sock, buf, sizeof(buf), 0);
		if (n < 0) { perror("recv event"); break; }
		struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
		if (nlh->nlmsg_type != family_id)
			continue;
		struct genlmsghdr *ghdr =
			(struct genlmsghdr *)NLMSG_DATA(nlh);
		if (ghdr->cmd != MPTCP_EVENT_SUB_ESTABLISHED_VAL)
			continue;

		events_seen++;
		struct nlattr *attr = (struct nlattr *)((char *)NLMSG_DATA(nlh) +
							 NLMSG_ALIGN(sizeof(*ghdr)));
		ssize_t left = nlh->nlmsg_len - NLMSG_HDRLEN -
			       NLMSG_ALIGN(sizeof(*ghdr));
		uint32_t event_token = 0;
		int backup_val = -1;
		while (left >= (ssize_t)NLA_HDRLEN && attr->nla_len >= NLA_HDRLEN) {
			uint16_t t = attr->nla_type & NLA_TYPE_MASK;
			if (t == MPTCP_ATTR_TOKEN &&
			    attr->nla_len >= NLA_HDRLEN + sizeof(uint32_t))
				event_token =
					*(uint32_t *)((char *)attr + NLA_HDRLEN);
			else if (t == MPTCP_ATTR_BACKUP &&
				 attr->nla_len >= NLA_HDRLEN + sizeof(uint8_t))
				backup_val =
					*(uint8_t *)((char *)attr + NLA_HDRLEN);
			left -= NLA_ALIGN(attr->nla_len);
			attr = (struct nlattr *)((char *)attr +
						 NLA_ALIGN(attr->nla_len));
		}
		int is_server_side = (event_token != client_token);
		fprintf(stderr,
			"  SUB_ESTABLISHED event #%d: token=0x%08x %s backup=%d\n",
			events_seen, event_token,
			is_server_side ? "(server-side)" : "(client-side)",
			backup_val);
		if (is_server_side)
			return backup_val;
		/* Otherwise client-side; keep reading. */
	}
	fprintf(stderr,
		"saw %d SUB_ESTABLISHED event(s), no server-side one found\n",
		events_seen);
	return -1;
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

	if (!write_sysctl("/proc/sys/net/mptcp/pm_type", "1")) {
		fprintf(stderr, "FAIL: cannot set pm_type=1\n");
		goto out;
	}
	printf("PASS: net.mptcp.pm_type = 1 (userspace PM enabled)\n");

	nl_send = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (nl_send < 0) { perror("socket(genl send)"); goto out; }
	if (bind(nl_send, (struct sockaddr *)&nlsa, sizeof(nlsa)) < 0) { perror("bind"); goto out; }
	if (resolve_mptcp_pm_family(nl_send, &family_id, &event_grp_id) < 0) goto out;
	printf("PASS: mptcp_pm family resolved: id=%u, events grp=%u\n",
	       family_id, event_grp_id);

	nl_event = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (nl_event < 0) { perror("socket(genl event)"); goto out; }
	if (bind(nl_event, (struct sockaddr *)&nlsa, sizeof(nlsa)) < 0) { perror("bind"); goto out; }
	if (setsockopt(nl_event, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
		       &event_grp_id, sizeof(event_grp_id)) < 0) {
		perror("NETLINK_ADD_MEMBERSHIP");
		goto out;
	}
	printf("PASS: subscribed to mptcp_pm_events (userspace_pm_active=true)\n");

	server = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (server < 0) { perror("socket server"); goto out; }
	setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	addr.sin_port = 0;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind server"); goto out; }
	if (getsockname(server, (struct sockaddr *)&addr, &alen) < 0) { perror("getsockname"); goto out; }
	if (listen(server, 1) < 0) { perror("listen"); goto out; }
	uint16_t server_port_h = ntohs(addr.sin_port);
	printf("server: bound 127.0.0.1:%u\n", server_port_h);

	client = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (client < 0) { perror("socket client"); goto out; }
	if (connect(client, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("connect"); goto out; }
	accepted = accept(server, NULL, NULL);
	if (accepted < 0) { perror("accept"); goto out; }
	printf("PASS: MP_CAPABLE handshake completed\n");

	/* Prime client-side fully_established (see design doc Section 10). */
	{
		char b = 'x';
		if (send(client, &b, 1, 0) != 1) { perror("prime c->s"); goto out; }
		if (recv(accepted, &b, 1, MSG_WAITALL) != 1) { perror("prime s recv"); goto out; }
		if (send(accepted, &b, 1, 0) != 1) { perror("prime s->c"); goto out; }
		if (recv(client, &b, 1, MSG_WAITALL) != 1) { perror("prime c recv"); goto out; }
		printf("PASS: 1-byte round-trip primed fully_established\n");
	}

	struct mptcp_info_short info;
	socklen_t ilen = sizeof(info);
	memset(&info, 0, sizeof(info));
	if (getsockopt(client, SOL_MPTCP, MPTCP_INFO, &info, &ilen) < 0) {
		perror("getsockopt MPTCP_INFO"); goto out;
	}
	uint32_t token = info.mptcpi_token;
	printf("client token: 0x%08x\n", token);

	/* Drain pre-existing events from MP_CAPABLE (MPTCP_EVENT_CREATED +
	 * MPTCP_EVENT_ESTABLISHED) before SUBFLOW_CREATE, so the next event
	 * we read is the one for OUR new subflow. */
	drain_events(nl_event);

	/* SUBFLOW_CREATE with MPTCP_PM_ADDR_FLAG_BACKUP set on local addr. */
	if (genl_subflow_create_backup(nl_send, family_id, token, 1,
				       MPTCP_PM_ADDR_FLAG_BACKUP,
				       htonl(0x7f000002), 0,
				       htonl(0x7f000001), server_port_h) < 0) {
		rc = 2;
		goto out;
	}
	printf("PASS: SUBFLOW_CREATE acked by kernel (with FLAGS=BACKUP)\n");

	/* Confirm the subflow established (server-side mptcpi_subflows >= 1). */
	int established = 0;
	for (int retry = 0; retry < 20; retry++) {
		memset(&info, 0, sizeof(info));
		ilen = sizeof(info);
		if (getsockopt(accepted, SOL_MPTCP, MPTCP_INFO, &info, &ilen) == 0 &&
		    info.mptcpi_subflows >= 1) {
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

	/* Wait for the SERVER-SIDE SUB_ESTABLISHED event and verify
	 * backup attr = 1.  Distinguishing the side via token: events
	 * whose MPTCP_ATTR_TOKEN matches our client token come from the
	 * client msk; the rest come from the server msk (whose
	 * MP_CAPABLE-derived token is independent of the client's). */
	int backup_observed = wait_for_sub_established_backup(nl_event, family_id,
							      token, 500);
	if (backup_observed < 0) {
		fprintf(stderr, "FAIL: SUB_ESTABLISHED event with backup attr "
				"not seen within 500ms\n");
		rc = 5;
		goto out;
	}
	if (backup_observed != 1) {
		fprintf(stderr, "FAIL: SUB_ESTABLISHED event has backup=%d, expected 1\n",
			backup_observed);
		rc = 6;
		goto out;
	}
	printf("PASS: SUB_ESTABLISHED event confirms backup=1\n");

	rc = 0;
out:
	if (accepted >= 0) close(accepted);
	if (client   >= 0) close(client);
	if (server   >= 0) close(server);
	if (nl_event >= 0) close(nl_event);
	if (nl_send  >= 0) close(nl_send);
	if (rc == 0)
		printf("\nresult: PASS (backup-flag plumbing verified end-to-end)\n");
	else
		fprintf(stderr, "\nresult: FAIL (rc=%d) -- see messages above\n", rc);
	return rc;
}
