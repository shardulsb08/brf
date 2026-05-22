
#define OBJ_LIST_SIZE 32

/* Weak stub for bpf_object__add_kcov_handle.  The real implementation
 * is provided by libbpf when the kernel tree has the kcov-for-BPF
 * series (brf/kernel_patches/bpf_kcov/0002 + 0003) applied and that
 * libbpf is installed system-wide.  When only the MPTCP harness side
 * of BRF is in use (no eBPF runtime fuzzing), the distro libbpf does
 * not export this symbol, so this weak no-op lets the executor link
 * cleanly.  Result: bpf-kcov collection from eBPF programs becomes a
 * no-op; the MPTCP harness path is unaffected.  Restore the real
 * behaviour by applying kernel_patches/bpf_kcov/0002 and 0003 and
 * rebuilding libbpf from kernel/tools/lib/bpf/. */
__attribute__((weak))
void bpf_object__add_kcov_handle(struct bpf_object *obj __attribute__((unused)),
				 __u64 kcov_remote_handle __attribute__((unused)))
{
}

static struct bpf_object *bpf_object_list[OBJ_LIST_SIZE];

/* BRF Phase 3, Stage D1/D3 -- struct_ops scheduler links + names.
 *
 * A BPF struct_ops MPTCP scheduler is registered by attaching its
 * BPF_MAP_TYPE_STRUCT_OPS map (bpf_map__attach_struct_ops); the
 * returned bpf_link must stay alive for the registration to persist,
 * exactly as bpf_object_list keeps the objects alive.  Both lists are
 * parallel to bpf_object_list -- index i is the link / registered
 * scheduler name for object i.  The name is the per-proc-unique name
 * patched in at load time (Stage D3) and is what syz_bpf_prog_attach
 * writes to /proc/sys/net/mptcp/scheduler to select the scheduler. */
#define BRF_MPTCP_SCHED_NAME_MAX 16
static struct bpf_link *struct_ops_link_list[OBJ_LIST_SIZE];
static char struct_ops_name_list[OBJ_LIST_SIZE][BRF_MPTCP_SCHED_NAME_MAX];

struct bpf_res {
	int prog_fds[32];
	int prog_num;
	int map_fds[32];
	int map_num;
};

static long syz_bpf_prog_open(volatile long a0)
{
	const char* file = (char*)a0;
	struct bpf_object* obj;
	char bpf_err_buf[256];
	unsigned int i;
	long err;

	obj = bpf_object__open(file);
	err = libbpf_get_error(obj);
	if (err) {
		debug("syz_bpf_prog_open: failed to open bpf object %s: %s\n", file, bpf_err_buf);
		return -1;
	}

	for (i = 0; i < OBJ_LIST_SIZE; i++) {
		if (!bpf_object_list[i]) {
			bpf_object_list[i] = obj;
			return 0;
		}
	}

	debug("syz_bpf_prog_open: bpf_object_list full\n");
	return -1;
}

static struct bpf_object *find_bpf_object_by_basename(const char *path)
{
	char name[BPF_OBJ_NAME_LEN];
	char *end;
	int i = 0;

	for (i = 0; i < OBJ_LIST_SIZE; i++) {
		if (!bpf_object_list[i])
			break;

		strncpy(name, basename(path), sizeof(name) - 1);
		end = strchr(name, '.');
		if (end)
			*end = 0;

		if (strcmp(bpf_object__name(bpf_object_list[i]), name) == 0)
			return bpf_object_list[i];
	}
	return NULL;
}

static __u64 kcov_common_handle(void);

/* BRF Phase 3, Stage D1/D3 -- BPF struct_ops MPTCP scheduler support.
 *
 * A generated MPTCP scheduler (prog/brf_structops.go) is a struct_ops
 * object: its BPF_MAP_TYPE_STRUCT_OPS map carries an mptcp_sched_ops
 * instance.  Registration is done by attaching that map (Stage D1,
 * syz_bpf_prog_attach), not by attaching the individual callback
 * programs.  The logic ports executor/bpf_progs/test_mptcp_bpf_sched.c.
 *
 * mptcp_register_scheduler() is kernel-global: two concurrent fuzzer
 * procs that load the same generated program would both register the
 * same brf_<hash> name and the second collides (-EEXIST).  Stage D3
 * makes the registered name per-proc-unique -- see
 * brf_struct_ops_uniquify_name. */

/* Find the single BPF_MAP_TYPE_STRUCT_OPS map in obj, or NULL.  A
 * generated MPTCP scheduler has exactly one. */
static struct bpf_map *brf_find_struct_ops_map(struct bpf_object *obj)
{
	struct bpf_map *map;

	bpf_object__for_each_map(map, obj) {
		if (bpf_map__type(map) == BPF_MAP_TYPE_STRUCT_OPS)
			return map;
	}
	return NULL;
}

/* Stage D3 -- patch the mptcp_sched_ops.name[] member of a struct_ops
 * map's initial value to a globally-unique name, BEFORE bpf_object__load
 * (libbpf folds the initial value into the kernel struct_ops value at
 * load time, so a later patch would have no effect).
 *
 * The generator names each scheduler brf_<hash> and uses that same
 * string both as the struct_ops map's libbpf name and as the
 * mptcp_sched_ops.name[] member.  The name[] field is located by
 * searching the initial-value blob for that string (it occurs there
 * exactly once -- the brf_<hash> byte sequence cannot appear in any
 * other field).  No BTF walking needed.
 *
 * Uniqueness: mptcp_register_scheduler() is kernel-global, so the
 * registered name must be unique across *all* live registrations --
 * both across concurrent fuzzer procs AND across successive struct_ops
 * programs within one proc (each keeps its bpf_link, hence its
 * registration, alive).  The patched name is
 *   brf_<11 hex chars>
 * which exactly fills MPTCP_SCHED_NAME_MAX (16: "brf_" + 11 + NUL).
 * The 44-bit value is (pid:24 << 20) | (counter:20):
 *   - low 24 bits of getpid() -- distinct per concurrent proc
 *     (covers the default pid_max of 4M with room to spare);
 *   - a 20-bit per-proc monotonic counter -- distinct per program
 *     within a proc (1M programs before wraparound).
 * out must hold BRF_MPTCP_SCHED_NAME_MAX bytes and receives the
 * registered name so the attach path selects exactly what was
 * registered. */
static unsigned brf_struct_ops_name_counter;

static int brf_struct_ops_uniquify_name(struct bpf_map *map, char *out)
{
	const char *orig = bpf_map__name(map);
	size_t blob_size = 0, orig_len, i;
	char *blob;
	char uniq[BRF_MPTCP_SCHED_NAME_MAX];
	unsigned long long tag;
	int n;

	if (!orig || !orig[0])
		return -1;
	orig_len = strlen(orig);

	tag = (((unsigned long long)((unsigned)getpid() & 0xFFFFFF)) << 20) |
	      (brf_struct_ops_name_counter++ & 0xFFFFF);
	n = snprintf(uniq, sizeof(uniq), "brf_%011llx", tag);
	if (n < 0 || n >= (int)sizeof(uniq))
		return -1;

	blob = (char *)bpf_map__initial_value(map, &blob_size);
	if (!blob || blob_size < orig_len) {
		debug("syz_bpf_prog_load: struct_ops map has no initial value\n");
		return -1;
	}

	/* Locate the original name string and overwrite the fixed-width
	 * name[] field in place.  field is the writable width -- the full
	 * MPTCP_SCHED_NAME_MAX, capped at the blob tail defensively (the
	 * real name[] is mid-struct, so the cap never actually trips). */
	for (i = 0; i + orig_len <= blob_size; i++) {
		size_t field = BRF_MPTCP_SCHED_NAME_MAX;
		size_t uniq_len = strlen(uniq);

		if (memcmp(blob + i, orig, orig_len) != 0)
			continue;
		if (i + field > blob_size)
			field = blob_size - i;
		memset(blob + i, 0, field);
		if (uniq_len > field)
			uniq_len = field;
		memcpy(blob + i, uniq, uniq_len);
		strncpy(out, uniq, BRF_MPTCP_SCHED_NAME_MAX - 1);
		out[BRF_MPTCP_SCHED_NAME_MAX - 1] = '\0';
		debug("syz_bpf_prog_load: struct_ops sched %s -> %s\n",
		      orig, uniq);
		return 0;
	}

	debug("syz_bpf_prog_load: struct_ops name %s not found in blob\n",
	      orig);
	return -1;
}

static long syz_bpf_prog_load(volatile long a0, volatile long a1)
{
	const char *file = (char *)a0;
	struct bpf_res *res = (struct bpf_res *)a1;
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_map *map;
	int i, err;

	obj = find_bpf_object_by_basename(file);
	if (!obj) {
		debug("syz_bpf_prog_load: cannot find %s\n", file);
		return -1;
	}

	/* Stage D3: for a struct_ops scheduler, make the registered name
	 * per-proc-unique before load.  The chosen name is stashed in the
	 * slot parallel to bpf_object_list so syz_bpf_prog_attach can
	 * select it.  Best-effort -- on failure the attach path falls
	 * back to the object's compiled-in name. */
	map = brf_find_struct_ops_map(obj);
	if (map) {
		char sched_name[BRF_MPTCP_SCHED_NAME_MAX] = {0};

		if (brf_struct_ops_uniquify_name(map, sched_name) == 0) {
			for (i = 0; i < OBJ_LIST_SIZE; i++) {
				if (bpf_object_list[i] == obj) {
					strncpy(struct_ops_name_list[i],
						sched_name,
						BRF_MPTCP_SCHED_NAME_MAX - 1);
					break;
				}
			}
		}
	}

	bpf_object__add_kcov_handle(obj, kcov_common_handle());
	err = bpf_object__load(obj);
	if (err) {
		debug("syz_bpf_prog_load: failed to load bpf prog, errno %d\n", err);
		return -1;
	}

	i = 0;
	bpf_object__for_each_program(prog, obj)
		res->prog_fds[i++] = bpf_program__fd(prog);

	i = 0;
	bpf_object__for_each_map(map, obj)
		res->map_fds[i++] = bpf_map__fd(map);

	return res->prog_fds[0];
}

#define LO_IFINDEX 1

static bool check_attach_res(struct bpf_program *prog, int *res)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_CPU_CYCLES,
		.sample_freq = 50,
		.inherit = 1,
		.freq = 1,
	};

	if (*res > 0)
		return true;

	switch (bpf_program__type(prog)) {
	case BPF_PROG_TYPE_SOCKET_FILTER:
		*res = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		goto check_fd;
	case BPF_PROG_TYPE_SCHED_CLS:
	case BPF_PROG_TYPE_SCHED_ACT:
	case BPF_PROG_TYPE_XDP:
		*res = LO_IFINDEX;
		return true;
	case BPF_PROG_TYPE_PERF_EVENT:
		*res = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
		goto check_fd;
	case BPF_PROG_TYPE_CGROUP_SKB:
	case BPF_PROG_TYPE_CGROUP_SOCK:
	case BPF_PROG_TYPE_CGROUP_DEVICE:
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
	case BPF_PROG_TYPE_CGROUP_SYSCTL:
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
		*res = open("/sys/fs/cgroup", O_RDONLY);
		goto check_fd;
	case BPF_PROG_TYPE_SK_SKB:
	case BPF_PROG_TYPE_SK_MSG:
		*res = bpf_map_create(BPF_MAP_TYPE_SOCKMAP, "brf",
				      sizeof(int), sizeof(int), 1, &opts);
		goto check_fd;
	case BPF_PROG_TYPE_LIRC_MODE2:
		*res = open("/dev/lirc0", O_RDWR);
		goto check_fd;
	case BPF_PROG_TYPE_SK_REUSEPORT:
		*res = socket(AF_INET, SOCK_DGRAM, 0);
		goto check_fd;
	case BPF_PROG_TYPE_FLOW_DISSECTOR:
	case BPF_PROG_TYPE_SK_LOOKUP:
		*res = open("/proc/self/ns/net", O_RDONLY);
		goto check_fd;
	default:
		return true;
	}

check_fd:
	return *res >= 0;
}

static int bpf_program_attach(struct bpf_program *prog, int res, struct bpf_link **link)
{
	struct bpf_tcx_opts tcx_opts;
	struct bpf_netfilter_opts nf_opts;
	int optval = 1;
	int fd, ret;

	if (!check_attach_res(prog, &res)) {
		debug("syz_bpf_prog_attach: no attach point for %s\n",
		      libbpf_bpf_prog_type_str(bpf_program__type(prog)));
		return -1;
	}

	fd = bpf_program__fd(prog);

	switch (bpf_program__type(prog)) {
	case BPF_PROG_TYPE_SOCKET_FILTER:
		return setsockopt(res, SOL_SOCKET, SO_ATTACH_BPF, &fd, sizeof(fd));
	case BPF_PROG_TYPE_KPROBE:
	case BPF_PROG_TYPE_TRACEPOINT:
	case BPF_PROG_TYPE_RAW_TRACEPOINT:
	case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE:
	case BPF_PROG_TYPE_TRACING:
		*link = bpf_program__attach(prog);
		goto check_link;
	case BPF_PROG_TYPE_SCHED_CLS:
	case BPF_PROG_TYPE_SCHED_ACT:
		*link = bpf_program__attach_tcx(prog, res, &tcx_opts);
		goto check_link;
	case BPF_PROG_TYPE_XDP:
		*link = bpf_program__attach_xdp(prog, res);
		goto check_link;
	case BPF_PROG_TYPE_PERF_EVENT:
		*link = bpf_program__attach_perf_event(prog, res);
		goto check_link;
	case BPF_PROG_TYPE_CGROUP_SKB:
	case BPF_PROG_TYPE_CGROUP_SOCK:
	case BPF_PROG_TYPE_CGROUP_DEVICE:
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
	case BPF_PROG_TYPE_CGROUP_SYSCTL:
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
		*link = bpf_program__attach_cgroup(prog, res);
		goto check_link;
	case BPF_PROG_TYPE_LWT_IN:
	case BPF_PROG_TYPE_LWT_OUT:
	case BPF_PROG_TYPE_LWT_XMIT:
	case BPF_PROG_TYPE_LWT_SEG6LOCAL:
		break;
	case BPF_PROG_TYPE_SOCK_OPS:
		*link = bpf_program__attach_cgroup(prog, res);
		goto check_link;
	case BPF_PROG_TYPE_SK_SKB:
		return bpf_prog_attach(fd, res, BPF_SK_SKB_VERDICT, 0);
	case BPF_PROG_TYPE_SK_MSG:
		return bpf_prog_attach(fd, res, BPF_SK_MSG_VERDICT, 0);
	case BPF_PROG_TYPE_LIRC_MODE2:
		return bpf_prog_attach(fd, res, BPF_LIRC_MODE2, 0);
	case BPF_PROG_TYPE_SK_REUSEPORT:
		ret = setsockopt(res, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
		return ret?: setsockopt(res, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &fd, sizeof(fd));
	case BPF_PROG_TYPE_FLOW_DISSECTOR:
		*link = bpf_program__attach_netns(prog, res);
		goto check_link;
	case BPF_PROG_TYPE_STRUCT_OPS:
	case BPF_PROG_TYPE_EXT:
	case BPF_PROG_TYPE_LSM:
		*link = bpf_program__attach_lsm(prog);
		goto check_link;
	case BPF_PROG_TYPE_SK_LOOKUP:
		*link = bpf_program__attach_netns(prog, res);
		goto check_link;
	case BPF_PROG_TYPE_SYSCALL:
		break;
	case BPF_PROG_TYPE_NETFILTER:
		*link = bpf_program__attach_netfilter(prog, &nf_opts);
		goto check_link;
	default:
		break;
	}

	return -1;

check_link:
	return (*link != NULL) ? 0 : -1;
}

#define BRF_MPTCP_SCHED_SYSCTL   "/proc/sys/net/mptcp/scheduler"

/* Write the scheduler name to the MPTCP scheduler sysctl, selecting it
 * as the netns default.  Best-effort: a failure is logged but does not
 * fail the attach -- the scheduler is registered regardless, and the
 * fuzzer still drives traffic over whatever scheduler is selected. */
static void brf_struct_ops_select(const char *name)
{
	int fd = open(BRF_MPTCP_SCHED_SYSCTL, O_WRONLY);

	if (fd < 0) {
		debug("syz_bpf_prog_attach: open %s: %d\n",
		      BRF_MPTCP_SCHED_SYSCTL, errno);
		return;
	}
	if (write(fd, name, strlen(name)) < 0)
		debug("syz_bpf_prog_attach: write %s = %s: %d\n",
		      BRF_MPTCP_SCHED_SYSCTL, name, errno);
	else
		debug("syz_bpf_prog_attach: selected MPTCP scheduler %s\n",
		      name);
	close(fd);
}

/* Register a struct_ops object's scheduler and select it.  obj must
 * already be bpf_object__load()ed (syz_bpf_prog_load does this).
 * Returns the link fd on success (and stores the link so it stays
 * alive), -1 on failure. */
static long brf_struct_ops_attach(struct bpf_object *obj, struct bpf_map *map)
{
	struct bpf_link *link;
	int i;

	link = bpf_map__attach_struct_ops(map);
	if (!link || libbpf_get_error(link)) {
		debug("syz_bpf_prog_attach: bpf_map__attach_struct_ops: %d\n",
		      errno);
		return -1;
	}

	/* Keep the link alive -- destroying it unregisters the
	 * scheduler.  Slot it parallel to bpf_object_list. */
	for (i = 0; i < OBJ_LIST_SIZE; i++) {
		if (bpf_object_list[i] == obj) {
			struct_ops_link_list[i] = link;
			break;
		}
	}
	if (i == OBJ_LIST_SIZE) {
		/* Object not tracked -- still leak the link rather than
		 * destroy it, so the registration persists. */
		debug("syz_bpf_prog_attach: struct_ops obj not in list\n");
	}

	return bpf_link__fd(link);
}

static long syz_bpf_prog_attach(volatile long a0)
{
	const char *file = (char *)a0;
	int attach_res = -1;
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_map *map;
	struct bpf_link *link = NULL;

	obj = find_bpf_object_by_basename(file);
	if (!obj) {
		debug("syz_bpf_prog_attach: cannot find %s\n", file);
		return -1;
	}

	/* BRF Phase 3, Stage D1: a struct_ops object (generated MPTCP
	 * scheduler) is registered map-side, not per-program.  Detect it
	 * and route through the struct_ops attach + select path.  The
	 * per-proc-unique name was chosen and stashed at load time
	 * (Stage D3, syz_bpf_prog_load); read it back here to select
	 * exactly what was registered. */
	map = brf_find_struct_ops_map(obj);
	if (map) {
		char sched_name[BRF_MPTCP_SCHED_NAME_MAX] = {0};
		int i;

		for (i = 0; i < OBJ_LIST_SIZE; i++) {
			if (bpf_object_list[i] == obj) {
				strncpy(sched_name, struct_ops_name_list[i],
					sizeof(sched_name) - 1);
				break;
			}
		}
		/* Fallback: load-time uniquify did not run / store a
		 * name -- select the object's compiled-in name. */
		if (!sched_name[0])
			strncpy(sched_name, bpf_map__name(map),
				sizeof(sched_name) - 1);

		if (brf_struct_ops_attach(obj, map) < 0)
			return -1;
		brf_struct_ops_select(sched_name);
		return 0;
	}

	bpf_object__for_each_program(prog, obj) {
		bpf_program_attach(prog, attach_res, &link);
	}

	return link? bpf_link__fd(link) : 0;
}
