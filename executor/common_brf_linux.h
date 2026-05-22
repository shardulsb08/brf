
/* For the verifier-accept instrumentation's 9p egress (VI3): mount()
 * for the brfstats share, mkdir() for its mountpoint.  Both headers
 * are guarded, so re-including them here is harmless and keeps this
 * file self-contained regardless of the conditional includes above. */
#include <sys/mount.h>
#include <sys/stat.h>

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

/* BRF Phase 3 -- verifier-accept instrumentation, Change 2.
 *
 * A generated syz-program can call syz_bpf_prog_load twice on the same
 * already-loaded bpf_object; the second bpf_object__load fails with
 * "object '...': load can't be attempted twice" -- which is NOT a
 * verifier rejection.  This parallel array (index i tracks object i,
 * exactly like struct_ops_link_list / struct_ops_name_list above)
 * records whether a verifier outcome has already been emitted for an
 * object, so a re-load never produces a second, spurious REJECT
 * record. */
static char struct_ops_verif_recorded[OBJ_LIST_SIZE];

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
		/* uniq is a full BRF_MPTCP_SCHED_NAME_MAX-byte buffer holding
		 * a NUL-terminated name -- copy all of it (memcpy avoids the
		 * gcc stringop-truncation warning strncpy(.,.,len) trips). */
		memcpy(out, uniq, BRF_MPTCP_SCHED_NAME_MAX);
		debug("syz_bpf_prog_load: struct_ops sched %s -> %s\n",
		      orig, uniq);
		return 0;
	}

	debug("syz_bpf_prog_load: struct_ops name %s not found in blob\n",
	      orig);
	return -1;
}

/* BRF Phase 3 -- continuous verifier-accept instrumentation.
 *
 * Generated mptcp_sched_ops struct_ops schedulers are run through the
 * kernel BPF verifier by bpf_object__load() in syz_bpf_prog_load().
 * To make the generator-tuning loop measure-driven, every struct_ops
 * load records its verifier outcome (ACCEPT / REJECT, and on reject
 * the key verifier-log line) to an append-only stats file.  A host-
 * side tally script (brf_verifier_tally.sh) buckets the results.
 *
 * Scope: struct_ops objects ONLY -- the recording is gated on
 * brf_find_struct_ops_map(obj) != NULL.  Regular BPF loads are not
 * instrumented.  The recording is pure observation: it never alters
 * the load path or its return value, and any instrumentation failure
 * (open/write error, full buffer) is silently ignored.
 *
 * Atomicity: each record is emitted as a SINGLE write() of a bounded
 * buffer well under PIPE_BUF (4 KiB), to an O_APPEND fd.  POSIX
 * guarantees such writes from concurrent executor procs interleave
 * atomically, so the file stays line-consistent across the whole run.
 *
 * VI2 -- verifier-log capture: a libbpf_set_print callback ACCUMULATES
 * every WARN-level message of a load into a file-scope buffer (libbpf
 * emits the verifier log and several generic wrapper warnings as
 * separate WARN messages during one bpf_object__load).  On a
 * struct_ops load failure brf_verif_pick_reason() scans that buffer
 * line-by-line and folds the most INFORMATIVE line into the REJECT
 * record -- skipping the generic "failed to load object/program"
 * wrapper lines and preferring the specific "libbpf: prog '...': ..."
 * verifier / map error.  The accumulator is reset at the start of each
 * struct_ops load.  The callback is installed once, lazily, and is
 * harmless for non-struct_ops loads (the buffer is simply ignored).
 *
 * VI4 -- host egress: the fuzzing guests run QEMU -snapshot (ephemeral
 * disk), so a guest-local stats file is lost on every VM restart and
 * is invisible to the host.  Instead the stats file lives on a 9p
 * host share (mount_tag "brfstats", added to qemu_args by the
 * syz-manager config) mounted at BRF_VERIF_STATS_DIR.  The mount is
 * idempotent and best-effort -- modelled on prog/brf.go's mount of
 * the "brf" share for /mnt/brf_work_dir.  The stats file name carries
 * the per-VM-boot UUID (/proc/sys/kernel/random/boot_id), so each
 * VM-boot writes its own file: no cross-VM 9p append contention, and
 * -snapshot restarts simply produce a fresh boot-id => a fresh file,
 * all durable on the host.  If the share is missing or the mount
 * fails, recording degrades to a /tmp fallback -- instrumentation
 * never disturbs fuzzing. */

#define BRF_VERIF_STATS_DIR     "/mnt/brf_verif_stats"
#define BRF_VERIF_STATS_TAG     "brfstats"
#define BRF_VERIF_STATS_FALLBACK "/tmp/brf_verifier_stats.log"
#define BRF_VERIF_BOOT_ID_PATH  "/proc/sys/kernel/random/boot_id"
/* Bound for one record and for the chosen verifier-log line.  A record
 * is timestamp + pid + verdict + reason; 512 bytes is far under
 * PIPE_BUF (4096) so the write() is atomic. */
#define BRF_VERIF_RECORD_MAX    512
#define BRF_VERIF_LOG_MAX       320
/* Bound for the WARN-message accumulator.  libbpf emits the verifier
 * log plus several wrapper warnings as separate WARN messages during
 * one load; this buffer accumulates them all so the most informative
 * line can be picked afterwards.  Sized generously -- it is a single
 * file-scope static, not on any hot path, and only the chosen line
 * (<= BRF_VERIF_LOG_MAX) ever reaches a record. */
#define BRF_VERIF_ACCUM_MAX     8192
/* Bound for the per-VM-boot stats path: BRF_VERIF_STATS_DIR +
 * "/stats." + boot-id (a 36-char UUID) + ".log".  256 is ample. */
#define BRF_VERIF_PATH_MAX      256

/* Accumulator for the WARN-level messages of the current struct_ops
 * load.  libbpf emits the verifier log and several generic wrapper
 * warnings as separate WARN messages; accumulating them all here lets
 * brf_verif_pick_reason() pick the most informative line afterwards.
 * brf_verif_accum_len is the current used length (always <
 * BRF_VERIF_ACCUM_MAX, NUL-terminated).  Single-threaded per executor
 * proc, so a plain file-scope static needs no locking. */
static char brf_verif_log_accum[BRF_VERIF_ACCUM_MAX];
static size_t brf_verif_accum_len;
static int brf_verif_print_installed;

/* libbpf print callback: APPEND WARN-level messages (the verifier log
 * is emitted at WARN level on a load failure) to brf_verif_log_accum.
 * Never prints; never fails the load.  Signature matches
 * libbpf_print_fn_t exactly. */
static int brf_verif_libbpf_print(enum libbpf_print_level level,
				  const char *fmt, va_list ap)
{
	int n;
	size_t avail;

	if (level != LIBBPF_WARN)
		return 0;
	if (brf_verif_accum_len + 1 >= sizeof(brf_verif_log_accum))
		return 0; /* accumulator full -- drop further messages */

	avail = sizeof(brf_verif_log_accum) - brf_verif_accum_len;
	n = vsnprintf(brf_verif_log_accum + brf_verif_accum_len, avail,
		      fmt, ap);
	/* vsnprintf returns the length it WOULD have written; clamp to
	 * what actually fit so brf_verif_accum_len never runs past the
	 * buffer.  A negative return (encoding error) appends nothing. */
	if (n < 0)
		return 0;
	if ((size_t)n >= avail)
		n = (int)avail - 1;
	brf_verif_accum_len += (size_t)n;
	return 0;
}

/* Sanitise a captured verifier-log fragment into out (size n): copy up
 * to the first newline, replacing any other control char with a space,
 * so the whole record stays one line.  out is always NUL-terminated. */
static void brf_verif_sanitize(const char *src, char *out, size_t n)
{
	size_t i = 0;

	if (n == 0)
		return;
	for (; src && src[i] && i + 1 < n; i++) {
		unsigned char c = (unsigned char)src[i];

		if (c == '\n' || c == '\r')
			break;
		out[i] = (c < 0x20 || c == 0x7f) ? ' ' : (char)c;
	}
	out[i] = '\0';
}

/* Change 1 (VI2): true if the line (a NUL-or-newline-bounded fragment
 * starting at s) is one of libbpf's GENERIC load-failure wrapper
 * warnings -- the LAST warnings libbpf emits, carrying no rejection
 * detail ("libbpf: failed to load object '...'", "libbpf: failed to
 * load object skeleton '...'", "libbpf: prog '...': failed to load:
 * ..." with no further reason).  These must be skipped in favour of
 * the earlier, specific verifier / map line. */
static int brf_verif_is_generic_line(const char *s)
{
	/* strstr over a line is safe: the accumulator is NUL-terminated
	 * and these substrings never span a newline. */
	return strstr(s, "failed to load object") != NULL ||
	       strstr(s, "failed to load program") != NULL;
}

/* Change 1 (VI2): pick the most INFORMATIVE line from the accumulated
 * WARN messages (brf_verif_log_accum) and sanitise it into out (size
 * n, <= BRF_VERIF_LOG_MAX).  out is always NUL-terminated.
 *
 * libbpf emits the specific rejection reason (the verifier-log line, a
 * "libbpf: prog '...': ..." or map error) as an EARLIER warning, then
 * finishes with the generic "failed to load object '...'" wrapper.  A
 * naive last-message capture keeps only that wrapper, so the host-side
 * histogram degenerates to "100% other".  This walks every accumulated
 * line and prefers, in order:
 *   1. a non-generic "libbpf: prog '...': ..." line (the verifier /
 *      program-specific reason) -- the FIRST such line wins, since the
 *      verifier log's head line carries the rejection cause;
 *   2. otherwise the first non-generic, non-empty line;
 *   3. otherwise the first non-empty line at all (last resort).
 * Pure observation -- never touches the load path. */
static void brf_verif_pick_reason(char *out, size_t n)
{
	const char *p = brf_verif_log_accum;
	const char *best = NULL;
	int best_rank = -1; /* 0: any non-empty; 1: non-generic; 2: prog line */

	if (n == 0)
		return;
	out[0] = '\0';

	while (*p) {
		const char *line = p;
		size_t len = 0;
		int rank;
		int is_prog;
		int generic;
		size_t i;
		int blank = 1;

		/* Bound this line at the next newline. */
		while (line[len] && line[len] != '\n' && line[len] != '\r')
			len++;

		/* A line is "blank" if it holds only whitespace. */
		for (i = 0; i < len; i++) {
			unsigned char c = (unsigned char)line[i];

			if (c != ' ' && c != '\t') {
				blank = 0;
				break;
			}
		}

		if (!blank) {
			/* strstr needs a NUL-terminated string; the
			 * accumulator already is, and the wrapper /
			 * "prog '" substrings never span a newline, so a
			 * search from line is correct even though it may
			 * read past this line's newline. */
			generic = brf_verif_is_generic_line(line);
			is_prog = (strncmp(line, "libbpf: prog '", 14) == 0);
			if (is_prog && !generic)
				rank = 2;
			else if (!generic)
				rank = 1;
			else
				rank = 0;

			/* Strictly-greater keeps the FIRST line of the
			 * top rank -- the verifier log's head line, which
			 * states the cause. */
			if (rank > best_rank) {
				best_rank = rank;
				best = line;
			}
		}

		/* Advance past this line and its newline(s). */
		p = line + len;
		while (*p == '\n' || *p == '\r')
			p++;
	}

	if (best)
		brf_verif_sanitize(best, out, n);
}

/* VI4 -- resolved per-VM-boot stats path, computed once on first use.
 * Empty until brf_verif_resolve_path() runs; on any failure it stays
 * the /tmp fallback so recording always has a usable target. */
static char brf_verif_stats_path[BRF_VERIF_PATH_MAX];

/* VI4: mount the brfstats 9p host share at BRF_VERIF_STATS_DIR.  Run
 * once, idempotent and best-effort -- modelled on prog/brf.go's mount
 * of the "brf" share (mount -t 9p -o trans=virtio,version=9p2000.L).
 * An already-mounted dir or a missing share just fails the mount()
 * silently; the caller then falls back to /tmp.  Never disturbs
 * fuzzing -- no errno is propagated. */
static void brf_verif_mount_share(void)
{
	/* mkdir the mountpoint; EEXIST (already there) is fine. */
	if (mkdir(BRF_VERIF_STATS_DIR, 0755) != 0 && errno != EEXIST)
		return;
	/* Best-effort mount.  If the share is absent, or the dir is
	 * already mounted, this fails harmlessly and we degrade to the
	 * /tmp fallback in brf_verif_resolve_path(). */
	(void)mount(BRF_VERIF_STATS_TAG, BRF_VERIF_STATS_DIR, "9p", 0,
		    "trans=virtio,version=9p2000.L");
}

/* VI4: compute brf_verif_stats_path once.  Mount the share, read this
 * VM-boot's UUID from /proc/sys/kernel/random/boot_id, and form
 * BRF_VERIF_STATS_DIR/stats.<boot-id>.log.  On any failure (no share,
 * unreadable boot_id) fall back to BRF_VERIF_STATS_FALLBACK so the
 * load path always has a durable-or-local target.  Idempotent: the
 * non-empty brf_verif_stats_path short-circuits later calls. */
static void brf_verif_resolve_path(void)
{
	char boot_id[64];
	int fd, n, i;
	ssize_t r;

	if (brf_verif_stats_path[0])
		return;

	/* Default to the local fallback; only upgrade on full success. */
	snprintf(brf_verif_stats_path, sizeof(brf_verif_stats_path), "%s",
		 BRF_VERIF_STATS_FALLBACK);

	brf_verif_mount_share();

	fd = open(BRF_VERIF_BOOT_ID_PATH, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	r = read(fd, boot_id, sizeof(boot_id) - 1);
	close(fd);
	if (r <= 0)
		return;
	boot_id[r] = '\0';
	/* boot_id is a UUID followed by '\n'; trim trailing whitespace
	 * and reject any non-UUID char so the path stays well-formed. */
	for (n = 0; n < (int)r; n++) {
		char c = boot_id[n];

		if (c == '\n' || c == '\r' || c == ' ' || c == '\0')
			break;
	}
	boot_id[n] = '\0';
	if (n == 0)
		return;
	for (i = 0; i < n; i++) {
		char c = boot_id[i];

		if (!((c >= '0' && c <= '9') ||
		      (c >= 'a' && c <= 'f') ||
		      (c >= 'A' && c <= 'F') || c == '-'))
			return;
	}
	/* Upgrade to the per-VM-boot host path only if it fits. */
	if (snprintf(brf_verif_stats_path, sizeof(brf_verif_stats_path),
		     "%s/stats.%s.log", BRF_VERIF_STATS_DIR, boot_id) >=
	    (int)sizeof(brf_verif_stats_path))
		snprintf(brf_verif_stats_path,
			 sizeof(brf_verif_stats_path), "%s",
			 BRF_VERIF_STATS_FALLBACK);
}

/* Append one struct_ops verifier-outcome record to the stats file.
 * Pure observation -- all failures are swallowed.  On a REJECT the
 * rejection reason is picked from the WARN-message accumulator
 * (brf_verif_log_accum) by brf_verif_pick_reason -- the most
 * informative verifier-log line, not libbpf's generic wrapper. */
static void brf_verif_record(int accepted)
{
	char rec[BRF_VERIF_RECORD_MAX];
	char clean[BRF_VERIF_LOG_MAX];
	int fd, len;
	ssize_t w;

	/* Resolve the per-VM-boot host path on first use; thereafter
	 * brf_verif_stats_path is a cached, non-empty target. */
	brf_verif_resolve_path();

	fd = open(brf_verif_stats_path,
		  O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
	if (fd < 0 &&
	    strcmp(brf_verif_stats_path, BRF_VERIF_STATS_FALLBACK) != 0)
		fd = open(BRF_VERIF_STATS_FALLBACK,
			  O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
	if (fd < 0)
		return;

	if (accepted) {
		len = snprintf(rec, sizeof(rec), "%lld %d ACCEPT\n",
			       (long long)time(NULL), (int)getpid());
	} else {
		/* Change 1: pick the informative rejection line from the
		 * accumulated WARN messages (skips the generic "failed to
		 * load object" wrapper).  brf_verif_pick_reason already
		 * sanitises to one line and NUL-terminates clean. */
		clean[0] = '\0';
		brf_verif_pick_reason(clean, sizeof(clean));
		len = snprintf(rec, sizeof(rec), "%lld %d REJECT %s\n",
			       (long long)time(NULL), (int)getpid(),
			       clean[0] ? clean : "(no-log)");
	}
	/* snprintf returns the length it WOULD have produced; given the
	 * bounds above (clean <= 320, rec = 512) it never truncates, but
	 * clamp defensively to the actual written length so the single
	 * write() stays bounded and never includes the NUL. */
	if (len < 0)
		len = 0;
	if (len > (int)sizeof(rec) - 1)
		len = (int)sizeof(rec) - 1;
	if (len > 0) {
		w = write(fd, rec, (size_t)len);
		(void)w;
	}
	close(fd);
}

static long syz_bpf_prog_load(volatile long a0, volatile long a1)
{
	const char *file = (char *)a0;
	struct bpf_res *res = (struct bpf_res *)a1;
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_map *map;
	int i, err;
	bool is_struct_ops;

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
	is_struct_ops = (map != NULL);
	if (map) {
		char sched_name[BRF_MPTCP_SCHED_NAME_MAX] = {0};

		if (brf_struct_ops_uniquify_name(map, sched_name) == 0) {
			for (i = 0; i < OBJ_LIST_SIZE; i++) {
				if (bpf_object_list[i] == obj) {
					memcpy(struct_ops_name_list[i],
					       sched_name,
					       BRF_MPTCP_SCHED_NAME_MAX);
					break;
				}
			}
		}
	}

	/* VI2: install the libbpf print callback once, so a struct_ops
	 * load failure below accumulates the verifier-log text in
	 * brf_verif_log_accum.  Cheap and idempotent; harmless for the
	 * non-struct_ops path. */
	if (is_struct_ops && !brf_verif_print_installed) {
		libbpf_set_print(brf_verif_libbpf_print);
		brf_verif_print_installed = 1;
	}
	/* Change 1: reset the WARN accumulator so it captures only this
	 * load's messages. */
	if (is_struct_ops) {
		brf_verif_log_accum[0] = '\0';
		brf_verif_accum_len = 0;
	}

	bpf_object__add_kcov_handle(obj, kcov_common_handle());
	err = bpf_object__load(obj);
	/* VI1/VI2: record the struct_ops verifier outcome -- pure
	 * observation, never affects the load result below.
	 *
	 * Change 2: a generated syz-program can call syz_bpf_prog_load
	 * twice on the same bpf_object; the second bpf_object__load fails
	 * with "load can't be attempted twice", which is NOT a verifier
	 * rejection.  Record an outcome only on the FIRST load of an
	 * object -- struct_ops_verif_recorded[] (parallel to
	 * bpf_object_list[]) marks objects already recorded, so a re-load
	 * never emits a second, spurious REJECT. */
	if (is_struct_ops) {
		int already = 0, slot = -1;

		for (i = 0; i < OBJ_LIST_SIZE; i++) {
			if (bpf_object_list[i] == obj) {
				slot = i;
				already = struct_ops_verif_recorded[i];
				break;
			}
		}
		if (!already) {
			brf_verif_record(err == 0);
			if (slot >= 0)
				struct_ops_verif_recorded[slot] = 1;
		}
	}
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
