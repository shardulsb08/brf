#!/usr/bin/env bash
# brf_verifier_tally.sh -- BRF Phase 3 verifier-accept tally.
#
# Reads one or more brf_verifier_stats.log files (the append-only
# stats files written by the executor's syz_bpf_prog_load
# instrumentation -- see executor/common_brf_linux.h, "continuous
# verifier-accept instrumentation") and prints, for the generated
# mptcp_sched_ops struct_ops schedulers:
#
#   - total struct_ops loads
#   - accept count / reject count
#   - accept rate %
#   - a rejection-reason histogram (verifier-log lines bucketed by
#     pattern)
#
# Each stats-file line has the form:
#     <unix-ts> <pid> ACCEPT
#     <unix-ts> <pid> REJECT <verifier-log line ...>
#
# Reason categorization lives HERE (host-side) so the buckets can be
# tuned without rebuilding the executor.  Add a pattern to
# categorize_reason() to refine the histogram.
#
# Usage:
#   brf_verifier_tally.sh [stats-file ...]
#
# With no arguments it tries the default guest path and the fallback:
#   /mnt/brf_work_dir/brf_verifier_stats.log
#   /tmp/brf_verifier_stats.log
# Multiple per-VM stats files may be passed at once; they are tallied
# together.
#
# Companion: .claude/designs/mptcp_bpf_sched_phase3.md
#            executor/common_brf_linux.h (the producer side)

set -u

DEFAULT_PATHS=(
	"/mnt/brf_work_dir/brf_verifier_stats.log"
	"/tmp/brf_verifier_stats.log"
)

# --- collect input files -----------------------------------------------
files=()
if [ "$#" -gt 0 ]; then
	files=("$@")
else
	for p in "${DEFAULT_PATHS[@]}"; do
		[ -f "$p" ] && files+=("$p")
	done
fi

if [ "${#files[@]}" -eq 0 ]; then
	echo "brf_verifier_tally: no stats files found." >&2
	echo "  pass one or more files, or create:" >&2
	for p in "${DEFAULT_PATHS[@]}"; do
		echo "    $p" >&2
	done
	exit 1
fi

existing=()
for f in "${files[@]}"; do
	if [ -f "$f" ] && [ -r "$f" ]; then
		existing+=("$f")
	else
		echo "brf_verifier_tally: skipping unreadable '$f'" >&2
	fi
done
if [ "${#existing[@]}" -eq 0 ]; then
	echo "brf_verifier_tally: no readable stats files." >&2
	exit 1
fi

# --- reason categorization (host-side, tunable) ------------------------
# Map a raw verifier-log line to a coarse bucket.  Ordered: first match
# wins.  Patterns are matched case-insensitively against the verifier
# text.  Tune freely -- this needs no executor rebuild.
categorize_reason() {
	local line
	line=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
	case "$line" in
		"(no-log)"|"")              echo "no verifier log captured" ;;
		*"unreleased reference"*)   echo "unreleased reference / resource" ;;
		*"reference"*"leak"*)       echo "unreleased reference / resource" ;;
		*"unreleased"*"iterator"*)  echo "unreleased iterator" ;;
		*"iterator"*)               echo "iterator misuse" ;;
		*"invalid mem access"*)     echo "invalid memory access" ;;
		*"invalid access to"*)      echo "invalid memory access" ;;
		*"min value is outside"*)   echo "pointer arithmetic / bounds" ;;
		*"max value is outside"*)   echo "pointer arithmetic / bounds" ;;
		*"pointer arithmetic"*)     echo "pointer arithmetic / bounds" ;;
		*"r0 not a scalar"*)        echo "bad return value" ;;
		*"r0 has value"*)           echo "bad return value" ;;
		*"r0 leaks addr"*)          echo "bad return value" ;;
		*"may be null"*)            echo "unchecked NULL pointer" ;;
		*"null pointer"*)           echo "unchecked NULL pointer" ;;
		*"dereference of modified"*) echo "unchecked NULL pointer" ;;
		*"too many instructions"*)  echo "program too large / complex" ;;
		*"processed"*"insns"*"limit"*) echo "program too large / complex" ;;
		*"complexity"*)             echo "program too large / complex" ;;
		*"back-edge"*)              echo "loop / back-edge" ;;
		*"infinite loop"*)          echo "loop / back-edge" ;;
		*"unknown func"*)           echo "unknown / unallowed kfunc or helper" ;;
		*"not allowed"*)            echo "unknown / unallowed kfunc or helper" ;;
		*"kernel function"*"not"*)  echo "unknown / unallowed kfunc or helper" ;;
		*"calling kernel function"*) echo "unknown / unallowed kfunc or helper" ;;
		*"btf"*)                    echo "BTF / type mismatch" ;;
		*"type mismatch"*)          echo "BTF / type mismatch" ;;
		*"expected"*"but got"*)     echo "BTF / type mismatch" ;;
		*"write into"*)             echo "disallowed context write" ;;
		*"cannot write"*)           echo "disallowed context write" ;;
		*)                          echo "other" ;;
	esac
}

# --- tally -------------------------------------------------------------
total=0
accept=0
reject=0
declare -A reason_hist

while IFS= read -r line; do
	[ -z "$line" ] && continue
	# Fields: ts pid verdict [reason...]
	verdict=$(printf '%s\n' "$line" | awk '{print $3}')
	case "$verdict" in
		ACCEPT)
			total=$((total + 1))
			accept=$((accept + 1))
			;;
		REJECT)
			total=$((total + 1))
			reject=$((reject + 1))
			# everything after the 3rd field is the verifier log
			reason=$(printf '%s\n' "$line" | cut -d' ' -f4-)
			bucket=$(categorize_reason "$reason")
			reason_hist["$bucket"]=$(( ${reason_hist["$bucket"]:-0} + 1 ))
			;;
		*)
			# malformed / partial line -- ignore, do not crash
			;;
	esac
done < <(cat "${existing[@]}")

# --- report ------------------------------------------------------------
echo "BRF struct_ops verifier-accept tally"
echo "===================================="
echo "stats files          : ${#existing[@]}"
for f in "${existing[@]}"; do
	echo "  - $f"
done
echo
echo "total struct_ops loads : $total"
echo "  accepted             : $accept"
echo "  rejected             : $reject"
if [ "$total" -gt 0 ]; then
	rate=$(awk -v a="$accept" -v t="$total" \
		'BEGIN { printf "%.2f", (a * 100.0) / t }')
	echo "  accept rate          : ${rate}%"
else
	echo "  accept rate          : n/a (no loads recorded)"
fi

if [ "$reject" -gt 0 ]; then
	echo
	echo "rejection-reason histogram"
	echo "--------------------------"
	# sort buckets by descending count
	for bucket in "${!reason_hist[@]}"; do
		printf '%d\t%s\n' "${reason_hist[$bucket]}" "$bucket"
	done | sort -rn -k1,1 | while IFS=$'\t' read -r count name; do
		pct=$(awk -v c="$count" -v r="$reject" \
			'BEGIN { printf "%.1f", (c * 100.0) / r }')
		printf '  %6d  (%5s%%)  %s\n' "$count" "$pct" "$name"
	done
fi

exit 0
