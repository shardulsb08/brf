#!/bin/bash
#
# run_stability.sh -- repeatedly invoke test_mp_pm_announce_leak with
# BRF_STABILITY=1 to confirm the MPCAPABLEDATAFALLBACK race ghost (the
# one that flipped on/off when we toggled the emit_mp SKIP log level)
# stays put on the currently-booted kernel.  Each iteration runs the
# full MP_CAPABLE handshake + accepted-msk MPTCP_INFO read + ANNOUNCE
# genl + close, then exits without the 35s kmemleak wait, so we can
# run many iterations in under a minute.
#
# Run as root inside the test VM:
#   ./run_stability.sh                # default 50 iterations
#   ./run_stability.sh 200            # explicit count
#
# Exit codes the underlying test can emit:
#   0   leak detected by kmemleak (not used in stability mode)
#   1   no leak detected (not used in stability mode)
#   2   prereq failure -- this is the SIGNAL.  Common cause = getsockopt
#       MPTCP_INFO -> EOPNOTSUPP, i.e. the fallback race resurfaced
#   3   ANNOUNCE genl call failed (kernel API mismatch)
#   4   stability fast-path pass (trigger sequence completed cleanly)
#
# Wrapper exits 0 iff all iterations returned 4.  Anything else means
# the run-up-to-trigger isn't deterministic and we should NOT add more
# pr_warn sites yet, because they'll perturb timing and make the
# kmemleak signal we're chasing harder to read.

set -u

ITER="${1:-50}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_BIN="$SCRIPT_DIR/test_mp_pm_announce_leak"

if [ ! -x "$TEST_BIN" ]; then
    echo "Error: test binary not found at $TEST_BIN" >&2
    echo "Build first:  gcc -O2 -Wall -o test_mp_pm_announce_leak test_mp_pm_announce_leak.c" >&2
    exit 2
fi

if [ "$EUID" -ne 0 ]; then
    echo "Error: must run as root (genl + /proc/sys/net/mptcp writes)" >&2
    exit 2
fi

declare -A counts
counts[0]=0; counts[1]=0; counts[2]=0; counts[3]=0; counts[4]=0; counts[other]=0
first_bad_iter=""
first_bad_code=""

echo "Running $ITER iterations of test_mp_pm_announce_leak with BRF_STABILITY=1..."
echo "Per-iteration output suppressed; tally printed at end."
echo

start_t=$(date +%s)
for i in $(seq 1 "$ITER"); do
    out=$(BRF_STABILITY=1 "$TEST_BIN" 2>&1)
    rc=$?
    case "$rc" in
        0|1|2|3|4) counts[$rc]=$((counts[$rc]+1)) ;;
        *)        counts[other]=$((counts[other]+1)) ;;
    esac
    if [ "$rc" -ne 4 ] && [ -z "$first_bad_iter" ]; then
        first_bad_iter="$i"
        first_bad_code="$rc"
        echo "--- first non-4 iteration: $i (exit $rc) ---"
        echo "$out" | tail -20
        echo "--- end of bad iteration output ---"
    fi
    # tiny inter-iter pause to keep MPTCP token bucket / ephemeral
    # port allocator from getting wedged
    sleep 0.05
done
end_t=$(date +%s)
elapsed=$((end_t - start_t))

echo
echo "Stability tally over $ITER iterations (${elapsed}s):"
echo "  exit 0 (leak detected, unexpected in stability mode):  ${counts[0]}"
echo "  exit 1 (no leak, unexpected in stability mode):         ${counts[1]}"
echo "  exit 2 (PREREQ FAIL -- fallback race resurfaced):       ${counts[2]}"
echo "  exit 3 (ANNOUNCE genl failed):                          ${counts[3]}"
echo "  exit 4 (STABILITY PASS):                                ${counts[4]}"
echo "  other:                                                  ${counts[other]}"
echo

if [ "${counts[4]}" -eq "$ITER" ]; then
    echo "VERDICT: stable.  All $ITER runs completed the trigger sequence cleanly."
    echo "OK to proceed to Stage 2 (add comprehensive BRF_LEAK logging)."
    exit 0
else
    echo "VERDICT: NOT stable."
    echo "First failure at iter $first_bad_iter with exit code $first_bad_code."
    echo "Do NOT add more pr_warn sites yet -- diagnose the flake first or"
    echo "the new logs will perturb timing and muddy the kmemleak signal."
    exit 1
fi
