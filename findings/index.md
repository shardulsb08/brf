# Findings registry

Newest first.  See per-finding `README.md` for details.

| #   | Date       | Subsystem | Title                                                                | Status |
|-----|------------|-----------|----------------------------------------------------------------------|--------|
| 002 | 2026-05-23 | net/mptcp | `__mptcp_push_pending()` close-path divide-by-zero in `tcp_tso_segs` | sent   |
| 001 | 2026-05-18 | net/mptcp | `mptcp_pm_destroy()` alloc-during-teardown race                      | sent   |

Status legend:
- **found** -- kmemleak / crash signature observed, root cause not yet diagnosed.
- **diagnosed** -- mechanism identified.
- **fixed** -- patch written and validated locally.
- **sent** -- patch sent to maintainer / mailing list.
- **acked** -- patch has at least one Reviewed-by / Acked-by upstream.
- **merged** -- in a maintainer tree (e.g. `mptcp/export-net`) or mainline.
