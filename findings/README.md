# Findings

Documentation tree for kernel bugs found via this BRF fork's
protocol-flow fuzzing harness work.  One subdirectory per
finding, numbered chronologically by discovery date.

Mpiric is the **extender**, not the author, of BRF; original
authorship is Hsin-Wei Hung and Ardalan Amiri Sani (UC Irvine,
arXiv:2305.08782).  Findings collected here come from running
the Mpiric MPTCP / QUIC / tlshd protocol-flow extensions on top
of BRF.

## Layout

```
findings/
├── README.md              # this file
├── index.md               # one-line registry of all findings
└── NNN_<short-name>/
    ├── README.md          # the per-finding writeup
    └── <patch-files>      # copy of the upstream patch(es), if any
```

## Adding a new entry

1. Pick the next number (`002_`, `003_`, ...) and a short
   underscored name.
2. Create the directory.
3. Drop a `README.md` using the existing entries as a template.
   Sections to include:
   - **Summary** -- one line.
   - **Subsystem** -- e.g. `net/mptcp/`.
   - **Discovered** -- date + how (which fuzzer run, which
     harness, what corpus).
   - **Anatomy** -- 1-3 paragraphs on what the bug is and
     why it fires.
   - **Reproduction** -- which reproducer artifacts exist
     (cross-reference `reproducer_analysis/` if applicable),
     and whether they reproduce standalone or only under
     fuzzer load.
   - **Upstream** -- patch link / commit / lore link, status
     (`found`, `diagnosed`, `fixed`, `sent`, `acked`, `merged`).
   - **Lessons** -- 1-3 bullets on what's reusable from this
     finding for future harness or triage work.
4. If an upstream patch exists, copy the
   `git format-patch` output into the directory.
5. Add a line at the top of `index.md`.

## Citation discipline

External artifacts (talks, papers, blog posts) that draw on
these findings cite BRF (Hung & Amiri Sani, UC Irvine,
arXiv:2305.08782) and Syzkaller (Vyukov et al.,
google/syzkaller), with the funding acknowledgment (NSF
#1763172, #1846230, Google ASPIRE 2020) on relevant slides.
Findings are presented as products of the Mpiric extension on
top of BRF, not as products of a separately-named tool.
