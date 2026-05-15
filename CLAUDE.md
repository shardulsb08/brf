# CLAUDE.md

Working notes for Claude Code in this BRF (BPF Runtime Fuzzer)
checkout.  BRF is Shardul's fork of Hsin-Wei Hung's published eBPF
runtime fuzzer (UC Irvine, arXiv:2305.08782, NSF + Google ASPIRE
funded), which is itself a fork of Google's Syzkaller.  The fork
exists primarily for Mpiric's network-security upstream work.

## Authorship chain (important -- preserve this in all external-facing work)

```
Syzkaller (Google, Dmitry Vyukov et al.)
   ↓ fork, Jan 2024
BRF (Hsin-Wei Hung + Ardalan Amiri Sani, UC Irvine; published
      arXiv:2305.08782, May 2023; ACM venue version at
      papers/3643778.pdf)
   ↓ fork, Aug 2025
shardulsb08/brf  (this checkout)
```

License: Apache 2.0.  No CLA.  Attribution requirements: preserve
`LICENSE`, `AUTHORS`, `CONTRIBUTORS`; cite Syzkaller and BRF (with
funding ack: NSF #1763172, NSF #1846230, Google ASPIRE 2020) in any
external presentation.

**Mpiric's contribution shape:** *extension*, not authorship.  We
never present BRF as our platform.  We present our protocol-flow
harness work as extending BRF.

## What's in flight here

See `.claude/tasks/index.md`.  Currently one active task:

- **netdev_0x1a_protocol_fuzzing** -- extending BRF's harness-generation
  approach to kernel transport-security protocol flows (MPTCP,
  QUIC, tlshd) with AI-augmented syscall description authoring.
  This is the substrate work for a netdev 0x1A submission and
  follow-on conferences (LPC, FOSDEM, etc.).

The task brief at `.claude/tasks/netdev_0x1a_protocol_fuzzing/CLAUDE.md`
is the primary read.  The companion document
`.claude/tasks/netdev_0x1a_protocol_fuzzing/context_reference.md`
contains the full strategic context (why we pivoted to this from a
MIB-counters framing, what the conference goals are, how this maps
to Mpiric's overall trajectory) and is required reading before
making strategic decisions about the work.

## Cross-repo context

Mpiric's main Linux kernel work happens in a separate clone at:

```
/mnt/work_4gb/Dev/mpiric_kernel_dev_env/open/src/kernel/linux
```

The netdev 0x1A submission task lives there too (the proposal-side
artifacts), with cross-references back here:

- Proposal task brief: `.claude/tasks/netdev_0x1a_proposal/CLAUDE.md`
  (in the Linux clone)
- Submission artifacts (draft, research questions, roadmap):
  `shared/mpiric/027_netdev_0x1a_proposal/` (in the same dev tree)

Read those when proposal-side decisions need updating.  Conversely,
the proposal-side Claude should read this BRF tree's
`context_reference.md` when needing technical grounding on the
BRF substrate.

## Auto-loaded references and session-setup methodology

The full per-repo layout convention is documented at
`.claude/README.md` (this is the methodology source-of-truth for
BRF; the canonical write-up lives in the microkernel repo).

Session contract:
1. This file (`CLAUDE.md`) auto-loads.
2. Claude reads `.claude/tasks/index.md` (small, always read).
3. When user requests match a task's keywords, Claude asks before
   loading the brief.
4. Principle files under `.claude/principles/` (none yet) and design
   files under `.claude/designs/` load automatically on the trigger
   conditions in the table below.

### Auto-loaded references (read without asking, when triggered)

| When the work involves...                                            | Read this without asking                                |
|----------------------------------------------------------------------|---------------------------------------------------------|
| Touching `prog/brf*.go`, `executor/common_brf*.h`, BRF pseudo-       | `.claude/designs/brf_architecture.md`                   |
| syscall lifecycle, or designing a new BRF-style harness extension    |                                                         |
| (MPTCP, QUIC, tlshd, or any new protocol substrate)                  |                                                         |

## Design principles (binding on all work in this tree)

- **Citation discipline.** Every external artifact (talk, paper,
  blog, lore post) that references BRF must cite both Syzkaller
  and Hung+Sani's BRF paper.  Funding acknowledgment for any
  presentation built on BRF.  No exceptions; this protects Mpiric's
  reputation in the academic-leaning kernel-security community.
- **Extension, not appropriation.** We can fork, modify, and present
  extensions.  We do not refer to BRF as ours, claim authorship,
  rename the project in any external materials, or strip upstream
  attribution from forks we publish.
- **Speaker-defensibility constraint.** Anything that lands in a
  conference talk has to be defendable by Shardul under Q&A from
  kernel veterans.  The learning model from the Linux clone applies
  here too: Claude excavates, Shardul diagnoses and owns the
  presentation.  If a piece of work can't be defended cold, it
  doesn't go on a slide.
- **AI use is in scope to discuss openly, not to hide.**  The
  methodology being developed here -- AI-augmented syscall
  description authoring for protocol flows -- is the substance of
  the talk, not a guilty secret.  Be honest about what works, what
  fails, where the human verification step lives.

## What's tracked in git here

Per the existing `.claude/README.md` recommendation:

| Path | Tracked? |
|---|---|
| `CLAUDE.md` (this file) | Yes |
| `.claude/README.md`, `.claude/SESSION_SETUP_PATTERN.md` | Yes |
| `.claude/principles/*.md` (when added) | Yes |
| `.claude/tasks/` | No (per-developer working memory) |
| `.claude/settings.local.json` | No (per-machine) |

When `tasks/` first appears in `git status` (which it just did),
add `/.claude/tasks/` and `/.claude/settings.local.json` to
`.gitignore`.

## Maintaining this file

`CLAUDE.md` is living.  Update it directly with `Edit`/`Write` when:

- A new task becomes active.
- A new design principle binds future sessions.
- The cross-repo context changes (paths move, related tasks shift).

Don't re-run `/init`; the hand-built sections above would be
clobbered.
