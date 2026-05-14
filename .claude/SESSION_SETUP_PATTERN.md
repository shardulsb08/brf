# Session-setup pattern -- canonical reference (BRF copy)

**Canonical source:**
`/mnt/work_4gb/Work/Redkill/002_sources/microkernel/.claude/SESSION_SETUP_PATTERN.md`

**Status:** Methodology developed in the Redkill microkernel repo on
2026-05-02 with Shardul. Applied to the Linux-clone working tree on
2026-05-08. Applied to BRF on 2026-05-14. The microkernel copy is the
source of truth -- if the methodology improves, edit it there and
refresh this file. Per-repo deviations are documented at the bottom
of this file, not by silently diverging the body.

## What problem this solves

In a repo with non-trivial domain context (Syzkaller grammar
conventions, BPF subsystem internals, fuzzer/runtime split, recurring
multi-session tasks like adding a new prog type or map type), Claude
sessions otherwise need to be told the same things every time:

- Who the user is and how they work
- The codebase conventions
- What is currently being worked on
- Which design principles flip "obvious" defaults
- Which past decisions matter

Re-explaining this is a tax on every session. The pattern below
encodes it in files Claude reads automatically or on-trigger, so the
first turn of a new session is productive instead of preparatory.

## The layout

```
<repo>/
  CLAUDE.md                            always-loaded entry point
  .claude/
    README.md                          explains THIS repo's layout
    SESSION_SETUP_PATTERN.md           this file -- the methodology
    settings.local.json                Claude Code local settings (gitignored)
    principles/                        short design-principle files (tracked)
      <aspect>.md                      e.g., tcb_and_verification.md
    tasks/                             per-task working dirs (gitignored)
      index.md                         registry: name, status, keywords, brief
      <task_slug>/
        CLAUDE.md                      task brief
        commits.md, patch_plan.md, ...  working notes
    archive/                           retired memories with index
      README.md                        index: what was moved and why
```

## What goes in repo-root `CLAUDE.md`

Five sections, in order:

1. **Task system.** Instruction to read `.claude/tasks/index.md` at
   session start; ask before loading any task brief; propose status
   updates on task switch.
2. **Design principles.** 3-5 invariants that drive non-obvious
   decisions in the repo. Short. The kind that flip "conservative"
   defaults.
3. **Auto-loaded references** trigger table. Rows mapping work
   conditions ("when the work involves X") to files Claude reads
   *without asking*, announcing each load. Includes both
   `.claude/principles/*.md` files and specific memory files.
4. **Always-load at session start.** A small list (4-6 entries) of
   universal memories Claude reads on the first turn of every
   session. Keep this tight -- it's a per-session cost.
5. **Codebase facts.** Build commands, architecture overview,
   run/debug, constraints worth remembering. The output of `/init`,
   trimmed.

## Asymmetric loading rules

| Class                    | Load when                            | Behavior                                                       |
|--------------------------|--------------------------------------|----------------------------------------------------------------|
| Repo-root `CLAUDE.md`    | Always                               | Auto                                                           |
| `MEMORY.md` index        | Always                               | Auto                                                           |
| Always-load memories     | Session start                        | Auto (per CLAUDE.md instruction)                               |
| Principle files          | Work matches trigger                 | Auto + announce                                                |
| Task brief               | User mentions task keywords          | **Ask first**, then auto-load referenced principles + memories |
| Other memories           | Mentioned by name or grep need       | On demand                                                      |

The asymmetry matters: principles are short and decision-shaping
(cheap to load, high judgment value). Briefs are larger and
task-specific (should not contaminate unrelated work).

## What's tracked in git vs not

| Path                              | Tracked? | Why                                                      |
|-----------------------------------|----------|----------------------------------------------------------|
| `CLAUDE.md` (repo root)           | Yes      | Repo convention; collaborators benefit                   |
| `.claude/README.md`               | Yes      | Explains the convention                                  |
| `.claude/SESSION_SETUP_PATTERN.md`| Yes      | This methodology                                         |
| `.claude/principles/*.md`         | Yes      | Design philosophy applies to all contributors            |
| `.claude/tasks/`                  | No       | Per-developer working memory                             |
| `.claude/settings.local.json`     | No       | Per-machine Claude Code settings                         |

The repo `.gitignore` should include `.claude/tasks/` and (typically
already) `.claude/settings.local.json`.

**Exception for upstream-mirror clones**: if the repo is a personal
clone of an upstream project that the user does NOT plan to push
this scaffolding to (e.g., a Linux kernel mirror tracking
kernel.org), put the whole `CLAUDE.md` and `.claude/` tree into
`.git/info/exclude` instead -- that keeps the scaffold per-clone and
prevents it from ever appearing in a public branch headed to
fsdevel/netdev/mptcp/etc. The Linux-clone README at
`/mnt/work_4gb/Dev/mpiric_kernel_dev_env/open/src/kernel/linux/.claude/README.md`
is the worked example.

## Adding a new design principle

1. Create `.claude/principles/<aspect>.md`. First line: a "Read this
   when:" trigger phrase so Claude (and humans) can decide when to
   pull it in. Keep dense and focused -- principles are *read into
   context*, so density wins over completeness.
2. Add a row to the "Auto-loaded references" table in `CLAUDE.md`
   mapping work conditions to the new file.
3. Cross-link from related memory files if a feedback memory exists
   in the same area.
4. Commit. Other contributors benefit.

## Adding a new task

1. Create `.claude/tasks/<task_slug>/CLAUDE.md` (the brief).
   Sections: goal, scope/anti-scope, memory load list (split:
   critical / helpful / skip), key files in repo, working principles,
   open questions, submission state if it's a patch series.
2. Optionally add skeleton sibling files (e.g., `commits.md`,
   `patch_plan.md`) for working notes.
3. Add an entry to `.claude/tasks/index.md` with status, keywords,
   brief path, one-line goal. Set `status: active` if it's the
   current focus.
4. When done: `status: done`. Don't delete the brief immediately --
   it's a record for adjacent future work. Consider moving it to
   `.claude/archive/` with an index entry.

**What counts as "active":** a task is active if it has open threads
-- including waiting on stakeholder input, hardware arrival, kernel
review, or external CI -- not only when code is being typed. A brief
that reads "all blockers resolved, pending approval" is active, not
done.

**Retired content lives in `.claude/archive/`** with an index at
`.claude/archive/README.md`. Two reasons content ends up there:
done-state snapshots (the work shipped) and converted-to-task
originals (content moved into a task brief, source preserved
verbatim). When moving any file to `.claude/archive/`, update the
README index in the same operation -- don't wait to be told.

## When to apply this pattern (to new repos)

Apply when the repo has at least two of:
- Strong implicit conventions a newcomer wouldn't infer (Syzkaller
  descriptor grammar, BPF subsystem layering, verification targets,
  RT constraints)
- Recurring tasks with distinct scope (new prog type, new map type,
  reproducer extraction, upstream-patch prep, refactor campaigns)
- Multi-session work that gets dropped and resumed
- Decision drivers that flip naive intuition

BRF passes all four. Microkernel and the Linux clone also pass.

Skip for small/exploratory repos -- the overhead exceeds the benefit.

## Bootstrapping the pattern in a new repo

1. Run `/init` to draft a codebase-overview `CLAUDE.md`.
2. Insert the four pre-codebase sections above (Task system, Design
   principles, Auto-loaded references, Always-load at session start).
   Use an existing repo's `CLAUDE.md` as a template:
   - Microkernel: `/mnt/work_4gb/Work/Redkill/002_sources/microkernel/CLAUDE.md`
   - Linux clone: `/mnt/work_4gb/Dev/mpiric_kernel_dev_env/open/src/kernel/linux/CLAUDE.md`
3. Identify 2-4 design principles unique to the new repo; write
   `.claude/principles/<aspect>.md` for each. **Don't write
   speculative principles** -- only the ones a real session has
   already shown Claude needs.
4. Populate the trigger table.
5. Copy `.claude/README.md` and `.claude/SESSION_SETUP_PATTERN.md`
   from this repo (or the microkernel canonical) as templates; adapt
   as needed.
6. Update `.gitignore` to keep `.claude/tasks/` and
   `.claude/settings.local.json` out (or use `.git/info/exclude` for
   upstream-mirror clones).
7. Create `.claude/tasks/index.md` and the first brief when the
   first multi-session task appears.

## Cross-machine sync

- Tracked files travel via `git pull`.
- `.claude/tasks/` is per-machine. To continue a task on another
  machine, copy the relevant `tasks/<slug>/` dir manually.
- Memory files are synced separately per
  `~/.claude/projects/-home-shardul/memory/reference_memory_sync.md`.

## Maintenance

This file is living documentation. When the pattern evolves:
- Update the *microkernel* copy first (it's the canonical source).
- Refresh this BRF copy from it.
- Update repo-root `CLAUDE.md` if the always-loaded surface changes.
- Trim or update the global meta-memory pointer if its bootstrap
  instructions become wrong.
- If a collaborator improves the pattern, the change lands in the
  microkernel copy via PR like any other repo change.

## BRF-specific deviations from canonical

None yet. This file is currently a clean copy of the canonical
methodology, plus the upstream-mirror exception (which itself is
borrowed from the Linux-clone deployment). If BRF needs a deviation
later -- for example, additional sections for the Syzkaller-derived
descriptor workflow, or for managing the relationship between BRF
commits and kernel-side patches that ship alongside them -- record
it here under a clearly-labelled "BRF deviation" heading rather than
silently changing the body above.
