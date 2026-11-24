# Coordination addendum: PR #2916 (#2407 item 2)

- Task: `task_fac901f30c6669452e3ec0ead11e123f` · Date: 2026-11-24 · Supplements the immutable packet `11a472f…/evidence-2407` (unchanged).

## Maintainer-approved base or stacked-work coordination
**None exists.** No maintainer comment approves a base for item 2 or coordinates stacked work. We did not ask on the issue (issue comments are unavailable to our tooling). Stated as a gap, not hidden.

## Base selection evidence (source-backed, not an approval)
- Item 2 is a follow-up the maintainer recorded on #2407 (2026-11-16T11:03:03Z) from the review of PR [#2405](https://github.com/CorbanuCore/CorbanuTerminal/pull/2405), which merged into **main** 2026-11-16T12:38:33Z (`f5e76703`). (`raw/issue-2407.json`, `raw/pr-2405.json`)
- PR [#2436](https://github.com/CorbanuCore/CorbanuTerminal/pull/2436) (for #2433, base `sync/upstream-rust-v0.167.0`, merged 2026-11-16T18:34:56Z) is adjacent: in `tui/src/app.rs` it cancels the **async-question** burst Enter (`chat_widget.cancel_question_burst_enter()`) before global shortcuts. It does not cancel the **composer** held Enter that item 2 names, and it is not on main. PR #2916 applies the composer cancel on main; disclosed so the verifier can judge overlap. (`raw/pr-2436.json`, `raw/issue-2407-comments.json`)
- PR [#2916](https://github.com/CorbanuCore/CorbanuTerminal/pull/2916) targets `main` at `5c05a8bb80359f57f589a1b9a2b558147a075650`, which is main's head as of this readback (`raw/branch-main.json`); not stacked on any other PR. Head `8112c24f`, all required CI checks SUCCESS, mergeState CLEAN, no reviews yet (`raw/pr-2916.json`).
- #2407 is open and unassigned (`raw/issue-2407.json`).

## Wording correction
The packet's `sec_437` note should read: fails in the full `codex-tui` lib run and passes alone 3/3 at head; the cause (parallel ordering) is **not proven**.

## Requested issuer disposition
Review PR #2916 with this gap disclosed. If prior maintainer approval of the base is a hard condition, treat the task as the dated stop branch for that reason; the PR stays open for maintainer review either way.
