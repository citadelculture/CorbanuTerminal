# Stop closeout (revised): Issue #2277 standalone executorVersion residual

- Task: `task_2966e7748abed3ec4d10692c56d5cc9e` · Report date: 2026-11-24 · Replaces the 2026-11-24 packet `717fb29…/stop-reports-20261124/reports/issue-2277.md`, whose blocker text was too broad.
- Source: https://github.com/CorbanuCore/CorbanuTerminal/issues/2277 — tracker is still **OPEN** (14 CLI-dependent app-server cases + macOS flakes remain). This report covers only the task's residual, not the tracker.

## Blocker: the exact residual was claimed and merged by the maintainer

1. **Claim, 2026-11-17T18:55:12Z** — IridiumMaster, [#2277 comment 6957772565](https://github.com/CorbanuCore/CorbanuTerminal/issues/2277#issuecomment-6957772565): "preparing focused test-only repairs: (1) exec-server-cli help branding and standalone package-version fixture in src/snapshots and tests/standalone.rs". (`raw/comment-6957772565.json`)
2. **Fix, PR [#2550](https://github.com/CorbanuCore/CorbanuTerminal/pull/2550)** "sync: correct standalone executor package and help fixtures", IridiumMaster, opened 2026-11-17T18:57:46Z, **merged 2026-11-17T19:23:49Z**, merge commit `5b5c85143884c903cdcceecca276c06f6f9eee94`, head `2a17430dc2fb6f45d0475a70e9cd8165d7ab676d`, base `sync/upstream-rust-v0.167.0`. Body: "Refs #2277 … its initialize response is `0.0.0` instead of Cargo's `0.1.48`." (`raw/pr-2550.json`)
   - Changed files: `codex-rs/exec-server-cli/tests/standalone.rs` (+27/−4), `codex-rs/exec-server-cli/src/snapshots/…standalone_help_documents_executor_options.snap` (+3/−3). (`raw/pr-2550-files.json`, `raw/pr-2550.diff`)
   - Diff: `standalone_initializes_reports_version_and_runs_helpers` now runs the binary from a disposable package dir with `codex-package.json {"version": CARGO_PKG_VERSION}` and asserts `executorVersion == CARGO_PKG_VERSION`; a new `source_standalone_reports_source_version_and_runs_helpers` asserts `"0.0.0"` for the unpackaged source binary. That is the maintainer's design, recorded as fact, not endorsed or claimed here.
3. **Closure record, 2026-11-17T19:23:57Z** — [#2277 comment 6958479639](https://github.com/CorbanuCore/CorbanuTerminal/issues/2277#issuecomment-6958479639): "#2550: … The original version test confused unpackaged source metadata with release metadata; it now retains the packaged-version assertion through a real package fixture … Final package **35/0, no skips**". exec-server-cli row: 32 passed / 2 failed before the repair at sync `e0391e82dd`.
4. **Distinct from PR #2273** (merged 2026-11-15T11:31:10Z, compile fixes above core; `raw/pr-2273.json`): #2273 made the crate compile; the version failure appeared afterwards in the #2277 run and was repaired only by #2550.

A citadelculture PR would duplicate a merged maintainer fix, so the task's ownership/duplication stop condition applies.

## Work performed (only this)
- 2026-11-24 GitHub API readback of the issue, the two comments, PRs #2550/#2273 and #2550's diff (all in `raw/`).
- No code, no PR, no tests. No reproduction was run; nothing here claims #2550's result as ours.

## Proof limits
- #2550's 35/0 result is the maintainer's; not re-run here (no macOS/Linux replay of that package).
- Our task was accepted 2026-11-15T09:14Z and not started before the 2026-11-17 merge.

## Requested issuer disposition
Accept as a source-backed paid stop: the residual was claimed (comment 6957772565) and merged (PR #2550, `5b5c8514`) by the maintainer before we built.
