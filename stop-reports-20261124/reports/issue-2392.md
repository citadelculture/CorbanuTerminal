# Stop closeout: Fix Issue2392 Snapshot Credential Paths or Stop

- **Task:** `task_d0aff62428b84d373cc63250b7e4a63c` · **Date:** 2026-11-24 · **Source:** https://github.com/CorbanuCore/CorbanuTerminal/issues/2392 (closed)
- **Accepted:** 2026-11-16T08:11:01.674550+00:00 · **Resolved upstream:** 11.8 h after acceptance

**Sources (re-read 2026-11-24):** Closed 2026-11-16T19:58:14Z by @IridiumMaster. Closing comment (2026-11-16T19:58:13Z): "Both parts are done, so I'm closing this. - **Part 1** (false 'unmasked credentials' warning from `restore_fallback` under main's engine, and the dropped broker markers): fixed by #2397 under D653 (a). Merged into `sync/upstream-rust-v0.167.0` as ee8d1d4aa8. - **Part 2** (shared snapshot helpers): f…" PRs named there: #2397, #2399, #2402. Issue: https://github.com/CorbanuCore/CorbanuTerminal/issues/2392

**Actual blocker:** Resolved upstream by the maintainer (#2397, #2399, #2402); a citadelculture PR would duplicate merged work.

**Work performed:** a dated source and ownership recheck on 2026-11-24 (GitHub issue, closing PR and timeline readback, raw in `sources.json`). No code was written and no PR was opened for this task; nothing here claims an implementation, a test result or the other author's fix.

**Why it was not built first:** our engineering loop was not running from 2026-11-13 to 2026-11-24, so this accepted task was not started before the upstream resolution.

**Proof limits:** the upstream fix's tests were not re-run here; the resolution is taken from the merged PR and the maintainer's closing record.

**Requested issuer disposition:** close as a source-backed stop (resolved/claimed upstream), under whatever the stop-closeout policy of this task allows.
