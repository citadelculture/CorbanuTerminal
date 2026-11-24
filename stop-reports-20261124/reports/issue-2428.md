# Stop closeout: Fix Issue2428 Sync Heredoc Amendment or Submit Stop

- **Task:** `task_52f27f81da5b5f8465085dd755dbb98a` · **Date:** 2026-11-24 · **Source:** https://github.com/CorbanuCore/CorbanuTerminal/issues/2428 (closed)
- **Accepted:** 2026-11-16T15:37:40.405499+00:00 · **Resolved upstream:** 3.2 h after acceptance

**Sources (re-read 2026-11-24):** Closed 2026-11-16T18:49:44Z by @IridiumMaster. Closing comment (2026-11-16T18:49:43Z): "Fixed by #2438, merged into sync/upstream-rust-v0.167.0. Wrapped top-level heredocs no longer propose remembered-command amendments; main #2396 parity restored. The regression fails before the fix and 122 focused exec-policy tests pass on both macOS and Linux. Exact-head independent Opus APPROVE and…" PRs named there: #2396, #2438. Issue: https://github.com/CorbanuCore/CorbanuTerminal/issues/2428

**Actual blocker:** Resolved upstream by the maintainer (#2396, #2438); a citadelculture PR would duplicate merged work.

**Work performed:** a dated source and ownership recheck on 2026-11-24 (GitHub issue, closing PR and timeline readback, raw in `sources.json`). No code was written and no PR was opened for this task; nothing here claims an implementation, a test result or the other author's fix.

**Why it was not built first:** our engineering loop was not running from 2026-11-13 to 2026-11-24, so this accepted task was not started before the upstream resolution.

**Proof limits:** the upstream fix's tests were not re-run here; the resolution is taken from the merged PR and the maintainer's closing record.

**Requested issuer disposition:** close as a source-backed stop (resolved/claimed upstream), under whatever the stop-closeout policy of this task allows.
