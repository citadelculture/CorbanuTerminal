# Stop closeout: Fix Issue2143 CODEX_HOME Symlink Opt-Out and Ship PR

- **Task:** `task_234be5d87a6360c59cb6d06070ccef17` · **Date:** 2026-11-24 · **Source:** https://github.com/CorbanuCore/CorbanuTerminal/issues/2143 (closed)
- **Accepted:** 2026-11-14T12:08:38.604745+00:00 · **Resolved upstream:** 42.5 h after acceptance

**Sources (re-read 2026-11-24):** Closed 2026-11-16T06:38:46Z by @IridiumMaster. Closing comment (2026-11-16T06:38:45Z): "Fixed by #2385 (merged into the sync branch as 68c3b767e5). - Seatbelt ordering: the runner's TMPDIR is `/var/folders/...`, so the cwd was spelled `/var/...` while its writable root resolved to `/private/var/...`; a default `.codex` carve-out then escaped the spelling check and stayed ahead of the e…" PRs named there: #2385. Issue: https://github.com/CorbanuCore/CorbanuTerminal/issues/2143

**Actual blocker:** Resolved upstream by the maintainer (#2385); a citadelculture PR would duplicate merged work.

**Work performed:** a dated source and ownership recheck on 2026-11-24 (GitHub issue, closing PR and timeline readback, raw in `sources.json`). No code was written and no PR was opened for this task; nothing here claims an implementation, a test result or the other author's fix.

**Why it was not built first:** our engineering loop was not running from 2026-11-13 to 2026-11-24, so this accepted task was not started before the upstream resolution.

**Proof limits:** the upstream fix's tests were not re-run here; the resolution is taken from the merged PR and the maintainer's closing record.

**Requested issuer disposition:** close as a source-backed stop (resolved/claimed upstream), under whatever the stop-closeout policy of this task allows.
