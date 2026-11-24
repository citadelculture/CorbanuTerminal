# Stop closeout: Fix Issue2446 Connection Reuse or Submit Stop

- **Task:** `task_4742e4c6626c4ede92b8406a18841f95` · **Date:** 2026-11-24 · **Source:** https://github.com/CorbanuCore/CorbanuTerminal/issues/2446 (closed)
- **Accepted:** 2026-11-16T20:29:31.408555+00:00 · **Resolved upstream:** 1.4 h after acceptance

**Sources (re-read 2026-11-24):** Closed 2026-11-16T21:51:48Z by @IridiumMaster. Closing comment (2026-11-16T21:51:46Z): "Fixed on the SYNC branch by merged PR #2449, merge `53eb2ce930cd06eb9ba7daa3ef16ecabc8df5b42` (reviewed head `1bd3749e95ac66c084e39cfb09d68279a48aac1c`). The builder disables transport pooling so the server cannot defeat Connection: close. Original regression unchanged; final glitch Rust 1.99.1 -j10…" PRs named there: #2449. Issue: https://github.com/CorbanuCore/CorbanuTerminal/issues/2446

**Actual blocker:** Resolved upstream by the maintainer (#2449); a citadelculture PR would duplicate merged work.

**Work performed:** a dated source and ownership recheck on 2026-11-24 (GitHub issue, closing PR and timeline readback, raw in `sources.json`). No code was written and no PR was opened for this task; nothing here claims an implementation, a test result or the other author's fix.

**Why it was not built first:** our engineering loop was not running from 2026-11-13 to 2026-11-24, so this accepted task was not started before the upstream resolution.

**Proof limits:** the upstream fix's tests were not re-run here; the resolution is taken from the merged PR and the maintainer's closing record.

**Requested issuer disposition:** close as a source-backed stop (resolved/claimed upstream), under whatever the stop-closeout policy of this task allows.
