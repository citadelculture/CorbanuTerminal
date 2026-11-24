# Stop closeout: Fix Issue2510 Item1 Cased Shell Checks or Submit Stop

- **Task:** `task_93dff16cfc5e16b2be59ae1bcc5bfdeb` · **Date:** 2026-11-24 · **Source:** https://github.com/CorbanuCore/CorbanuTerminal/issues/2510 (closed)
- **Accepted:** 2026-11-17T09:30:25.168810+00:00 · **Resolved upstream:** 7.9 h after acceptance

**Sources (re-read 2026-11-24):** Closed 2026-11-17T17:22:59Z by @IridiumMaster. Closing comment (2026-11-17T17:22:58Z): "All four items are done.  - **Items 1–3** shipped in #2523, merge commit 8e1ffa79. - **Item 4 (D692 option a)** shipped in #2537, merge commit d3a8020e. On macOS and Windows, forbidden and prompt rules now match program names in any case. Allow rules still need the exact name. On Windows, main's hos…" PRs named there: #2523, #2537. Issue: https://github.com/CorbanuCore/CorbanuTerminal/issues/2510

**Actual blocker:** Resolved upstream by the maintainer (#2523, #2537); a citadelculture PR would duplicate merged work.

**Work performed:** a dated source and ownership recheck on 2026-11-24 (GitHub issue, closing PR and timeline readback, raw in `sources.json`). No code was written and no PR was opened for this task; nothing here claims an implementation, a test result or the other author's fix.

**Why it was not built first:** our engineering loop was not running from 2026-11-13 to 2026-11-24, so this accepted task was not started before the upstream resolution.

**Proof limits:** the upstream fix's tests were not re-run here; the resolution is taken from the merged PR and the maintainer's closing record.

**Requested issuer disposition:** close as a source-backed stop (resolved/claimed upstream), under whatever the stop-closeout policy of this task allows.
