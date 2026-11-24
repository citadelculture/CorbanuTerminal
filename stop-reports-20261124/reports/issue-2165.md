# Stop closeout: Fix Issue2165 Chroot-Wrapped Exec-Policy Enforcement and Ship PR

- **Task:** `task_48256c8f78d308a1f145d572a8c0fe1c` · **Date:** 2026-11-24 · **Source:** https://github.com/CorbanuCore/CorbanuTerminal/issues/2165 (closed)
- **Accepted:** 2026-11-14T17:48:20.451331+00:00 · **Resolved upstream:** 40.3 h after acceptance

**Sources (re-read 2026-11-24):** Closed by @IridiumMaster. Closing comment (2026-11-16T10:06:33Z): "Fixed on main by #2396 under owner decision D553(a). Exec-policy allow/prompt/forbidden rules now apply at every sudo/chroot/env wrapper layer and to the inner command; the stricter result wins." PRs named there: #2396. Issue: https://github.com/CorbanuCore/CorbanuTerminal/issues/2165

**Actual blocker:** Resolved upstream by the maintainer (#2396); a citadelculture PR would duplicate merged work. (#2396 reuses the wrapper classification citadelculture contributed in #1837, per the maintainer's 2026-11-16T08:08Z comment; this task's own scope was implemented by the maintainer.)

**Work performed:** a dated source and ownership recheck on 2026-11-24 (GitHub issue, closing PR and timeline readback, raw in `sources.json`). No code was written and no PR was opened for this task; nothing here claims an implementation, a test result or the other author's fix.

**Why it was not built first:** our engineering loop was not running from 2026-11-13 to 2026-11-24, so this accepted task was not started before the upstream resolution.

**Proof limits:** the upstream fix's tests were not re-run here; the resolution is taken from the merged PR and the maintainer's closing record.

**Requested issuer disposition:** close as a source-backed stop (resolved/claimed upstream), under whatever the stop-closeout policy of this task allows.
