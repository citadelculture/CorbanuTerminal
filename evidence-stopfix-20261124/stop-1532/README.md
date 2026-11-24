# Stop closeout (revised): Issue #1532 queued-message diagnostics residual

- Task: `task_e0b956043be1322cf0cab86cb8954690` · Report date: 2026-11-24 · Replaces `717fb29…/stop-reports-20261124/reports/issue-1532.md`, which wrongly inferred overlap from tracker PR volume and mentioned a closing record. #1532 is **OPEN** and the residual is **not** shown absorbed.

## The residual (separate from PR #2393 — preserved)
[#1532 comment 6911191840](https://github.com/CorbanuCore/CorbanuTerminal/issues/1532#issuecomment-6911191840), IridiumMaster, 2026-11-16T08:21:42Z, on PR #2393 head `d006b4dc9d`: Opus round 1 "noted a low, nonblocking follow-up: the queued-agent-message wrapper can combine 'messages remain queued' with the detached-child refusal's 'This message was not kept', and idle wake-up may emit the refusal instead of `NotSubmitted`. … left here without expanding the owner-decision patch." (`raw/comment-6911191840.json`)
PR [#2393](https://github.com/CorbanuCore/CorbanuTerminal/pull/2393) merged 2026-11-16T09:21:20Z (`0e962a49`) without it. No credit for #2393 is claimed.

## Current source state (sync head `18302669eff6a197b4cf193a403222c28aa2a3bb`, 2026-11-24T09:31:41Z)
- `core/src/tasks/mod.rs:620` still formats any `turn_refusal` error as `"Agent messages remain queued: {err}. After recovery, …"`.
- `core/src/client.rs:1293` still returns the detached-child refusal ending "This message was not kept."
- Both files saved in `raw/`. Only the coexistence of the two strings was checked; no run reproduced the combined message.

## Later maintainer work on the same function (none claims the residual)
| PR | Merged | Touches | Residual addressed? |
|---|---|---|---|
| [#2452](https://github.com/CorbanuCore/CorbanuTerminal/pull/2452) D659–D664 | 2026-11-17T00:03:11Z `b6f84e18` | `tasks/mod.rs` reserve/refusal order | No; wrapper string kept |
| [#2458](https://github.com/CorbanuCore/CorbanuTerminal/pull/2458) | 2026-11-17T02:10:24Z `d7451716` | `tasks/mod.rs` refusal before mail consumption | No |
| [#2840](https://github.com/CorbanuCore/CorbanuTerminal/pull/2840) D742 | 2026-11-20T08:51:59Z `81890da1` | `tasks/mod.rs` idle event order | No |
PR searches for `NotSubmitted`, `"not kept"`, `queued agent message`, `detached-child refusal`: `raw/pr-searches.tsv`. No open or contributor PR claims the residual.

## Actual blocker
Task step 2 requires source-owner or issuer confirmation of the reporting semantics (what the combined message and idle wake should say), approved base and #2393 coordination before engineering, "otherwise use the stop branch". The public record has none: the maintainer deferred the wording as a follow-up and has not stated the intended text or target base, and every change to this function since (#2452, #2458, #2840) went to maintainer-owned owner-decision lanes (D663, D742) on `sync/upstream-rust-v0.167.0`. We cannot post issue comments under our tooling policy, so no confirmation was requested there.

## Work performed (only this)
- 2026-11-24 API readback of #1532, comment 6911191840, PRs #2393/#2452/#2458/#2840, sync branch head, two sync-head source files, PR keyword searches (`raw/`).
- No code, tests, reproduction or PR.

## Proof limits
- Residual presence is from source reading of two strings; the combined message and the idle-wake refusal path were not executed.

## Requested issuer disposition
Either (a) accept this as a paid stop for missing owner confirmation, or (b) state the intended wording for both cases and the target base (sync or main), and the residual can be built as a reporting-only change.
