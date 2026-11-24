# Raw readback: issue #2143 and PR #2385 (2026-11-24)

Captured with:
```
gh issue view 2143 --repo CorbanuCore/CorbanuTerminal --json state,stateReason,closedAt,closedByPullRequestsReferences,comments,title > issue-2143.json
gh api repos/CorbanuCore/CorbanuTerminal/issues/2143 --jq '{state,closed_at,closed_by:.closed_by.login}' > issue-2143-closed-by.json
gh pr view 2385 --repo CorbanuCore/CorbanuTerminal --json number,title,state,mergedAt,mergeCommit,baseRefName,headRefOid,author,files,url > pr-2385.json
gh api 'repos/CorbanuCore/CorbanuTerminal/issues/2143/timeline?per_page=100' > issue-2143-timeline.json
gh pr diff 2385 -R CorbanuCore/CorbanuTerminal > pr-2385.diff
```
(`closedBy` is not a `gh issue view` field; the REST `closed_by` is used instead.)

- #2143: closed 2026-11-16T06:38:46Z by IridiumMaster; closing comment 2026-11-16T06:38:45Z reads "Fixed by #2385 (merged into the sync branch as 68c3b767e5)" and names the item-3 test `codex_home_symlink_opt_out_respects_host_config_and_scope`, renamed `codex_home_symlink_roots_write_at_their_real_location`.
- #2385: MERGED 2026-11-16T06:38:30Z, merge commit `68c3b767e517c46d02b61b2c316cb2b640af95fb`, base `sync/upstream-rust-v0.167.0`, author IridiumMaster; files `codex-rs/exec-server/tests/exec_process.rs`, `codex-rs/protocol/src/permissions.rs`. `pr-2385.diff` shows the rename of the item-3 symlink opt-out test.
- No work by us is claimed in #2385.
