#!/usr/bin/env bash
# Read-only re-fetch of every source cited. Compare with raw/ (live fields like updated_at may move).
set -euo pipefail
R=CorbanuCore/CorbanuTerminal; S=18302669eff6a197b4cf193a403222c28aa2a3bb
out=${1:-replay-out}; mkdir -p "$out"
gh api repos/$R/issues/comments/6957772565 --jq .body > "$out/2277-claim.txt"
gh api repos/$R/pulls/2550 --jq '[.merged_at,.merge_commit_sha,.base.ref]|@tsv' > "$out/pr-2550.tsv"
gh pr diff 2550 -R $R > "$out/pr-2550.diff"
gh api repos/$R/issues/comments/6911191840 --jq .body > "$out/1532-residual.txt"
for n in 2393 2452 2458 2840 2405 2436 2916; do gh api repos/$R/pulls/$n --jq '[.number,.state,.merged_at,.merge_commit_sha,.base.ref,.head.sha]|@tsv'; done > "$out/prs.tsv"
gh api "repos/$R/contents/codex-rs/core/src/tasks/mod.rs?ref=$S" -H "Accept: application/vnd.github.raw" | grep -n "remain queued" > "$out/sync-wrapper.txt"
gh api "repos/$R/contents/codex-rs/core/src/client.rs?ref=$S" -H "Accept: application/vnd.github.raw" | grep -n "not kept" > "$out/sync-notkept.txt"
gh api repos/$R/issues/2407 --jq '[.state,(.assignees|length)]|@tsv' > "$out/2407.tsv"
echo "replay ok: $out"
