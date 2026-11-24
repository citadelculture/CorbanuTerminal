#!/bin/sh
set -e
R=CorbanuCore/CorbanuTerminal; O=replay-out; mkdir -p $O
gh api repos/$R/issues/2088 --jq '{state,closed_at,updated_at}' > $O/issue-2088.json
gh api "repos/$R/issues/2088/comments?per_page=100" --jq '[.[]|{user:.user.login,created_at}]' > $O/comments.json
gh api repos/$R/pulls/2087 --jq '{merged_at,merge_commit_sha}' > $O/pr-2087.json
gh api repos/$R/pulls/2257 --jq '{merged_at,merge_commit_sha}' > $O/pr-2257.json
cat $O/*.json
