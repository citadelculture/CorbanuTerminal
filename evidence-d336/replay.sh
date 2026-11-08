#!/usr/bin/env bash
# Replays the D336 red/green runs of CorbanuTerminal PR #1736.
# Needs bash, git and python3 (no third-party packages). Run from any
# directory; it clones into a temporary folder and prints both logs.
set -euo pipefail
BASE=ca204cfefe11ea25e2c8d9973ba6779687a9c686   # main before the PR (PR base)
HEAD=e9a0cf6ca714c84f1ce4f1ecec95795843573d6a   # PR head (D336 commit)
work="$(mktemp -d)"
git clone -q https://github.com/CorbanuCore/CorbanuTerminal.git "$work/repo"
cd "$work/repo"
git fetch -q https://github.com/citadelculture/CorbanuTerminal.git "$HEAD" 2>/dev/null \
  || git fetch -q origin "pull/1736/head"
git checkout -q "$HEAD"
echo "== RED: base sdk.yml ($BASE) + head test"
git checkout -q "$BASE" -- .github/workflows/sdk.yml
python3 .github/scripts/test_sdk_path_filter.py || echo "exit=$?"
echo "== GREEN: head sdk.yml + head test"
git checkout -q "$HEAD" -- .github/workflows/sdk.yml
python3 .github/scripts/test_sdk_path_filter.py && echo "exit=0"
