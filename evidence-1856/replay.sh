#!/usr/bin/env bash
# Replays the #1856 checks at the PR head. Needs bash, git, python3 (and npx for Prettier).
set -euo pipefail
HEAD=d359ed66ee9c1c452a96d458aa9ac56e0704bcc4
work="$(mktemp -d)"
git clone -q https://github.com/CorbanuCore/CorbanuTerminal.git "$work/repo"
cd "$work/repo"
git fetch -q https://github.com/citadelculture/CorbanuTerminal.git "$HEAD" || git fetch -q origin pull/1864/head
git checkout -q "$HEAD"
python3 .github/scripts/test_windows_integration_disclosure.py
npx --yes prettier@3.5.3 --check .github/workflows/bazel.yml docs/ci.md
