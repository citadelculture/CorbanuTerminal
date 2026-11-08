# D336 evidence packet: CorbanuTerminal PR #1736

**Scope.** This covers only the D336 increment: the TypeScript SDK job also runs when a PR changes the root `package.json`, `pnpm-workspace.yaml` or `.npmrc`. The maintainer invited it on 2026-11-07T17:56:13Z ([comment](https://github.com/CorbanuCore/CorbanuTerminal/pull/1736#issuecomment-6710978392), `api-invitation-comment.json`).

**Not claimed here:**
- D314 (lockfiles), already paid, which landed in #1692.
- D287 (the original path filter).
- The harness `test_sdk_path_filter.py` as such, written earlier for D314.
- Anything else in #1692.

**Pinned commits** (independently fetched in `api-pr-1736.json`):
- Base (PR base): `ca204cfefe11ea25e2c8d9973ba6779687a9c686`
- Head (the D336 commit): `e9a0cf6ca714c84f1ce4f1ecec95795843573d6a`, whose parent is `5b94c9a5ef`, a merge of main.
- Merged as `2e85e24e91b40990e2daab190b5970040a3592ab` at 2026-11-07T19:36:16Z. Merging was not required for this task.

**Scoped diff** (`d336-scoped.diff`, head^ → head):
- `.github/workflows/sdk.yml` (+5): the `case` arm `package.json | pnpm-workspace.yaml | .npmrc` and the D336 comment.
- `.github/scripts/test_sdk_path_filter.py` (+15/−1): 11 new cases and the docstring.
- `base-to-head.diff` shows the whole PR against base, including the pre-existing harness.

**Results** (`red.log`, `green.log`, `cases-base.log`, `cases-head.log`):

| | sdk.yml from | test from | result |
|---|---|---|---|
| red | base | head | `FAILED (failures=6)`: exactly the 6 new root-file "runs" cases |
| green | head | head | `OK`, all 26 cases right |

The per-case table (`cases.py`) prints all 26 cases with expected and actual results:
- **Runs:** each root file alone and beside an unrelated file, `sdk/typescript/package.json` (through `sdk/typescript/*`), the D314 lockfiles, and the D287 triggers.
- **Skips:** `sdk/python/package.json`, `.devcontainer/codex-install/package.json`, `sdk/python/.npmrc`, `package.json.bak`, other lockfiles, and unrelated files.

The `case`-form detector from main is kept. The only change to the step is one added arm.

**DCO:** the head commit message carries `Signed-off-by: citadelculture <citadelculture@gmail.com>` (`head-commit.txt`, `api-commit-head.json`). No new commit was needed: validation found no D336 defect.

**CI on head** (`api-head-checks.json`): 28 succeeded, 11 skipped, 0 failed.

**Replay:** `bash replay.sh` clones the repo, checks out head, swaps in base's `sdk.yml` (red), restores head's (green), and runs the test. It needs bash, git and python3 only. Alternatively, run `python3 cases.py <repo-root>` on any checkout.

**Limitations:**
- Runs were on macOS (python 3.9.6, git 2.39.5). CI ran Linux.
- The test executes the step's own bash script against real git diffs. It doesn't run the GitHub Actions runner itself.
- The rest of `.github/scripts` wasn't run locally: it has macOS-only failures that are identical on main.
- `SHA256SUMS` covers every file here except itself.
