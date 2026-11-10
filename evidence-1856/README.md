# #1856 option 3 evidence packet

- **PR:** https://github.com/CorbanuCore/CorbanuTerminal/pull/1864 (`api-pr-1864.json`, `api-readback.txt`)
- **Base:** main `d0002812b4aed3032580cc47b661cf394097cc5c`
- **Head:** `d359ed66ee9c1c452a96d458aa9ac56e0704bcc4`. The DCO line `Signed-off-by: citadelculture <citadelculture@gmail.com>` was confirmed by API readback (`api-commit-head.json`).
- **Changed files** (`changed-files.txt`, `fix.diff`): `.github/workflows/bazel.yml`, `docs/ci.md`, and `.github/scripts/test_windows_integration_disclosure.py`.

**Scope:** reporting and docs only. When a Windows gnullvm cross shard skips its bazel test step (no BuildBuddy), its notice and job summary say so, and `docs/ci.md` documents the cross shards.
- Integration tests are **not** enabled, and no Windows execution or proof is claimed.
- Unchanged: which tests run, the gates, authentication, platforms and outcomes.
- **Wording follows the maintainers' review:** the issue's original premise was too broad, because the native lane runs most crates' integration tests. Only the shard's own skip is stated, and the nightly line is unchanged.
- **Excluded:** #1852, #1812, and the D314/D336 triggers.

**Results** (macOS, Python 3.13, git 2.39.5, Node via npx):

| check | file | result |
|---|---|---|
| first version: red on main, green on the first head | `red.log`, `green.log` | 2 FAIL → 4 OK |
| reviewed version (current head) | `r2-green.log` | 4/4 OK, exit 0 |
| Prettier 3.5.3 `--check` on `bazel.yml` and `docs/ci.md` (the `repo-checks` format step) | `r2-prettier.log` | pass, exit 0 |
| YAML parse (`ruby -ryaml`) | `r2-yaml.log` | ok |
| `.github/scripts` suite | `scripts-*` | identical local failures on main and head (missing modules) |

**Replay:** `bash replay.sh`.

**Not run:** any Windows job, and `actionlint` (not installed). `SHA256SUMS` covers every file here except itself.
