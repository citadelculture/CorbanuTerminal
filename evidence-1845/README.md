# #1845 evidence packet (item 1, zsh `[[ … ]]` short-loop part only)

- **PR:** https://github.com/CorbanuCore/CorbanuTerminal/pull/ (see PR link in the comment)
- **Base:** main `cea7ffa7ee160bd3b681bb59ff79dbfd750c9e9c`
- **Head:** `c922bd363d9485b927c1ee3abd550dd3984dd070`, DCO `Signed-off-by: citadelculture <citadelculture@gmail.com>`
- **Changed files** (`changed-files.txt`, `fix.diff`): `tainted_action/code_tables.rs` (+12) and `tainted_action_tests.rs` (+54).

**Change:** `code_tables::writes_table` read a zsh `[[` test as the command and stopped, so in a short loop (`if [[ 1 ]] read -A functions`) the writer after it was never judged. The walk now continues past the test's `]]`. Each word is read once, and the change only adds prompts.

**Results** (Mac, rustc 1.99.1, run from `codex-rs/`, with `CARGO_INCREMENTAL=0 RUST_MIN_STACK=16777216`):

| run | command | result |
|---|---|---|
| red (main's `code_tables.rs` + the new tests) | `cargo test -p codex-core --lib issue1845` | regression test FAILED, linearity ok (`red.log`) |
| green (head) | same | 2 passed, 0 failed (`green.log`) |
| suite | `cargo test -p codex-core --lib security::tainted_action` | 338 passed, 0 failed (`suite.log`) |
| clippy | `cargo clippy -p codex-core --tests -- -D warnings` | exit status 0 (`clippy.log`) |
| fmt | `cargo fmt -p codex-core --check` | exit status 0 (`fmt.log`) |

**Never-quieter-than-main sweep** (`sweep-report.txt`):
- **Corpus:** 5,574 shell lines (`sweep-lines.txt`): every shell-like string literal in the classifier's test files, plus `tainted_action/grammar_corpus.txt`.
- **Method:** each line was classified in bash and zsh, once with main's `code_tables.rs` (`sweep-main.tsv`) and once with the PR's (`sweep-head.tsv`), using `sweep_dump_test.rs`.
- **Result:** 11,148 verdicts compared. **0 are quieter than main** and 0 changed kind. 14 newly ask, which are exactly the 7 regression lines × 2 shells.

**Limitations:**
- This isn't the maintainers' ~166k real-command corpus, which isn't available here.
- Native Windows wasn't run (not required).
- The full workspace suite wasn't run; CI runs it.

**Scope:** redirections (#1794), item 2's lexer corners, item 3's obfuscation, #1840/D410 and the #1704 target rules are all untouched.
