# #2407 item 2 evidence packet

- **PR:** https://github.com/CorbanuCore/CorbanuTerminal/pull/2916
- **Base:** `5c05a8bb80359f57f589a1b9a2b558147a075650` · **Head:** `8112c24f1169b323c6a940d0c7541d94e4c06ce0` (DCO `Signed-off-by: citadelculture`, see `api-readback.txt`)
- **Changed:** see `changed-files.txt` and `fix.diff`. Production code: `tui/src/app/input.rs` (+7) and the `ChatWidget::cancel_pending_burst_submission` passthrough. Everything else is test code or `#[cfg(test)]`.

Environment: macOS 26 (Darwin 25.6.0) aarch64, Rust 1.99.1, run from `codex-rs/` with `CARGO_INCREMENTAL=0 RUST_MIN_STACK=16777216`.

| run | log | result |
|---|---|---|
| red: base `app/input.rs` + head tests | `red.log` | 2 passed, 2 failed (Ctrl+T leaves Enter armed; Ctrl+G seed empty); exit 101 |
| green: head | `green.log` | 4 passed; exit 0 |
| full `cargo test -p codex-tui --lib` at head | `suite.log` | 4800 passed, 3 failed (see below); exit 101 |
| the 3 suite failures, run alone on base | `base-preexisting-failures.log` | 2 fail on base too (de-CH locale snapshot, rate-limit snapshot); `sec_437` passes alone |
| `sec_437` alone at head, 3 runs | `sec437-head.log` | 3/3 passed (fails only inside the full parallel run) |
| clippy `--tests -D warnings` | `clippy.log` | exit 0 |
| fmt `--check` | `fmt.log` | exit 0 |

**Controlled clock:** `arm_burst_enter_for_tests` types the burst at 1 ms spacing from a test-chosen `Instant` and holds the Enter. Each case then checks whether a submission would fire at `now + 1s`, so the result doesn't depend on the wall clock. The real Ctrl+T / Ctrl+G events go through `App::handle_key_event`.

**Semantics:** a held Enter cancelled by these shortcuts is dropped and its burst text kept as the draft. That is the existing behaviour for every Ctrl/Alt key that reaches ChatWidget (`chatwidget/interaction.rs`).

**Not run / limits:** Linux and Windows (left to CI), and no live-terminal check of the real 32 ms timing. Items 1 and 3 of #2407 are out of scope.

`SHA256SUMS` covers every file except itself. Replay: `replay.sh`.
