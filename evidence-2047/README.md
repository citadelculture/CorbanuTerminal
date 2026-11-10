# #2047 evidence packet

- **PR:** https://github.com/CorbanuCore/CorbanuTerminal/pull/2076
- **Base:** `27b317cad7a08cdb771095496e3f4b913b85afd8`
- **Head:** `fb4419930e6a5e7852e92bcdf418eed1dfad16de`. DCO confirmed by API readback (`api-readback.txt`).
- **Changed files:** see `changed-files.txt` and `fix.diff`.

**Commands** (macOS, rustc 1.99.1, run from `codex-rs/`, with `CARGO_INCREMENTAL=0 RUST_MIN_STACK=16777216`):

| run | command | exit / result |
|---|---|---|
| red: base `session/input_queue.rs` + head tests (`red.log`) | `cargo test -p codex-core --lib session::` | 402 passed, 1 failed: `get_pending_input_without_active_turn_leaves_mailbox_mail_queued` |
| green: head (`green.log`) | same | 403 passed, 0 failed |
| clippy (`clippy.log`) | `cargo clippy -p codex-core --tests -- -D warnings` | exit status 0 |
| fmt (`fmt.log`) | `cargo fmt -p codex-core --check` | exit status 0 |

**Replay:** check out the head commit (`git fetch https://github.com/citadelculture/CorbanuTerminal.git fb4419930e6a5e7852e92bcdf418eed1dfad16de`) and run the commands above. For the red run, first do `git checkout 27b317cad7a08cdb771095496e3f4b913b85afd8 -- codex-rs/core/src/session/input_queue.rs`.

**Scope:**
- Production behavior is unchanged: the removed branch was reachable only from `#[cfg(test)]`.
- The four rewritten checks keep their assertions; `drain_mailbox_input_items` drains exactly as the old helper did there.
- Not run: the full workspace suite. `SHA256SUMS` covers every file here except itself.
