Fixes item 2 of #2407 only (items 1 and 3 and #2405's raw-key grouping are out of scope).

**Cause.** Ctrl+T (transcript) and Ctrl+G (external editor) are handled in `App::handle_key_event` and never reach `ChatWidget::handle_key_event`, which cancels a held burst Enter for every other Ctrl/Alt key. Inside the 32 ms lookahead:
- Ctrl+T opened the overlay with the submission still armed, so the draft submitted on a later tick.
- Ctrl+G seeded the editor from `composer_text_with_pending()`, which does not include the unmaterialized burst, so the draft was missing.

**Change.** Both handlers first call a new `ChatWidget::cancel_pending_burst_submission()`, which delegates to the existing `BottomPane`/composer cancellation: it drops the held Enter and materializes the burst into the draft, the same thing a Ctrl/Alt key routed to ChatWidget does. Ctrl+G cancels even when the editor can't launch, because the key is consumed either way. Production diff: 7 lines in `app/input.rs` plus the 3-line passthrough. Everything else is `#[cfg(test)]`.

**Tests** (`app/tests/held_enter_shortcuts.rs`, controlled clock: the burst and the held Enter are typed at a test-chosen `Instant` and the deadline is checked at `now + 1s`; the real keys go through `App::handle_key_event`):
- `ctrl_t_transcript_cancels_held_enter_and_keeps_the_draft`: fails on base (Enter still armed), passes at head
- `ctrl_g_editor_seeds_from_held_burst_and_cancels_its_enter`: fails on base (editor seed is empty), passes at head
- controls: `held_burst_enter_submits_without_a_shortcut_control` (the armed Enter really submits) and `ctrl_t_with_ordinary_draft_leaves_it_unchanged`; both pass on base and head

**Runs** (macOS 26 aarch64, Rust 1.99.1, `codex-rs/`):
- `cargo test -p codex-tui --lib held_enter_shortcuts`: base 2 passed / 2 failed (exit 101); head 4 passed (exit 0)
- `cargo test -p codex-tui --lib`: 4800 passed, 3 failed, none of them in input code:
  - `status_snapshot_includes_enterprise_monthly_credit_limit` fails on base too: this Mac's de-CH locale renders `8'000`
  - `rolling_rate_limit_snapshot_preserves_prior_individual_limit` fails on base too
  - `sec_437_thread_settings_keep_the_aggressive_rows` passes alone at head 3/3 (and on base); it only fails inside the full parallel run
- clippy `--tests -D warnings`: 0; fmt `--check`: 0

Not run: Linux and Windows (left to CI), and a live terminal check of the real 32 ms timing.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
